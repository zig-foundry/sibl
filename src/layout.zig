//! Phase 7.1 – 7.4: Section Grouping, Address/Alignment, Memory Map, and Size Accounting.
//!
//! Groups matching input sections, assigns virtual addresses and file offsets,
//! builds PT_LOAD-style segments, and computes exact file and memory sizes
//! for each segment. Follows ELF gABI rules:
//! - Consecutive sections with the same protection form one segment
//! - Loadable segments are ordered by virtual address
//! - `p_vaddr` and `p_offset` are congruent modulo page size
//! - `p_memsz >= p_filesz` (`.bss` extends memory without file bytes)

const std = @import("std");

/// Normalized input section contributed by an object file.
pub const InputSection = struct {
    /// Original section name (owned by caller or arena).
    name: []const u8,
    /// Raw bytes (empty for NOBITS / .bss).
    data: []const u8,
    /// Required alignment in bytes (at least 1).
    alignment: u64,
    is_alloc: bool,
    is_writable: bool,
    is_executable: bool,
    is_nobits: bool,
    /// Index of the input file that contributed this section.
    file_index: u32,
    /// Index of this section inside the originating object (0-based for ELF
    /// and Mach-O, 1-based for COFF section numbers). Lets the entry resolver
    /// (Phase 9.1) map a symbol back to the member it was defined in.
    /// 0 means "unknown / not tracked".
    section_index: u32 = 0,
};

/// An output section that collects one or more input sections.
pub const OutputSection = struct {
    /// Canonical name (e.g. ".text", ".data").
    name: []const u8,
    /// Input sections that were merged into this output section.
    members: std.ArrayListUnmanaged(InputSection),
    /// Maximum alignment required by any member.
    alignment: u64,
    /// Total size in bytes after merging (including internal padding).
    size: u64,
    /// Final virtual address assigned by layout.
    virtual_address: u64,
    /// Final file offset assigned by layout (0 for pure NOBITS).
    file_offset: u64,
    is_alloc: bool,
    is_writable: bool,
    is_executable: bool,
    is_nobits: bool,

    pub fn deinit(self: *OutputSection, allocator: std.mem.Allocator) void {
        allocator.free(self.name);
        self.members.deinit(allocator);
    }
};

/// Program header / segment flags (ELF PF_* style).
pub const SegmentFlags = struct {
    pub const R: u32 = 4;
    pub const W: u32 = 2;
    pub const X: u32 = 1;
};

/// A loadable segment built from one or more consecutive output sections
/// that share the same memory protection.
pub const Segment = struct {
    /// Virtual address of the first byte.
    virtual_address: u64,
    /// File offset of the first byte (congruent with VA modulo page size).
    file_offset: u64,
    /// Bytes present in the file (excludes trailing NOBITS).
    file_size: u64,
    /// Bytes occupied in memory (includes NOBITS / .bss).
    memory_size: u64,
    /// Alignment (typically the page size).
    alignment: u64,
    /// Protection flags (R/W/X).
    flags: u32,
    /// Indices of output sections that belong to this segment.
    section_indices: std.ArrayListUnmanaged(usize),

    pub fn deinit(self: *Segment, allocator: std.mem.Allocator) void {
        self.section_indices.deinit(allocator);
    }

    pub fn isReadable(self: Segment) bool {
        return (self.flags & SegmentFlags.R) != 0;
    }
    pub fn isWritable(self: Segment) bool {
        return (self.flags & SegmentFlags.W) != 0;
    }
    pub fn isExecutable(self: Segment) bool {
        return (self.flags & SegmentFlags.X) != 0;
    }

    /// Return true if p_vaddr and p_offset are congruent modulo alignment.
    pub fn isCongruent(self: Segment) bool {
        if (self.alignment <= 1) return true;
        return (self.virtual_address % self.alignment) == (self.file_offset % self.alignment);
    }
};

/// Final size accounting for one segment (Phase 7.4).
pub const SegmentSize = struct {
    /// Index into `Layout.segments`.
    index: usize,
    /// Bytes stored in the file (`p_filesz`).
    file_size: u64,
    /// Bytes occupied in memory (`p_memsz`).
    memory_size: u64,
    /// Extra zero-filled bytes in memory (`p_memsz - p_filesz`).
    bss_size: u64,
    /// Virtual address of the first byte.
    virtual_address: u64,
    /// File offset of the first byte.
    file_offset: u64,
};

/// Aggregate size report for the whole image.
pub const SizeReport = struct {
    /// Sum of all segment file sizes.
    total_file_size: u64,
    /// Sum of all segment memory sizes.
    total_memory_size: u64,
    /// Highest virtual address used (end of last ALLOC section).
    virtual_end: u64,
    /// Highest file offset used.
    file_end: u64,
    /// Per-segment breakdown.
    segments: []SegmentSize,
};
pub const Error = error{
    OutOfMemory,
    EmptyName,
    /// `pinOutput` was called twice on the same output section with
    /// different addresses (Phase 9.2).
    PinConflict,
};

/// Layout engine that groups input sections and assigns addresses.
pub const Layout = struct {
    sections: std.ArrayListUnmanaged(OutputSection),
    segments: std.ArrayListUnmanaged(Segment),
    allocator: std.mem.Allocator,
    /// Preferred base virtual address (e.g. 0x400000 for non-PIE ELF).
    base_address: u64,
    /// Target page size used for protection-boundary alignment.
    page_size: u64,
    /// Virtual-address pins set by placement rules (Phase 9.2).
    /// Key: canonical output section name (heap-owned). Value: pinned VA.
    address_overrides: std.StringHashMapUnmanaged(u64),

    pub fn init(allocator: std.mem.Allocator, base_address: u64, page_size: u64) Layout {
        return .{
            .sections = .empty,
            .segments = .empty,
            .allocator = allocator,
            .base_address = base_address,
            .page_size = if (page_size == 0) 4096 else page_size,
            .address_overrides = .empty,
        };
    }

    pub fn deinit(self: *Layout) void {
        for (self.sections.items) |*sec| {
            sec.deinit(self.allocator);
        }
        self.sections.deinit(self.allocator);
        for (self.segments.items) |*seg| {
            seg.deinit(self.allocator);
        }
        self.segments.deinit(self.allocator);
        var pit = self.address_overrides.iterator();
        while (pit.next()) |pin_entry| {
            self.allocator.free(pin_entry.key_ptr.*);
        }
        self.address_overrides.deinit(self.allocator);
        self.* = undefined;
    }

    /// Number of output sections created so far.
    pub fn count(self: *const Layout) usize {
        return self.sections.items.len;
    }

    /// Look up an output section by canonical name.
    pub fn get(self: *const Layout, name: []const u8) ?*const OutputSection {
        for (self.sections.items) |*sec| {
            if (std.mem.eql(u8, sec.name, name)) return sec;
        }
        return null;
    }

    /// Add an input section, grouping it with compatible existing output sections.
    ///
    /// Grouping rules (Phase 7.1):
    /// - Canonicalize names (`.text.foo` → `.text`, `.rodata.str1.1` → `.rodata`)
    /// - Only merge sections with compatible flags (ALLOC / WRITE / EXEC / NOBITS)
    /// - First occurrence determines the output section order
    pub fn addInput(self: *Layout, input: InputSection) Error!void {
        if (input.name.len == 0) return error.EmptyName;

        const canon = canonicalizeName(input.name);

        // Try to find an existing compatible output section.
        for (self.sections.items) |*out| {
            if (std.mem.eql(u8, out.name, canon) and flagsCompatible(out, &input)) {
                try out.members.append(self.allocator, input);
                if (input.alignment > out.alignment) out.alignment = input.alignment;
                return;
            }
        }

        // Create a new output section.
        const owned_name = try self.allocator.dupe(u8, canon);
        errdefer self.allocator.free(owned_name);

        var members: std.ArrayListUnmanaged(InputSection) = .empty;
        try members.append(self.allocator, input);

        try self.sections.append(self.allocator, .{
            .name = owned_name,
            .members = members,
            .alignment = @max(input.alignment, 1),
            .size = 0,
            .virtual_address = 0,
            .file_offset = 0,
            .is_alloc = input.is_alloc,
            .is_writable = input.is_writable,
            .is_executable = input.is_executable,
            .is_nobits = input.is_nobits,
        });
    }

    /// Pin an output section at an exact virtual address (Phase 9.2).
    ///
    /// `out_name` is the canonical output section name. `computeAddresses`
    /// then places the section at `address` (aligned up to the section's
    /// own alignment) and continues assigning following sections from the
    /// pinned end. Calling `pinOutput` twice on the same section with a
    /// different address is `error.PinConflict`; the same address is fine.
    pub fn pinOutput(self: *Layout, out_name: []const u8, address: u64) Error!void {
        const gop = try self.address_overrides.getOrPut(self.allocator, out_name);
        if (gop.found_existing) {
            if (gop.value_ptr.* != address) return error.PinConflict;
        } else {
            gop.key_ptr.* = try self.allocator.dupe(u8, out_name);
        }
        gop.value_ptr.* = address;
    }

    /// Assign virtual addresses and file offsets to all output sections.
    ///
    /// Rules (Phase 7.2):
    /// - Start at `base_address`
    /// - Align each section to its own alignment
    /// - When crossing a protection boundary (exec ↔ non-exec, or write change),
    ///   also align to page size
    /// - `.bss` / NOBITS contributes to virtual size but not file size
    /// - File offset tracks only non-NOBITS content
    pub fn computeAddresses(self: *Layout) void {
        var va = self.base_address;
        var file_off: u64 = 0;
        var prev_exec = false;
        var prev_write = false;
        var first = true;

        for (self.sections.items) |*out| {
            // Internal merge: sum member sizes with per-member alignment.
            var sec_size: u64 = 0;
            for (out.members.items) |mem| {
                const aligned = alignTo(sec_size, @max(mem.alignment, 1));
                sec_size = aligned + mem.data.len;
            }
            out.size = sec_size;

            // Alignment for this output section.
            var align_req = @max(out.alignment, 1);

            // Page-align when protection changes (best practice for PT_LOAD).
            if (!first) {
                const prot_changed = (out.is_executable != prev_exec) or (out.is_writable != prev_write);
                if (prot_changed and out.is_alloc) {
                    align_req = @max(align_req, self.page_size);
                }
            }

            if (self.address_overrides.get(out.name)) |pin| {
                // Pinned section (Phase 9.2): place it exactly where the
                // rule asked (respecting alignment) and continue from its end.
                const pinned_va = alignTo(pin, align_req);
                out.virtual_address = pinned_va;
                if (out.is_alloc) {
                    va = pinned_va + out.size;
                }
            } else if (out.is_alloc) {
                va = alignTo(va, align_req);
                out.virtual_address = va;
                va += out.size;
            } else {
                out.virtual_address = 0;
            }

            if (!out.is_nobits) {
                file_off = alignTo(file_off, align_req);
                out.file_offset = file_off;
                file_off += out.size;
            } else {
                out.file_offset = 0;
            }

            prev_exec = out.is_executable;
            prev_write = out.is_writable;
            first = false;
        }
    }

    /// Total virtual size of all allocated sections (from base to end).
    pub fn virtualSize(self: *const Layout) u64 {
        var end: u64 = self.base_address;
        for (self.sections.items) |sec| {
            if (sec.is_alloc) {
                const sec_end = sec.virtual_address + sec.size;
                if (sec_end > end) end = sec_end;
            }
        }
        return end - self.base_address;
    }

    /// Total file size occupied by non-NOBITS sections.
    pub fn fileSize(self: *const Layout) u64 {
        var end: u64 = 0;
        for (self.sections.items) |sec| {
            if (!sec.is_nobits) {
                const sec_end = sec.file_offset + sec.size;
                if (sec_end > end) end = sec_end;
            }
        }
        return end;
    }

    /// Number of loadable segments created by `buildSegments`.
    pub fn segmentCount(self: *const Layout) usize {
        return self.segments.items.len;
    }

    /// Build PT_LOAD-style segments from the current section layout.
    ///
    /// Must be called after `computeAddresses`.
    ///
    /// Rules (Phase 7.3):
    /// - Only ALLOC sections participate
    /// - Consecutive sections with identical protection (R/W/X) form one segment
    /// - Segments are ordered by virtual address
    /// - `p_vaddr % page_size == p_offset % page_size`
    /// - `memory_size >= file_size` (NOBITS extends memory)
    /// - Alignment is the page size
    pub fn buildSegments(self: *Layout) Error!void {
        // Clear any previous segments.
        for (self.segments.items) |*seg| {
            seg.deinit(self.allocator);
        }
        self.segments.clearRetainingCapacity();

        var current: ?Segment = null;

        for (self.sections.items, 0..) |sec, idx| {
            if (!sec.is_alloc) continue;

            const flags = protectionFlags(sec.is_writable, sec.is_executable);
            const can_extend = if (current) |*cur|
                cur.flags == flags and sec.virtual_address >= cur.virtual_address
            else
                false;

            if (can_extend) {
                var cur = &current.?;
                try cur.section_indices.append(self.allocator, idx);
                const end_va = sec.virtual_address + sec.size;
                cur.memory_size = end_va - cur.virtual_address;
                if (!sec.is_nobits) {
                    const end_off = sec.file_offset + sec.size;
                    if (end_off > cur.file_offset) {
                        cur.file_size = end_off - cur.file_offset;
                    }
                }
            } else {
                if (current) |seg| {
                    try self.segments.append(self.allocator, seg);
                }
                var indices: std.ArrayListUnmanaged(usize) = .empty;
                try indices.append(self.allocator, idx);

                const file_size: u64 = if (sec.is_nobits) 0 else sec.size;
                current = .{
                    .virtual_address = sec.virtual_address,
                    .file_offset = if (sec.is_nobits) 0 else sec.file_offset,
                    .file_size = file_size,
                    .memory_size = sec.size,
                    .alignment = self.page_size,
                    .flags = flags,
                    .section_indices = indices,
                };
            }
        }

        if (current) |seg| {
            try self.segments.append(self.allocator, seg);
        }

        // Enforce congruence: adjust file_offset so it matches VA modulo page size.
        for (self.segments.items) |*seg| {
            if (seg.alignment > 1) {
                const va_mod = seg.virtual_address % seg.alignment;
                const off_mod = seg.file_offset % seg.alignment;
                if (va_mod != off_mod) {
                    // Bump file offset up to the next congruent value.
                    const delta = if (va_mod >= off_mod)
                        va_mod - off_mod
                    else
                        seg.alignment - (off_mod - va_mod);
                    seg.file_offset += delta;
                }
            }
        }
    }

    /// Finalize per-segment file and memory sizes (Phase 7.4).
    ///
    /// Must be called after `buildSegments`.
    ///
    /// Rules:
    /// - `file_size` = bytes of non-NOBITS content in the segment
    /// - `memory_size` = virtual span from first to last byte (includes NOBITS)
    /// - `file_size <= memory_size` is enforced
    /// - Trailing NOBITS contribute only to `memory_size`
    pub fn accountSizes(self: *Layout) Error!SizeReport {
        const items = try self.allocator.alloc(SegmentSize, self.segments.items.len);
        errdefer self.allocator.free(items);

        var total_file: u64 = 0;
        var total_mem: u64 = 0;
        var virtual_end: u64 = self.base_address;
        var file_end: u64 = 0;

        for (self.segments.items, 0..) |*seg, i| {
            var file_sz: u64 = 0;
            var mem_end = seg.virtual_address;
            var file_end_seg = seg.file_offset;

            for (seg.section_indices.items) |sec_idx| {
                const sec = self.sections.items[sec_idx];
                const sec_va_end = sec.virtual_address + sec.size;
                if (sec_va_end > mem_end) mem_end = sec_va_end;

                if (!sec.is_nobits) {
                    const sec_file_end = sec.file_offset + sec.size;
                    if (sec_file_end > file_end_seg) file_end_seg = sec_file_end;
                    file_sz += sec.size;
                }
            }

            const mem_sz = if (mem_end > seg.virtual_address) mem_end - seg.virtual_address else 0;
            // Prefer the span-based file size when sections have offsets.
            const span_file = if (file_end_seg > seg.file_offset) file_end_seg - seg.file_offset else 0;
            const final_file = if (span_file > 0) span_file else file_sz;

            // Enforce gABI: file size must not exceed memory size.
            const safe_file = if (final_file > mem_sz) mem_sz else final_file;

            seg.file_size = safe_file;
            seg.memory_size = mem_sz;

            items[i] = .{
                .index = i,
                .file_size = safe_file,
                .memory_size = mem_sz,
                .bss_size = mem_sz - safe_file,
                .virtual_address = seg.virtual_address,
                .file_offset = seg.file_offset,
            };

            total_file += safe_file;
            total_mem += mem_sz;
            if (mem_end > virtual_end) virtual_end = mem_end;
            if (file_end_seg > file_end) file_end = file_end_seg;
        }

        return .{
            .total_file_size = total_file,
            .total_memory_size = total_mem,
            .virtual_end = virtual_end,
            .file_end = file_end,
            .segments = items,
        };
    }

    /// Free a SizeReport previously returned by `accountSizes`.
    pub fn freeSizeReport(self: *Layout, report: SizeReport) void {
        self.allocator.free(report.segments);
    }
};

/// Canonicalize a section name for grouping.
///
/// Examples:
/// - `.text.main` → `.text`
/// - `.rodata.str1.1` → `.rodata`
/// - `.data.rel.ro` → `.data.rel.ro` (kept distinct)
/// - `.bss` → `.bss`
pub fn canonicalizeName(name: []const u8) []const u8 {
    // Known prefixes that should be collapsed to their base.
    const prefixes = [_][]const u8{
        ".text",
        ".rodata",
        ".data",
        ".bss",
        ".tdata",
        ".tbss",
        ".init_array",
        ".fini_array",
        ".preinit_array",
    };

    for (prefixes) |prefix| {
        if (std.mem.eql(u8, name, prefix)) return prefix;
        if (std.mem.startsWith(u8, name, prefix) and name.len > prefix.len and name[prefix.len] == '.') {
            // Special case: keep .data.rel.ro distinct from .data
            if (std.mem.eql(u8, prefix, ".data") and std.mem.startsWith(u8, name, ".data.rel.ro")) {
                return ".data.rel.ro";
            }
            return prefix;
        }
    }
    return name;
}

fn flagsCompatible(out: *const OutputSection, input: *const InputSection) bool {
    return out.is_alloc == input.is_alloc and
        out.is_writable == input.is_writable and
        out.is_executable == input.is_executable and
        out.is_nobits == input.is_nobits;
}

/// Map writable/executable bits to ELF-style PF flags (always readable).
fn protectionFlags(writable: bool, executable: bool) u32 {
    var f: u32 = SegmentFlags.R;
    if (writable) f |= SegmentFlags.W;
    if (executable) f |= SegmentFlags.X;
    return f;
}

/// Align `value` up to the next multiple of `alignment`.
pub fn alignTo(value: u64, alignment: u64) u64 {
    if (alignment <= 1) return value;
    const mask = alignment - 1;
    // Only works for power-of-two; fall back for other values.
    if (alignment & mask == 0) {
        return (value + mask) & ~mask;
    }
    const rem = value % alignment;
    return if (rem == 0) value else value + (alignment - rem);
}

// === Unit Tests ===

test "canonicalizeName collapses common prefixes" {
    try std.testing.expectEqualStrings(".text", canonicalizeName(".text"));
    try std.testing.expectEqualStrings(".text", canonicalizeName(".text.main"));
    try std.testing.expectEqualStrings(".rodata", canonicalizeName(".rodata.str1.1"));
    try std.testing.expectEqualStrings(".data", canonicalizeName(".data.foo"));
    try std.testing.expectEqualStrings(".bss", canonicalizeName(".bss.bar"));
    try std.testing.expectEqualStrings(".data.rel.ro", canonicalizeName(".data.rel.ro.local"));
    try std.testing.expectEqualStrings(".debug_info", canonicalizeName(".debug_info"));
}

test "section grouping merges compatible sections" {
    var layout = Layout.init(std.testing.allocator, 0x400000, 4096);
    defer layout.deinit();

    try layout.addInput(.{
        .name = ".text.main",
        .data = "\x90\x90",
        .alignment = 16,
        .is_alloc = true,
        .is_writable = false,
        .is_executable = true,
        .is_nobits = false,
        .file_index = 0,
    });

    try layout.addInput(.{
        .name = ".text.foo",
        .data = "\xC3",
        .alignment = 4,
        .is_alloc = true,
        .is_writable = false,
        .is_executable = true,
        .is_nobits = false,
        .file_index = 1,
    });

    try layout.addInput(.{
        .name = ".data",
        .data = "\x01\x00\x00\x00",
        .alignment = 4,
        .is_alloc = true,
        .is_writable = true,
        .is_executable = false,
        .is_nobits = false,
        .file_index = 0,
    });

    try std.testing.expectEqual(@as(usize, 2), layout.count());

    const text = layout.get(".text") orelse return error.TestExpectedSection;
    try std.testing.expectEqual(@as(usize, 2), text.members.items.len);
    try std.testing.expectEqual(@as(u64, 16), text.alignment);

    const data = layout.get(".data") orelse return error.TestExpectedSection;
    try std.testing.expectEqual(@as(usize, 1), data.members.items.len);
}

test "incompatible flags create separate output sections" {
    var layout = Layout.init(std.testing.allocator, 0x400000, 4096);
    defer layout.deinit();

    try layout.addInput(.{
        .name = ".text",
        .data = "A",
        .alignment = 1,
        .is_alloc = true,
        .is_writable = false,
        .is_executable = true,
        .is_nobits = false,
        .file_index = 0,
    });

    // Same name but writable — should not merge.
    try layout.addInput(.{
        .name = ".text",
        .data = "B",
        .alignment = 1,
        .is_alloc = true,
        .is_writable = true,
        .is_executable = true,
        .is_nobits = false,
        .file_index = 1,
    });

    try std.testing.expectEqual(@as(usize, 2), layout.count());
}

test "computeAddresses assigns aligned virtual addresses" {
    var layout = Layout.init(std.testing.allocator, 0x400000, 4096);
    defer layout.deinit();

    try layout.addInput(.{
        .name = ".text",
        .data = "\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90",
        .alignment = 16,
        .is_alloc = true,
        .is_writable = false,
        .is_executable = true,
        .is_nobits = false,
        .file_index = 0,
    });

    try layout.addInput(.{
        .name = ".rodata",
        .data = "hello",
        .alignment = 1,
        .is_alloc = true,
        .is_writable = false,
        .is_executable = false,
        .is_nobits = false,
        .file_index = 0,
    });

    try layout.addInput(.{
        .name = ".data",
        .data = "\x01\x02",
        .alignment = 4,
        .is_alloc = true,
        .is_writable = true,
        .is_executable = false,
        .is_nobits = false,
        .file_index = 0,
    });

    try layout.addInput(.{
        .name = ".bss",
        .data = "",
        .alignment = 8,
        .is_alloc = true,
        .is_writable = true,
        .is_executable = false,
        .is_nobits = true,
        .file_index = 0,
    });

    layout.computeAddresses();

    const text = layout.get(".text") orelse return error.TestExpectedSection;
    try std.testing.expectEqual(@as(u64, 0x400000), text.virtual_address);
    try std.testing.expectEqual(@as(u64, 16), text.size);

    const rodata = layout.get(".rodata") orelse return error.TestExpectedSection;
    // Protection changed (exec → non-exec) → page aligned.
    try std.testing.expect(rodata.virtual_address >= text.virtual_address + text.size);
    try std.testing.expectEqual(@as(u64, 0), rodata.virtual_address % 4096);

    const data = layout.get(".data") orelse return error.TestExpectedSection;
    try std.testing.expect(data.is_writable);
    try std.testing.expect(data.virtual_address >= rodata.virtual_address + rodata.size);

    const bss = layout.get(".bss") orelse return error.TestExpectedSection;
    try std.testing.expect(bss.is_nobits);
    try std.testing.expectEqual(@as(u64, 0), bss.file_offset);
    try std.testing.expect(bss.virtual_address >= data.virtual_address);
}

test "bss does not contribute to file size" {
    var layout = Layout.init(std.testing.allocator, 0x400000, 4096);
    defer layout.deinit();

    try layout.addInput(.{
        .name = ".text",
        .data = "ABCD",
        .alignment = 1,
        .is_alloc = true,
        .is_writable = false,
        .is_executable = true,
        .is_nobits = false,
        .file_index = 0,
    });

    try layout.addInput(.{
        .name = ".bss",
        .data = "",
        .alignment = 1,
        .is_alloc = true,
        .is_writable = true,
        .is_executable = false,
        .is_nobits = true,
        .file_index = 0,
    });

    layout.computeAddresses();

    try std.testing.expect(layout.fileSize() >= 4);
    // Virtual size includes .bss region.
    try std.testing.expect(layout.virtualSize() >= layout.fileSize());
}

test "alignTo handles power-of-two and non-power-of-two" {
    try std.testing.expectEqual(@as(u64, 0), alignTo(0, 16));
    try std.testing.expectEqual(@as(u64, 16), alignTo(1, 16));
    try std.testing.expectEqual(@as(u64, 16), alignTo(16, 16));
    try std.testing.expectEqual(@as(u64, 32), alignTo(17, 16));
    try std.testing.expectEqual(@as(u64, 10), alignTo(7, 5));
    try std.testing.expectEqual(@as(u64, 5), alignTo(5, 5));
}

test "empty name is rejected" {
    var layout = Layout.init(std.testing.allocator, 0x400000, 4096);
    defer layout.deinit();

    const result = layout.addInput(.{
        .name = "",
        .data = "",
        .alignment = 1,
        .is_alloc = true,
        .is_writable = false,
        .is_executable = false,
        .is_nobits = false,
        .file_index = 0,
    });
    try std.testing.expectError(error.EmptyName, result);
}

test "member alignment pads inside output section" {
    var layout = Layout.init(std.testing.allocator, 0x1000, 4096);
    defer layout.deinit();

    try layout.addInput(.{
        .name = ".text",
        .data = "A",
        .alignment = 1,
        .is_alloc = true,
        .is_writable = false,
        .is_executable = true,
        .is_nobits = false,
        .file_index = 0,
    });

    try layout.addInput(.{
        .name = ".text",
        .data = "BB",
        .alignment = 4,
        .is_alloc = true,
        .is_writable = false,
        .is_executable = true,
        .is_nobits = false,
        .file_index = 1,
    });

    layout.computeAddresses();
    const text = layout.get(".text") orelse return error.TestExpectedSection;
    // First member 1 byte, then pad to 4, then 2 bytes → size >= 6.
    try std.testing.expect(text.size >= 6);
}

// === Phase 7.3 tests ===

test "buildSegments creates one segment for same protection" {
    var layout = Layout.init(std.testing.allocator, 0x400000, 4096);
    defer layout.deinit();

    try layout.addInput(.{
        .name = ".text",
        .data = "\x90\x90\x90\x90",
        .alignment = 4,
        .is_alloc = true,
        .is_writable = false,
        .is_executable = true,
        .is_nobits = false,
        .file_index = 0,
    });
    try layout.addInput(.{
        .name = ".text.hot",
        .data = "\xC3",
        .alignment = 1,
        .is_alloc = true,
        .is_writable = false,
        .is_executable = true,
        .is_nobits = false,
        .file_index = 1,
    });

    layout.computeAddresses();
    try layout.buildSegments();

    try std.testing.expectEqual(@as(usize, 1), layout.segmentCount());
    const seg = layout.segments.items[0];
    try std.testing.expect(seg.isExecutable());
    try std.testing.expect(!seg.isWritable());
    try std.testing.expectEqual(@as(usize, 1), seg.section_indices.items.len);
}

test "buildSegments splits on protection change" {
    var layout = Layout.init(std.testing.allocator, 0x400000, 4096);
    defer layout.deinit();

    try layout.addInput(.{
        .name = ".text",
        .data = "code",
        .alignment = 1,
        .is_alloc = true,
        .is_writable = false,
        .is_executable = true,
        .is_nobits = false,
        .file_index = 0,
    });
    try layout.addInput(.{
        .name = ".rodata",
        .data = "ro",
        .alignment = 1,
        .is_alloc = true,
        .is_writable = false,
        .is_executable = false,
        .is_nobits = false,
        .file_index = 0,
    });
    try layout.addInput(.{
        .name = ".data",
        .data = "\x01\x02",
        .alignment = 1,
        .is_alloc = true,
        .is_writable = true,
        .is_executable = false,
        .is_nobits = false,
        .file_index = 0,
    });

    layout.computeAddresses();
    try layout.buildSegments();

    try std.testing.expectEqual(@as(usize, 3), layout.segmentCount());
    try std.testing.expect(layout.segments.items[0].isExecutable());
    try std.testing.expect(!layout.segments.items[1].isExecutable());
    try std.testing.expect(!layout.segments.items[1].isWritable());
    try std.testing.expect(layout.segments.items[2].isWritable());
}

test "segments are ordered by virtual address" {
    var layout = Layout.init(std.testing.allocator, 0x400000, 4096);
    defer layout.deinit();

    try layout.addInput(.{ .name = ".text", .data = "A", .alignment = 1, .is_alloc = true, .is_writable = false, .is_executable = true, .is_nobits = false, .file_index = 0 });
    try layout.addInput(.{ .name = ".data", .data = "B", .alignment = 1, .is_alloc = true, .is_writable = true, .is_executable = false, .is_nobits = false, .file_index = 0 });

    layout.computeAddresses();
    try layout.buildSegments();

    try std.testing.expect(layout.segments.items[0].virtual_address <= layout.segments.items[1].virtual_address);
}

test "bss extends memory size but not file size" {
    var layout = Layout.init(std.testing.allocator, 0x400000, 4096);
    defer layout.deinit();

    try layout.addInput(.{
        .name = ".data",
        .data = "\x01\x02\x03\x04",
        .alignment = 4,
        .is_alloc = true,
        .is_writable = true,
        .is_executable = false,
        .is_nobits = false,
        .file_index = 0,
    });
    try layout.addInput(.{
        .name = ".bss",
        .data = "",
        .alignment = 1,
        .is_alloc = true,
        .is_writable = true,
        .is_executable = false,
        .is_nobits = true,
        .file_index = 0,
    });

    layout.computeAddresses();
    try layout.buildSegments();

    try std.testing.expectEqual(@as(usize, 1), layout.segmentCount());
    const seg = layout.segments.items[0];
    try std.testing.expect(seg.memory_size >= seg.file_size);
    try std.testing.expect(seg.file_size >= 4);
}

test "segment congruence modulo page size" {
    var layout = Layout.init(std.testing.allocator, 0x400000, 4096);
    defer layout.deinit();

    try layout.addInput(.{
        .name = ".text",
        .data = "hello",
        .alignment = 1,
        .is_alloc = true,
        .is_writable = false,
        .is_executable = true,
        .is_nobits = false,
        .file_index = 0,
    });

    layout.computeAddresses();
    try layout.buildSegments();

    const seg = layout.segments.items[0];
    try std.testing.expect(seg.isCongruent());
    try std.testing.expectEqual(seg.virtual_address % 4096, seg.file_offset % 4096);
}

test "empty layout produces no segments" {
    var layout = Layout.init(std.testing.allocator, 0x400000, 4096);
    defer layout.deinit();

    layout.computeAddresses();
    try layout.buildSegments();
    try std.testing.expectEqual(@as(usize, 0), layout.segmentCount());
}

test "non-alloc sections are ignored by segments" {
    var layout = Layout.init(std.testing.allocator, 0x400000, 4096);
    defer layout.deinit();

    try layout.addInput(.{
        .name = ".debug_info",
        .data = "dbg",
        .alignment = 1,
        .is_alloc = false,
        .is_writable = false,
        .is_executable = false,
        .is_nobits = false,
        .file_index = 0,
    });
    try layout.addInput(.{
        .name = ".text",
        .data = "X",
        .alignment = 1,
        .is_alloc = true,
        .is_writable = false,
        .is_executable = true,
        .is_nobits = false,
        .file_index = 0,
    });

    layout.computeAddresses();
    try layout.buildSegments();

    try std.testing.expectEqual(@as(usize, 1), layout.segmentCount());
    try std.testing.expect(layout.segments.items[0].isExecutable());
}

test "segment flags match section protection" {
    var layout = Layout.init(std.testing.allocator, 0x1000, 4096);
    defer layout.deinit();

    try layout.addInput(.{ .name = ".text", .data = "c", .alignment = 1, .is_alloc = true, .is_writable = false, .is_executable = true, .is_nobits = false, .file_index = 0 });
    try layout.addInput(.{ .name = ".rodata", .data = "r", .alignment = 1, .is_alloc = true, .is_writable = false, .is_executable = false, .is_nobits = false, .file_index = 0 });
    try layout.addInput(.{ .name = ".data", .data = "w", .alignment = 1, .is_alloc = true, .is_writable = true, .is_executable = false, .is_nobits = false, .file_index = 0 });

    layout.computeAddresses();
    try layout.buildSegments();

    try std.testing.expectEqual(SegmentFlags.R | SegmentFlags.X, layout.segments.items[0].flags);
    try std.testing.expectEqual(SegmentFlags.R, layout.segments.items[1].flags);
    try std.testing.expectEqual(SegmentFlags.R | SegmentFlags.W, layout.segments.items[2].flags);
}

test "rebuildSegments replaces previous segments" {
    var layout = Layout.init(std.testing.allocator, 0x400000, 4096);
    defer layout.deinit();

    try layout.addInput(.{ .name = ".text", .data = "A", .alignment = 1, .is_alloc = true, .is_writable = false, .is_executable = true, .is_nobits = false, .file_index = 0 });
    layout.computeAddresses();
    try layout.buildSegments();
    try std.testing.expectEqual(@as(usize, 1), layout.segmentCount());

    try layout.buildSegments();
    try std.testing.expectEqual(@as(usize, 1), layout.segmentCount());
}

test "data and bss share one writable segment" {
    var layout = Layout.init(std.testing.allocator, 0x200000, 4096);
    defer layout.deinit();

    try layout.addInput(.{ .name = ".data", .data = "\x00\x00\x00\x00", .alignment = 4, .is_alloc = true, .is_writable = true, .is_executable = false, .is_nobits = false, .file_index = 0 });
    try layout.addInput(.{ .name = ".bss", .data = "", .alignment = 8, .is_alloc = true, .is_writable = true, .is_executable = false, .is_nobits = true, .file_index = 0 });

    layout.computeAddresses();
    try layout.buildSegments();

    try std.testing.expectEqual(@as(usize, 1), layout.segmentCount());
    try std.testing.expect(layout.segments.items[0].isWritable());
    try std.testing.expect(layout.segments.items[0].memory_size > layout.segments.items[0].file_size);
}

test "segment alignment equals page size" {
    var layout = Layout.init(std.testing.allocator, 0x400000, 65536);
    defer layout.deinit();

    try layout.addInput(.{ .name = ".text", .data = "Z", .alignment = 1, .is_alloc = true, .is_writable = false, .is_executable = true, .is_nobits = false, .file_index = 0 });
    layout.computeAddresses();
    try layout.buildSegments();

    try std.testing.expectEqual(@as(u64, 65536), layout.segments.items[0].alignment);
}

test "multiple text sections stay in one RX segment" {
    var layout = Layout.init(std.testing.allocator, 0x400000, 4096);
    defer layout.deinit();

    try layout.addInput(.{ .name = ".text.a", .data = "aa", .alignment = 2, .is_alloc = true, .is_writable = false, .is_executable = true, .is_nobits = false, .file_index = 0 });
    try layout.addInput(.{ .name = ".text.b", .data = "bbb", .alignment = 1, .is_alloc = true, .is_writable = false, .is_executable = true, .is_nobits = false, .file_index = 1 });
    try layout.addInput(.{ .name = ".text.c", .data = "c", .alignment = 1, .is_alloc = true, .is_writable = false, .is_executable = true, .is_nobits = false, .file_index = 2 });

    layout.computeAddresses();
    try layout.buildSegments();

    try std.testing.expectEqual(@as(usize, 1), layout.segmentCount());
    try std.testing.expect(layout.segments.items[0].isExecutable());
    try std.testing.expect(layout.segments.items[0].file_size >= 6);
}

test "protectionFlags helper values" {
    try std.testing.expectEqual(SegmentFlags.R, protectionFlags(false, false));
    try std.testing.expectEqual(SegmentFlags.R | SegmentFlags.W, protectionFlags(true, false));
    try std.testing.expectEqual(SegmentFlags.R | SegmentFlags.X, protectionFlags(false, true));
    try std.testing.expectEqual(SegmentFlags.R | SegmentFlags.W | SegmentFlags.X, protectionFlags(true, true));
}

test "segment isCongruent for zero alignment" {
    const seg = Segment{
        .virtual_address = 100,
        .file_offset = 50,
        .file_size = 10,
        .memory_size = 10,
        .alignment = 0,
        .flags = SegmentFlags.R,
        .section_indices = .empty,
    };
    try std.testing.expect(seg.isCongruent());
}

// === Phase 7.4 tests ===

test "accountSizes reports exact file and memory sizes" {
    var layout = Layout.init(std.testing.allocator, 0x400000, 4096);
    defer layout.deinit();

    try layout.addInput(.{ .name = ".text", .data = "ABCD", .alignment = 1, .is_alloc = true, .is_writable = false, .is_executable = true, .is_nobits = false, .file_index = 0 });
    try layout.addInput(.{ .name = ".data", .data = "\x01\x02", .alignment = 1, .is_alloc = true, .is_writable = true, .is_executable = false, .is_nobits = false, .file_index = 0 });

    layout.computeAddresses();
    try layout.buildSegments();
    const report = try layout.accountSizes();
    defer layout.freeSizeReport(report);

    try std.testing.expectEqual(@as(usize, 2), report.segments.len);
    try std.testing.expect(report.total_file_size >= 6);
    try std.testing.expect(report.total_memory_size >= report.total_file_size);
    try std.testing.expect(report.virtual_end > layout.base_address);
}

test "accountSizes bss contributes only to memory" {
    var layout = Layout.init(std.testing.allocator, 0x400000, 4096);
    defer layout.deinit();

    try layout.addInput(.{ .name = ".data", .data = "XXXX", .alignment = 4, .is_alloc = true, .is_writable = true, .is_executable = false, .is_nobits = false, .file_index = 0 });
    try layout.addInput(.{ .name = ".bss", .data = "", .alignment = 1, .is_alloc = true, .is_writable = true, .is_executable = false, .is_nobits = true, .file_index = 0 });

    layout.computeAddresses();
    try layout.buildSegments();
    const report = try layout.accountSizes();
    defer layout.freeSizeReport(report);

    try std.testing.expectEqual(@as(usize, 1), report.segments.len);
    const s = report.segments[0];
    try std.testing.expect(s.file_size >= 4);
    try std.testing.expect(s.memory_size >= s.file_size);
    try std.testing.expectEqual(s.memory_size - s.file_size, s.bss_size);
}

test "accountSizes enforces file_size <= memory_size" {
    var layout = Layout.init(std.testing.allocator, 0x1000, 4096);
    defer layout.deinit();

    try layout.addInput(.{ .name = ".text", .data = "hi", .alignment = 1, .is_alloc = true, .is_writable = false, .is_executable = true, .is_nobits = false, .file_index = 0 });
    layout.computeAddresses();
    try layout.buildSegments();
    const report = try layout.accountSizes();
    defer layout.freeSizeReport(report);

    for (report.segments) |s| {
        try std.testing.expect(s.file_size <= s.memory_size);
    }
}

test "accountSizes empty layout" {
    var layout = Layout.init(std.testing.allocator, 0x400000, 4096);
    defer layout.deinit();

    layout.computeAddresses();
    try layout.buildSegments();
    const report = try layout.accountSizes();
    defer layout.freeSizeReport(report);

    try std.testing.expectEqual(@as(usize, 0), report.segments.len);
    try std.testing.expectEqual(@as(u64, 0), report.total_file_size);
    try std.testing.expectEqual(@as(u64, 0), report.total_memory_size);
}

test "accountSizes updates segment fields in place" {
    var layout = Layout.init(std.testing.allocator, 0x400000, 4096);
    defer layout.deinit();

    try layout.addInput(.{ .name = ".rodata", .data = "const", .alignment = 1, .is_alloc = true, .is_writable = false, .is_executable = false, .is_nobits = false, .file_index = 0 });
    layout.computeAddresses();
    try layout.buildSegments();
    const report = try layout.accountSizes();
    defer layout.freeSizeReport(report);

    try std.testing.expectEqual(report.segments[0].file_size, layout.segments.items[0].file_size);
    try std.testing.expectEqual(report.segments[0].memory_size, layout.segments.items[0].memory_size);
}

test "accountSizes virtual_end covers all segments" {
    var layout = Layout.init(std.testing.allocator, 0x800000, 4096);
    defer layout.deinit();

    try layout.addInput(.{ .name = ".text", .data = "T", .alignment = 1, .is_alloc = true, .is_writable = false, .is_executable = true, .is_nobits = false, .file_index = 0 });
    try layout.addInput(.{ .name = ".data", .data = "D", .alignment = 1, .is_alloc = true, .is_writable = true, .is_executable = false, .is_nobits = false, .file_index = 0 });

    layout.computeAddresses();
    try layout.buildSegments();
    const report = try layout.accountSizes();
    defer layout.freeSizeReport(report);

    var max_end: u64 = 0;
    for (report.segments) |s| {
        const end = s.virtual_address + s.memory_size;
        if (end > max_end) max_end = end;
    }
    try std.testing.expectEqual(max_end, report.virtual_end);
}

// === Phase 9.2 tests ===

test "pinOutput places a section at an exact address" {
    var layout = Layout.init(std.testing.allocator, 0x400000, 4096);
    defer layout.deinit();

    try layout.addInput(.{ .name = ".text", .data = "AAAA", .alignment = 1, .is_alloc = true, .is_writable = false, .is_executable = true, .is_nobits = false, .file_index = 0 });
    try layout.addInput(.{ .name = ".data", .data = "BBB", .alignment = 1, .is_alloc = true, .is_writable = true, .is_executable = false, .is_nobits = false, .file_index = 0 });
    try layout.pinOutput(".data", 0x20000000);
    layout.computeAddresses();

    try std.testing.expectEqual(@as(u64, 0x400000), layout.get(".text").?.virtual_address);
    try std.testing.expectEqual(@as(u64, 0x20000000), layout.get(".data").?.virtual_address);
}

test "computeAddresses continues from a pinned section's end" {
    var layout = Layout.init(std.testing.allocator, 0x400000, 4096);
    defer layout.deinit();

    try layout.addInput(.{ .name = ".text", .data = "AAAA", .alignment = 1, .is_alloc = true, .is_writable = false, .is_executable = true, .is_nobits = false, .file_index = 0 });
    try layout.addInput(.{ .name = ".data", .data = "BBB", .alignment = 1, .is_alloc = true, .is_writable = true, .is_executable = false, .is_nobits = false, .file_index = 0 });
    try layout.addInput(.{ .name = ".rodata", .data = "C", .alignment = 1, .is_alloc = true, .is_writable = false, .is_executable = false, .is_nobits = false, .file_index = 0 });
    try layout.pinOutput(".data", 0x20000000);
    layout.computeAddresses();

    // .data pinned at 0x20000000, size 3. The next section crosses a write
    // protection boundary and lands on the next page.
    try std.testing.expectEqual(@as(u64, 0x20001000), layout.get(".rodata").?.virtual_address);
}

test "pinOutput respects the section's own alignment" {
    var layout = Layout.init(std.testing.allocator, 0x400000, 4096);
    defer layout.deinit();

    try layout.addInput(.{ .name = ".vector", .data = "1234", .alignment = 4, .is_alloc = true, .is_writable = false, .is_executable = false, .is_nobits = false, .file_index = 0 });
    try layout.pinOutput(".vector", 0x1001);
    layout.computeAddresses();

    // 0x1001 rounded up to the section's 4-byte alignment.
    try std.testing.expectEqual(@as(u64, 0x1004), layout.get(".vector").?.virtual_address);
}

test "pinOutput rejects conflicting addresses but allows repeats" {
    var layout = Layout.init(std.testing.allocator, 0x400000, 4096);
    defer layout.deinit();

    try layout.pinOutput(".text", 0x1000);
    // Same address again: fine.
    try layout.pinOutput(".text", 0x1000);
    // Different address: conflict.
    const result = layout.pinOutput(".text", 0x2000);
    try std.testing.expectError(error.PinConflict, result);
}

test "unpinned sections keep the normal base-address flow" {
    var layout = Layout.init(std.testing.allocator, 0x400000, 4096);
    defer layout.deinit();

    try layout.addInput(.{ .name = ".text", .data = "A", .alignment = 1, .is_alloc = true, .is_writable = false, .is_executable = true, .is_nobits = false, .file_index = 0 });
    layout.computeAddresses();
    try std.testing.expectEqual(@as(u64, 0x400000), layout.get(".text").?.virtual_address);
}
