//! Phase 7.1 – 7.2: Section Grouping and Address/Alignment Calculation.
//!
//! Groups matching input sections (`.text.*` → `.text`, `.rodata.*` → `.rodata`,
//! etc.) into output sections, then assigns virtual addresses and file offsets
//! with proper alignment. Follows common ELF linker practice:
//! - Canonical section names for grouping
//! - Page-size alignment when protection changes
//! - `.bss` occupies virtual memory but no file space
//! - `p_vaddr` / `p_offset` congruence is prepared for later segment emission

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

/// Errors that can occur during section layout.
pub const Error = error{
    OutOfMemory,
    EmptyName,
};

/// Layout engine that groups input sections and assigns addresses.
pub const Layout = struct {
    sections: std.ArrayListUnmanaged(OutputSection),
    allocator: std.mem.Allocator,
    /// Preferred base virtual address (e.g. 0x400000 for non-PIE ELF).
    base_address: u64,
    /// Target page size used for protection-boundary alignment.
    page_size: u64,

    pub fn init(allocator: std.mem.Allocator, base_address: u64, page_size: u64) Layout {
        return .{
            .sections = .empty,
            .allocator = allocator,
            .base_address = base_address,
            .page_size = if (page_size == 0) 4096 else page_size,
        };
    }

    pub fn deinit(self: *Layout) void {
        for (self.sections.items) |*sec| {
            sec.deinit(self.allocator);
        }
        self.sections.deinit(self.allocator);
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

            if (out.is_alloc) {
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
