//! Phase 2.1 & 2.2: ELF Header and Section Header Table Parsing.
//!
//! Provides zero-copy parsing for ELF headers and section headers
//! across 32-bit, 64-bit, little-endian, and big-endian targets.

const std = @import("std");

// === Constants and Types ===

/// The 4-byte magic signature present at the start of every valid ELF binary.
pub const MAGIC = [4]u8{ 0x7F, 'E', 'L', 'F' };

/// ELF architecture width (EI_CLASS).
pub const Class = enum(u8) {
    none = 0,
    elf32 = 1,
    elf64 = 2,

    pub fn name(self: Class) []const u8 {
        return switch (self) {
            .none => "none",
            .elf32 => "elf32",
            .elf64 => "elf64",
        };
    }
};

/// ELF data byte order encoding (EI_DATA).
pub const DataEncoding = enum(u8) {
    none = 0,
    lsb = 1, // Little-endian (2's complement)
    msb = 2, // Big-endian (2's complement)
};

/// ELF file type (e_type).
pub const FileType = enum(u16) {
    none = 0,
    rel = 1, // Relocatable object (.o)
    exec = 2, // Executable binary
    dyn = 3, // Shared library (.so) or position-independent executable (PIE)
    core = 4, // Core dump
    _,

    pub fn name(self: FileType) []const u8 {
        return switch (self) {
            .none => "none",
            .rel => "rel",
            .exec => "exec",
            .dyn => "dyn",
            .core => "core",
            _ => "unknown",
        };
    }
};

/// Target processor architecture (e_machine).
pub const Machine = enum(u16) {
    none = 0,
    x86 = 3,
    arm = 40,
    x86_64 = 62,
    aarch64 = 183,
    riscv = 243,
    _,

    pub fn name(self: Machine) []const u8 {
        return switch (self) {
            .none => "none",
            .x86 => "x86",
            .arm => "arm",
            .x86_64 => "x86_64",
            .aarch64 => "aarch64",
            .riscv => "riscv",
            _ => "unknown",
        };
    }
};

/// Operating System and ABI identifier (EI_OSABI).
pub const OsAbi = enum(u8) {
    sysv = 0,
    hpux = 1,
    netbsd = 2,
    linux = 3,
    solaris = 6,
    freebsd = 9,
    openbsd = 12,
    arm_aeabi = 64,
    standalone = 255,
    _,
};

/// Section type identifying section contents and semantics (sh_type).
pub const SectionType = enum(u32) {
    null = 0,
    progbits = 1, // Program code or initialized data
    symtab = 2, // Linker symbol table
    strtab = 3, // String table
    rela = 4, // Relocation entries with explicit addends
    hash = 5, // Symbol hash table
    dynamic = 6, // Dynamic linking information
    note = 7, // Information notes
    nobits = 8, // Uninitialized data (.bss)
    rel = 9, // Relocation entries without addends
    shlib = 10, // Reserved
    dynsym = 11, // Dynamic linker symbol table
    init_array = 14, // Array of constructors
    fini_array = 15, // Array of destructors
    preinit_array = 16, // Array of pre-constructors
    group = 17, // Section group
    symtab_shndx = 18, // Extended section indices for symbol table

    // Android-specific sections
    android_rel = 0x60000001,
    android_rela = 0x60000002,

    // GNU extension sections
    gnu_attributes = 0x6ffffff5,
    gnu_hash = 0x6ffffff6,
    gnu_verdef = 0x6ffffffd,
    gnu_verneed = 0x6ffffffe,
    gnu_versym = 0x6fffffff,

    // Processor-specific (ARM / AArch64)
    arm_exidx = 0x70000001,
    arm_preemptmap = 0x70000002,
    arm_attributes = 0x70000003,

    _,

    /// Safe string conversion that will never panic on unknown or OS-specific section types.
    pub fn name(self: SectionType) []const u8 {
        return switch (self) {
            .null => "null",
            .progbits => "progbits",
            .symtab => "symtab",
            .strtab => "strtab",
            .rela => "rela",
            .hash => "hash",
            .dynamic => "dynamic",
            .note => "note",
            .nobits => "nobits",
            .rel => "rel",
            .shlib => "shlib",
            .dynsym => "dynsym",
            .init_array => "init_array",
            .fini_array => "fini_array",
            .preinit_array => "preinit_array",
            .group => "group",
            .symtab_shndx => "symtab_shndx",
            .android_rel => "android_rel",
            .android_rela => "android_rela",
            .gnu_attributes => "gnu_attributes",
            .gnu_hash => "gnu_hash",
            .gnu_verdef => "gnu_verdef",
            .gnu_verneed => "gnu_verneed",
            .gnu_versym => "gnu_versym",
            .arm_exidx => "arm_exidx",
            .arm_preemptmap => "arm_preemptmap",
            .arm_attributes => "arm_attributes",
            _ => "unknown",
        };
    }
};

/// Section attribute flags (sh_flags bitmask).
pub const flags = struct {
    pub const WRITE: u64 = 1 << 0; // Writable at runtime
    pub const ALLOC: u64 = 1 << 1; // Occupies memory during execution
    pub const EXECINSTR: u64 = 1 << 2; // Executable machine instructions
    pub const MERGE: u64 = 1 << 4; // Might be merged to eliminate duplication
    pub const STRINGS: u64 = 1 << 5; // Contains null-terminated strings
    pub const INFO_LINK: u64 = 1 << 6; // sh_info holds section header table index
    pub const LINK_ORDER: u64 = 1 << 7; // Preserve order after combining
    pub const OS_NONCONFORMING: u64 = 1 << 8; // OS-specific processing required
    pub const GROUP: u64 = 1 << 9; // Section is member of a group
    pub const TLS: u64 = 1 << 10; // Holds thread-local data
};

/// Errors encountered while reading ELF structures.
pub const HeaderError = error{
    TruncatedHeader,
    InvalidMagic,
    InvalidClass,
    InvalidEndian,
    InvalidVersion,
};

pub const SectionError = error{
    TruncatedSectionTable,
    InvalidSectionIndex,
    InvalidSectionSize,
    StringTableOutOfBounds,
};

// === Section Header Representation ===

/// Normalized section header representation for 32-bit and 64-bit ELF sections.
pub const SectionHeader = struct {
    /// Byte offset into the section header string table (.shstrtab)
    name_offset: u32,
    /// Type of section
    sh_type: SectionType,
    /// Bitmask of section attributes
    sh_flags: u64,
    /// Virtual memory address where section should load (0 if not loaded)
    addr: u64,
    /// Byte offset in the file where section raw data begins
    offset: u64,
    /// Size of the section in bytes
    size: u64,
    /// Section header table index link (meaning depends on section type)
    link: u32,
    /// Extra information (e.g. symbol index or relocation target section)
    info: u32,
    /// Address alignment constraints (must be a power of two)
    addralign: u64,
    /// Size of each entry if the section holds a fixed-size entry table
    entsize: u64,

    /// Returns true if this section occupies memory during program execution.
    pub fn isAlloc(self: SectionHeader) bool {
        return (self.sh_flags & flags.ALLOC) != 0;
    }

    /// Returns true if memory for this section is writable at runtime.
    pub fn isWritable(self: SectionHeader) bool {
        return (self.sh_flags & flags.WRITE) != 0;
    }

    /// Returns true if this section contains executable instructions.
    pub fn isExecutable(self: SectionHeader) bool {
        return (self.sh_flags & flags.EXECINSTR) != 0;
    }

    /// Returns a zero-copy slice of the raw section data from file bytes.
    /// Returns an empty slice for NOBITS (.bss) sections as they have no file bytes.
    pub fn getData(self: SectionHeader, file_bytes: []const u8) SectionError![]const u8 {
        if (self.sh_type == .nobits or self.size == 0) {
            return &.{};
        }

        const end_offset = std.math.add(u64, self.offset, self.size) catch {
            return error.InvalidSectionSize;
        };

        if (end_offset > file_bytes.len) {
            return error.InvalidSectionSize;
        }

        const start: usize = @intCast(self.offset);
        const end: usize = @intCast(end_offset);
        return file_bytes[start..end];
    }

    /// Extract section name string from the section header string table.
    pub fn getName(self: SectionHeader, shstrtab_data: []const u8) SectionError![:0]const u8 {
        if (self.name_offset >= shstrtab_data.len) {
            return error.StringTableOutOfBounds;
        }

        const slice = shstrtab_data[self.name_offset..];
        const len = std.mem.indexOfScalar(u8, slice, 0) orelse return error.StringTableOutOfBounds;

        return slice[0..len :0];
    }
};

// === ELF Header Structure ===

/// Normalized ELF header representation for both 32-bit and 64-bit objects.
pub const Header = struct {
    class: Class,
    endian: std.builtin.Endian,
    os_abi: OsAbi,
    abi_version: u8,
    file_type: FileType,
    machine: Machine,
    entry: u64,
    phoff: u64,
    shoff: u64,
    flags: u32,
    ehsize: u16,
    phentsize: u16,
    phnum: u16,
    shentsize: u16,
    shnum: u16,
    shstrndx: u16,

    /// Parse an ELF header from a raw byte slice.
    pub fn parse(bytes: []const u8) HeaderError!Header {
        if (bytes.len < 16) return error.TruncatedHeader;

        if (!std.mem.eql(u8, bytes[0..4], &MAGIC)) {
            return error.InvalidMagic;
        }

        const class: Class = switch (bytes[4]) {
            1 => .elf32,
            2 => .elf64,
            else => return error.InvalidClass,
        };

        const endian: std.builtin.Endian = switch (bytes[5]) {
            1 => .little,
            2 => .big,
            else => return error.InvalidEndian,
        };

        if (bytes[6] != 1) {
            return error.InvalidVersion;
        }

        const os_abi: OsAbi = @fromBackingInt(@intCast(bytes[7]));
        const abi_version = bytes[8];

        return switch (class) {
            .elf64 => parseElf64(bytes, endian, os_abi, abi_version),
            .elf32 => parseElf32(bytes, endian, os_abi, abi_version),
            .none => error.InvalidClass,
        };
    }

    /// Parse a single section header entry at the given index.
    pub fn parseSectionHeader(self: Header, bytes: []const u8, index: usize) SectionError!SectionHeader {
        if (index >= self.shnum) {
            return error.InvalidSectionIndex;
        }

        const entry_size: u64 = self.shentsize;
        const entry_offset = std.math.add(u64, self.shoff, @as(u64, index) * entry_size) catch {
            return error.TruncatedSectionTable;
        };

        const end_offset = std.math.add(u64, entry_offset, entry_size) catch {
            return error.TruncatedSectionTable;
        };

        if (end_offset > bytes.len) {
            return error.TruncatedSectionTable;
        }

        const start: usize = @intCast(entry_offset);
        const end: usize = @intCast(end_offset);
        const entry_bytes = bytes[start..end];

        return switch (self.class) {
            .elf64 => parseSectionHeader64(entry_bytes, self.endian),
            .elf32 => parseSectionHeader32(entry_bytes, self.endian),
            .none => error.TruncatedSectionTable,
        };
    }

    /// Parse all section headers into an allocated slice.
    pub fn parseAllSectionHeaders(
        self: Header,
        allocator: std.mem.Allocator,
        bytes: []const u8,
    ) (SectionError || std.mem.Allocator.Error)![]SectionHeader {
        const sections = try allocator.alloc(SectionHeader, self.shnum);
        errdefer allocator.free(sections);

        var i: usize = 0;
        while (i < self.shnum) : (i += 1) {
            sections[i] = try self.parseSectionHeader(bytes, i);
        }

        return sections;
    }

    /// Retrieve the raw bytes of the section header string table (.shstrtab).
    pub fn getSectionStringTable(self: Header, bytes: []const u8) SectionError![]const u8 {
        if (self.shstrndx >= self.shnum) {
            return error.InvalidSectionIndex;
        }

        const shstr_header = try self.parseSectionHeader(bytes, self.shstrndx);
        return shstr_header.getData(bytes);
    }

    // --- Private Helper Parsers ---

    fn parseElf64(
        bytes: []const u8,
        endian: std.builtin.Endian,
        os_abi: OsAbi,
        abi_version: u8,
    ) HeaderError!Header {
        if (bytes.len < 64) return error.TruncatedHeader;

        const raw_type = std.mem.readInt(u16, bytes[16..18], endian);
        const raw_machine = std.mem.readInt(u16, bytes[18..20], endian);
        const version = std.mem.readInt(u32, bytes[20..24], endian);
        if (version != 1) return error.InvalidVersion;

        return .{
            .class = .elf64,
            .endian = endian,
            .os_abi = os_abi,
            .abi_version = abi_version,
            .file_type = @fromBackingInt(@intCast(raw_type)),
            .machine = @fromBackingInt(@intCast(raw_machine)),
            .entry = std.mem.readInt(u64, bytes[24..32], endian),
            .phoff = std.mem.readInt(u64, bytes[32..40], endian),
            .shoff = std.mem.readInt(u64, bytes[40..48], endian),
            .flags = std.mem.readInt(u32, bytes[48..52], endian),
            .ehsize = std.mem.readInt(u16, bytes[52..54], endian),
            .phentsize = std.mem.readInt(u16, bytes[54..56], endian),
            .phnum = std.mem.readInt(u16, bytes[56..58], endian),
            .shentsize = std.mem.readInt(u16, bytes[58..60], endian),
            .shnum = std.mem.readInt(u16, bytes[60..62], endian),
            .shstrndx = std.mem.readInt(u16, bytes[62..64], endian),
        };
    }

    fn parseElf32(
        bytes: []const u8,
        endian: std.builtin.Endian,
        os_abi: OsAbi,
        abi_version: u8,
    ) HeaderError!Header {
        if (bytes.len < 52) return error.TruncatedHeader;

        const raw_type = std.mem.readInt(u16, bytes[16..18], endian);
        const raw_machine = std.mem.readInt(u16, bytes[18..20], endian);
        const version = std.mem.readInt(u32, bytes[20..24], endian);
        if (version != 1) return error.InvalidVersion;

        return .{
            .class = .elf32,
            .endian = endian,
            .os_abi = os_abi,
            .abi_version = abi_version,
            .file_type = @fromBackingInt(@intCast(raw_type)),
            .machine = @fromBackingInt(@intCast(raw_machine)),
            .entry = std.mem.readInt(u32, bytes[24..28], endian),
            .phoff = std.mem.readInt(u32, bytes[28..32], endian),
            .shoff = std.mem.readInt(u32, bytes[32..36], endian),
            .flags = std.mem.readInt(u32, bytes[36..40], endian),
            .ehsize = std.mem.readInt(u16, bytes[40..42], endian),
            .phentsize = std.mem.readInt(u16, bytes[42..44], endian),
            .phnum = std.mem.readInt(u16, bytes[44..46], endian),
            .shentsize = std.mem.readInt(u16, bytes[46..48], endian),
            .shnum = std.mem.readInt(u16, bytes[48..50], endian),
            .shstrndx = std.mem.readInt(u16, bytes[50..52], endian),
        };
    }

    fn parseSectionHeader64(bytes: []const u8, endian: std.builtin.Endian) SectionError!SectionHeader {
        if (bytes.len < 64) return error.TruncatedSectionTable;

        const raw_type = std.mem.readInt(u32, bytes[4..8], endian);

        return .{
            .name_offset = std.mem.readInt(u32, bytes[0..4], endian),
            .sh_type = @fromBackingInt(@intCast(raw_type)),
            .sh_flags = std.mem.readInt(u64, bytes[8..16], endian),
            .addr = std.mem.readInt(u64, bytes[16..24], endian),
            .offset = std.mem.readInt(u64, bytes[24..32], endian),
            .size = std.mem.readInt(u64, bytes[32..40], endian),
            .link = std.mem.readInt(u32, bytes[40..44], endian),
            .info = std.mem.readInt(u32, bytes[44..48], endian),
            .addralign = std.mem.readInt(u64, bytes[48..56], endian),
            .entsize = std.mem.readInt(u64, bytes[56..64], endian),
        };
    }

    fn parseSectionHeader32(bytes: []const u8, endian: std.builtin.Endian) SectionError!SectionHeader {
        if (bytes.len < 40) return error.TruncatedSectionTable;

        const raw_type = std.mem.readInt(u32, bytes[4..8], endian);

        return .{
            .name_offset = std.mem.readInt(u32, bytes[0..4], endian),
            .sh_type = @fromBackingInt(@intCast(raw_type)),
            .sh_flags = std.mem.readInt(u32, bytes[8..12], endian),
            .addr = std.mem.readInt(u32, bytes[12..16], endian),
            .offset = std.mem.readInt(u32, bytes[16..20], endian),
            .size = std.mem.readInt(u32, bytes[20..24], endian),
            .link = std.mem.readInt(u32, bytes[24..28], endian),
            .info = std.mem.readInt(u32, bytes[28..32], endian),
            .addralign = std.mem.readInt(u32, bytes[32..36], endian),
            .entsize = std.mem.readInt(u32, bytes[36..40], endian),
        };
    }
};

// === Unit Tests ===

test "reject file with invalid magic bytes" {
    var invalid_bytes: [64]u8 = undefined;
    @memset(&invalid_bytes, 0);
    @memcpy(invalid_bytes[0..8], &[_]u8{ 'N', 'O', 'P', 'E', 2, 1, 1, 0 });
    try std.testing.expectError(error.InvalidMagic, Header.parse(&invalid_bytes));
}

test "reject file shorter than minimum identification bytes" {
    const short_bytes = [_]u8{ 0x7F, 'E', 'L' };
    try std.testing.expectError(error.TruncatedHeader, Header.parse(&short_bytes));
}

test "reject invalid class and endianness codes" {
    var bad_class: [64]u8 = undefined;
    @memset(&bad_class, 0);
    @memcpy(bad_class[0..8], &[_]u8{ 0x7F, 'E', 'L', 'F', 99, 1, 1, 0 });
    try std.testing.expectError(error.InvalidClass, Header.parse(&bad_class));

    var bad_endian: [64]u8 = undefined;
    @memset(&bad_endian, 0);
    @memcpy(bad_endian[0..8], &[_]u8{ 0x7F, 'E', 'L', 'F', 2, 99, 1, 0 });
    try std.testing.expectError(error.InvalidEndian, Header.parse(&bad_endian));
}

test "parse 64-bit little-endian ELF relocatable header" {
    var hdr_buf: [64]u8 = undefined;
    @memset(&hdr_buf, 0);

    @memcpy(hdr_buf[0..4], &MAGIC);
    hdr_buf[4] = 2; // ELFCLASS64
    hdr_buf[5] = 1; // ELFDATA2LSB (little-endian)
    hdr_buf[6] = 1; // EV_CURRENT
    hdr_buf[7] = 0; // System V
    hdr_buf[8] = 0; // ABI version

    std.mem.writeInt(u16, hdr_buf[16..18], 1, .little); // ET_REL
    std.mem.writeInt(u16, hdr_buf[18..20], 183, .little); // EM_AARCH64
    std.mem.writeInt(u32, hdr_buf[20..24], 1, .little);
    std.mem.writeInt(u64, hdr_buf[24..32], 0, .little);
    std.mem.writeInt(u64, hdr_buf[32..40], 0, .little);
    std.mem.writeInt(u64, hdr_buf[40..48], 0x1000, .little); // e_shoff
    std.mem.writeInt(u32, hdr_buf[48..52], 0, .little);
    std.mem.writeInt(u16, hdr_buf[52..54], 64, .little);
    std.mem.writeInt(u16, hdr_buf[54..56], 0, .little);
    std.mem.writeInt(u16, hdr_buf[56..58], 0, .little);
    std.mem.writeInt(u16, hdr_buf[58..60], 64, .little); // e_shentsize
    std.mem.writeInt(u16, hdr_buf[60..62], 12, .little); // e_shnum
    std.mem.writeInt(u16, hdr_buf[62..64], 11, .little); // e_shstrndx

    const parsed = try Header.parse(&hdr_buf);

    try std.testing.expectEqual(Class.elf64, parsed.class);
    try std.testing.expectEqual(std.builtin.Endian.little, parsed.endian);
    try std.testing.expectEqual(FileType.rel, parsed.file_type);
    try std.testing.expectEqual(Machine.aarch64, parsed.machine);
    try std.testing.expectEqual(@as(u64, 0x1000), parsed.shoff);
    try std.testing.expectEqual(@as(u16, 64), parsed.ehsize);
    try std.testing.expectEqual(@as(u16, 64), parsed.shentsize);
    try std.testing.expectEqual(@as(u16, 12), parsed.shnum);
    try std.testing.expectEqual(@as(u16, 11), parsed.shstrndx);
}

test "parse 32-bit big-endian ELF header" {
    var hdr_buf: [52]u8 = undefined;
    @memset(&hdr_buf, 0);

    @memcpy(hdr_buf[0..4], &MAGIC);
    hdr_buf[4] = 1; // ELFCLASS32
    hdr_buf[5] = 2; // ELFDATA2MSB (big-endian)
    hdr_buf[6] = 1; // EV_CURRENT

    std.mem.writeInt(u16, hdr_buf[16..18], 2, .big); // ET_EXEC
    std.mem.writeInt(u16, hdr_buf[18..20], 40, .big); // EM_ARM
    std.mem.writeInt(u32, hdr_buf[20..24], 1, .big);
    std.mem.writeInt(u32, hdr_buf[24..28], 0x8000, .big);
    std.mem.writeInt(u32, hdr_buf[28..32], 0x34, .big);
    std.mem.writeInt(u32, hdr_buf[32..36], 0x2000, .big);
    std.mem.writeInt(u32, hdr_buf[36..40], 0x05000000, .big);
    std.mem.writeInt(u16, hdr_buf[40..42], 52, .big);
    std.mem.writeInt(u16, hdr_buf[42..44], 32, .big);
    std.mem.writeInt(u16, hdr_buf[44..46], 2, .big);
    std.mem.writeInt(u16, hdr_buf[46..48], 40, .big);
    std.mem.writeInt(u16, hdr_buf[48..50], 8, .big);
    std.mem.writeInt(u16, hdr_buf[50..52], 7, .big);

    const parsed = try Header.parse(&hdr_buf);

    try std.testing.expectEqual(Class.elf32, parsed.class);
    try std.testing.expectEqual(std.builtin.Endian.big, parsed.endian);
    try std.testing.expectEqual(FileType.exec, parsed.file_type);
    try std.testing.expectEqual(Machine.arm, parsed.machine);
    try std.testing.expectEqual(@as(u64, 0x8000), parsed.entry);
    try std.testing.expectEqual(@as(u64, 0x2000), parsed.shoff);
    try std.testing.expectEqual(@as(u16, 52), parsed.ehsize);
    try std.testing.expectEqual(@as(u16, 40), parsed.shentsize);
    try std.testing.expectEqual(@as(u16, 8), parsed.shnum);
    try std.testing.expectEqual(@as(u16, 7), parsed.shstrndx);
}

test "parse 64-bit ELF section header" {
    var sh_buf: [64]u8 = undefined;
    @memset(&sh_buf, 0);

    std.mem.writeInt(u32, sh_buf[0..4], 12, .little); // sh_name
    std.mem.writeInt(u32, sh_buf[4..8], 1, .little); // SHT_PROGBITS
    std.mem.writeInt(u64, sh_buf[8..16], flags.ALLOC | flags.EXECINSTR, .little); // flags
    std.mem.writeInt(u64, sh_buf[16..24], 0x400000, .little); // addr
    std.mem.writeInt(u64, sh_buf[24..32], 0x100, .little); // offset
    std.mem.writeInt(u64, sh_buf[32..40], 0x48, .little); // size
    std.mem.writeInt(u32, sh_buf[40..44], 0, .little); // link
    std.mem.writeInt(u32, sh_buf[44..48], 0, .little); // info
    std.mem.writeInt(u64, sh_buf[48..56], 16, .little); // addralign
    std.mem.writeInt(u64, sh_buf[56..64], 0, .little); // entsize

    var hdr: Header = undefined;
    hdr.class = .elf64;
    hdr.endian = .little;
    hdr.shoff = 0;
    hdr.shentsize = 64;
    hdr.shnum = 1;

    const sh = try hdr.parseSectionHeader(&sh_buf, 0);

    try std.testing.expectEqual(@as(u32, 12), sh.name_offset);
    try std.testing.expectEqual(SectionType.progbits, sh.sh_type);
    try std.testing.expect(sh.isAlloc());
    try std.testing.expect(sh.isExecutable());
    try std.testing.expect(!sh.isWritable());
    try std.testing.expectEqual(@as(u64, 0x400000), sh.addr);
    try std.testing.expectEqual(@as(u64, 0x100), sh.offset);
    try std.testing.expectEqual(@as(u64, 0x48), sh.size);
    try std.testing.expectEqual(@as(u64, 16), sh.addralign);
}

test "parse 32-bit ELF section header" {
    var sh_buf: [40]u8 = undefined;
    @memset(&sh_buf, 0);

    std.mem.writeInt(u32, sh_buf[0..4], 5, .big); // sh_name
    std.mem.writeInt(u32, sh_buf[4..8], 8, .big); // SHT_NOBITS (.bss)
    std.mem.writeInt(u32, sh_buf[8..12], @as(u32, @truncate(flags.ALLOC | flags.WRITE)), .big);
    std.mem.writeInt(u32, sh_buf[12..16], 0x20000, .big);
    std.mem.writeInt(u32, sh_buf[16..20], 0x80, .big);
    std.mem.writeInt(u32, sh_buf[20..24], 0x20, .big);
    std.mem.writeInt(u32, sh_buf[24..28], 0, .big);
    std.mem.writeInt(u32, sh_buf[28..32], 0, .big);
    std.mem.writeInt(u32, sh_buf[32..36], 4, .big);
    std.mem.writeInt(u32, sh_buf[36..40], 0, .big);

    var hdr: Header = undefined;
    hdr.class = .elf32;
    hdr.endian = .big;
    hdr.shoff = 0;
    hdr.shentsize = 40;
    hdr.shnum = 1;

    const sh = try hdr.parseSectionHeader(&sh_buf, 0);

    try std.testing.expectEqual(@as(u32, 5), sh.name_offset);
    try std.testing.expectEqual(SectionType.nobits, sh.sh_type);
    try std.testing.expect(sh.isAlloc());
    try std.testing.expect(sh.isWritable());
    try std.testing.expect(!sh.isExecutable());
    try std.testing.expectEqual(@as(u64, 0x20000), sh.addr);
    try std.testing.expectEqual(@as(u64, 0x20), sh.size);
}

test "section data slice retrieval and nobits empty return" {
    var file_mock: [256]u8 = undefined;
    @memset(&file_mock, 0);
    @memcpy(file_mock[64..80], "embedded payload");

    const progbits_sh = SectionHeader{
        .name_offset = 0,
        .sh_type = .progbits,
        .sh_flags = flags.ALLOC,
        .addr = 0,
        .offset = 64,
        .size = 16,
        .link = 0,
        .info = 0,
        .addralign = 8,
        .entsize = 0,
    };

    const data = try progbits_sh.getData(&file_mock);
    try std.testing.expectEqualStrings("embedded payload", data);

    const nobits_sh = SectionHeader{
        .name_offset = 0,
        .sh_type = .nobits,
        .sh_flags = flags.ALLOC | flags.WRITE,
        .addr = 0,
        .offset = 64,
        .size = 1024,
        .link = 0,
        .info = 0,
        .addralign = 8,
        .entsize = 0,
    };

    const nobits_data = try nobits_sh.getData(&file_mock);
    try std.testing.expectEqual(@as(usize, 0), nobits_data.len);
}

test "section name lookup from string table" {
    const shstrtab = "\x00.text\x00.data\x00.bss\x00.shstrtab\x00";

    const text_sh = SectionHeader{
        .name_offset = 1,
        .sh_type = .progbits,
        .sh_flags = flags.ALLOC | flags.EXECINSTR,
        .addr = 0,
        .offset = 0,
        .size = 0,
        .link = 0,
        .info = 0,
        .addralign = 4,
        .entsize = 0,
    };

    const name = try text_sh.getName(shstrtab);
    try std.testing.expectEqualStrings(".text", name);

    const data_sh = SectionHeader{
        .name_offset = 7,
        .sh_type = .progbits,
        .sh_flags = flags.ALLOC | flags.WRITE,
        .addr = 0,
        .offset = 0,
        .size = 0,
        .link = 0,
        .info = 0,
        .addralign = 4,
        .entsize = 0,
    };

    const data_name = try data_sh.getName(shstrtab);
    try std.testing.expectEqualStrings(".data", data_name);
}

test "section parsing reports out of bounds errors cleanly" {
    var short_buf: [30]u8 = undefined;
    @memset(&short_buf, 0);

    var hdr: Header = undefined;
    hdr.class = .elf64;
    hdr.endian = .little;
    hdr.shoff = 100;
    hdr.shentsize = 64;
    hdr.shnum = 2;

    try std.testing.expectError(error.TruncatedSectionTable, hdr.parseSectionHeader(&short_buf, 0));
    try std.testing.expectError(error.InvalidSectionIndex, hdr.parseSectionHeader(&short_buf, 5));
}

test "section type name handles custom and unknown integer values without panicking" {
    const custom_sec: SectionType = @fromBackingInt(@intCast(0x6ffffff6));
    try std.testing.expectEqualStrings("gnu_hash", custom_sec.name());

    const unknown_sec: SectionType = @fromBackingInt(@intCast(0x12345678));
    try std.testing.expectEqualStrings("unknown", unknown_sec.name());
}
