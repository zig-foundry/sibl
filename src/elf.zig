//! Phase 2.1: ELF Header Parsing and Magic Byte Validation.
//!
//! Provides types and zero-copy parsers for 32-bit and 64-bit ELF headers
//! across both little-endian and big-endian targets.

const std = @import("std");

// === Constants and Types ===

/// The 4-byte magic signature present at the start of every valid ELF binary.
pub const MAGIC = [4]u8{ 0x7F, 'E', 'L', 'F' };

/// ELF architecture width (EI_CLASS).
pub const Class = enum(u8) {
    none = 0,
    elf32 = 1,
    elf64 = 2,
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
    dyn = 3, // Shared library (.so)
    core = 4, // Core dump
    _,
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

/// Errors encountered while reading raw ELF headers.
pub const HeaderError = error{
    TruncatedHeader,
    InvalidMagic,
    InvalidClass,
    InvalidEndian,
    InvalidVersion,
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
        // Minimum check: 16 bytes for e_ident
        if (bytes.len < 16) return error.TruncatedHeader;

        // Step 1: Check magic bytes 0x7F 'E' 'L' 'F'
        if (!std.mem.eql(u8, bytes[0..4], &MAGIC)) {
            return error.InvalidMagic;
        }

        // Step 2: Read class (32-bit vs 64-bit)
        const class: Class = switch (bytes[4]) {
            1 => .elf32,
            2 => .elf64,
            else => return error.InvalidClass,
        };

        // Step 3: Read endianness
        const endian: std.builtin.Endian = switch (bytes[5]) {
            1 => .little,
            2 => .big,
            else => return error.InvalidEndian,
        };

        // Step 4: Validate ELF version (must be 1 for EV_CURRENT)
        if (bytes[6] != 1) {
            return error.InvalidVersion;
        }

        const os_abi: OsAbi = @fromBackingInt(@intCast(bytes[7]));
        const abi_version = bytes[8];

        // Step 5: Parse architecture-specific layout
        return switch (class) {
            .elf64 => parseElf64(bytes, endian, os_abi, abi_version),
            .elf32 => parseElf32(bytes, endian, os_abi, abi_version),
            .none => error.InvalidClass,
        };
    }

    // --- Private Helper Parsers ---

    fn parseElf64(
        bytes: []const u8,
        endian: std.builtin.Endian,
        os_abi: OsAbi,
        abi_version: u8,
    ) HeaderError!Header {
        // Elf64_Ehdr is 64 bytes total
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
        // Elf32_Ehdr is 52 bytes total
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

    // e_ident
    @memcpy(hdr_buf[0..4], &MAGIC);
    hdr_buf[4] = 2; // ELFCLASS64
    hdr_buf[5] = 1; // ELFDATA2LSB (little-endian)
    hdr_buf[6] = 1; // EV_CURRENT
    hdr_buf[7] = 0; // System V
    hdr_buf[8] = 0; // ABI version

    // e_type: ET_REL (1)
    std.mem.writeInt(u16, hdr_buf[16..18], 1, .little);
    // e_machine: EM_AARCH64 (183)
    std.mem.writeInt(u16, hdr_buf[18..20], 183, .little);
    // e_version: 1
    std.mem.writeInt(u32, hdr_buf[20..24], 1, .little);
    // e_entry: 0x0 (relocatable objects have no entry point)
    std.mem.writeInt(u64, hdr_buf[24..32], 0, .little);
    // e_phoff: 0x0 (no program headers in .o)
    std.mem.writeInt(u64, hdr_buf[32..40], 0, .little);
    // e_shoff: 0x1000 (section header offset)
    std.mem.writeInt(u64, hdr_buf[40..48], 0x1000, .little);
    // e_flags: 0x0
    std.mem.writeInt(u32, hdr_buf[48..52], 0, .little);
    // e_ehsize: 64
    std.mem.writeInt(u16, hdr_buf[52..54], 64, .little);
    // e_phentsize: 0
    std.mem.writeInt(u16, hdr_buf[54..56], 0, .little);
    // e_phnum: 0
    std.mem.writeInt(u16, hdr_buf[56..58], 0, .little);
    // e_shentsize: 64
    std.mem.writeInt(u16, hdr_buf[58..60], 64, .little);
    // e_shnum: 12
    std.mem.writeInt(u16, hdr_buf[60..62], 12, .little);
    // e_shstrndx: 11
    std.mem.writeInt(u16, hdr_buf[62..64], 11, .little);

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

    // e_type: ET_EXEC (2)
    std.mem.writeInt(u16, hdr_buf[16..18], 2, .big);
    // e_machine: EM_ARM (40)
    std.mem.writeInt(u16, hdr_buf[18..20], 40, .big);
    // e_version: 1
    std.mem.writeInt(u32, hdr_buf[20..24], 1, .big);
    // e_entry: 0x8000
    std.mem.writeInt(u32, hdr_buf[24..28], 0x8000, .big);
    // e_phoff: 0x34
    std.mem.writeInt(u32, hdr_buf[28..32], 0x34, .big);
    // e_shoff: 0x2000
    std.mem.writeInt(u32, hdr_buf[32..36], 0x2000, .big);
    // e_flags: 0x05000000
    std.mem.writeInt(u32, hdr_buf[36..40], 0x05000000, .big);
    // e_ehsize: 52
    std.mem.writeInt(u16, hdr_buf[40..42], 52, .big);
    // e_phentsize: 32
    std.mem.writeInt(u16, hdr_buf[42..44], 32, .big);
    // e_phnum: 2
    std.mem.writeInt(u16, hdr_buf[44..46], 2, .big);
    // e_shentsize: 40
    std.mem.writeInt(u16, hdr_buf[46..48], 40, .big);
    // e_shnum: 8
    std.mem.writeInt(u16, hdr_buf[48..50], 8, .big);
    // e_shstrndx: 7
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
