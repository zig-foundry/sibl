//! Phase 4.1: Mach-O Header and Magic Parser for sibl.
//!
//! Provides zero-copy parsing for 32-bit and 64-bit Mach-O binaries,
//! detecting Apple Silicon (ARM64), Intel (x86_64), and FAT containers.

const std = @import("std");

// === Constants and Magic Signatures ===

/// 32-bit Mach-O magic numbers.
pub const MH_MAGIC: u32 = 0xFEEDFACE;
pub const MH_CIGAM: u32 = 0xCEFAEDFE;

/// 64-bit Mach-O magic numbers.
pub const MH_MAGIC_64: u32 = 0xFEEDFACF;
pub const MH_CIGAM_64: u32 = 0xCFFACEED;

/// Universal / FAT binary magic numbers.
pub const FAT_MAGIC: u32 = 0xCAFEBABE;
pub const FAT_CIGAM: u32 = 0xBEBAFECA;
pub const FAT_MAGIC_64: u32 = 0xCAFEBABF;
pub const FAT_CIGAM_64: u32 = 0xBFBAFECA;

/// Mach-O CPU architecture types.
pub const CpuType = enum(u32) {
    any = 0xFFFFFFFF,
    i386 = 7,
    x86_64 = 0x01000007,
    arm = 12,
    arm64 = 0x0100000C,
    arm64_32 = 0x0200000C,
    _,

    pub fn name(self: CpuType) []const u8 {
        return switch (self) {
            .any => "any",
            .i386 => "i386",
            .x86_64 => "x86_64",
            .arm => "arm",
            .arm64 => "arm64",
            .arm64_32 => "arm64_32",
            _ => "unknown",
        };
    }
};

/// Mach-O file type identifier (filetype).
pub const FileType = enum(u32) {
    object = 0x1, // Relocatable object (.o)
    execute = 0x2, // Standard executable binary
    fvmlib = 0x3,
    core = 0x4,
    preload = 0x5,
    dylib = 0x6, // Dynamic library (.dylib)
    dylinker = 0x7, // Dynamic linker runtime (/usr/lib/dyld)
    bundle = 0x8, // Dynamically loaded plugin bundle
    dylib_stub = 0x9,
    dsym = 0xA, // Debug symbols companion
    kext_bundle = 0xB,
    _,

    pub fn name(self: FileType) []const u8 {
        return switch (self) {
            .object => "object",
            .execute => "execute",
            .fvmlib => "fvmlib",
            .core => "core",
            .preload => "preload",
            .dylib => "dylib",
            .dylinker => "dylinker",
            .bundle => "bundle",
            .dylib_stub => "dylib_stub",
            .dsym => "dsym",
            .kext_bundle => "kext_bundle",
            _ => "unknown",
        };
    }
};

/// Mach-O header flags bitmask (flags).
pub const flags = struct {
    pub const NOUNDEFS: u32 = 0x1;
    pub const INCRLINK: u32 = 0x2;
    pub const DYLDLINK: u32 = 0x4;
    pub const BINDATLOAD: u32 = 0x8;
    pub const PREBOUND: u32 = 0x10;
    pub const SPLIT_SEGS: u32 = 0x20;
    pub const LAZY_INIT: u32 = 0x40;
    pub const TWOLEVEL: u32 = 0x80;
    pub const FORCE_FLAT: u32 = 0x100;
    pub const NOMULTIDEFS: u32 = 0x200;
    pub const NOFIXPREBINDING: u32 = 0x400;
    pub const PREBINDABLE: u32 = 0x800;
    pub const ALLMODSBOUND: u32 = 0x1000;
    pub const SUBSECTIONS_VIA_SYMBOLS: u32 = 0x2000;
    pub const CANONICAL: u32 = 0x4000;
    pub const WEAK_DEFINES: u32 = 0x8000;
    pub const BINDS_TO_WEAK: u32 = 0x10000;
    pub const ALLOW_STACK_EXECUTION: u32 = 0x20000;
    pub const ROOT_SAFE: u32 = 0x40000;
    pub const SETUID_SAFE: u32 = 0x80000;
    pub const NO_REEXPORTED_DYLIBS: u32 = 0x100000;
    pub const PIE: u32 = 0x200000;
    pub const DEAD_STRIPPABLE_DYLIB: u32 = 0x400000;
    pub const HAS_TLV_DESCRIPTORS: u32 = 0x800000;
    pub const NO_HEAP_EXECUTION: u32 = 0x1000000;
};

/// Errors encountered while reading Mach-O headers.
pub const Error = error{
    TruncatedHeader,
    InvalidMagic,
    UnsupportedFatBinary,
};

// === Normalized Mach-O Header Structure ===

/// Normalized representation for both 32-bit and 64-bit Mach-O headers.
pub const Header = struct {
    /// True if 64-bit (mach_header_64, 32 bytes), false if 32-bit (28 bytes)
    is_64bit: bool,
    /// Byte order encoding
    endian: std.builtin.Endian,
    /// Target CPU architecture
    cpu_type: CpuType,
    /// Target machine sub-type specifier
    cpu_subtype: u32,
    /// File type (object, execute, dylib, etc.)
    file_type: FileType,
    /// Number of load commands following this header
    ncmds: u32,
    /// Byte size of all load commands combined
    sizeofcmds: u32,
    /// Header flags bitmask
    flags: u32,
    /// Reserved 4-byte padding field (present only in 64-bit headers)
    reserved: u32,

    /// Returns true if this is a relocatable object file (.o).
    pub fn isObject(self: *const Header) bool {
        return self.file_type == .object;
    }

    /// Returns true if this is an executable binary.
    pub fn isExecutable(self: *const Header) bool {
        return self.file_type == .execute;
    }

    /// Returns true if this is a dynamic library (.dylib).
    pub fn isDylib(self: *const Header) bool {
        return self.file_type == .dylib;
    }

    /// Returns true if this binary is position-independent (PIE).
    pub fn isPie(self: *const Header) bool {
        return (self.flags & flags.PIE) != 0;
    }

    /// Header size in bytes (32 bytes for 64-bit, 28 bytes for 32-bit).
    pub fn headerSize(self: *const Header) usize {
        return if (self.is_64bit) 32 else 28;
    }

    /// Parse a Mach-O header from raw byte slice.
    pub fn parse(bytes: []const u8) Error!Header {
        if (bytes.len < 4) return error.TruncatedHeader;

        // Read first 4 bytes in native/little-endian to check magic
        const raw_magic_le = std.mem.readInt(u32, bytes[0..4], .little);

        // Check for FAT / Universal Binaries first
        if (raw_magic_le == FAT_MAGIC or raw_magic_le == FAT_CIGAM or
            raw_magic_le == FAT_MAGIC_64 or raw_magic_le == FAT_CIGAM_64)
        {
            return error.UnsupportedFatBinary;
        }

        var is_64bit: bool = false;
        var endian: std.builtin.Endian = .little;

        if (raw_magic_le == MH_MAGIC_64) {
            is_64bit = true;
            endian = .little;
        } else if (raw_magic_le == MH_CIGAM_64) {
            is_64bit = true;
            endian = .big;
        } else if (raw_magic_le == MH_MAGIC) {
            is_64bit = false;
            endian = .little;
        } else if (raw_magic_le == MH_CIGAM) {
            is_64bit = false;
            endian = .big;
        } else {
            return error.InvalidMagic;
        }

        const required_size: usize = if (is_64bit) 32 else 28;
        if (bytes.len < required_size) {
            return error.TruncatedHeader;
        }

        const raw_cpu = std.mem.readInt(u32, bytes[4..8], endian);
        const raw_subtype = std.mem.readInt(u32, bytes[8..12], endian);
        const raw_filetype = std.mem.readInt(u32, bytes[12..16], endian);
        const ncmds = std.mem.readInt(u32, bytes[16..20], endian);
        const sizeofcmds = std.mem.readInt(u32, bytes[20..24], endian);
        const raw_flags = std.mem.readInt(u32, bytes[24..28], endian);

        const reserved: u32 = if (is_64bit)
            std.mem.readInt(u32, bytes[28..32], endian)
        else
            0;

        return .{
            .is_64bit = is_64bit,
            .endian = endian,
            .cpu_type = @fromBackingInt(@intCast(raw_cpu)),
            .cpu_subtype = raw_subtype,
            .file_type = @fromBackingInt(@intCast(raw_filetype)),
            .ncmds = ncmds,
            .sizeofcmds = sizeofcmds,
            .flags = raw_flags,
            .reserved = reserved,
        };
    }
};

// === Unit Tests ===

test "reject file shorter than minimum identification bytes" {
    const short_buf = [_]u8{ 0xCF, 0xFA };
    try std.testing.expectError(error.TruncatedHeader, Header.parse(&short_buf));
}

test "reject file with invalid magic bytes" {
    var bad_magic: [32]u8 = undefined;
    @memset(&bad_magic, 0);
    @memcpy(bad_magic[0..4], "NOPE");
    try std.testing.expectError(error.InvalidMagic, Header.parse(&bad_magic));
}

test "detect and reject universal fat binaries with explicit error" {
    var fat_buf: [32]u8 = undefined;
    @memset(&fat_buf, 0);
    std.mem.writeInt(u32, fat_buf[0..4], FAT_MAGIC, .little);
    try std.testing.expectError(error.UnsupportedFatBinary, Header.parse(&fat_buf));

    std.mem.writeInt(u32, fat_buf[0..4], FAT_CIGAM, .little);
    try std.testing.expectError(error.UnsupportedFatBinary, Header.parse(&fat_buf));
}

test "parse 64-bit little-endian ARM64 Mach-O relocatable object header" {
    var hdr_buf: [32]u8 = undefined;
    @memset(&hdr_buf, 0);

    std.mem.writeInt(u32, hdr_buf[0..4], MH_MAGIC_64, .little); // 0xFEEDFACF
    std.mem.writeInt(u32, hdr_buf[4..8], 0x0100000C, .little); // CPU_TYPE_ARM64
    std.mem.writeInt(u32, hdr_buf[8..12], 0x80000002, .little); // CPU_SUBTYPE_ARM64_ALL
    std.mem.writeInt(u32, hdr_buf[12..16], 0x1, .little); // MH_OBJECT
    std.mem.writeInt(u32, hdr_buf[16..20], 4, .little); // 4 load commands
    std.mem.writeInt(u32, hdr_buf[20..24], 688, .little); // sizeofcmds
    std.mem.writeInt(u32, hdr_buf[24..28], flags.SUBSECTIONS_VIA_SYMBOLS, .little);
    std.mem.writeInt(u32, hdr_buf[28..32], 0, .little); // reserved

    const hdr = try Header.parse(&hdr_buf);

    try std.testing.expect(hdr.is_64bit);
    try std.testing.expectEqual(std.builtin.Endian.little, hdr.endian);
    try std.testing.expectEqual(CpuType.arm64, hdr.cpu_type);
    try std.testing.expectEqualStrings("arm64", hdr.cpu_type.name());
    try std.testing.expectEqual(FileType.object, hdr.file_type);
    try std.testing.expectEqualStrings("object", hdr.file_type.name());
    try std.testing.expect(hdr.isObject());
    try std.testing.expect(!hdr.isExecutable());
    try std.testing.expect(!hdr.isDylib());
    try std.testing.expectEqual(@as(u32, 4), hdr.ncmds);
    try std.testing.expectEqual(@as(u32, 688), hdr.sizeofcmds);
    try std.testing.expectEqual(@as(usize, 32), hdr.headerSize());
}

test "parse 64-bit little-endian x86_64 Mach-O executable header" {
    var hdr_buf: [32]u8 = undefined;
    @memset(&hdr_buf, 0);

    std.mem.writeInt(u32, hdr_buf[0..4], MH_MAGIC_64, .little);
    std.mem.writeInt(u32, hdr_buf[4..8], 0x01000007, .little); // CPU_TYPE_X86_64
    std.mem.writeInt(u32, hdr_buf[8..12], 3, .little); // CPU_SUBTYPE_X86_64_ALL
    std.mem.writeInt(u32, hdr_buf[12..16], 0x2, .little); // MH_EXECUTE
    std.mem.writeInt(u32, hdr_buf[16..20], 16, .little);
    std.mem.writeInt(u32, hdr_buf[20..24], 1480, .little);
    std.mem.writeInt(u32, hdr_buf[24..28], flags.NOUNDEFS | flags.DYLDLINK | flags.TWOLEVEL | flags.PIE, .little);
    std.mem.writeInt(u32, hdr_buf[28..32], 0, .little);

    const hdr = try Header.parse(&hdr_buf);

    try std.testing.expect(hdr.is_64bit);
    try std.testing.expectEqual(CpuType.x86_64, hdr.cpu_type);
    try std.testing.expectEqual(FileType.execute, hdr.file_type);
    try std.testing.expect(hdr.isExecutable());
    try std.testing.expect(hdr.isPie());
}

test "parse 64-bit big-endian Mach-O header (MH_CIGAM_64)" {
    var hdr_buf: [32]u8 = undefined;
    @memset(&hdr_buf, 0);

    std.mem.writeInt(u32, hdr_buf[0..4], MH_CIGAM_64, .little); // 0xCFFACEED in little-endian representation
    std.mem.writeInt(u32, hdr_buf[4..8], 0x0100000C, .big); // written in big-endian
    std.mem.writeInt(u32, hdr_buf[8..12], 0, .big);
    std.mem.writeInt(u32, hdr_buf[12..16], 0x6, .big); // MH_DYLIB
    std.mem.writeInt(u32, hdr_buf[16..20], 8, .big);
    std.mem.writeInt(u32, hdr_buf[20..24], 512, .big);
    std.mem.writeInt(u32, hdr_buf[24..28], 0, .big);
    std.mem.writeInt(u32, hdr_buf[28..32], 0, .big);

    const hdr = try Header.parse(&hdr_buf);

    try std.testing.expect(hdr.is_64bit);
    try std.testing.expectEqual(std.builtin.Endian.big, hdr.endian);
    try std.testing.expectEqual(CpuType.arm64, hdr.cpu_type);
    try std.testing.expectEqual(FileType.dylib, hdr.file_type);
    try std.testing.expect(hdr.isDylib());
}

test "parse 32-bit Mach-O header (28 bytes)" {
    var hdr_buf: [28]u8 = undefined;
    @memset(&hdr_buf, 0);

    std.mem.writeInt(u32, hdr_buf[0..4], MH_MAGIC, .little); // 0xFEEDFACE
    std.mem.writeInt(u32, hdr_buf[4..8], 7, .little); // i386
    std.mem.writeInt(u32, hdr_buf[8..12], 3, .little);
    std.mem.writeInt(u32, hdr_buf[12..16], 0x1, .little); // MH_OBJECT
    std.mem.writeInt(u32, hdr_buf[16..20], 3, .little);
    std.mem.writeInt(u32, hdr_buf[20..24], 280, .little);
    std.mem.writeInt(u32, hdr_buf[24..28], 0, .little);

    const hdr = try Header.parse(&hdr_buf);

    try std.testing.expect(!hdr.is_64bit);
    try std.testing.expectEqual(CpuType.i386, hdr.cpu_type);
    try std.testing.expectEqual(@as(usize, 28), hdr.headerSize());
}
