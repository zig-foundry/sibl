//! Phase 4.1 & 4.2: Mach-O Header and Load Commands Decoder.
//!
//! Provides zero-copy parsing for 32-bit and 64-bit Mach-O headers,
//! universal binary detection, and decoders for all core load commands
//! (LC_SEGMENT_64, LC_SYMTAB, LC_DYSYMTAB, LC_LOAD_DYLIB, LC_MAIN, LC_BUILD_VERSION).

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
    object = 0x1,
    execute = 0x2,
    fvmlib = 0x3,
    core = 0x4,
    preload = 0x5,
    dylib = 0x6,
    dylinker = 0x7,
    bundle = 0x8,
    dylib_stub = 0x9,
    dsym = 0xA,
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

/// Load Command Type IDs (cmd).
pub const CommandType = enum(u32) {
    segment = 0x1,
    symtab = 0x2,
    symseg = 0x3,
    thread = 0x4,
    unixthread = 0x5,
    loadfvmlib = 0x6,
    idfvmlib = 0x7,
    ident = 0x8,
    fvmfile = 0x9,
    prepage = 0xA,
    dysymtab = 0xB,
    load_dylib = 0xC,
    id_dylib = 0xD,
    load_dylinker = 0xE,
    id_dylinker = 0xF,
    prebound_dylib = 0x10,
    routines = 0x11,
    sub_framework = 0x12,
    sub_umbrella = 0x13,
    sub_client = 0x14,
    sub_library = 0x15,
    twolevel_hints = 0x16,
    prebind_cksum = 0x17,
    load_weak_dylib = 0x18 | 0x80000000,
    segment_64 = 0x19,
    routines_64 = 0x1A,
    uuid = 0x1B,
    rpath = 0x1C | 0x80000000,
    code_signature = 0x1D,
    segment_split_info = 0x1E,
    reexport_dylib = 0x1F | 0x80000000,
    lazy_load_dylib = 0x20,
    encryption_info = 0x21,
    dyld_info = 0x22,
    dyld_info_only = 0x22 | 0x80000000,
    load_upward_dylib = 0x23 | 0x80000000,
    version_min_macosx = 0x24,
    version_min_iphoneos = 0x25,
    function_starts = 0x26,
    dyld_environment = 0x27,
    main = 0x28 | 0x80000000,
    data_in_code = 0x29,
    source_version = 0x2A,
    dylib_code_sign_drs = 0x2B,
    encryption_info_64 = 0x2C,
    linker_option = 0x2D,
    linker_optimization_hint = 0x2E,
    version_min_tvos = 0x2F,
    version_min_watchos = 0x30,
    note = 0x31,
    build_version = 0x32,
    dyld_exports_trie = 0x33 | 0x80000000,
    dyld_chained_fixups = 0x34 | 0x80000000,
    fileset_entry = 0x35 | 0x80000000,
    _,

    pub fn name(self: CommandType) []const u8 {
        return switch (self) {
            .segment => "SEGMENT",
            .symtab => "SYMTAB",
            .symseg => "SYMSEG",
            .thread => "THREAD",
            .unixthread => "UNIXTHREAD",
            .loadfvmlib => "LOADFVMLIB",
            .idfvmlib => "IDFVMLIB",
            .ident => "IDENT",
            .fvmfile => "FVMFILE",
            .prepage => "PREPAGE",
            .dysymtab => "DYSYMTAB",
            .load_dylib => "LOAD_DYLIB",
            .id_dylib => "ID_DYLIB",
            .load_dylinker => "LOAD_DYLINKER",
            .id_dylinker => "ID_DYLINKER",
            .prebound_dylib => "PREBOUND_DYLIB",
            .routines => "ROUTINES",
            .sub_framework => "SUB_FRAMEWORK",
            .sub_umbrella => "SUB_UMBRELLA",
            .sub_client => "SUB_CLIENT",
            .sub_library => "SUB_LIBRARY",
            .twolevel_hints => "TWOLEVEL_HINTS",
            .prebind_cksum => "PREBIND_CKSUM",
            .load_weak_dylib => "LOAD_WEAK_DYLIB",
            .segment_64 => "SEGMENT_64",
            .routines_64 => "ROUTINES_64",
            .uuid => "UUID",
            .rpath => "RPATH",
            .code_signature => "CODE_SIGNATURE",
            .segment_split_info => "SEGMENT_SPLIT_INFO",
            .reexport_dylib => "REEXPORT_DYLIB",
            .lazy_load_dylib => "LAZY_LOAD_DYLIB",
            .encryption_info => "ENCRYPTION_INFO",
            .dyld_info => "DYLD_INFO",
            .dyld_info_only => "DYLD_INFO_ONLY",
            .load_upward_dylib => "LOAD_UPWARD_DYLIB",
            .version_min_macosx => "VERSION_MIN_MACOSX",
            .version_min_iphoneos => "VERSION_MIN_IPHONEOS",
            .function_starts => "FUNCTION_STARTS",
            .dyld_environment => "DYLD_ENVIRONMENT",
            .main => "MAIN",
            .data_in_code => "DATA_IN_CODE",
            .source_version => "SOURCE_VERSION",
            .dylib_code_sign_drs => "DYLIB_CODE_SIGN_DRS",
            .encryption_info_64 => "ENCRYPTION_INFO_64",
            .linker_option => "LINKER_OPTION",
            .linker_optimization_hint => "LINKER_OPTIMIZATION_HINT",
            .version_min_tvos => "VERSION_MIN_TVOS",
            .version_min_watchos => "VERSION_MIN_WATCHOS",
            .note => "NOTE",
            .build_version => "BUILD_VERSION",
            .dyld_exports_trie => "DYLD_EXPORTS_TRIE",
            .dyld_chained_fixups => "DYLD_CHAINED_FIXUPS",
            .fileset_entry => "FILESET_ENTRY",
            else => "LOAD_COMMAND",
        };
    }
};

/// Memory VM Protection Flags.
pub const vm_prot = struct {
    pub const NONE: u32 = 0x0;
    pub const READ: u32 = 0x1;
    pub const WRITE: u32 = 0x2;
    pub const EXECUTE: u32 = 0x4;
};

// === Error Sets ===

pub const Error = error{
    TruncatedHeader,
    InvalidMagic,
    UnsupportedFatBinary,
};

pub const CommandError = error{
    TruncatedCommand,
    InvalidCommandSize,
    OutOfBounds,
};

// === Decoded Load Command Structures ===

/// Decoded LC_SEGMENT_64 command (72 bytes before sections).
pub const Segment64Command = struct {
    raw_name: [16]u8,
    vmaddr: u64,
    vmsize: u64,
    fileoff: u64,
    filesize: u64,
    maxprot: u32,
    initprot: u32,
    nsects: u32,
    flags: u32,

    pub fn getName(self: *const Segment64Command) []const u8 {
        const len = std.mem.indexOfScalar(u8, &self.raw_name, 0) orelse self.raw_name.len;
        return self.raw_name[0..len];
    }

    pub fn isExecutable(self: *const Segment64Command) bool {
        return (self.initprot & vm_prot.EXECUTE) != 0;
    }

    pub fn isWritable(self: *const Segment64Command) bool {
        return (self.initprot & vm_prot.WRITE) != 0;
    }

    pub fn isReadable(self: *const Segment64Command) bool {
        return (self.initprot & vm_prot.READ) != 0;
    }
};

/// Decoded LC_SYMTAB command (24 bytes).
pub const SymtabCommand = struct {
    symoff: u32,
    nsyms: u32,
    stroff: u32,
    strsize: u32,
};

/// Decoded LC_DYSYMTAB command (80 bytes).
pub const DysymtabCommand = struct {
    ilocalsym: u32,
    nlocalsym: u32,
    iextdefsym: u32,
    nextdefsym: u32,
    iundefsym: u32,
    nundefsym: u32,
    tocoff: u32,
    ntoc: u32,
    modtaboff: u32,
    nmodtab: u32,
    extrefsymoff: u32,
    nextrefsyms: u32,
    indirectsymoff: u32,
    nindirectsyms: u32,
    extreloff: u32,
    nextrel: u32,
    locreloff: u32,
    nlocrel: u32,
};

/// Decoded LC_MAIN command (24 bytes).
pub const MainCommand = struct {
    entryoff: u64,
    stacksize: u64,
};

/// Decoded LC_LOAD_DYLIB / LC_ID_DYLIB / LC_RPATH command.
pub const DylibCommand = struct {
    name_offset: u32,
    timestamp: u32,
    current_version: u32,
    compatibility_version: u32,
    raw_data: []const u8,

    pub fn getName(self: *const DylibCommand) ?[:0]const u8 {
        if (self.name_offset >= self.raw_data.len) return null;
        const slice = self.raw_data[self.name_offset..];
        const len = std.mem.indexOfScalar(u8, slice, 0) orelse return null;
        return slice[0..len :0];
    }
};

/// Decoded LC_BUILD_VERSION command (24 bytes minimum).
pub const BuildVersionCommand = struct {
    platform: u32, // 1 = macOS, 2 = iOS, 7 = watchOS
    minos: u32, // X.Y.Z encoded: (X << 16) | (Y << 8) | Z
    sdk: u32,
    ntools: u32,

    pub fn platformName(self: *const BuildVersionCommand) []const u8 {
        return switch (self.platform) {
            1 => "macOS",
            2 => "iOS",
            3 => "tvOS",
            4 => "watchOS",
            5 => "bridgeOS",
            6 => "MacCatalyst",
            7 => "iOSSimulator",
            8 => "tvOSSimulator",
            9 => "watchOSSimulator",
            else => "unknown",
        };
    }
};

/// Generic view over any raw Mach-O Load Command.
pub const LoadCommand = struct {
    cmd: CommandType,
    cmdsize: u32,
    bytes: []const u8,

    pub fn asSegment64(self: LoadCommand, endian: std.builtin.Endian) CommandError!Segment64Command {
        if (self.cmd != .segment_64) return error.TruncatedCommand;
        if (self.bytes.len < 72) return error.TruncatedCommand;

        var name_buf: [16]u8 = undefined;
        @memcpy(&name_buf, self.bytes[8..24]);

        return .{
            .raw_name = name_buf,
            .vmaddr = std.mem.readInt(u64, self.bytes[24..32], endian),
            .vmsize = std.mem.readInt(u64, self.bytes[32..40], endian),
            .fileoff = std.mem.readInt(u64, self.bytes[40..48], endian),
            .filesize = std.mem.readInt(u64, self.bytes[48..56], endian),
            .maxprot = std.mem.readInt(u32, self.bytes[56..60], endian),
            .initprot = std.mem.readInt(u32, self.bytes[60..64], endian),
            .nsects = std.mem.readInt(u32, self.bytes[64..68], endian),
            .flags = std.mem.readInt(u32, self.bytes[68..72], endian),
        };
    }

    pub fn asSymtab(self: LoadCommand, endian: std.builtin.Endian) CommandError!SymtabCommand {
        if (self.cmd != .symtab) return error.TruncatedCommand;
        if (self.bytes.len < 24) return error.TruncatedCommand;

        return .{
            .symoff = std.mem.readInt(u32, self.bytes[8..12], endian),
            .nsyms = std.mem.readInt(u32, self.bytes[12..16], endian),
            .stroff = std.mem.readInt(u32, self.bytes[16..20], endian),
            .strsize = std.mem.readInt(u32, self.bytes[20..24], endian),
        };
    }

    pub fn asDysymtab(self: LoadCommand, endian: std.builtin.Endian) CommandError!DysymtabCommand {
        if (self.cmd != .dysymtab) return error.TruncatedCommand;
        if (self.bytes.len < 80) return error.TruncatedCommand;

        return .{
            .ilocalsym = std.mem.readInt(u32, self.bytes[8..12], endian),
            .nlocalsym = std.mem.readInt(u32, self.bytes[12..16], endian),
            .iextdefsym = std.mem.readInt(u32, self.bytes[16..20], endian),
            .nextdefsym = std.mem.readInt(u32, self.bytes[20..24], endian),
            .iundefsym = std.mem.readInt(u32, self.bytes[24..28], endian),
            .nundefsym = std.mem.readInt(u32, self.bytes[28..32], endian),
            .tocoff = std.mem.readInt(u32, self.bytes[32..36], endian),
            .ntoc = std.mem.readInt(u32, self.bytes[36..40], endian),
            .modtaboff = std.mem.readInt(u32, self.bytes[40..44], endian),
            .nmodtab = std.mem.readInt(u32, self.bytes[44..48], endian),
            .extrefsymoff = std.mem.readInt(u32, self.bytes[48..52], endian),
            .nextrefsyms = std.mem.readInt(u32, self.bytes[52..56], endian),
            .indirectsymoff = std.mem.readInt(u32, self.bytes[56..60], endian),
            .nindirectsyms = std.mem.readInt(u32, self.bytes[60..64], endian),
            .extreloff = std.mem.readInt(u32, self.bytes[64..68], endian),
            .nextrel = std.mem.readInt(u32, self.bytes[68..72], endian),
            .locreloff = std.mem.readInt(u32, self.bytes[72..76], endian),
            .nlocrel = std.mem.readInt(u32, self.bytes[76..80], endian),
        };
    }

    pub fn asMain(self: LoadCommand, endian: std.builtin.Endian) CommandError!MainCommand {
        if (self.cmd != .main) return error.TruncatedCommand;
        if (self.bytes.len < 24) return error.TruncatedCommand;

        return .{
            .entryoff = std.mem.readInt(u64, self.bytes[8..16], endian),
            .stacksize = std.mem.readInt(u64, self.bytes[16..24], endian),
        };
    }

    pub fn asDylib(self: LoadCommand, endian: std.builtin.Endian) CommandError!DylibCommand {
        if (self.bytes.len < 24) return error.TruncatedCommand;

        return .{
            .name_offset = std.mem.readInt(u32, self.bytes[8..12], endian),
            .timestamp = std.mem.readInt(u32, self.bytes[12..16], endian),
            .current_version = std.mem.readInt(u32, self.bytes[16..20], endian),
            .compatibility_version = std.mem.readInt(u32, self.bytes[20..24], endian),
            .raw_data = self.bytes,
        };
    }

    pub fn asBuildVersion(self: LoadCommand, endian: std.builtin.Endian) CommandError!BuildVersionCommand {
        if (self.cmd != .build_version) return error.TruncatedCommand;
        if (self.bytes.len < 24) return error.TruncatedCommand;

        return .{
            .platform = std.mem.readInt(u32, self.bytes[8..12], endian),
            .minos = std.mem.readInt(u32, self.bytes[12..16], endian),
            .sdk = std.mem.readInt(u32, self.bytes[16..20], endian),
            .ntools = std.mem.readInt(u32, self.bytes[20..24], endian),
        };
    }
};

/// Iterator to scan through all load commands inside a Mach-O file.
pub const LoadCommandIterator = struct {
    file_bytes: []const u8,
    cursor: usize,
    end_offset: usize,
    commands_left: u32,
    endian: std.builtin.Endian,

    pub fn next(self: *LoadCommandIterator) CommandError!?LoadCommand {
        if (self.commands_left == 0) return null;
        if (self.cursor + 8 > self.end_offset) return error.TruncatedCommand;

        const raw_cmd = std.mem.readInt(u32, self.file_bytes[self.cursor..][0..4], self.endian);
        const cmdsize = std.mem.readInt(u32, self.file_bytes[self.cursor + 4 ..][0..4], self.endian);

        if (cmdsize < 8 or self.cursor + cmdsize > self.end_offset) {
            return error.InvalidCommandSize;
        }

        const cmd_slice = self.file_bytes[self.cursor .. self.cursor + cmdsize];
        self.cursor += cmdsize;
        self.commands_left -= 1;

        return .{
            .cmd = @fromBackingInt(@intCast(raw_cmd)),
            .cmdsize = cmdsize,
            .bytes = cmd_slice,
        };
    }
};

// === Normalized Mach-O Header Structure ===

/// Normalized representation for both 32-bit and 64-bit Mach-O headers.
pub const Header = struct {
    is_64bit: bool,
    endian: std.builtin.Endian,
    cpu_type: CpuType,
    cpu_subtype: u32,
    file_type: FileType,
    ncmds: u32,
    sizeofcmds: u32,
    flags: u32,
    reserved: u32,

    pub fn isObject(self: *const Header) bool {
        return self.file_type == .object;
    }

    pub fn isExecutable(self: *const Header) bool {
        return self.file_type == .execute;
    }

    pub fn isDylib(self: *const Header) bool {
        return self.file_type == .dylib;
    }

    pub fn isPie(self: *const Header) bool {
        return (self.flags & flags.PIE) != 0;
    }

    pub fn headerSize(self: *const Header) usize {
        return if (self.is_64bit) 32 else 28;
    }

    pub fn parse(bytes: []const u8) Error!Header {
        if (bytes.len < 4) return error.TruncatedHeader;

        const raw_magic_le = std.mem.readInt(u32, bytes[0..4], .little);

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

    /// Return an iterator over all load commands in the binary.
    pub fn loadCommands(self: *const Header, file_bytes: []const u8) CommandError!LoadCommandIterator {
        const start = self.headerSize();
        const end = std.math.add(usize, start, self.sizeofcmds) catch return error.OutOfBounds;

        if (end > file_bytes.len) {
            return error.TruncatedCommand;
        }

        return .{
            .file_bytes = file_bytes,
            .cursor = start,
            .end_offset = end,
            .commands_left = self.ncmds,
            .endian = self.endian,
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

    std.mem.writeInt(u32, hdr_buf[0..4], MH_MAGIC_64, .little);
    std.mem.writeInt(u32, hdr_buf[4..8], 0x0100000C, .little);
    std.mem.writeInt(u32, hdr_buf[8..12], 0x80000002, .little);
    std.mem.writeInt(u32, hdr_buf[12..16], 0x1, .little);
    std.mem.writeInt(u32, hdr_buf[16..20], 4, .little);
    std.mem.writeInt(u32, hdr_buf[20..24], 688, .little);
    std.mem.writeInt(u32, hdr_buf[24..28], flags.SUBSECTIONS_VIA_SYMBOLS, .little);
    std.mem.writeInt(u32, hdr_buf[28..32], 0, .little);

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
    std.mem.writeInt(u32, hdr_buf[4..8], 0x01000007, .little);
    std.mem.writeInt(u32, hdr_buf[8..12], 3, .little);
    std.mem.writeInt(u32, hdr_buf[12..16], 0x2, .little);
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

    std.mem.writeInt(u32, hdr_buf[0..4], MH_CIGAM_64, .little);
    std.mem.writeInt(u32, hdr_buf[4..8], 0x0100000C, .big);
    std.mem.writeInt(u32, hdr_buf[8..12], 0, .big);
    std.mem.writeInt(u32, hdr_buf[12..16], 0x6, .big);
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

    std.mem.writeInt(u32, hdr_buf[0..4], MH_MAGIC, .little);
    std.mem.writeInt(u32, hdr_buf[4..8], 7, .little);
    std.mem.writeInt(u32, hdr_buf[8..12], 3, .little);
    std.mem.writeInt(u32, hdr_buf[12..16], 0x1, .little);
    std.mem.writeInt(u32, hdr_buf[16..20], 3, .little);
    std.mem.writeInt(u32, hdr_buf[20..24], 280, .little);
    std.mem.writeInt(u32, hdr_buf[24..28], 0, .little);

    const hdr = try Header.parse(&hdr_buf);

    try std.testing.expect(!hdr.is_64bit);
    try std.testing.expectEqual(CpuType.i386, hdr.cpu_type);
    try std.testing.expectEqual(@as(usize, 28), hdr.headerSize());
}

test "decode LC_SEGMENT_64 load command" {
    var cmd_buf: [72]u8 = undefined;
    @memset(&cmd_buf, 0);

    std.mem.writeInt(u32, cmd_buf[0..4], @backingInt(CommandType.segment_64), .little);
    std.mem.writeInt(u32, cmd_buf[4..8], 72, .little); // cmdsize
    @memcpy(cmd_buf[8..14], "__TEXT");
    std.mem.writeInt(u64, cmd_buf[24..32], 0x100000000, .little); // vmaddr
    std.mem.writeInt(u64, cmd_buf[32..40], 0x4000, .little); // vmsize
    std.mem.writeInt(u64, cmd_buf[40..48], 0, .little); // fileoff
    std.mem.writeInt(u64, cmd_buf[48..56], 0x4000, .little); // filesize
    std.mem.writeInt(u32, cmd_buf[56..60], vm_prot.READ | vm_prot.EXECUTE, .little); // maxprot
    std.mem.writeInt(u32, cmd_buf[60..64], vm_prot.READ | vm_prot.EXECUTE, .little); // initprot
    std.mem.writeInt(u32, cmd_buf[64..68], 2, .little); // nsects

    const lc = LoadCommand{
        .cmd = .segment_64,
        .cmdsize = 72,
        .bytes = &cmd_buf,
    };

    const seg = try lc.asSegment64(.little);
    try std.testing.expectEqualStrings("__TEXT", seg.getName());
    try std.testing.expectEqual(@as(u64, 0x100000000), seg.vmaddr);
    try std.testing.expectEqual(@as(u64, 0x4000), seg.vmsize);
    try std.testing.expectEqual(@as(u32, 2), seg.nsects);
    try std.testing.expect(seg.isReadable());
    try std.testing.expect(seg.isExecutable());
    try std.testing.expect(!seg.isWritable());
}

test "decode LC_SYMTAB and LC_MAIN load commands" {
    // LC_SYMTAB (24 bytes)
    var sym_buf: [24]u8 = undefined;
    @memset(&sym_buf, 0);
    std.mem.writeInt(u32, sym_buf[0..4], @backingInt(CommandType.symtab), .little);
    std.mem.writeInt(u32, sym_buf[4..8], 24, .little);
    std.mem.writeInt(u32, sym_buf[8..12], 0x2000, .little); // symoff
    std.mem.writeInt(u32, sym_buf[12..16], 128, .little); // nsyms
    std.mem.writeInt(u32, sym_buf[16..20], 0x3000, .little); // stroff
    std.mem.writeInt(u32, sym_buf[20..24], 1024, .little); // strsize

    const sym_lc = LoadCommand{ .cmd = .symtab, .cmdsize = 24, .bytes = &sym_buf };
    const symtab = try sym_lc.asSymtab(.little);
    try std.testing.expectEqual(@as(u32, 0x2000), symtab.symoff);
    try std.testing.expectEqual(@as(u32, 128), symtab.nsyms);
    try std.testing.expectEqual(@as(u32, 0x3000), symtab.stroff);
    try std.testing.expectEqual(@as(u32, 1024), symtab.strsize);

    // LC_MAIN (24 bytes)
    var main_buf: [24]u8 = undefined;
    @memset(&main_buf, 0);
    std.mem.writeInt(u32, main_buf[0..4], @backingInt(CommandType.main), .little);
    std.mem.writeInt(u32, main_buf[4..8], 24, .little);
    std.mem.writeInt(u64, main_buf[8..16], 0x1240, .little); // entryoff
    std.mem.writeInt(u64, main_buf[16..24], 0x800000, .little); // stacksize

    const main_lc = LoadCommand{ .cmd = .main, .cmdsize = 24, .bytes = &main_buf };
    const main_cmd = try main_lc.asMain(.little);
    try std.testing.expectEqual(@as(u64, 0x1240), main_cmd.entryoff);
    try std.testing.expectEqual(@as(u64, 0x800000), main_cmd.stacksize);
}

test "decode LC_LOAD_DYLIB command" {
    // 24 bytes header + string path: "/usr/lib/libSystem.B.dylib\0" + padding (total 56 bytes)
    var dylib_buf: [56]u8 = undefined;
    @memset(&dylib_buf, 0);

    std.mem.writeInt(u32, dylib_buf[0..4], @backingInt(CommandType.load_dylib), .little);
    std.mem.writeInt(u32, dylib_buf[4..8], 56, .little);
    std.mem.writeInt(u32, dylib_buf[8..12], 24, .little); // string starts at offset 24
    std.mem.writeInt(u32, dylib_buf[12..16], 0, .little);
    std.mem.writeInt(u32, dylib_buf[16..20], 0x05000000, .little); // current version
    std.mem.writeInt(u32, dylib_buf[20..24], 0x01000000, .little); // compatibility version
    @memcpy(dylib_buf[24..51], "/usr/lib/libSystem.B.dylib\x00");

    const lc = LoadCommand{ .cmd = .load_dylib, .cmdsize = 56, .bytes = &dylib_buf };
    const dylib = try lc.asDylib(.little);
    try std.testing.expectEqualStrings("/usr/lib/libSystem.B.dylib", dylib.getName().?);
}

test "iterate through multiple load commands in sequence" {
    // File buffer with 32-byte header + two load commands (72 bytes + 24 bytes = 96 bytes)
    var file_buf: [128]u8 = undefined;
    @memset(&file_buf, 0);

    // 1. Header
    std.mem.writeInt(u32, file_buf[0..4], MH_MAGIC_64, .little);
    std.mem.writeInt(u32, file_buf[4..8], 0x0100000C, .little); // arm64
    std.mem.writeInt(u32, file_buf[16..20], 2, .little); // ncmds = 2
    std.mem.writeInt(u32, file_buf[20..24], 96, .little); // sizeofcmds = 96

    // 2. Command 1: LC_SEGMENT_64 (72 bytes) at offset 32
    std.mem.writeInt(u32, file_buf[32..36], @backingInt(CommandType.segment_64), .little);
    std.mem.writeInt(u32, file_buf[36..40], 72, .little);
    @memcpy(file_buf[40..46], "__DATA");

    // 3. Command 2: LC_SYMTAB (24 bytes) at offset 104
    std.mem.writeInt(u32, file_buf[104..108], @backingInt(CommandType.symtab), .little);
    std.mem.writeInt(u32, file_buf[108..112], 24, .little);
    std.mem.writeInt(u32, file_buf[112..116], 0x4000, .little);

    const hdr = try Header.parse(&file_buf);
    var iter = try hdr.loadCommands(&file_buf);

    const cmd1 = (try iter.next()).?;
    try std.testing.expectEqual(CommandType.segment_64, cmd1.cmd);
    const seg1 = try cmd1.asSegment64(.little);
    try std.testing.expectEqualStrings("__DATA", seg1.getName());

    const cmd2 = (try iter.next()).?;
    try std.testing.expectEqual(CommandType.symtab, cmd2.cmd);
    const sym2 = try cmd2.asSymtab(.little);
    try std.testing.expectEqual(@as(u32, 0x4000), sym2.symoff);

    try std.testing.expect((try iter.next()) == null);
}
