//! Phase 4.1 - 4.3: Mach-O Header, Load Commands, and Section Parser for sibl.
//!
//! Provides zero-copy parsing for 32-bit and 64-bit Mach-O binaries,
//! load command decoding, and section extraction from LC_SEGMENT_64 commands.

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
            else => "unknown",
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
            else => "unknown",
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

/// Section type constants (flags & SECTION_TYPE_MASK).
pub const SectionType = enum(u8) {
    regular = 0x0,
    zerofill = 0x1,
    cstring_literals = 0x2,
    four_byte_literals = 0x3,
    eight_byte_literals = 0x4,
    literal_pointers = 0x5,
    non_lazy_symbol_pointers = 0x6,
    lazy_symbol_pointers = 0x7,
    symbol_stubs = 0x8,
    mod_init_func_pointers = 0x9,
    mod_term_func_pointers = 0xA,
    coalesced = 0xB,
    gb_zerofill = 0xC,
    interposing = 0xD,
    sixteen_byte_literals = 0xE,
    dtrace_dof = 0xF,
    lazy_dylib_symbol_pointers = 0x10,
    thread_local_regular = 0x11,
    thread_local_zerofill = 0x12,
    thread_local_variables = 0x13,
    thread_local_variable_pointers = 0x14,
    thread_local_init_function_pointers = 0x15,
    init_func_offsets = 0x16,
    _,

    pub fn name(self: SectionType) []const u8 {
        return switch (self) {
            .regular => "regular",
            .zerofill => "zerofill",
            .cstring_literals => "cstring_literals",
            .four_byte_literals => "4byte_literals",
            .eight_byte_literals => "8byte_literals",
            .literal_pointers => "literal_pointers",
            .non_lazy_symbol_pointers => "non_lazy_ptrs",
            .lazy_symbol_pointers => "lazy_ptrs",
            .symbol_stubs => "stubs",
            .mod_init_func_pointers => "mod_init_funcs",
            .mod_term_func_pointers => "mod_term_funcs",
            .coalesced => "coalesced",
            .gb_zerofill => "gb_zerofill",
            .interposing => "interposing",
            .sixteen_byte_literals => "16byte_literals",
            .dtrace_dof => "dtrace_dof",
            .lazy_dylib_symbol_pointers => "lazy_dylib_ptrs",
            .thread_local_regular => "tl_regular",
            .thread_local_zerofill => "tl_zerofill",
            .thread_local_variables => "tl_variables",
            .thread_local_variable_pointers => "tl_variable_ptrs",
            .thread_local_init_function_pointers => "tl_init_funcs",
            .init_func_offsets => "init_func_offsets",
            else => "other",
        };
    }
};

/// Section attribute bitmask flags (flags & SECTION_ATTRIBUTES_MASK).
pub const section_attributes = struct {
    pub const SECTION_TYPE_MASK: u32 = 0x000000FF;
    pub const SECTION_ATTRIBUTES_MASK: u32 = 0xFFFFFF00;

    pub const PURE_INSTRUCTIONS: u32 = 0x80000000;
    pub const NO_TOC: u32 = 0x40000000;
    pub const STRIP_STATIC_SYMS: u32 = 0x20000000;
    pub const NO_DEAD_STRIP: u32 = 0x10000000;
    pub const LIVE_SUPPORT: u32 = 0x08000000;
    pub const SELF_MODIFYING_CODE: u32 = 0x04000000;
    pub const DEBUG_INFO: u32 = 0x02000000;

    pub const SOME_INSTRUCTIONS: u32 = 0x00000400;
    pub const EXT_RELOC: u32 = 0x00000200;
    pub const LOC_RELOC: u32 = 0x00000100;
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

pub const SectionError = error{
    TruncatedSectionTable,
    InvalidSectionIndex,
    InvalidSectionSize,
};

// === Decoded Section 64 Structure ===

/// Normalized representation for an 80-byte Mach-O section_64 header.
pub const Section64 = struct {
    raw_sectname: [16]u8,
    raw_segname: [16]u8,
    addr: u64,
    size: u64,
    offset: u32,
    align_p2: u32,
    reloff: u32,
    nreloc: u32,
    flags: u32,
    reserved1: u32,
    reserved2: u32,
    reserved3: u32,

    pub fn getSectName(self: *const Section64) []const u8 {
        const len = std.mem.indexOfScalar(u8, &self.raw_sectname, 0) orelse self.raw_sectname.len;
        return self.raw_sectname[0..len];
    }

    pub fn getSegName(self: *const Section64) []const u8 {
        const len = std.mem.indexOfScalar(u8, &self.raw_segname, 0) orelse self.raw_segname.len;
        return self.raw_segname[0..len];
    }

    /// Calculate alignment in bytes (1 << align_p2).
    pub fn getAlignment(self: *const Section64) u32 {
        if (self.align_p2 >= 31) return 1 << 31;
        return @as(u32, 1) << @intCast(self.align_p2);
    }

    pub fn getType(self: *const Section64) SectionType {
        const raw_type: u8 = @truncate(self.flags & section_attributes.SECTION_TYPE_MASK);
        return @fromBackingInt(@intCast(raw_type));
    }

    pub fn isZeroFill(self: *const Section64) bool {
        const t = self.getType();
        return t == .zerofill or t == .gb_zerofill or t == .thread_local_zerofill;
    }

    pub fn hasInstructions(self: *const Section64) bool {
        return (self.flags & (section_attributes.PURE_INSTRUCTIONS | section_attributes.SOME_INSTRUCTIONS)) != 0;
    }

    pub fn getData(self: *const Section64, file_bytes: []const u8) SectionError![]const u8 {
        if (self.isZeroFill() or self.size == 0) return &.{};

        const start: usize = self.offset;
        const end: usize = std.math.add(usize, start, @as(usize, @intCast(self.size))) catch {
            return error.InvalidSectionSize;
        };

        if (end > file_bytes.len) {
            return error.InvalidSectionSize;
        }

        return file_bytes[start..end];
    }
};

// === Decoded Load Command Structures ===

/// Decoded LC_SEGMENT_64 command (72 bytes header, followed by nsects * 80 bytes).
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
    sections_data: []const u8,

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

    /// Parse a single section_64 header nested within this segment.
    pub fn parseSection(self: *const Segment64Command, endian: std.builtin.Endian, index: usize) SectionError!Section64 {
        if (index >= self.nsects) return error.InvalidSectionIndex;
        const offset = index * 80;
        if (offset + 80 > self.sections_data.len) return error.TruncatedSectionTable;
        return parseSection64(self.sections_data[offset .. offset + 80], endian);
    }

    /// Parse all sections in this segment into an allocated slice.
    pub fn parseAllSections(
        self: *const Segment64Command,
        allocator: std.mem.Allocator,
        endian: std.builtin.Endian,
    ) (SectionError || std.mem.Allocator.Error)![]Section64 {
        const sections = try allocator.alloc(Section64, self.nsects);
        errdefer allocator.free(sections);

        var i: usize = 0;
        while (i < self.nsects) : (i += 1) {
            sections[i] = try self.parseSection(endian, i);
        }
        return sections;
    }
};

/// Helper to decode a single 80-byte section_64 entry from raw bytes.
pub fn parseSection64(bytes: []const u8, endian: std.builtin.Endian) SectionError!Section64 {
    if (bytes.len < 80) return error.TruncatedSectionTable;

    var sect_buf: [16]u8 = undefined;
    @memcpy(&sect_buf, bytes[0..16]);

    var seg_buf: [16]u8 = undefined;
    @memcpy(&seg_buf, bytes[16..32]);

    return .{
        .raw_sectname = sect_buf,
        .raw_segname = seg_buf,
        .addr = std.mem.readInt(u64, bytes[32..][0..8], endian),
        .size = std.mem.readInt(u64, bytes[40..][0..8], endian),
        .offset = std.mem.readInt(u32, bytes[48..][0..4], endian),
        .align_p2 = std.mem.readInt(u32, bytes[52..][0..4], endian),
        .reloff = std.mem.readInt(u32, bytes[56..][0..4], endian),
        .nreloc = std.mem.readInt(u32, bytes[60..][0..4], endian),
        .flags = std.mem.readInt(u32, bytes[64..][0..4], endian),
        .reserved1 = std.mem.readInt(u32, bytes[68..][0..4], endian),
        .reserved2 = std.mem.readInt(u32, bytes[72..][0..4], endian),
        .reserved3 = std.mem.readInt(u32, bytes[76..][0..4], endian),
    };
}

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
    platform: u32,
    minos: u32,
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

        const nsects = std.mem.readInt(u32, self.bytes[64..][0..4], endian);
        const sec_data = if (self.bytes.len >= 72) self.bytes[72..] else &.{};

        var name_buf: [16]u8 = undefined;
        @memcpy(&name_buf, self.bytes[8..24]);

        return .{
            .raw_name = name_buf,
            .vmaddr = std.mem.readInt(u64, self.bytes[24..][0..8], endian),
            .vmsize = std.mem.readInt(u64, self.bytes[32..][0..8], endian),
            .fileoff = std.mem.readInt(u64, self.bytes[40..][0..8], endian),
            .filesize = std.mem.readInt(u64, self.bytes[48..][0..8], endian),
            .maxprot = std.mem.readInt(u32, self.bytes[56..][0..4], endian),
            .initprot = std.mem.readInt(u32, self.bytes[60..][0..4], endian),
            .nsects = nsects,
            .flags = std.mem.readInt(u32, self.bytes[68..][0..4], endian),
            .sections_data = sec_data,
        };
    }

    pub fn asSymtab(self: LoadCommand, endian: std.builtin.Endian) CommandError!SymtabCommand {
        if (self.cmd != .symtab) return error.TruncatedCommand;
        if (self.bytes.len < 24) return error.TruncatedCommand;

        return .{
            .symoff = std.mem.readInt(u32, self.bytes[8..][0..4], endian),
            .nsyms = std.mem.readInt(u32, self.bytes[12..][0..4], endian),
            .stroff = std.mem.readInt(u32, self.bytes[16..][0..4], endian),
            .strsize = std.mem.readInt(u32, self.bytes[20..][0..4], endian),
        };
    }

    pub fn asDysymtab(self: LoadCommand, endian: std.builtin.Endian) CommandError!DysymtabCommand {
        if (self.cmd != .dysymtab) return error.TruncatedCommand;
        if (self.bytes.len < 80) return error.TruncatedCommand;

        return .{
            .ilocalsym = std.mem.readInt(u32, self.bytes[8..][0..4], endian),
            .nlocalsym = std.mem.readInt(u32, self.bytes[12..][0..4], endian),
            .iextdefsym = std.mem.readInt(u32, self.bytes[16..][0..4], endian),
            .nextdefsym = std.mem.readInt(u32, self.bytes[20..][0..4], endian),
            .iundefsym = std.mem.readInt(u32, self.bytes[24..][0..4], endian),
            .nundefsym = std.mem.readInt(u32, self.bytes[28..][0..4], endian),
            .tocoff = std.mem.readInt(u32, self.bytes[32..][0..4], endian),
            .ntoc = std.mem.readInt(u32, self.bytes[36..][0..4], endian),
            .modtaboff = std.mem.readInt(u32, self.bytes[40..][0..4], endian),
            .nmodtab = std.mem.readInt(u32, self.bytes[44..][0..4], endian),
            .extrefsymoff = std.mem.readInt(u32, self.bytes[48..][0..4], endian),
            .nextrefsyms = std.mem.readInt(u32, self.bytes[52..][0..4], endian),
            .indirectsymoff = std.mem.readInt(u32, self.bytes[56..][0..4], endian),
            .nindirectsyms = std.mem.readInt(u32, self.bytes[60..][0..4], endian),
            .extreloff = std.mem.readInt(u32, self.bytes[64..][0..4], endian),
            .nextrel = std.mem.readInt(u32, self.bytes[68..][0..4], endian),
            .locreloff = std.mem.readInt(u32, self.bytes[72..][0..4], endian),
            .nlocrel = std.mem.readInt(u32, self.bytes[76..][0..4], endian),
        };
    }

    pub fn asMain(self: LoadCommand, endian: std.builtin.Endian) CommandError!MainCommand {
        if (self.cmd != .main) return error.TruncatedCommand;
        if (self.bytes.len < 24) return error.TruncatedCommand;

        return .{
            .entryoff = std.mem.readInt(u64, self.bytes[8..][0..8], endian),
            .stacksize = std.mem.readInt(u64, self.bytes[16..][0..8], endian),
        };
    }

    pub fn asDylib(self: LoadCommand, endian: std.builtin.Endian) CommandError!DylibCommand {
        if (self.bytes.len < 24) return error.TruncatedCommand;

        return .{
            .name_offset = std.mem.readInt(u32, self.bytes[8..][0..4], endian),
            .timestamp = std.mem.readInt(u32, self.bytes[12..][0..4], endian),
            .current_version = std.mem.readInt(u32, self.bytes[16..][0..4], endian),
            .compatibility_version = std.mem.readInt(u32, self.bytes[20..][0..4], endian),
            .raw_data = self.bytes,
        };
    }

    pub fn asBuildVersion(self: LoadCommand, endian: std.builtin.Endian) CommandError!BuildVersionCommand {
        if (self.cmd != .build_version) return error.TruncatedCommand;
        if (self.bytes.len < 24) return error.TruncatedCommand;

        return .{
            .platform = std.mem.readInt(u32, self.bytes[8..][0..4], endian),
            .minos = std.mem.readInt(u32, self.bytes[12..][0..4], endian),
            .sdk = std.mem.readInt(u32, self.bytes[16..][0..4], endian),
            .ntools = std.mem.readInt(u32, self.bytes[20..][0..4], endian),
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
    std.mem.writeInt(u32, cmd_buf[4..8], 72, .little);
    @memcpy(cmd_buf[8..14], "__TEXT");
    std.mem.writeInt(u64, cmd_buf[24..32], 0x100000000, .little);
    std.mem.writeInt(u64, cmd_buf[32..40], 0x4000, .little);
    std.mem.writeInt(u64, cmd_buf[40..48], 0, .little);
    std.mem.writeInt(u64, cmd_buf[48..56], 0x4000, .little);
    std.mem.writeInt(u32, cmd_buf[56..60], vm_prot.READ | vm_prot.EXECUTE, .little);
    std.mem.writeInt(u32, cmd_buf[60..64], vm_prot.READ | vm_prot.EXECUTE, .little);
    std.mem.writeInt(u32, cmd_buf[64..68], 0, .little); // nsects = 0

    const lc = LoadCommand{
        .cmd = .segment_64,
        .cmdsize = 72,
        .bytes = &cmd_buf,
    };

    const seg = try lc.asSegment64(.little);
    try std.testing.expectEqualStrings("__TEXT", seg.getName());
    try std.testing.expectEqual(@as(u64, 0x100000000), seg.vmaddr);
    try std.testing.expectEqual(@as(u64, 0x4000), seg.vmsize);
    try std.testing.expectEqual(@as(u32, 0), seg.nsects);
    try std.testing.expect(seg.isReadable());
    try std.testing.expect(seg.isExecutable());
    try std.testing.expect(!seg.isWritable());
}

test "parse 80-byte Mach-O section_64 header" {
    var sec_buf: [80]u8 = undefined;
    @memset(&sec_buf, 0);

    @memcpy(sec_buf[0..6], "__text");
    @memcpy(sec_buf[16..22], "__TEXT");
    std.mem.writeInt(u64, sec_buf[32..40], 0x100001000, .little); // addr
    std.mem.writeInt(u64, sec_buf[40..48], 0x250, .little); // size
    std.mem.writeInt(u32, sec_buf[48..52], 0x1000, .little); // offset
    std.mem.writeInt(u32, sec_buf[52..56], 4, .little); // align_p2 = 4 (16 bytes)
    std.mem.writeInt(u32, sec_buf[56..60], 0x2000, .little); // reloff
    std.mem.writeInt(u32, sec_buf[60..64], 12, .little); // nreloc
    const s_flags = @backingInt(SectionType.regular) | section_attributes.PURE_INSTRUCTIONS | section_attributes.SOME_INSTRUCTIONS;
    std.mem.writeInt(u32, sec_buf[64..68], s_flags, .little);

    const sec = try parseSection64(&sec_buf, .little);

    try std.testing.expectEqualStrings("__text", sec.getSectName());
    try std.testing.expectEqualStrings("__TEXT", sec.getSegName());
    try std.testing.expectEqual(@as(u64, 0x100001000), sec.addr);
    try std.testing.expectEqual(@as(u64, 0x250), sec.size);
    try std.testing.expectEqual(@as(u32, 0x1000), sec.offset);
    try std.testing.expectEqual(@as(u32, 16), sec.getAlignment()); // 1 << 4 = 16
    try std.testing.expectEqual(@as(u32, 0x2000), sec.reloff);
    try std.testing.expectEqual(@as(u32, 12), sec.nreloc);
    try std.testing.expectEqual(SectionType.regular, sec.getType());
    try std.testing.expect(sec.hasInstructions());
    try std.testing.expect(!sec.isZeroFill());
}

test "retrieve section data and zerofill slice" {
    var file_mock: [512]u8 = undefined;
    @memset(&file_mock, 0);
    @memcpy(file_mock[200..216], "macho_text_bytes");

    const reg_sec = Section64{
        .raw_sectname = [_]u8{ '_', '_', 't', 'e', 'x', 't', 0, 0, 0, 0, 0, 0, 0, 0, 0, 0 },
        .raw_segname = [_]u8{ '_', '_', 'T', 'E', 'X', 'T', 0, 0, 0, 0, 0, 0, 0, 0, 0, 0 },
        .addr = 0,
        .size = 16,
        .offset = 200,
        .align_p2 = 2,
        .reloff = 0,
        .nreloc = 0,
        .flags = @backingInt(SectionType.regular),
        .reserved1 = 0,
        .reserved2 = 0,
        .reserved3 = 0,
    };

    const reg_data = try reg_sec.getData(&file_mock);
    try std.testing.expectEqualStrings("macho_text_bytes", reg_data);

    // Zerofill section returns empty slice without out-of-bounds error
    const zero_sec = Section64{
        .raw_sectname = [_]u8{ '_', '_', 'b', 's', 's', 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0 },
        .raw_segname = [_]u8{ '_', '_', 'D', 'A', 'T', 'A', 0, 0, 0, 0, 0, 0, 0, 0, 0, 0 },
        .addr = 0,
        .size = 4096,
        .offset = 0,
        .align_p2 = 3,
        .reloff = 0,
        .nreloc = 0,
        .flags = @backingInt(SectionType.zerofill),
        .reserved1 = 0,
        .reserved2 = 0,
        .reserved3 = 0,
    };

    const zero_data = try zero_sec.getData(&file_mock);
    try std.testing.expectEqual(@as(usize, 0), zero_data.len);
}

test "parse nested sections inside Segment64Command" {
    // 72 bytes segment header + 80 bytes section header = 152 bytes total
    var cmd_buf: [152]u8 = undefined;
    @memset(&cmd_buf, 0);

    // Segment header
    std.mem.writeInt(u32, cmd_buf[0..4], @backingInt(CommandType.segment_64), .little);
    std.mem.writeInt(u32, cmd_buf[4..8], 152, .little);
    @memcpy(cmd_buf[8..14], "__DATA");
    std.mem.writeInt(u32, cmd_buf[64..68], 1, .little); // nsects = 1

    // Section header at offset 72
    @memcpy(cmd_buf[72..78], "__data");
    @memcpy(cmd_buf[88..94], "__DATA");
    std.mem.writeInt(u64, cmd_buf[104..112], 0x2000, .little); // addr
    std.mem.writeInt(u64, cmd_buf[112..120], 0x100, .little); // size
    std.mem.writeInt(u32, cmd_buf[120..124], 0x800, .little); // offset
    std.mem.writeInt(u32, cmd_buf[124..128], 3, .little); // align = 3 (8 bytes)
    std.mem.writeInt(u32, cmd_buf[136..140], @backingInt(SectionType.regular), .little);

    const lc = LoadCommand{
        .cmd = .segment_64,
        .cmdsize = 152,
        .bytes = &cmd_buf,
    };

    const seg = try lc.asSegment64(.little);
    try std.testing.expectEqual(@as(u32, 1), seg.nsects);

    const sec = try seg.parseSection(.little, 0);
    try std.testing.expectEqualStrings("__data", sec.getSectName());
    try std.testing.expectEqualStrings("__DATA", sec.getSegName());
    try std.testing.expectEqual(@as(u32, 8), sec.getAlignment());
    try std.testing.expectEqual(@as(u64, 0x2000), sec.addr);
    try std.testing.expectEqual(@as(u64, 0x100), sec.size);

    try std.testing.expectError(error.InvalidSectionIndex, seg.parseSection(.little, 1));
}
