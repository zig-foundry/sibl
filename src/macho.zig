//! Phase 4.1 - 4.5: Mach-O Header, Load Commands, Sections, Symbols, and Relocations.
//!
//! Provides zero-copy parsing for 32-bit and 64-bit Mach-O binaries,
//! load command decoding, section extraction, nlist_64 symbol reading,
//! and 8-byte relocation_info bitfield decoding.

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

// === Nlist Symbol Table Constants ===

/// Bitmasks for n_type field in nlist_64.
pub const nlist_masks = struct {
    pub const STAB: u8 = 0xE0;
    pub const PEXT: u8 = 0x10;
    pub const TYPE: u8 = 0x0E;
    pub const EXT: u8 = 0x01;
};

/// Symbol types for n_type field in nlist_64.
pub const nlist_type = struct {
    pub const UNDF: u8 = 0x0;
    pub const ABS: u8 = 0x2;
    pub const SECT: u8 = 0xE;
    pub const PBUD: u8 = 0xC;
    pub const INDR: u8 = 0xA;
};

/// Reference flags and attributes for n_desc field in nlist_64.
pub const nlist_desc = struct {
    pub const REFERENCE_TYPE_MASK: u16 = 0x0007;
    pub const REFERENCE_FLAG_UNDEFINED_NON_LAZY: u16 = 0x0000;
    pub const REFERENCE_FLAG_UNDEFINED_LAZY: u16 = 0x0001;
    pub const REFERENCE_FLAG_DEFINED: u16 = 0x0002;
    pub const REFERENCE_FLAG_PRIVATE_DEFINED: u16 = 0x0003;
    pub const REFERENCE_FLAG_PRIVATE_UNDEFINED_LAZY: u16 = 0x0004;
    pub const REFERENCE_FLAG_PRIVATE_UNDEFINED_NON_LAZY: u16 = 0x0005;

    pub const ARM_THUMB_DEF: u16 = 0x0008;
    pub const NO_DEAD_STRIP: u16 = 0x0020;
    pub const WEAK_REF: u16 = 0x0040;
    pub const WEAK_DEF: u16 = 0x0080;
    pub const REF_TO_WEAK: u16 = 0x0080;
    pub const SYMBOL_RESOLVER: u16 = 0x0100;
    pub const ALT_ENTRY: u16 = 0x0200;
    pub const COLD_FUNC: u16 = 0x0400;
};

// === Relocation Constants ===

pub const reloc_constants = struct {
    pub const R_SCATTERED: u32 = 0x80000000;
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

pub const SymbolError = error{
    TruncatedSymbolTable,
    InvalidSymbolIndex,
    StringTableOutOfBounds,
};

pub const RelocationError = error{
    TruncatedRelocationTable,
    InvalidRelocationIndex,
};

// === Decoded Relocation Structure ===

/// Normalized representation for an 8-byte Mach-O relocation_info record.
pub const Relocation = struct {
    address: u32,
    symbolnum: u32,
    pcrel: bool,
    length: u2, // 0=1 byte, 1=2 bytes, 2=4 bytes, 3=8 bytes
    is_extern: bool,
    type_id: u4,
    is_scattered: bool,
    scattered_value: u32,

    pub fn byteSize(self: Relocation) usize {
        return @as(usize, 1) << self.length;
    }

    pub fn typeName(self: Relocation, cpu: CpuType) []const u8 {
        return switch (cpu) {
            .arm64, .arm64_32 => switch (self.type_id) {
                0 => "UNSIGNED",
                1 => "SUBTRACTOR",
                2 => "BRANCH26",
                3 => "PAGE21",
                4 => "PAGEOFF12",
                5 => "GOT_LOAD_PAGE21",
                6 => "GOT_LOAD_PAGEOFF12",
                7 => "POINTER_TO_GOT",
                8 => "TLVP_PAGE21",
                9 => "TLVP_PAGEOFF12",
                10 => "ADDEND",
                11 => "AUTHENTICATED_POINTER",
                else => "ARM64_RELOC",
            },
            .x86_64 => switch (self.type_id) {
                0 => "UNSIGNED",
                1 => "SIGNED",
                2 => "BRANCH",
                3 => "GOT_LOAD",
                4 => "GOT",
                5 => "SUBTRACTOR",
                6 => "SIGNED_1",
                7 => "SIGNED_2",
                8 => "SIGNED_4",
                9 => "TLV",
                else => "X86_64_RELOC",
            },
            .i386 => switch (self.type_id) {
                0 => "VANILLA",
                1 => "PAIR",
                2 => "SECTDIFF",
                3 => "PB_LA_PTR",
                4 => "LOCAL_SECTDIFF",
                5 => "TLV",
                else => "GENERIC_RELOC",
            },
            else => "RELOC",
        };
    }
};

/// Helper to decode an 8-byte relocation_info record from raw bytes.
pub fn parseRelocation(bytes: []const u8, endian: std.builtin.Endian) RelocationError!Relocation {
    if (bytes.len < 8) return error.TruncatedRelocationTable;

    const raw_addr = std.mem.readInt(u32, bytes[0..][0..4], endian);
    const is_scattered = (raw_addr & reloc_constants.R_SCATTERED) != 0;

    if (is_scattered) {
        // Scattered relocation:
        // raw_addr layout: [1 bit scattered][1 bit pcrel][2 bits length][4 bits type][24 bits address]
        const pcrel = ((raw_addr >> 30) & 1) != 0;
        const length: u2 = @truncate((raw_addr >> 28) & 3);
        const type_id: u4 = @truncate((raw_addr >> 24) & 0xF);
        const address = raw_addr & 0x00FFFFFF;
        const value = std.mem.readInt(u32, bytes[4..][0..4], endian);

        return .{
            .address = address,
            .symbolnum = 0,
            .pcrel = pcrel,
            .length = length,
            .is_extern = false,
            .type_id = type_id,
            .is_scattered = true,
            .scattered_value = value,
        };
    } else {
        // Standard relocation:
        // bytes[4..8] layout: [24 bits symbolnum][1 bit pcrel][2 bits length][1 bit extern][4 bits type]
        const r_info = std.mem.readInt(u32, bytes[4..][0..4], endian);
        const symbolnum = r_info & 0x00FFFFFF;
        const pcrel = ((r_info >> 24) & 1) != 0;
        const length: u2 = @truncate((r_info >> 25) & 3);
        const is_extern = ((r_info >> 27) & 1) != 0;
        const type_id: u4 = @truncate((r_info >> 28) & 0xF);

        return .{
            .address = raw_addr,
            .symbolnum = symbolnum,
            .pcrel = pcrel,
            .length = length,
            .is_extern = is_extern,
            .type_id = type_id,
            .is_scattered = false,
            .scattered_value = 0,
        };
    }
}

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

    /// Parse a single 8-byte relocation entry for this section.
    pub fn parseRelocation(self: *const Section64, file_bytes: []const u8, endian: std.builtin.Endian, index: usize) RelocationError!Relocation {
        if (index >= self.nreloc) return error.InvalidRelocationIndex;
        const offset: usize = self.reloff + (index * 8);
        if (offset + 8 > file_bytes.len) return error.TruncatedRelocationTable;
        return @import("macho.zig").parseRelocation(file_bytes[offset .. offset + 8], endian);
    }

    /// Parse all relocations for this section into an allocated slice.
    pub fn parseAllRelocations(
        self: *const Section64,
        allocator: std.mem.Allocator,
        file_bytes: []const u8,
        endian: std.builtin.Endian,
    ) (RelocationError || std.mem.Allocator.Error)![]Relocation {
        const relocs = try allocator.alloc(Relocation, self.nreloc);
        errdefer allocator.free(relocs);

        var i: usize = 0;
        while (i < self.nreloc) : (i += 1) {
            relocs[i] = try self.parseRelocation(file_bytes, endian, i);
        }
        return relocs;
    }
};

// === Decoded Nlist 64 Symbol Structure ===

/// Normalized representation for a 16-byte Mach-O nlist_64 symbol entry.
pub const Nlist64 = struct {
    strx: u32,
    type_flags: u8,
    sect: u8,
    desc: u16,
    value: u64,

    pub const NO_SECT: u8 = 0;

    pub fn isStab(self: *const Nlist64) bool {
        return (self.type_flags & nlist_masks.STAB) != 0;
    }

    pub fn isExternal(self: *const Nlist64) bool {
        return (self.type_flags & nlist_masks.EXT) != 0;
    }

    pub fn isPrivateExternal(self: *const Nlist64) bool {
        return (self.type_flags & nlist_masks.PEXT) != 0;
    }

    pub fn getType(self: *const Nlist64) u8 {
        return self.type_flags & nlist_masks.TYPE;
    }

    pub fn isUndefined(self: *const Nlist64) bool {
        return !self.isStab() and self.getType() == nlist_type.UNDF and self.value == 0;
    }

    pub fn isCommon(self: *const Nlist64) bool {
        return !self.isStab() and self.getType() == nlist_type.UNDF and self.value > 0;
    }

    pub fn isAbsolute(self: *const Nlist64) bool {
        return !self.isStab() and self.getType() == nlist_type.ABS;
    }

    pub fn isSection(self: *const Nlist64) bool {
        return !self.isStab() and self.getType() == nlist_type.SECT;
    }

    pub fn isIndirect(self: *const Nlist64) bool {
        return !self.isStab() and self.getType() == nlist_type.INDR;
    }

    pub fn isWeakDef(self: *const Nlist64) bool {
        return (self.desc & nlist_desc.WEAK_DEF) != 0;
    }

    pub fn isWeakRef(self: *const Nlist64) bool {
        return (self.desc & nlist_desc.WEAK_REF) != 0;
    }

    pub fn getLibraryOrdinal(self: *const Nlist64) u8 {
        return @truncate((self.desc >> 8) & 0xFF);
    }

    pub fn getName(self: *const Nlist64, strtab_bytes: []const u8) SymbolError![]const u8 {
        if (self.strx == 0) return "";
        if (self.strx >= strtab_bytes.len) return error.StringTableOutOfBounds;

        const slice = strtab_bytes[self.strx..];
        const len = std.mem.indexOfScalar(u8, slice, 0) orelse return error.StringTableOutOfBounds;
        return slice[0..len];
    }

    pub fn typeName(self: *const Nlist64) []const u8 {
        if (self.isStab()) return "STAB";
        return switch (self.getType()) {
            nlist_type.UNDF => if (self.value > 0) "COMMON" else "UNDF",
            nlist_type.ABS => "ABS",
            nlist_type.SECT => "SECT",
            nlist_type.PBUD => "PBUD",
            nlist_type.INDR => "INDR",
            else => "OTHER",
        };
    }
};

/// Helper to decode a 16-byte nlist_64 entry from raw bytes.
pub fn parseNlist64(bytes: []const u8, endian: std.builtin.Endian) SymbolError!Nlist64 {
    if (bytes.len < 16) return error.TruncatedSymbolTable;
    return .{
        .strx = std.mem.readInt(u32, bytes[0..][0..4], endian),
        .type_flags = bytes[4],
        .sect = bytes[5],
        .desc = std.mem.readInt(u16, bytes[6..][0..2], endian),
        .value = std.mem.readInt(u64, bytes[8..][0..8], endian),
    };
}

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

    pub fn parseSection(self: *const Segment64Command, endian: std.builtin.Endian, index: usize) SectionError!Section64 {
        if (index >= self.nsects) return error.InvalidSectionIndex;
        const offset = index * 80;
        if (offset + 80 > self.sections_data.len) return error.TruncatedSectionTable;
        return parseSection64(self.sections_data[offset .. offset + 80], endian);
    }

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

    pub fn getStringTable(self: *const SymtabCommand, file_bytes: []const u8) []const u8 {
        const start: usize = self.stroff;
        const end: usize = std.math.add(usize, start, self.strsize) catch return &.{};
        if (end > file_bytes.len) return &.{};
        return file_bytes[start..end];
    }

    pub fn parseSymbol(self: *const SymtabCommand, file_bytes: []const u8, endian: std.builtin.Endian, index: usize) SymbolError!Nlist64 {
        if (index >= self.nsyms) return error.InvalidSymbolIndex;
        const offset: usize = self.symoff + (index * 16);
        if (offset + 16 > file_bytes.len) return error.TruncatedSymbolTable;
        return parseNlist64(file_bytes[offset .. offset + 16], endian);
    }

    pub fn parseAllSymbols(
        self: *const SymtabCommand,
        allocator: std.mem.Allocator,
        file_bytes: []const u8,
        endian: std.builtin.Endian,
    ) (SymbolError || std.mem.Allocator.Error)![]Nlist64 {
        const syms = try allocator.alloc(Nlist64, self.nsyms);
        errdefer allocator.free(syms);

        var i: usize = 0;
        while (i < self.nsyms) : (i += 1) {
            syms[i] = try self.parseSymbol(file_bytes, endian, i);
        }
        return syms;
    }
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

    /// Parse a Mach-O header from the start of a file.
    /// Supports both 32-bit and 64-bit little- and big-endian encodings.
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
    std.mem.writeInt(u32, cmd_buf[64..68], 0, .little);

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
    std.mem.writeInt(u64, sec_buf[32..40], 0x100001000, .little);
    std.mem.writeInt(u64, sec_buf[40..48], 0x250, .little);
    std.mem.writeInt(u32, sec_buf[48..52], 0x1000, .little);
    std.mem.writeInt(u32, sec_buf[52..56], 4, .little);
    std.mem.writeInt(u32, sec_buf[56..60], 0x2000, .little);
    std.mem.writeInt(u32, sec_buf[60..64], 12, .little);
    const s_flags = @backingInt(SectionType.regular) | section_attributes.PURE_INSTRUCTIONS | section_attributes.SOME_INSTRUCTIONS;
    std.mem.writeInt(u32, sec_buf[64..68], s_flags, .little);

    const sec = try parseSection64(&sec_buf, .little);

    try std.testing.expectEqualStrings("__text", sec.getSectName());
    try std.testing.expectEqualStrings("__TEXT", sec.getSegName());
    try std.testing.expectEqual(@as(u64, 0x100001000), sec.addr);
    try std.testing.expectEqual(@as(u64, 0x250), sec.size);
    try std.testing.expectEqual(@as(u32, 0x1000), sec.offset);
    try std.testing.expectEqual(@as(u32, 16), sec.getAlignment());
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
    var cmd_buf: [152]u8 = undefined;
    @memset(&cmd_buf, 0);

    std.mem.writeInt(u32, cmd_buf[0..4], @backingInt(CommandType.segment_64), .little);
    std.mem.writeInt(u32, cmd_buf[4..8], 152, .little);
    @memcpy(cmd_buf[8..14], "__DATA");
    std.mem.writeInt(u32, cmd_buf[64..68], 1, .little);

    @memcpy(cmd_buf[72..78], "__data");
    @memcpy(cmd_buf[88..94], "__DATA");
    std.mem.writeInt(u64, cmd_buf[104..112], 0x2000, .little);
    std.mem.writeInt(u64, cmd_buf[112..120], 0x100, .little);
    std.mem.writeInt(u32, cmd_buf[120..124], 0x800, .little);
    std.mem.writeInt(u32, cmd_buf[124..128], 3, .little);
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

test "parse 16-byte Mach-O nlist_64 defined section symbol" {
    var sym_buf: [16]u8 = undefined;
    @memset(&sym_buf, 0);

    std.mem.writeInt(u32, sym_buf[0..4], 1, .little);
    sym_buf[4] = nlist_type.SECT | nlist_masks.EXT;
    sym_buf[5] = 1;
    std.mem.writeInt(u16, sym_buf[6..8], 0, .little);
    std.mem.writeInt(u64, sym_buf[8..16], 0x1000, .little);

    const sym = try parseNlist64(&sym_buf, .little);

    try std.testing.expect(!sym.isStab());
    try std.testing.expect(sym.isExternal());
    try std.testing.expect(!sym.isPrivateExternal());
    try std.testing.expect(sym.isSection());
    try std.testing.expect(!sym.isUndefined());
    try std.testing.expect(!sym.isCommon());
    try std.testing.expect(!sym.isAbsolute());
    try std.testing.expectEqual(@as(u8, 1), sym.sect);
    try std.testing.expectEqual(@as(u64, 0x1000), sym.value);
    try std.testing.expectEqualStrings("SECT", sym.typeName());

    const strtab_mock = "\x00_foo\x00";
    try std.testing.expectEqualStrings("_foo", try sym.getName(strtab_mock));
}

test "parse Mach-O nlist_64 undefined and weak symbols" {
    var sym_buf: [16]u8 = undefined;
    @memset(&sym_buf, 0);

    std.mem.writeInt(u32, sym_buf[0..4], 1, .little);
    sym_buf[4] = nlist_type.UNDF | nlist_masks.EXT;
    sym_buf[5] = Nlist64.NO_SECT;
    const desc: u16 = (2 << 8) | nlist_desc.WEAK_REF;
    std.mem.writeInt(u16, sym_buf[6..8], desc, .little);
    std.mem.writeInt(u64, sym_buf[8..16], 0, .little);

    const sym = try parseNlist64(&sym_buf, .little);

    try std.testing.expect(sym.isUndefined());
    try std.testing.expect(!sym.isCommon());
    try std.testing.expect(sym.isWeakRef());
    try std.testing.expect(!sym.isWeakDef());
    try std.testing.expectEqual(@as(u8, 2), sym.getLibraryOrdinal());
    try std.testing.expectEqualStrings("UNDF", sym.typeName());
}

test "parse Mach-O common and stab symbols" {
    const common_sym = Nlist64{
        .strx = 1,
        .type_flags = nlist_type.UNDF | nlist_masks.EXT,
        .sect = 0,
        .desc = 0,
        .value = 512,
    };
    try std.testing.expect(common_sym.isCommon());
    try std.testing.expect(!common_sym.isUndefined());
    try std.testing.expectEqualStrings("COMMON", common_sym.typeName());

    const stab_sym = Nlist64{
        .strx = 0,
        .type_flags = 0x64,
        .sect = 0,
        .desc = 0,
        .value = 0,
    };
    try std.testing.expect(stab_sym.isStab());
    try std.testing.expectEqualStrings("STAB", stab_sym.typeName());
    try std.testing.expectEqualStrings("", try stab_sym.getName(""));
}

test "parse standard 8-byte ARM64 Mach-O relocation entry" {
    var rel_buf: [8]u8 = undefined;
    @memset(&rel_buf, 0);

    // r_address = 0x48 (patch offset)
    std.mem.writeInt(u32, rel_buf[0..4], 0x48, .little);

    // r_info:
    // symbolnum = 42
    // pcrel = 1 (bit 24)
    // length = 2 (bits 25..26: 4 bytes)
    // is_extern = 1 (bit 27)
    // type = 3 (bits 28..31: ARM64_RELOC_PAGE21)
    const symbolnum: u32 = 42;
    const pcrel: u32 = 1 << 24;
    const length: u32 = 2 << 25;
    const is_extern: u32 = 1 << 27;
    const r_type: u32 = 3 << 28;
    const r_info = symbolnum | pcrel | length | is_extern | r_type;
    std.mem.writeInt(u32, rel_buf[4..8], r_info, .little);

    const rel = try parseRelocation(&rel_buf, .little);

    try std.testing.expect(!rel.is_scattered);
    try std.testing.expectEqual(@as(u32, 0x48), rel.address);
    try std.testing.expectEqual(@as(u32, 42), rel.symbolnum);
    try std.testing.expect(rel.pcrel);
    try std.testing.expectEqual(@as(u2, 2), rel.length);
    try std.testing.expectEqual(@as(usize, 4), rel.byteSize());
    try std.testing.expect(rel.is_extern);
    try std.testing.expectEqual(@as(u4, 3), rel.type_id);
    try std.testing.expectEqualStrings("PAGE21", rel.typeName(.arm64));
}

test "parse standard 8-byte x86_64 Mach-O relocation entry" {
    var rel_buf: [8]u8 = undefined;
    @memset(&rel_buf, 0);

    // r_address = 0x1A
    std.mem.writeInt(u32, rel_buf[0..4], 0x1A, .little);

    // symbolnum = 12, pcrel = 1, length = 2 (4 bytes), is_extern = 1, type = 2 (X86_64_RELOC_BRANCH)
    const r_info: u32 = 12 | (1 << 24) | (2 << 25) | (1 << 27) | (2 << 28);
    std.mem.writeInt(u32, rel_buf[4..8], r_info, .little);

    const rel = try parseRelocation(&rel_buf, .little);

    try std.testing.expect(!rel.is_scattered);
    try std.testing.expectEqual(@as(u32, 0x1A), rel.address);
    try std.testing.expectEqual(@as(u32, 12), rel.symbolnum);
    try std.testing.expect(rel.pcrel);
    try std.testing.expectEqualStrings("BRANCH", rel.typeName(.x86_64));
}

test "parse scattered Mach-O relocation entry" {
    var rel_buf: [8]u8 = undefined;
    @memset(&rel_buf, 0);

    // raw_addr with R_SCATTERED (bit 31), pcrel (bit 30), length 2 (bits 28..29), type 0 (bits 24..27), address 0x100
    const raw_addr: u32 = reloc_constants.R_SCATTERED | (1 << 30) | (2 << 28) | (0 << 24) | 0x100;
    std.mem.writeInt(u32, rel_buf[0..4], raw_addr, .little);
    std.mem.writeInt(u32, rel_buf[4..8], 0x4000, .little); // target value

    const rel = try parseRelocation(&rel_buf, .little);

    try std.testing.expect(rel.is_scattered);
    try std.testing.expectEqual(@as(u32, 0x100), rel.address);
    try std.testing.expect(rel.pcrel);
    try std.testing.expectEqual(@as(u2, 2), rel.length);
    try std.testing.expectEqual(@as(u32, 0x4000), rel.scattered_value);
}

test "parse section relocations slice from Section64" {
    var file_mock: [64]u8 = undefined;
    @memset(&file_mock, 0);

    // Write a relocation at offset 32
    std.mem.writeInt(u32, file_mock[32..36], 0x20, .little);
    const r_info: u32 = 5 | (0 << 24) | (3 << 25) | (1 << 27) | (0 << 28); // 8-byte UNSIGNED
    std.mem.writeInt(u32, file_mock[36..40], r_info, .little);

    const sec = Section64{
        .raw_sectname = [_]u8{ '_', '_', 'd', 'a', 't', 'a', 0, 0, 0, 0, 0, 0, 0, 0, 0, 0 },
        .raw_segname = [_]u8{ '_', '_', 'D', 'A', 'T', 'A', 0, 0, 0, 0, 0, 0, 0, 0, 0, 0 },
        .addr = 0,
        .size = 64,
        .offset = 0,
        .align_p2 = 3,
        .reloff = 32,
        .nreloc = 1,
        .flags = @backingInt(SectionType.regular),
        .reserved1 = 0,
        .reserved2 = 0,
        .reserved3 = 0,
    };

    const rel = try sec.parseRelocation(&file_mock, .little, 0);
    try std.testing.expectEqual(@as(u32, 0x20), rel.address);
    try std.testing.expectEqual(@as(u32, 5), rel.symbolnum);
    try std.testing.expect(!rel.pcrel);
    try std.testing.expectEqual(@as(usize, 8), rel.byteSize());
    try std.testing.expectEqualStrings("UNSIGNED", rel.typeName(.arm64));

    try std.testing.expectError(error.InvalidRelocationIndex, sec.parseRelocation(&file_mock, .little, 1));
}
