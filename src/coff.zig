//! Phase 3.1 - 3.5: DOS, COFF Header, Sections, Symbols, Relocations, and Flags.
//!
//! Provides zero-copy parsing for Windows PE executables (.exe, .dll)
//! and raw COFF relocatable object files (.obj), including cross-platform
//! section normalization, dollar-sign grouping, and COMDAT rules.

const std = @import("std");

// === Constants and Signatures ===

/// The 2-byte MS-DOS magic signature ("MZ").
pub const DOS_MAGIC = [2]u8{ 'M', 'Z' };

/// The 4-byte PE signature ("PE\0\0").
pub const PE_SIGNATURE = [4]u8{ 'P', 'E', 0, 0 };

/// Optional Header Magic numbers.
pub const OptionalHeaderMagic = struct {
    pub const PE32: u16 = 0x010B; // 32-bit executable
    pub const PE32_PLUS: u16 = 0x020B; // 64-bit executable (PE32+)
    pub const ROM: u16 = 0x0107;
};

/// Target machine architecture identifiers (IMAGE_FILE_MACHINE_*).
pub const Machine = enum(u16) {
    unknown = 0,
    i386 = 0x014C, // Intel 386 or later
    armnt = 0x01C0, // ARM Thumb-2
    x86_64 = 0x8664, // AMD64 / x86_64
    arm64 = 0xAA64, // ARM64
    riscv64 = 0x5064, // RISC-V 64-bit
    _,

    pub fn name(self: Machine) []const u8 {
        return switch (self) {
            .unknown => "unknown",
            .i386 => "i386",
            .armnt => "armnt",
            .x86_64 => "x86_64",
            .arm64 => "arm64",
            .riscv64 => "riscv64",
            _ => "unknown",
        };
    }

    pub fn isKnown(raw: u16) bool {
        return switch (raw) {
            0x014C, 0x01C0, 0x8664, 0xAA64, 0x5064 => true,
            else => false,
        };
    }
};

/// COFF file characteristics bitmask (IMAGE_FILE_*).
pub const characteristics = struct {
    pub const RELOCS_STRIPPED: u16 = 0x0001;
    pub const EXECUTABLE_IMAGE: u16 = 0x0002;
    pub const LINE_NUMS_STRIPPED: u16 = 0x0004;
    pub const LOCAL_SYMS_STRIPPED: u16 = 0x0008;
    pub const LARGE_ADDRESS_AWARE: u16 = 0x0020;
    pub const BIT32_MACHINE: u16 = 0x0100;
    pub const DEBUG_STRIPPED: u16 = 0x0200;
    pub const REMOVABLE_RUN_FROM_SWAP: u16 = 0x0400;
    pub const NET_RUN_FROM_SWAP: u16 = 0x0800;
    pub const SYSTEM: u16 = 0x1000;
    pub const DLL: u16 = 0x2000;
    pub const UP_SYSTEM_ONLY: u16 = 0x4000;
};

/// Section characteristics bitmask (IMAGE_SCN_*).
pub const section_flags = struct {
    pub const TYPE_NO_PAD: u32 = 0x00000008;
    pub const CNT_CODE: u32 = 0x00000020;
    pub const CNT_INITIALIZED_DATA: u32 = 0x00000040;
    pub const CNT_UNINITIALIZED_DATA: u32 = 0x00000080;
    pub const LNK_INFO: u32 = 0x00000200;
    pub const LNK_REMOVE: u32 = 0x00000800;
    pub const LNK_COMDAT: u32 = 0x00001000;
    pub const GPREL: u32 = 0x00008000;
    pub const MEM_PURGEABLE: u32 = 0x00020000;
    pub const MEM_16BIT: u32 = 0x00020000;
    pub const MEM_LOCKED: u32 = 0x00040000;
    pub const MEM_PRELOAD: u32 = 0x00080000;
    pub const LNK_NRELOC_OVFL: u32 = 0x01000000;
    pub const MEM_DISCARDABLE: u32 = 0x02000000;
    pub const MEM_NOT_CACHED: u32 = 0x04000000;
    pub const MEM_NOT_PAGED: u32 = 0x08000000;
    pub const MEM_SHARED: u32 = 0x10000000;
    pub const MEM_EXECUTE: u32 = 0x20000000;
    pub const MEM_READ: u32 = 0x40000000;
    pub const MEM_WRITE: u32 = 0x80000000;
};

/// COMDAT selection rules (IMAGE_COMDAT_SELECT_*).
pub const ComdatSelection = enum(u8) {
    no_duplicates = 1, // Linker emits an error if symbol is multiply defined
    any = 2, // Arbitrarily pick one definition; discard all others
    same_size = 3, // Pick any, but emit an error if byte sizes differ
    exact_match = 4, // Pick any, but emit an error if bytes or checksums differ
    associative = 5, // Tied to another leader section; kept only if leader is kept
    largest = 6, // Pick the definition with the largest byte size
    _,

    pub fn name(self: ComdatSelection) []const u8 {
        return switch (self) {
            .no_duplicates => "NODUPLICATES",
            .any => "ANY",
            .same_size => "SAME_SIZE",
            .exact_match => "EXACT_MATCH",
            .associative => "ASSOCIATIVE",
            .largest => "LARGEST",
            _ => "UNKNOWN",
        };
    }
};

/// Normalized section semantic kind across ELF and PE/COFF.
pub const SectionKind = enum {
    text, // Executable machine instructions
    rodata, // Read-only constants, string literals, and exception tables
    data, // Initialized read-write global variables
    bss, // Uninitialized zero-allocated memory
    tls, // Thread-local storage template
    debug, // DWARF / CodeView debug data
    discard, // Temporary directives or discarded sections (.drectve)
    metadata, // Non-allocatable linker comments or info (.comment)

    pub fn name(self: SectionKind) []const u8 {
        return switch (self) {
            .text => "text",
            .rodata => "rodata",
            .data => "data",
            .bss => "bss",
            .tls => "tls",
            .debug => "debug",
            .discard => "discard",
            .metadata => "metadata",
        };
    }
};

/// Section access permissions normalized for the memory loader.
pub const SectionPermissions = struct {
    read: bool,
    write: bool,
    execute: bool,

    pub fn toChars(self: SectionPermissions) [3]u8 {
        return .{
            if (self.read) 'R' else '-',
            if (self.write) 'W' else '-',
            if (self.execute) 'X' else '-',
        };
    }
};

/// COFF symbol storage class identifiers (IMAGE_SYM_CLASS_*).
pub const StorageClass = enum(u8) {
    null = 0,
    automatic = 1,
    external = 2,
    static = 3,
    register = 4,
    external_def = 5,
    label = 6,
    undefined_label = 7,
    member_of_struct = 8,
    argument = 9,
    struct_tag = 10,
    member_of_union = 11,
    union_tag = 12,
    type_definition = 13,
    undefined_static = 14,
    enum_tag = 15,
    member_of_enum = 16,
    register_param = 17,
    bit_field = 18,
    block = 100,
    function = 101,
    end_of_struct = 102,
    file = 103,
    section = 104,
    weak_external = 105,
    clr_token = 107,
    end_of_function = 0xFF,
    _,

    pub fn name(self: StorageClass) []const u8 {
        return switch (self) {
            .null => "NULL",
            .automatic => "AUTOMATIC",
            .external => "EXTERNAL",
            .static => "STATIC",
            .register => "REGISTER",
            .external_def => "EXT_DEF",
            .label => "LABEL",
            .undefined_label => "UNDEF_LABEL",
            .member_of_struct => "STRUCT_MEM",
            .argument => "ARGUMENT",
            .struct_tag => "STRUCT_TAG",
            .member_of_union => "UNION_MEM",
            .union_tag => "UNION_TAG",
            .type_definition => "TYPEDEF",
            .undefined_static => "UNDEF_STATIC",
            .enum_tag => "ENUM_TAG",
            .member_of_enum => "ENUM_MEM",
            .register_param => "REG_PARAM",
            .bit_field => "BIT_FIELD",
            .block => "BLOCK",
            .function => "FUNCTION",
            .end_of_struct => "END_STRUCT",
            .file => "FILE",
            .section => "SECTION",
            .weak_external => "WEAK_EXT",
            .clr_token => "CLR_TOKEN",
            .end_of_function => "END_OF_FUNC",
            _ => "UNKNOWN",
        };
    }
};

/// Special section numbers in COFF symbol table.
pub const SpecialSection = struct {
    pub const UNDEFINED: i16 = 0;
    pub const ABSOLUTE: i16 = -1;
    pub const DEBUG: i16 = -2;
};

/// Windows Subsystem types.
pub const Subsystem = enum(u16) {
    unknown = 0,
    native = 1,
    windows_gui = 2,
    windows_cui = 3,
    posix_cui = 7,
    windows_ce_gui = 9,
    efi_application = 10,
    efi_boot_service_driver = 11,
    efi_runtime_driver = 12,
    efi_rom = 13,
    xbox = 14,
    windows_boot_application = 16,
    _,

    pub fn name(self: Subsystem) []const u8 {
        return switch (self) {
            .unknown => "unknown",
            .native => "native",
            .windows_gui => "windows_gui",
            .windows_cui => "windows_cui",
            .posix_cui => "posix_cui",
            .windows_ce_gui => "windows_ce_gui",
            .efi_application => "efi_app",
            .efi_boot_service_driver => "efi_boot_driver",
            .efi_runtime_driver => "efi_runtime_driver",
            .efi_rom => "efi_rom",
            .xbox => "xbox",
            .windows_boot_application => "boot_app",
            _ => "other",
        };
    }
};

/// Data Directory entry inside the Optional Header.
pub const DataDirectory = struct {
    virtual_address: u32,
    size: u32,
};

/// Parsed Optional Header fields for executables and DLLs.
pub const OptionalHeader = struct {
    is_64bit: bool,
    magic: u16,
    major_linker_version: u8,
    minor_linker_version: u8,
    size_of_code: u32,
    size_of_initialized_data: u32,
    size_of_uninitialized_data: u32,
    address_of_entry_point: u32,
    base_of_code: u32,
    image_base: u64,
    section_alignment: u32,
    file_alignment: u32,
    major_os_version: u16,
    minor_os_version: u16,
    major_image_version: u16,
    minor_image_version: u16,
    major_subsystem_version: u16,
    minor_subsystem_version: u16,
    win32_version_value: u32,
    size_of_image: u32,
    size_of_headers: u32,
    checksum: u32,
    subsystem: Subsystem,
    dll_characteristics: u16,
    size_of_stack_reserve: u64,
    size_of_stack_commit: u64,
    size_of_heap_reserve: u64,
    size_of_heap_commit: u64,
    data_directories: [16]DataDirectory,
};

// === Relocation Representation ===

/// Normalized representation for a 10-byte COFF relocation record.
pub const Relocation = struct {
    virtual_address: u32,
    symbol_table_index: u32,
    type_id: u16,

    pub fn typeName(self: Relocation, machine: Machine) []const u8 {
        return switch (machine) {
            .x86_64 => switch (self.type_id) {
                0x0000 => "ABSOLUTE",
                0x0001 => "ADDR64",
                0x0002 => "ADDR32",
                0x0003 => "ADDR32NB",
                0x0004 => "REL32",
                0x0005 => "REL32_1",
                0x0006 => "REL32_2",
                0x0007 => "REL32_3",
                0x0008 => "REL32_4",
                0x0009 => "REL32_5",
                0x000A => "SECTION",
                0x000B => "SECREL",
                0x000C => "SECREL7",
                0x000D => "TOKEN",
                0x000E => "PCRQUAD",
                else => "AMD64_RELOC",
            },
            .arm64 => switch (self.type_id) {
                0x0000 => "ABSOLUTE",
                0x0001 => "ADDR32",
                0x0002 => "ADDR32NB",
                0x0003 => "BRANCH26",
                0x0004 => "PAGEBASE_REL21",
                0x0005 => "REL21",
                0x0006 => "PAGEOFFSET_12A",
                0x0007 => "PAGEOFFSET_12L",
                0x0008 => "SECREL",
                0x0009 => "SECREL_LOW12A",
                0x000A => "SECREL_HIGH12A",
                0x000B => "SECREL_LOW12L",
                0x000C => "TOKEN",
                0x000D => "SECTION",
                0x000E => "ADDR64",
                0x000F => "BRANCH19",
                else => "ARM64_RELOC",
            },
            .i386 => switch (self.type_id) {
                0x0000 => "ABSOLUTE",
                0x0001 => "DIR16",
                0x0002 => "REL16",
                0x0006 => "DIR32",
                0x0007 => "DIR32NB",
                0x0009 => "SEG12",
                0x000A => "SECTION",
                0x000B => "SECREL",
                0x0014 => "REL32",
                else => "I386_RELOC",
            },
            else => "RELOC",
        };
    }
};

// === Error Sets ===

pub const Error = error{
    TruncatedHeader,
    NotCoffOrPe,
    InvalidDosMagic,
    InvalidPeSignature,
    InvalidOptionalHeaderMagic,
    TruncatedOptionalHeader,
};

pub const SectionError = error{
    TruncatedSectionTable,
    InvalidSectionIndex,
    InvalidSectionSize,
    StringTableOutOfBounds,
    InvalidStringOffset,
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

// === Section Header Representation ===

/// Normalized representation for a 40-byte COFF / PE section header.
pub const SectionHeader = struct {
    raw_name: [8]u8,
    virtual_size: u32,
    virtual_address: u32,
    size_of_raw_data: u32,
    pointer_to_raw_data: u32,
    pointer_to_relocations: u32,
    pointer_to_linenumbers: u32,
    number_of_relocations: u16,
    number_of_linenumbers: u16,
    characteristics: u32,

    pub fn isExecutable(self: *const SectionHeader) bool {
        return (self.characteristics & section_flags.MEM_EXECUTE) != 0;
    }

    pub fn isReadable(self: *const SectionHeader) bool {
        return (self.characteristics & section_flags.MEM_READ) != 0;
    }

    pub fn isWritable(self: *const SectionHeader) bool {
        return (self.characteristics & section_flags.MEM_WRITE) != 0;
    }

    pub fn hasCode(self: *const SectionHeader) bool {
        return (self.characteristics & section_flags.CNT_CODE) != 0;
    }

    pub fn hasInitializedData(self: *const SectionHeader) bool {
        return (self.characteristics & section_flags.CNT_INITIALIZED_DATA) != 0;
    }

    pub fn hasUninitializedData(self: *const SectionHeader) bool {
        return (self.characteristics & section_flags.CNT_UNINITIALIZED_DATA) != 0;
    }

    pub fn isComdat(self: *const SectionHeader) bool {
        return (self.characteristics & section_flags.LNK_COMDAT) != 0;
    }

    pub fn isDiscardable(self: *const SectionHeader) bool {
        return (self.characteristics & (section_flags.MEM_DISCARDABLE | section_flags.LNK_REMOVE)) != 0;
    }

    pub fn hasRelocationOverflow(self: *const SectionHeader) bool {
        return (self.characteristics & section_flags.LNK_NRELOC_OVFL) != 0 and self.number_of_relocations == 0xFFFF;
    }

    pub fn getAlignment(self: *const SectionHeader) u32 {
        const align_val = (self.characteristics >> 20) & 0x0F;
        if (align_val == 0) return 16;
        if (align_val > 14) return 8192;
        return @as(u32, 1) << @intCast(align_val - 1);
    }

    pub fn getPermissions(self: *const SectionHeader) SectionPermissions {
        return .{
            .read = self.isReadable(),
            .write = self.isWritable(),
            .execute = self.isExecutable(),
        };
    }

    /// Classify the section into a normalized cross-platform semantic kind.
    pub fn getNormalizedKind(self: *const SectionHeader, resolved_name: []const u8) SectionKind {
        // Directives and explicitly removed sections
        if ((self.characteristics & section_flags.LNK_REMOVE) != 0 or
            std.mem.eql(u8, resolved_name, ".drectve"))
        {
            return .discard;
        }

        // Debug sections (.debug$S, .debug$T, etc.)
        if (std.mem.startsWith(u8, resolved_name, ".debug") or
            (self.characteristics & section_flags.MEM_DISCARDABLE) != 0)
        {
            return .debug;
        }

        // Thread-Local Storage (.tls, .tls$)
        if (std.mem.startsWith(u8, resolved_name, ".tls")) {
            return .tls;
        }

        // Linker info and comments
        if ((self.characteristics & section_flags.LNK_INFO) != 0) {
            return .metadata;
        }

        // Uninitialized data / BSS
        if (self.hasUninitializedData() or std.mem.startsWith(u8, resolved_name, ".bss")) {
            return .bss;
        }

        // Executable code (.text)
        if (self.isExecutable() or self.hasCode()) {
            return .text;
        }

        // Read-only vs. read-write data
        if (self.isWritable()) {
            return .data;
        }

        return .rodata;
    }

    /// Extract section name string, resolving long names from the COFF string table.
    pub fn getName(self: *const SectionHeader, strtab_bytes: []const u8) SectionError![]const u8 {
        if (self.raw_name[0] == '/') {
            const len = std.mem.indexOfScalar(u8, &self.raw_name, 0) orelse self.raw_name.len;
            const num_str = self.raw_name[1..len];

            const offset = std.fmt.parseInt(u32, num_str, 10) catch {
                return error.InvalidStringOffset;
            };

            if (offset >= strtab_bytes.len) {
                return error.StringTableOutOfBounds;
            }

            const slice = strtab_bytes[offset..];
            const str_len = std.mem.indexOfScalar(u8, slice, 0) orelse return error.StringTableOutOfBounds;
            return slice[0..str_len];
        }

        const len = std.mem.indexOfScalar(u8, &self.raw_name, 0) orelse self.raw_name.len;
        return self.raw_name[0..len];
    }

    /// Returns the base container section name under the COFF '$' grouping rule.
    /// E.g. ".rdata$T" -> ".rdata", ".CRT$XCA" -> ".CRT", ".text" -> ".text".
    pub fn getBaseName(resolved_name: []const u8) []const u8 {
        if (std.mem.indexOfScalar(u8, resolved_name, '$')) |dollar_idx| {
            return resolved_name[0..dollar_idx];
        }
        return resolved_name;
    }

    /// Returns the sort suffix under the COFF '$' rule, or null if no '$' exists.
    /// E.g. ".rdata$T" -> "T", ".CRT$XCA" -> "XCA", ".text" -> null.
    pub fn getSortKey(resolved_name: []const u8) ?[]const u8 {
        if (std.mem.indexOfScalar(u8, resolved_name, '$')) |dollar_idx| {
            return resolved_name[dollar_idx + 1 ..];
        }
        return null;
    }

    pub fn getData(self: *const SectionHeader, file_bytes: []const u8) SectionError![]const u8 {
        if (self.size_of_raw_data == 0) return &.{};

        const start: usize = self.pointer_to_raw_data;
        const end: usize = std.math.add(usize, start, self.size_of_raw_data) catch {
            return error.InvalidSectionSize;
        };

        if (end > file_bytes.len) {
            return error.InvalidSectionSize;
        }

        return file_bytes[start..end];
    }

    pub fn getRelocationCount(self: *const SectionHeader, file_bytes: []const u8) RelocationError!u32 {
        if (self.number_of_relocations == 0 and !self.hasRelocationOverflow()) return 0;

        if (self.hasRelocationOverflow()) {
            const start: usize = self.pointer_to_relocations;
            if (start + 10 > file_bytes.len) {
                return error.TruncatedRelocationTable;
            }
            return std.mem.readInt(u32, file_bytes[start..][0..4], .little);
        }

        return self.number_of_relocations;
    }

    pub fn parseRelocation(self: *const SectionHeader, file_bytes: []const u8, index: usize) RelocationError!Relocation {
        const count = try self.getRelocationCount(file_bytes);
        if (index >= count) {
            return error.InvalidRelocationIndex;
        }

        const entry_index: usize = if (self.hasRelocationOverflow()) index + 1 else index;
        const offset: usize = self.pointer_to_relocations + (entry_index * 10);
        const end: usize = offset + 10;

        if (end > file_bytes.len) {
            return error.TruncatedRelocationTable;
        }

        const rel_bytes = file_bytes[offset..end];

        return .{
            .virtual_address = std.mem.readInt(u32, rel_bytes[0..][0..4], .little),
            .symbol_table_index = std.mem.readInt(u32, rel_bytes[4..][0..4], .little),
            .type_id = std.mem.readInt(u16, rel_bytes[8..][0..2], .little),
        };
    }

    pub fn parseAllRelocations(
        self: *const SectionHeader,
        allocator: std.mem.Allocator,
        file_bytes: []const u8,
    ) (RelocationError || std.mem.Allocator.Error)![]Relocation {
        const count = try self.getRelocationCount(file_bytes);
        const relocs = try allocator.alloc(Relocation, count);
        errdefer allocator.free(relocs);

        var i: usize = 0;
        while (i < count) : (i += 1) {
            relocs[i] = try self.parseRelocation(file_bytes, i);
        }

        return relocs;
    }
};

// === Symbol Table Representation ===

/// Normalized representation for an 18-byte COFF symbol entry.
pub const Symbol = struct {
    raw_name: [8]u8,
    value: u32,
    section_number: i16,
    sym_type: u16,
    storage_class: StorageClass,
    num_aux_symbols: u8,

    pub fn isUndefined(self: *const Symbol) bool {
        return self.section_number == SpecialSection.UNDEFINED and self.value == 0;
    }

    pub fn isCommon(self: *const Symbol) bool {
        return self.section_number == SpecialSection.UNDEFINED and self.value > 0;
    }

    pub fn isAbsolute(self: *const Symbol) bool {
        return self.section_number == SpecialSection.ABSOLUTE;
    }

    pub fn isExternal(self: *const Symbol) bool {
        return self.storage_class == .external;
    }

    pub fn isStatic(self: *const Symbol) bool {
        return self.storage_class == .static;
    }

    pub fn isFunction(self: *const Symbol) bool {
        return (self.sym_type & 0x20) != 0 or self.storage_class == .function;
    }

    pub fn getName(self: *const Symbol, strtab_bytes: []const u8) SymbolError![]const u8 {
        const zeroes = std.mem.readInt(u32, self.raw_name[0..4], .little);
        if (zeroes == 0) {
            const offset = std.mem.readInt(u32, self.raw_name[4..8], .little);
            if (offset >= strtab_bytes.len) {
                return error.StringTableOutOfBounds;
            }

            const slice = strtab_bytes[offset..];
            const len = std.mem.indexOfScalar(u8, slice, 0) orelse return error.StringTableOutOfBounds;
            return slice[0..len];
        }

        const len = std.mem.indexOfScalar(u8, &self.raw_name, 0) orelse self.raw_name.len;
        return self.raw_name[0..len];
    }
};

// === Normalized COFF / PE Header ===

/// Normalized representation for COFF object files and PE binaries.
pub const Header = struct {
    is_pe: bool,
    machine: Machine,
    section_count: u16,
    time_date_stamp: u32,
    symbol_table_offset: u32,
    symbol_count: u32,
    size_of_optional_header: u16,
    characteristics_flags: u16,
    section_headers_offset: u32,
    optional_header: ?OptionalHeader,

    pub fn isExecutable(self: Header) bool {
        return (self.characteristics_flags & characteristics.EXECUTABLE_IMAGE) != 0;
    }

    pub fn isDll(self: Header) bool {
        return (self.characteristics_flags & characteristics.DLL) != 0;
    }

    pub fn hasRelocsStripped(self: Header) bool {
        return (self.characteristics_flags & characteristics.RELOCS_STRIPPED) != 0;
    }

    pub fn parse(bytes: []const u8) Error!Header {
        if (bytes.len < 20) return error.TruncatedHeader;

        if (std.mem.eql(u8, bytes[0..2], &DOS_MAGIC)) {
            return parsePeImage(bytes);
        }

        const raw_machine = std.mem.readInt(u16, bytes[0..2], .little);
        if (Machine.isKnown(raw_machine)) {
            return parseCoffObject(bytes);
        }

        return error.NotCoffOrPe;
    }

    pub fn parseSectionHeader(self: Header, file_bytes: []const u8, index: usize) SectionError!SectionHeader {
        if (index >= self.section_count) {
            return error.InvalidSectionIndex;
        }

        const offset: usize = self.section_headers_offset + (index * 40);
        const end: usize = offset + 40;

        if (end > file_bytes.len) {
            return error.TruncatedSectionTable;
        }

        const sh_bytes = file_bytes[offset..end];
        var name_buf: [8]u8 = undefined;
        @memcpy(&name_buf, sh_bytes[0..8]);

        return .{
            .raw_name = name_buf,
            .virtual_size = std.mem.readInt(u32, sh_bytes[8..][0..4], .little),
            .virtual_address = std.mem.readInt(u32, sh_bytes[12..][0..4], .little),
            .size_of_raw_data = std.mem.readInt(u32, sh_bytes[16..][0..4], .little),
            .pointer_to_raw_data = std.mem.readInt(u32, sh_bytes[20..][0..4], .little),
            .pointer_to_relocations = std.mem.readInt(u32, sh_bytes[24..][0..4], .little),
            .pointer_to_linenumbers = std.mem.readInt(u32, sh_bytes[28..][0..4], .little),
            .number_of_relocations = std.mem.readInt(u16, sh_bytes[32..][0..2], .little),
            .number_of_linenumbers = std.mem.readInt(u16, sh_bytes[34..][0..2], .little),
            .characteristics = std.mem.readInt(u32, sh_bytes[36..][0..4], .little),
        };
    }

    pub fn parseAllSectionHeaders(
        self: Header,
        allocator: std.mem.Allocator,
        file_bytes: []const u8,
    ) (SectionError || std.mem.Allocator.Error)![]SectionHeader {
        const sections = try allocator.alloc(SectionHeader, self.section_count);
        errdefer allocator.free(sections);

        var i: usize = 0;
        while (i < self.section_count) : (i += 1) {
            sections[i] = try self.parseSectionHeader(file_bytes, i);
        }

        return sections;
    }

    pub fn getStringTable(self: Header, file_bytes: []const u8) []const u8 {
        if (self.symbol_table_offset == 0 or self.symbol_count == 0) {
            return &.{};
        }

        const sym_table_bytes = @as(usize, self.symbol_count) * 18;
        const strtab_offset: usize = self.symbol_table_offset + sym_table_bytes;

        if (strtab_offset + 4 > file_bytes.len) {
            return &.{};
        }

        const strtab_size = std.mem.readInt(u32, file_bytes[strtab_offset..][0..4], .little);
        if (strtab_size < 4 or strtab_offset + strtab_size > file_bytes.len) {
            return &.{};
        }

        return file_bytes[strtab_offset .. strtab_offset + strtab_size];
    }

    pub fn parseSymbol(self: Header, file_bytes: []const u8, index: usize) SymbolError!Symbol {
        if (index >= self.symbol_count) {
            return error.InvalidSymbolIndex;
        }

        const offset: usize = self.symbol_table_offset + (index * 18);
        const end: usize = offset + 18;

        if (end > file_bytes.len) {
            return error.TruncatedSymbolTable;
        }

        const sym_bytes = file_bytes[offset..end];
        var name_buf: [8]u8 = undefined;
        @memcpy(&name_buf, sym_bytes[0..8]);

        return .{
            .raw_name = name_buf,
            .value = std.mem.readInt(u32, sym_bytes[8..][0..4], .little),
            .section_number = std.mem.readInt(i16, sym_bytes[12..][0..2], .little),
            .sym_type = std.mem.readInt(u16, sym_bytes[14..][0..2], .little),
            .storage_class = @fromBackingInt(@intCast(sym_bytes[16])),
            .num_aux_symbols = sym_bytes[17],
        };
    }

    pub fn parseAllSymbols(
        self: Header,
        allocator: std.mem.Allocator,
        file_bytes: []const u8,
    ) (SymbolError || std.mem.Allocator.Error)![]Symbol {
        const symbols = try allocator.alloc(Symbol, self.symbol_count);
        errdefer allocator.free(symbols);

        var i: usize = 0;
        while (i < self.symbol_count) : (i += 1) {
            symbols[i] = try self.parseSymbol(file_bytes, i);
        }

        return symbols;
    }

    // --- Private Parsers ---

    fn parseCoffObject(bytes: []const u8) Error!Header {
        if (bytes.len < 20) return error.TruncatedHeader;

        const raw_machine = std.mem.readInt(u16, bytes[0..2], .little);
        const section_count = std.mem.readInt(u16, bytes[2..4], .little);
        const timestamp = std.mem.readInt(u32, bytes[4..8], .little);
        const symtab_offset = std.mem.readInt(u32, bytes[8..12], .little);
        const sym_count = std.mem.readInt(u32, bytes[12..16], .little);
        const opt_size = std.mem.readInt(u16, bytes[16..18], .little);
        const chars = std.mem.readInt(u16, bytes[18..20], .little);

        const sec_hdr_offset: u32 = 20 + @as(u32, opt_size);

        return .{
            .is_pe = false,
            .machine = @fromBackingInt(@intCast(raw_machine)),
            .section_count = section_count,
            .time_date_stamp = timestamp,
            .symbol_table_offset = symtab_offset,
            .symbol_count = sym_count,
            .size_of_optional_header = opt_size,
            .characteristics_flags = chars,
            .section_headers_offset = sec_hdr_offset,
            .optional_header = null,
        };
    }

    fn parsePeImage(bytes: []const u8) Error!Header {
        if (bytes.len < 64) return error.TruncatedHeader;

        const pe_offset = std.mem.readInt(u32, bytes[0x3C..0x40], .little);

        if (pe_offset + 24 > bytes.len) return error.TruncatedHeader;

        const sig_slice = bytes[pe_offset .. pe_offset + 4];
        if (!std.mem.eql(u8, sig_slice, &PE_SIGNATURE)) {
            return error.InvalidPeSignature;
        }

        const coff_start = pe_offset + 4;
        const coff_bytes = bytes[coff_start .. coff_start + 20];

        const raw_machine = std.mem.readInt(u16, coff_bytes[0..2], .little);
        const section_count = std.mem.readInt(u16, coff_bytes[2..4], .little);
        const timestamp = std.mem.readInt(u32, coff_bytes[4..8], .little);
        const symtab_offset = std.mem.readInt(u32, coff_bytes[8..12], .little);
        const sym_count = std.mem.readInt(u32, coff_bytes[12..16], .little);
        const opt_size = std.mem.readInt(u16, coff_bytes[16..18], .little);
        const chars = std.mem.readInt(u16, coff_bytes[18..20], .little);

        const sec_hdr_offset: u32 = @intCast(coff_start + 20 + opt_size);

        var opt_header: ?OptionalHeader = null;
        if (opt_size > 0) {
            const opt_start = coff_start + 20;
            const opt_end = opt_start + opt_size;
            if (opt_end > bytes.len) return error.TruncatedOptionalHeader;

            opt_header = try parseOptionalHeader(bytes[opt_start..opt_end]);
        }

        return .{
            .is_pe = true,
            .machine = @fromBackingInt(@intCast(raw_machine)),
            .section_count = section_count,
            .time_date_stamp = timestamp,
            .symbol_table_offset = symtab_offset,
            .symbol_count = sym_count,
            .size_of_optional_header = opt_size,
            .characteristics_flags = chars,
            .section_headers_offset = sec_hdr_offset,
            .optional_header = opt_header,
        };
    }

    fn parseOptionalHeader(bytes: []const u8) Error!OptionalHeader {
        if (bytes.len < 2) return error.TruncatedOptionalHeader;
        const magic = std.mem.readInt(u16, bytes[0..2], .little);

        if (magic == OptionalHeaderMagic.PE32_PLUS) {
            if (bytes.len < 112) return error.TruncatedOptionalHeader;

            const major_linker = bytes[2];
            const minor_linker = bytes[3];
            const size_of_code = std.mem.readInt(u32, bytes[4..8], .little);
            const size_of_init = std.mem.readInt(u32, bytes[8..12], .little);
            const size_of_uninit = std.mem.readInt(u32, bytes[12..16], .little);
            const entry_point = std.mem.readInt(u32, bytes[16..20], .little);
            const base_of_code = std.mem.readInt(u32, bytes[20..24], .little);
            const image_base = std.mem.readInt(u64, bytes[24..32], .little);
            const sec_align = std.mem.readInt(u32, bytes[32..36], .little);
            const file_align = std.mem.readInt(u32, bytes[36..40], .little);
            const major_os = std.mem.readInt(u16, bytes[40..42], .little);
            const minor_os = std.mem.readInt(u16, bytes[42..44], .little);
            const major_img = std.mem.readInt(u16, bytes[44..46], .little);
            const minor_img = std.mem.readInt(u16, bytes[46..48], .little);
            const major_sub = std.mem.readInt(u16, bytes[48..50], .little);
            const minor_sub = std.mem.readInt(u16, bytes[50..52], .little);
            const win32_ver = std.mem.readInt(u32, bytes[52..56], .little);
            const size_of_image = std.mem.readInt(u32, bytes[56..60], .little);
            const size_of_hdrs = std.mem.readInt(u32, bytes[60..64], .little);
            const checksum = std.mem.readInt(u32, bytes[64..68], .little);
            const raw_subsystem = std.mem.readInt(u16, bytes[68..70], .little);
            const dll_chars = std.mem.readInt(u16, bytes[70..72], .little);
            const stack_reserve = std.mem.readInt(u64, bytes[72..80], .little);
            const stack_commit = std.mem.readInt(u64, bytes[80..88], .little);
            const heap_reserve = std.mem.readInt(u64, bytes[88..96], .little);
            const heap_commit = std.mem.readInt(u64, bytes[96..104], .little);
            const num_rva = std.mem.readInt(u32, bytes[108..112], .little);

            var dirs: [16]DataDirectory = undefined;
            @memset(&dirs, .{ .virtual_address = 0, .size = 0 });

            const dir_count = @min(num_rva, 16);
            var i: usize = 0;
            while (i < dir_count) : (i += 1) {
                const dir_start = 112 + (i * 8);
                if (dir_start + 8 <= bytes.len) {
                    dirs[i] = .{
                        .virtual_address = std.mem.readInt(u32, bytes[dir_start..][0..4], .little),
                        .size = std.mem.readInt(u32, bytes[dir_start + 4 ..][0..4], .little),
                    };
                }
            }

            return .{
                .is_64bit = true,
                .magic = magic,
                .major_linker_version = major_linker,
                .minor_linker_version = minor_linker,
                .size_of_code = size_of_code,
                .size_of_initialized_data = size_of_init,
                .size_of_uninitialized_data = size_of_uninit,
                .address_of_entry_point = entry_point,
                .base_of_code = base_of_code,
                .image_base = image_base,
                .section_alignment = sec_align,
                .file_alignment = file_align,
                .major_os_version = major_os,
                .minor_os_version = minor_os,
                .major_image_version = major_img,
                .minor_image_version = minor_img,
                .major_subsystem_version = major_sub,
                .minor_subsystem_version = minor_sub,
                .win32_version_value = win32_ver,
                .size_of_image = size_of_image,
                .size_of_headers = size_of_hdrs,
                .checksum = checksum,
                .subsystem = @fromBackingInt(@intCast(raw_subsystem)),
                .dll_characteristics = dll_chars,
                .size_of_stack_reserve = stack_reserve,
                .size_of_stack_commit = stack_commit,
                .size_of_heap_reserve = heap_reserve,
                .size_of_heap_commit = heap_commit,
                .data_directories = dirs,
            };
        } else if (magic == OptionalHeaderMagic.PE32) {
            if (bytes.len < 96) return error.TruncatedOptionalHeader;

            const major_linker = bytes[2];
            const minor_linker = bytes[3];
            const size_of_code = std.mem.readInt(u32, bytes[4..8], .little);
            const size_of_init = std.mem.readInt(u32, bytes[8..12], .little);
            const size_of_uninit = std.mem.readInt(u32, bytes[12..16], .little);
            const entry_point = std.mem.readInt(u32, bytes[16..20], .little);
            const base_of_code = std.mem.readInt(u32, bytes[20..24], .little);
            const image_base = @as(u64, std.mem.readInt(u32, bytes[28..32], .little));
            const sec_align = std.mem.readInt(u32, bytes[32..36], .little);
            const file_align = std.mem.readInt(u32, bytes[36..40], .little);
            const major_os = std.mem.readInt(u16, bytes[40..42], .little);
            const minor_os = std.mem.readInt(u16, bytes[42..44], .little);
            const major_img = std.mem.readInt(u16, bytes[44..46], .little);
            const minor_img = std.mem.readInt(u16, bytes[46..48], .little);
            const major_sub = std.mem.readInt(u16, bytes[48..50], .little);
            const minor_sub = std.mem.readInt(u16, bytes[50..52], .little);
            const win32_ver = std.mem.readInt(u32, bytes[52..56], .little);
            const size_of_image = std.mem.readInt(u32, bytes[56..60], .little);
            const size_of_hdrs = std.mem.readInt(u32, bytes[60..64], .little);
            const checksum = std.mem.readInt(u32, bytes[64..68], .little);
            const raw_subsystem = std.mem.readInt(u16, bytes[68..70], .little);
            const dll_chars = std.mem.readInt(u16, bytes[70..72], .little);
            const stack_reserve = @as(u64, std.mem.readInt(u32, bytes[72..76], .little));
            const stack_commit = @as(u64, std.mem.readInt(u32, bytes[76..80], .little));
            const heap_reserve = @as(u64, std.mem.readInt(u32, bytes[80..84], .little));
            const heap_commit = @as(u64, std.mem.readInt(u32, bytes[84..88], .little));
            const num_rva = std.mem.readInt(u32, bytes[92..96], .little);

            var dirs: [16]DataDirectory = undefined;
            @memset(&dirs, .{ .virtual_address = 0, .size = 0 });

            const dir_count = @min(num_rva, 16);
            var i: usize = 0;
            while (i < dir_count) : (i += 1) {
                const dir_start = 96 + (i * 8);
                if (dir_start + 8 <= bytes.len) {
                    dirs[i] = .{
                        .virtual_address = std.mem.readInt(u32, bytes[dir_start..][0..4], .little),
                        .size = std.mem.readInt(u32, bytes[dir_start + 4 ..][0..4], .little),
                    };
                }
            }

            return .{
                .is_64bit = false,
                .magic = magic,
                .major_linker_version = major_linker,
                .minor_linker_version = minor_linker,
                .size_of_code = size_of_code,
                .size_of_initialized_data = size_of_init,
                .size_of_uninitialized_data = size_of_uninit,
                .address_of_entry_point = entry_point,
                .base_of_code = base_of_code,
                .image_base = image_base,
                .section_alignment = sec_align,
                .file_alignment = file_align,
                .major_os_version = major_os,
                .minor_os_version = minor_os,
                .major_image_version = major_img,
                .minor_image_version = minor_img,
                .major_subsystem_version = major_sub,
                .minor_subsystem_version = minor_sub,
                .win32_version_value = win32_ver,
                .size_of_image = size_of_image,
                .size_of_headers = size_of_hdrs,
                .checksum = checksum,
                .subsystem = @fromBackingInt(@intCast(raw_subsystem)),
                .dll_characteristics = dll_chars,
                .size_of_stack_reserve = stack_reserve,
                .size_of_stack_commit = stack_commit,
                .size_of_heap_reserve = heap_reserve,
                .size_of_heap_commit = heap_commit,
                .data_directories = dirs,
            };
        }

        return error.InvalidOptionalHeaderMagic;
    }
};

// === Unit Tests ===

test "parse 64-bit x86_64 COFF relocatable object header" {
    var obj_buf: [20]u8 = undefined;
    @memset(&obj_buf, 0);

    std.mem.writeInt(u16, obj_buf[0..2], 0x8664, .little);
    std.mem.writeInt(u16, obj_buf[2..4], 4, .little);
    std.mem.writeInt(u32, obj_buf[4..8], 1700000000, .little);
    std.mem.writeInt(u32, obj_buf[8..12], 0x200, .little);
    std.mem.writeInt(u32, obj_buf[12..16], 25, .little);
    std.mem.writeInt(u16, obj_buf[16..18], 0, .little);
    std.mem.writeInt(u16, obj_buf[18..20], 0, .little);

    const hdr = try Header.parse(&obj_buf);

    try std.testing.expect(!hdr.is_pe);
    try std.testing.expectEqual(Machine.x86_64, hdr.machine);
    try std.testing.expectEqual(@as(u16, 4), hdr.section_count);
    try std.testing.expectEqual(@as(u32, 0x200), hdr.symbol_table_offset);
    try std.testing.expectEqual(@as(u32, 25), hdr.symbol_count);
    try std.testing.expectEqual(@as(u16, 0), hdr.size_of_optional_header);
    try std.testing.expectEqual(@as(u32, 20), hdr.section_headers_offset);
    try std.testing.expect(hdr.optional_header == null);
}

test "parse ARM64 COFF object header" {
    var obj_buf: [20]u8 = undefined;
    @memset(&obj_buf, 0);

    std.mem.writeInt(u16, obj_buf[0..2], 0xAA64, .little);
    std.mem.writeInt(u16, obj_buf[2..4], 6, .little);
    std.mem.writeInt(u32, obj_buf[8..12], 0x400, .little);
    std.mem.writeInt(u32, obj_buf[12..16], 40, .little);

    const hdr = try Header.parse(&obj_buf);

    try std.testing.expectEqual(Machine.arm64, hdr.machine);
    try std.testing.expectEqual(@as(u16, 6), hdr.section_count);
    try std.testing.expectEqualStrings("arm64", hdr.machine.name());
}

test "parse complete Windows 64-bit PE binary with DOS stub" {
    var pe_buf: [350]u8 = undefined;
    @memset(&pe_buf, 0);

    @memcpy(pe_buf[0..2], &DOS_MAGIC);
    std.mem.writeInt(u32, pe_buf[0x3C..0x40], 64, .little);

    @memcpy(pe_buf[64..68], &PE_SIGNATURE);

    std.mem.writeInt(u16, pe_buf[68..70], 0x8664, .little);
    std.mem.writeInt(u16, pe_buf[70..72], 5, .little);
    std.mem.writeInt(u32, pe_buf[72..76], 123456, .little);
    std.mem.writeInt(u32, pe_buf[76..80], 0, .little);
    std.mem.writeInt(u32, pe_buf[80..84], 0, .little);
    std.mem.writeInt(u16, pe_buf[84..86], 240, .little);
    std.mem.writeInt(u16, pe_buf[86..88], characteristics.EXECUTABLE_IMAGE | characteristics.LARGE_ADDRESS_AWARE, .little);

    std.mem.writeInt(u16, pe_buf[88..90], OptionalHeaderMagic.PE32_PLUS, .little);
    pe_buf[90] = 14;
    pe_buf[91] = 0;
    std.mem.writeInt(u32, pe_buf[92..96], 0x1000, .little);
    std.mem.writeInt(u32, pe_buf[104..108], 0x1200, .little);
    std.mem.writeInt(u64, pe_buf[112..120], 0x140000000, .little);
    std.mem.writeInt(u32, pe_buf[120..124], 4096, .little);
    std.mem.writeInt(u32, pe_buf[124..128], 512, .little);
    std.mem.writeInt(u16, pe_buf[156..158], 3, .little);
    std.mem.writeInt(u32, pe_buf[196..200], 16, .little);

    std.mem.writeInt(u32, pe_buf[208..212], 0x3000, .little);
    std.mem.writeInt(u32, pe_buf[212..216], 0x200, .little);

    const hdr = try Header.parse(&pe_buf);

    try std.testing.expect(hdr.is_pe);
    try std.testing.expect(hdr.isExecutable());
    try std.testing.expect(!hdr.isDll());
    try std.testing.expectEqual(Machine.x86_64, hdr.machine);
    try std.testing.expectEqual(@as(u16, 5), hdr.section_count);
    try std.testing.expectEqual(@as(u32, 68 + 20 + 240), hdr.section_headers_offset);

    const opt = hdr.optional_header.?;
    try std.testing.expect(opt.is_64bit);
    try std.testing.expectEqual(@as(u32, 0x1200), opt.address_of_entry_point);
    try std.testing.expectEqual(@as(u64, 0x140000000), opt.image_base);
    try std.testing.expectEqual(Subsystem.windows_cui, opt.subsystem);
    try std.testing.expectEqual(@as(u32, 0x3000), opt.data_directories[1].virtual_address);
    try std.testing.expectEqual(@as(u32, 0x200), opt.data_directories[1].size);
}

test "parse 32-bit Windows PE DLL binary" {
    var pe_buf: [320]u8 = undefined;
    @memset(&pe_buf, 0);

    @memcpy(pe_buf[0..2], &DOS_MAGIC);
    std.mem.writeInt(u32, pe_buf[0x3C..0x40], 64, .little);
    @memcpy(pe_buf[64..68], &PE_SIGNATURE);

    std.mem.writeInt(u16, pe_buf[68..70], 0x014C, .little);
    std.mem.writeInt(u16, pe_buf[70..72], 3, .little);
    std.mem.writeInt(u16, pe_buf[84..86], 224, .little);
    std.mem.writeInt(u16, pe_buf[86..88], characteristics.DLL | characteristics.EXECUTABLE_IMAGE, .little);

    std.mem.writeInt(u16, pe_buf[88..90], OptionalHeaderMagic.PE32, .little);
    std.mem.writeInt(u32, pe_buf[104..108], 0x1000, .little);
    std.mem.writeInt(u32, pe_buf[116..120], 0x10000000, .little);
    std.mem.writeInt(u16, pe_buf[156..158], 2, .little);

    const hdr = try Header.parse(&pe_buf);

    try std.testing.expect(hdr.is_pe);
    try std.testing.expect(hdr.isDll());
    try std.testing.expect(hdr.isExecutable());
    try std.testing.expectEqual(Machine.i386, hdr.machine);

    const opt = hdr.optional_header.?;
    try std.testing.expect(!opt.is_64bit);
    try std.testing.expectEqual(@as(u64, 0x10000000), opt.image_base);
    try std.testing.expectEqual(Subsystem.windows_gui, opt.subsystem);
}

test "reject invalid signatures" {
    var bad_dos: [64]u8 = undefined;
    @memset(&bad_dos, 0);
    @memcpy(bad_dos[0..2], "XX");
    try std.testing.expectError(error.NotCoffOrPe, Header.parse(&bad_dos));

    var bad_pe: [128]u8 = undefined;
    @memset(&bad_pe, 0);
    @memcpy(bad_pe[0..2], &DOS_MAGIC);
    std.mem.writeInt(u32, bad_pe[0x3C..0x40], 64, .little);
    @memcpy(bad_pe[64..68], "NOTP");
    try std.testing.expectError(error.InvalidPeSignature, Header.parse(&bad_pe));
}

test "parse 40-byte COFF section header" {
    var sh_buf: [40]u8 = undefined;
    @memset(&sh_buf, 0);

    @memcpy(sh_buf[0..5], ".text");
    std.mem.writeInt(u32, sh_buf[8..12], 0x120, .little);
    std.mem.writeInt(u32, sh_buf[12..16], 0x1000, .little);
    std.mem.writeInt(u32, sh_buf[16..20], 0x200, .little);
    std.mem.writeInt(u32, sh_buf[20..24], 0x400, .little);
    std.mem.writeInt(u32, sh_buf[24..28], 0x600, .little);
    std.mem.writeInt(u16, sh_buf[32..34], 3, .little);
    const flags = section_flags.CNT_CODE | section_flags.MEM_EXECUTE | section_flags.MEM_READ | 0x00500000;
    std.mem.writeInt(u32, sh_buf[36..40], flags, .little);

    const hdr = Header{
        .is_pe = false,
        .machine = .x86_64,
        .section_count = 1,
        .time_date_stamp = 0,
        .symbol_table_offset = 0,
        .symbol_count = 0,
        .size_of_optional_header = 0,
        .characteristics_flags = 0,
        .section_headers_offset = 0,
        .optional_header = null,
    };

    const sh = try hdr.parseSectionHeader(&sh_buf, 0);

    try std.testing.expectEqualStrings(".text", try sh.getName(""));
    try std.testing.expect(sh.hasCode());
    try std.testing.expect(sh.isExecutable());
    try std.testing.expect(sh.isReadable());
    try std.testing.expect(!sh.isWritable());
    try std.testing.expectEqual(@as(u32, 16), sh.getAlignment());
    try std.testing.expectEqual(@as(u32, 0x120), sh.virtual_size);
    try std.testing.expectEqual(@as(u32, 0x200), sh.size_of_raw_data);
    try std.testing.expectEqual(@as(u32, 0x400), sh.pointer_to_raw_data);
    try std.testing.expectEqual(@as(u32, 0x600), sh.pointer_to_relocations);
    try std.testing.expectEqual(@as(u16, 3), sh.number_of_relocations);
}

test "resolve long COFF section name from string table" {
    const sh = SectionHeader{
        .raw_name = [_]u8{ '/', '4', 0, 0, 0, 0, 0, 0 },
        .virtual_size = 0,
        .virtual_address = 0,
        .size_of_raw_data = 64,
        .pointer_to_raw_data = 100,
        .pointer_to_relocations = 0,
        .pointer_to_linenumbers = 0,
        .number_of_relocations = 0,
        .number_of_linenumbers = 0,
        .characteristics = section_flags.CNT_INITIALIZED_DATA | section_flags.MEM_READ,
    };

    const strtab_mock = "\x18\x00\x00\x00.very_long_section_name\x00";
    const name = try sh.getName(strtab_mock);
    try std.testing.expectEqualStrings(".very_long_section_name", name);
}

test "retrieve COFF section raw data bytes" {
    var file_mock: [512]u8 = undefined;
    @memset(&file_mock, 0);
    @memcpy(file_mock[128..144], "windows_obj_data");

    const sh = SectionHeader{
        .raw_name = [_]u8{ '.', 'd', 'a', 't', 'a', 0, 0, 0 },
        .virtual_size = 0,
        .virtual_address = 0,
        .size_of_raw_data = 16,
        .pointer_to_raw_data = 128,
        .pointer_to_relocations = 0,
        .pointer_to_linenumbers = 0,
        .number_of_relocations = 0,
        .number_of_linenumbers = 0,
        .characteristics = section_flags.CNT_INITIALIZED_DATA | section_flags.MEM_READ,
    };

    const data = try sh.getData(&file_mock);
    try std.testing.expectEqualStrings("windows_obj_data", data);
}

test "parse 18-byte inline COFF symbol entry" {
    var sym_buf: [18]u8 = undefined;
    @memset(&sym_buf, 0);

    @memcpy(sym_buf[0..5], "_main");
    std.mem.writeInt(u32, sym_buf[8..12], 0x10, .little);
    std.mem.writeInt(i16, sym_buf[12..14], 1, .little);
    std.mem.writeInt(u16, sym_buf[14..16], 0x20, .little);
    sym_buf[16] = 2; // External
    sym_buf[17] = 0;

    const hdr = Header{
        .is_pe = false,
        .machine = .x86_64,
        .section_count = 1,
        .time_date_stamp = 0,
        .symbol_table_offset = 0,
        .symbol_count = 1,
        .size_of_optional_header = 0,
        .characteristics_flags = 0,
        .section_headers_offset = 0,
        .optional_header = null,
    };

    const sym = try hdr.parseSymbol(&sym_buf, 0);

    try std.testing.expectEqualStrings("_main", try sym.getName(""));
    try std.testing.expectEqual(@as(u32, 0x10), sym.value);
    try std.testing.expectEqual(@as(i16, 1), sym.section_number);
    try std.testing.expect(sym.isExternal());
    try std.testing.expect(sym.isFunction());
    try std.testing.expect(!sym.isUndefined());
    try std.testing.expect(!sym.isCommon());
    try std.testing.expect(!sym.isAbsolute());
    try std.testing.expectEqualStrings("EXTERNAL", sym.storage_class.name());
}

test "parse COFF symbol with long name referencing string table" {
    var sym_buf: [18]u8 = undefined;
    @memset(&sym_buf, 0);

    std.mem.writeInt(u32, sym_buf[0..4], 0, .little);
    std.mem.writeInt(u32, sym_buf[4..8], 4, .little);
    std.mem.writeInt(u32, sym_buf[8..12], 0, .little);
    std.mem.writeInt(i16, sym_buf[12..14], SpecialSection.UNDEFINED, .little);
    std.mem.writeInt(u16, sym_buf[14..16], 0x20, .little);
    sym_buf[16] = 2;
    sym_buf[17] = 0;

    const hdr = Header{
        .is_pe = false,
        .machine = .x86_64,
        .section_count = 1,
        .time_date_stamp = 0,
        .symbol_table_offset = 0,
        .symbol_count = 1,
        .size_of_optional_header = 0,
        .characteristics_flags = 0,
        .section_headers_offset = 0,
        .optional_header = null,
    };

    const sym = try hdr.parseSymbol(&sym_buf, 0);
    const strtab_mock = "\x20\x00\x00\x00MyVeryLongExportedFunctionName\x00";

    const name = try sym.getName(strtab_mock);
    try std.testing.expectEqualStrings("MyVeryLongExportedFunctionName", name);
    try std.testing.expect(sym.isUndefined());
    try std.testing.expect(!sym.isCommon());
}

test "parse COFF common and absolute symbols" {
    const common_sym = Symbol{
        .raw_name = [_]u8{ 'g', '_', 'b', 'u', 'f', 0, 0, 0 },
        .value = 1024,
        .section_number = SpecialSection.UNDEFINED,
        .sym_type = 0,
        .storage_class = .external,
        .num_aux_symbols = 0,
    };

    try std.testing.expect(common_sym.isCommon());
    try std.testing.expect(!common_sym.isUndefined());

    const abs_sym = Symbol{
        .raw_name = [_]u8{ 'M', 'A', 'X', '_', 'S', 'Z', 0, 0 },
        .value = 4096,
        .section_number = SpecialSection.ABSOLUTE,
        .sym_type = 0,
        .storage_class = .external,
        .num_aux_symbols = 0,
    };

    try std.testing.expect(abs_sym.isAbsolute());
    try std.testing.expect(!abs_sym.isUndefined());
}

test "parse 10-byte x86_64 COFF relocation entry" {
    var rel_buf: [10]u8 = undefined;
    @memset(&rel_buf, 0);

    std.mem.writeInt(u32, rel_buf[0..4], 0x14, .little);
    std.mem.writeInt(u32, rel_buf[4..8], 7, .little);
    std.mem.writeInt(u16, rel_buf[8..10], 0x0004, .little);

    const sh = SectionHeader{
        .raw_name = [_]u8{ '.', 't', 'e', 'x', 't', 0, 0, 0 },
        .virtual_size = 0,
        .virtual_address = 0,
        .size_of_raw_data = 64,
        .pointer_to_raw_data = 0,
        .pointer_to_relocations = 0,
        .pointer_to_linenumbers = 0,
        .number_of_relocations = 1,
        .number_of_linenumbers = 0,
        .characteristics = section_flags.CNT_CODE,
    };

    const count = try sh.getRelocationCount(&rel_buf);
    try std.testing.expectEqual(@as(u32, 1), count);

    const rel = try sh.parseRelocation(&rel_buf, 0);
    try std.testing.expectEqual(@as(u32, 0x14), rel.virtual_address);
    try std.testing.expectEqual(@as(u32, 7), rel.symbol_table_index);
    try std.testing.expectEqual(@as(u16, 0x0004), rel.type_id);
    try std.testing.expectEqualStrings("REL32", rel.typeName(.x86_64));
}

test "parse ARM64 COFF relocation entry" {
    var rel_buf: [10]u8 = undefined;
    @memset(&rel_buf, 0);

    std.mem.writeInt(u32, rel_buf[0..4], 0x40, .little);
    std.mem.writeInt(u32, rel_buf[4..8], 12, .little);
    std.mem.writeInt(u16, rel_buf[8..10], 0x0003, .little);

    const sh = SectionHeader{
        .raw_name = [_]u8{ '.', 't', 'e', 'x', 't', 0, 0, 0 },
        .virtual_size = 0,
        .virtual_address = 0,
        .size_of_raw_data = 128,
        .pointer_to_raw_data = 0,
        .pointer_to_relocations = 0,
        .pointer_to_linenumbers = 0,
        .number_of_relocations = 1,
        .number_of_linenumbers = 0,
        .characteristics = section_flags.CNT_CODE,
    };

    const rel = try sh.parseRelocation(&rel_buf, 0);
    try std.testing.expectEqual(@as(u32, 0x40), rel.virtual_address);
    try std.testing.expectEqual(@as(u32, 12), rel.symbol_table_index);
    try std.testing.expectEqualStrings("BRANCH26", rel.typeName(.arm64));
}

test "parse COFF relocation with overflow table (LNK_NRELOC_OVFL)" {
    var file_buf: [20]u8 = undefined;
    @memset(&file_buf, 0);

    std.mem.writeInt(u32, file_buf[0..4], 1, .little);
    std.mem.writeInt(u32, file_buf[4..8], 0, .little);
    std.mem.writeInt(u16, file_buf[8..10], 0, .little);

    std.mem.writeInt(u32, file_buf[10..14], 0x100, .little);
    std.mem.writeInt(u32, file_buf[14..18], 5, .little);
    std.mem.writeInt(u16, file_buf[18..20], 0x0001, .little);

    const sh = SectionHeader{
        .raw_name = [_]u8{ '.', 't', 'e', 'x', 't', 0, 0, 0 },
        .virtual_size = 0,
        .virtual_address = 0,
        .size_of_raw_data = 512,
        .pointer_to_raw_data = 0,
        .pointer_to_relocations = 0,
        .pointer_to_linenumbers = 0,
        .number_of_relocations = 0xFFFF,
        .number_of_linenumbers = 0,
        .characteristics = section_flags.CNT_CODE | section_flags.LNK_NRELOC_OVFL,
    };

    const count = try sh.getRelocationCount(&file_buf);
    try std.testing.expectEqual(@as(u32, 1), count);

    const rel = try sh.parseRelocation(&file_buf, 0);
    try std.testing.expectEqual(@as(u32, 0x100), rel.virtual_address);
    try std.testing.expectEqual(@as(u32, 5), rel.symbol_table_index);
    try std.testing.expectEqualStrings("ADDR64", rel.typeName(.x86_64));
}

test "COFF dollar sign section name splitting" {
    // Normal section
    try std.testing.expectEqualStrings(".text", SectionHeader.getBaseName(".text"));
    try std.testing.expect(SectionHeader.getSortKey(".text") == null);

    // Grouped section with sort suffix
    try std.testing.expectEqualStrings(".rdata", SectionHeader.getBaseName(".rdata$T"));
    try std.testing.expectEqualStrings("T", SectionHeader.getSortKey(".rdata$T").?);

    try std.testing.expectEqualStrings(".CRT", SectionHeader.getBaseName(".CRT$XLA"));
    try std.testing.expectEqualStrings("XLA", SectionHeader.getSortKey(".CRT$XLA").?);

    try std.testing.expectEqualStrings(".tls", SectionHeader.getBaseName(".tls$ZZZ"));
    try std.testing.expectEqualStrings("ZZZ", SectionHeader.getSortKey(".tls$ZZZ").?);
}

test "COFF normalized section kind and permissions" {
    // 1. .text (Code, Read + Execute)
    const text_sh = SectionHeader{
        .raw_name = [_]u8{ '.', 't', 'e', 'x', 't', 0, 0, 0 },
        .virtual_size = 0,
        .virtual_address = 0,
        .size_of_raw_data = 100,
        .pointer_to_raw_data = 0,
        .pointer_to_relocations = 0,
        .pointer_to_linenumbers = 0,
        .number_of_relocations = 0,
        .number_of_linenumbers = 0,
        .characteristics = section_flags.CNT_CODE | section_flags.MEM_READ | section_flags.MEM_EXECUTE,
    };
    try std.testing.expectEqual(SectionKind.text, text_sh.getNormalizedKind(".text"));
    const text_perm = text_sh.getPermissions();
    try std.testing.expect(text_perm.read and !text_perm.write and text_perm.execute);
    try std.testing.expectEqualStrings("R-X", &text_perm.toChars());

    // 2. .data (Initialized, Read + Write)
    const data_sh = SectionHeader{
        .raw_name = [_]u8{ '.', 'd', 'a', 't', 'a', 0, 0, 0 },
        .virtual_size = 0,
        .virtual_address = 0,
        .size_of_raw_data = 100,
        .pointer_to_raw_data = 0,
        .pointer_to_relocations = 0,
        .pointer_to_linenumbers = 0,
        .number_of_relocations = 0,
        .number_of_linenumbers = 0,
        .characteristics = section_flags.CNT_INITIALIZED_DATA | section_flags.MEM_READ | section_flags.MEM_WRITE,
    };
    try std.testing.expectEqual(SectionKind.data, data_sh.getNormalizedKind(".data"));
    const data_perm = data_sh.getPermissions();
    try std.testing.expect(data_perm.read and data_perm.write and !data_perm.execute);

    // 3. .rdata (Initialized, Read-Only)
    const rdata_sh = SectionHeader{
        .raw_name = [_]u8{ '.', 'r', 'd', 'a', 't', 'a', 0, 0 },
        .virtual_size = 0,
        .virtual_address = 0,
        .size_of_raw_data = 100,
        .pointer_to_raw_data = 0,
        .pointer_to_relocations = 0,
        .pointer_to_linenumbers = 0,
        .number_of_relocations = 0,
        .number_of_linenumbers = 0,
        .characteristics = section_flags.CNT_INITIALIZED_DATA | section_flags.MEM_READ,
    };
    try std.testing.expectEqual(SectionKind.rodata, rdata_sh.getNormalizedKind(".rdata"));

    // 4. .debug$S (Discardable Debug Data)
    const debug_sh = SectionHeader{
        .raw_name = [_]u8{ '.', 'd', 'e', 'b', 'u', 'g', '$', 'S' },
        .virtual_size = 0,
        .virtual_address = 0,
        .size_of_raw_data = 100,
        .pointer_to_raw_data = 0,
        .pointer_to_relocations = 0,
        .pointer_to_linenumbers = 0,
        .number_of_relocations = 0,
        .number_of_linenumbers = 0,
        .characteristics = section_flags.MEM_READ | section_flags.MEM_DISCARDABLE,
    };
    try std.testing.expectEqual(SectionKind.debug, debug_sh.getNormalizedKind(".debug$S"));

    // 5. Directives (.drectve) -> Discard
    const drectve_sh = SectionHeader{
        .raw_name = [_]u8{ '.', 'd', 'r', 'e', 'c', 't', 'v', 'e' },
        .virtual_size = 0,
        .virtual_address = 0,
        .size_of_raw_data = 50,
        .pointer_to_raw_data = 0,
        .pointer_to_relocations = 0,
        .pointer_to_linenumbers = 0,
        .number_of_relocations = 0,
        .number_of_linenumbers = 0,
        .characteristics = section_flags.LNK_INFO | section_flags.LNK_REMOVE,
    };
    try std.testing.expectEqual(SectionKind.discard, drectve_sh.getNormalizedKind(".drectve"));
}

test "COMDAT selection name mappings" {
    const sel_any: ComdatSelection = .any;
    try std.testing.expectEqualStrings("ANY", sel_any.name());

    const sel_exact: ComdatSelection = .exact_match;
    try std.testing.expectEqualStrings("EXACT_MATCH", sel_exact.name());

    const sel_largest: ComdatSelection = .largest;
    try std.testing.expectEqualStrings("LARGEST", sel_largest.name());
}
