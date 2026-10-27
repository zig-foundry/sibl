//! Phase 3.1 & 3.2: DOS, COFF Header, and Section Table Parser for sibl.
//!
//! Provides zero-copy parsing for Windows PE executables (.exe, .dll)
//! and raw COFF relocatable object files (.obj).

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
    pub const CNT_CODE: u32 = 0x00000020; // Section contains executable code
    pub const CNT_INITIALIZED_DATA: u32 = 0x00000040; // Section contains initialized data
    pub const CNT_UNINITIALIZED_DATA: u32 = 0x00000080; // Section contains uninitialized data (.bss)
    pub const LNK_INFO: u32 = 0x00000200; // Section contains comments or other info
    pub const LNK_REMOVE: u32 = 0x00000800; // Section will not become part of image
    pub const LNK_COMDAT: u32 = 0x00001000; // Section contains COMDAT data
    pub const GPREL: u32 = 0x00008000; // Section contains data referenced through GP
    pub const MEM_PURGEABLE: u32 = 0x00020000;
    pub const MEM_16BIT: u32 = 0x00020000;
    pub const MEM_LOCKED: u32 = 0x00040000;
    pub const MEM_PRELOAD: u32 = 0x00080000;
    pub const LNK_NRELOC_OVFL: u32 = 0x01000000; // Section contains extended relocations
    pub const MEM_DISCARDABLE: u32 = 0x02000000; // Section can be discarded as needed
    pub const MEM_NOT_CACHED: u32 = 0x04000000; // Section cannot be cached
    pub const MEM_NOT_PAGED: u32 = 0x08000000; // Section cannot be paged
    pub const MEM_SHARED: u32 = 0x10000000; // Section can be shared in memory
    pub const MEM_EXECUTE: u32 = 0x20000000; // Section can be executed as code
    pub const MEM_READ: u32 = 0x40000000; // Section can be read
    pub const MEM_WRITE: u32 = 0x80000000; // Section can be written to
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

// === Section Header Representation ===

/// Normalized representation for a 40-byte COFF / PE section header.
pub const SectionHeader = struct {
    /// Raw 8-byte name buffer from the header
    raw_name: [8]u8,
    /// Total size in memory when loaded (or 0 for object files)
    virtual_size: u32,
    /// Relative virtual address (RVA) in memory
    virtual_address: u32,
    /// Size of raw data on disk
    size_of_raw_data: u32,
    /// File pointer to raw data bytes
    pointer_to_raw_data: u32,
    /// File pointer to relocation entries
    pointer_to_relocations: u32,
    /// File pointer to line numbers (deprecated)
    pointer_to_linenumbers: u32,
    /// Number of relocation entries
    number_of_relocations: u16,
    /// Number of line numbers (deprecated)
    number_of_linenumbers: u16,
    /// Characteristics bitmask flags
    characteristics: u32,

    /// Returns true if section contains executable instructions.
    pub fn isExecutable(self: SectionHeader) bool {
        return (self.characteristics & section_flags.MEM_EXECUTE) != 0;
    }

    /// Returns true if section memory is readable at runtime.
    pub fn isReadable(self: SectionHeader) bool {
        return (self.characteristics & section_flags.MEM_READ) != 0;
    }

    /// Returns true if section memory is writable at runtime.
    pub fn isWritable(self: SectionHeader) bool {
        return (self.characteristics & section_flags.MEM_WRITE) != 0;
    }

    /// Returns true if section contains machine code.
    pub fn hasCode(self: SectionHeader) bool {
        return (self.characteristics & section_flags.CNT_CODE) != 0;
    }

    /// Returns true if section contains initialized variables.
    pub fn hasInitializedData(self: SectionHeader) bool {
        return (self.characteristics & section_flags.CNT_INITIALIZED_DATA) != 0;
    }

    /// Returns true if section contains uninitialized data (.bss).
    pub fn hasUninitializedData(self: SectionHeader) bool {
        return (self.characteristics & section_flags.CNT_UNINITIALIZED_DATA) != 0;
    }

    /// Returns true if this section is a COMDAT section.
    pub fn isComdat(self: SectionHeader) bool {
        return (self.characteristics & section_flags.LNK_COMDAT) != 0;
    }

    /// Compute byte alignment required for this section (1 to 8192 bytes).
    pub fn getAlignment(self: SectionHeader) u32 {
        const align_val = (self.characteristics >> 20) & 0x0F;
        if (align_val == 0) return 16; // Default to 16 bytes if unspecified
        if (align_val > 14) return 8192;
        return @as(u32, 1) << @intCast(align_val - 1);
    }

    /// Extract section name string, resolving long names from the COFF string table if needed.
    pub fn getName(self: SectionHeader, strtab_bytes: []const u8) SectionError![]const u8 {
        // If name begins with '/', it references an offset in the string table (e.g. "/4")
        if (self.raw_name[0] == '/') {
            // Find null terminator or end of 8-byte field
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

        // Inline short name (up to 8 characters)
        const len = std.mem.indexOfScalar(u8, &self.raw_name, 0) orelse self.raw_name.len;
        return self.raw_name[0..len];
    }

    /// Retrieve raw section bytes from the file buffer.
    pub fn getData(self: SectionHeader, file_bytes: []const u8) SectionError![]const u8 {
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

    /// Parse a single section header entry by index (each is 40 bytes).
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

    /// Parse all section headers into an allocated slice.
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

    /// Retrieve raw slice of the COFF string table.
    /// In COFF, the string table begins immediately after the symbol table:
    /// string_table_offset = symbol_table_offset + (symbol_count * 18).
    pub fn getStringTable(self: Header, file_bytes: []const u8) []const u8 {
        if (self.symbol_table_offset == 0 or self.symbol_count == 0) {
            return &.{};
        }

        const sym_table_bytes = @as(usize, self.symbol_count) * 18;
        const strtab_offset: usize = self.symbol_table_offset + sym_table_bytes;

        // The first 4 bytes of the string table is a u32 storing its total size
        if (strtab_offset + 4 > file_bytes.len) {
            return &.{};
        }

        const strtab_size = std.mem.readInt(u32, file_bytes[strtab_offset..][0..4], .little);
        if (strtab_size < 4 or strtab_offset + strtab_size > file_bytes.len) {
            return &.{};
        }

        return file_bytes[strtab_offset .. strtab_offset + strtab_size];
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
    std.mem.writeInt(u32, sh_buf[8..12], 0x120, .little); // VirtualSize
    std.mem.writeInt(u32, sh_buf[12..16], 0x1000, .little); // VirtualAddress
    std.mem.writeInt(u32, sh_buf[16..20], 0x200, .little); // SizeOfRawData
    std.mem.writeInt(u32, sh_buf[20..24], 0x400, .little); // PointerToRawData
    std.mem.writeInt(u32, sh_buf[24..28], 0x600, .little); // PointerToRelocations
    std.mem.writeInt(u16, sh_buf[32..34], 3, .little); // NumberOfRelocations
    // Flags: CNT_CODE | MEM_EXECUTE | MEM_READ | ALIGN_16BYTES (0x00500000)
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
    var sh_buf: [40]u8 = undefined;
    @memset(&sh_buf, 0);

    // Write slash followed by offset 4: "/4"
    @memcpy(sh_buf[0..2], "/4");
    std.mem.writeInt(u32, sh_buf[36..40], section_flags.CNT_INITIALIZED_DATA | section_flags.MEM_READ, .little);

    const sh = SectionHeader{
        .raw_name = sh_buf[0..8].*,
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

    // Mock string table: first 4 bytes are table size (e.g. 24 bytes), followed by strings
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
