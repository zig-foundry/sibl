//! Phase 3.1: DOS and COFF Header Parser for sibl.
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

/// COFF characteristics bitmask (IMAGE_FILE_*).
pub const characteristics = struct {
    pub const RELOCS_STRIPPED: u16 = 0x0001; // Relocation information was stripped
    pub const EXECUTABLE_IMAGE: u16 = 0x0002; // File is executable
    pub const LINE_NUMS_STRIPPED: u16 = 0x0004; // Line numbers stripped
    pub const LOCAL_SYMS_STRIPPED: u16 = 0x0008; // Local symbols stripped
    pub const LARGE_ADDRESS_AWARE: u16 = 0x0020; // Can handle addresses > 2 GB
    pub const BIT32_MACHINE: u16 = 0x0100; // 32-bit word architecture
    pub const DEBUG_STRIPPED: u16 = 0x0200; // Debugging info stripped
    pub const REMOVABLE_RUN_FROM_SWAP: u16 = 0x0400;
    pub const NET_RUN_FROM_SWAP: u16 = 0x0800;
    pub const SYSTEM: u16 = 0x1000; // System file (driver)
    pub const DLL: u16 = 0x2000; // Dynamic link library
    pub const UP_SYSTEM_ONLY: u16 = 0x4000; // Uniprocessor machine only
};

/// Windows Subsystem types.
pub const Subsystem = enum(u16) {
    unknown = 0,
    native = 1, // Device drivers and native system processes
    windows_gui = 2, // Windows GUI subsystem
    windows_cui = 3, // Windows Console subsystem
    posix_cui = 7, // POSIX console
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

/// Errors encountered while reading COFF and PE headers.
pub const Error = error{
    TruncatedHeader,
    NotCoffOrPe,
    InvalidDosMagic,
    InvalidPeSignature,
    InvalidOptionalHeaderMagic,
    TruncatedOptionalHeader,
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

        // Check if the file starts with DOS magic ("MZ")
        if (std.mem.eql(u8, bytes[0..2], &DOS_MAGIC)) {
            return parsePeImage(bytes);
        }

        // Check if it starts directly as a raw COFF relocatable object file (.obj)
        const raw_machine = std.mem.readInt(u16, bytes[0..2], .little);
        if (Machine.isKnown(raw_machine)) {
            return parseCoffObject(bytes);
        }

        return error.NotCoffOrPe;
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

    // DOS Header
    @memcpy(pe_buf[0..2], &DOS_MAGIC);
    std.mem.writeInt(u32, pe_buf[0x3C..0x40], 64, .little);

    // PE Signature
    @memcpy(pe_buf[64..68], &PE_SIGNATURE);

    // COFF File Header
    std.mem.writeInt(u16, pe_buf[68..70], 0x8664, .little);
    std.mem.writeInt(u16, pe_buf[70..72], 5, .little);
    std.mem.writeInt(u32, pe_buf[72..76], 123456, .little);
    std.mem.writeInt(u32, pe_buf[76..80], 0, .little);
    std.mem.writeInt(u32, pe_buf[80..84], 0, .little);
    std.mem.writeInt(u16, pe_buf[84..86], 240, .little);
    std.mem.writeInt(u16, pe_buf[86..88], characteristics.EXECUTABLE_IMAGE | characteristics.LARGE_ADDRESS_AWARE, .little);

    // Optional Header PE32+
    std.mem.writeInt(u16, pe_buf[88..90], OptionalHeaderMagic.PE32_PLUS, .little);
    pe_buf[90] = 14;
    pe_buf[91] = 0;
    std.mem.writeInt(u32, pe_buf[92..96], 0x1000, .little);
    std.mem.writeInt(u32, pe_buf[104..108], 0x1200, .little);
    std.mem.writeInt(u64, pe_buf[112..120], 0x140000000, .little);
    std.mem.writeInt(u32, pe_buf[120..124], 4096, .little);
    std.mem.writeInt(u32, pe_buf[124..128], 512, .little);
    std.mem.writeInt(u16, pe_buf[156..158], 3, .little); // windows_cui
    std.mem.writeInt(u32, pe_buf[196..200], 16, .little);

    // Data Directory #1 (Import Table)
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

    std.mem.writeInt(u16, pe_buf[68..70], 0x014C, .little); // i386
    std.mem.writeInt(u16, pe_buf[70..72], 3, .little);
    std.mem.writeInt(u16, pe_buf[84..86], 224, .little);
    std.mem.writeInt(u16, pe_buf[86..88], characteristics.DLL | characteristics.EXECUTABLE_IMAGE, .little);

    std.mem.writeInt(u16, pe_buf[88..90], OptionalHeaderMagic.PE32, .little);
    std.mem.writeInt(u32, pe_buf[104..108], 0x1000, .little);
    std.mem.writeInt(u32, pe_buf[116..120], 0x10000000, .little);
    std.mem.writeInt(u16, pe_buf[156..158], 2, .little); // windows_gui

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
