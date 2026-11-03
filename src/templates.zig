//! Phase 9.4: Default Layout Templates.
//!
//! Provides built-in standard layouts for Linux (ELF), Windows (PE/COFF),
//! macOS (Mach-O), and bare-metal targets. Each template supplies:
//! - preferred base virtual address
//! - page size
//! - default entry symbol
//! - default output filename
//! - a preferred output section order
//! - standard boundary symbols (`etext`, `_end`, `__bss_start`, ...) that
//!   are provided after address assignment, only if the name is not already
//!   defined
//!
//! Templates do not replace custom `--place` / `--pin` / `--region` rules
//! (Phase 9.2). They supply the defaults used when the user does not pin
//! the image themselves.

const std = @import("std");
const target = @import("target.zig");
const layout = @import("layout.zig");
const symbol = @import("symbol.zig");

/// Built-in layout template kinds.
pub const Kind = enum {
    /// Non-PIE ELF executable (Linux, FreeBSD, ...). Base `0x400000`.
    linux_elf,
    /// PE/COFF executable (Windows). 64-bit base `0x140000000`, 32-bit `0x400000`.
    windows_pe,
    /// Mach-O executable (macOS). Base `0x100000000`.
    macos_macho,
    /// Bare-metal / embedded. Base `0`, page size from the target.
    bare_metal,

    /// Short human-readable name.
    pub fn name(self: Kind) []const u8 {
        return switch (self) {
            .linux_elf => "linux-elf",
            .windows_pe => "windows-pe",
            .macos_macho => "macos-macho",
            .bare_metal => "bare-metal",
        };
    }
};

/// A complete default layout description.
pub const Template = struct {
    kind: Kind,
    /// Preferred base virtual address for the first loadable section.
    base_address: u64,
    /// Page size used for protection-boundary alignment.
    page_size: u64,
    /// Default entry symbol when the user did not pass `-e`.
    default_entry: []const u8,
    /// Default output filename when the user did not pass `-o`.
    default_output: []const u8,
    /// Preferred canonical output section order. Informational for now;
    /// actual order is still determined by first-seen input sections and
    /// placement rules.
    preferred_sections: []const []const u8,
};

/// Preferred section lists used by the built-in templates.
pub const linux_sections = [_][]const u8{ ".text", ".rodata", ".data", ".bss" };
pub const windows_sections = [_][]const u8{ ".text", ".rdata", ".data", ".bss" };
pub const macos_sections = [_][]const u8{ ".text", ".const", ".data", ".bss" };
pub const bare_sections = [_][]const u8{ ".text", ".rodata", ".data", ".bss" };

/// Build the template that matches a resolved target.
///
/// Bare-metal is selected when the caller passes `bare_metal = true`
/// (for example after seeing a `--region` rule). Otherwise the template
/// follows the binary format and pointer width.
pub fn forTarget(info: target.TargetInfo, bare_metal: bool) Template {
    if (bare_metal) {
        return .{
            .kind = .bare_metal,
            .base_address = 0,
            .page_size = info.page_size,
            .default_entry = "_start",
            .default_output = "a.out",
            .preferred_sections = &bare_sections,
        };
    }

    return switch (info.format) {
        .elf => .{
            .kind = .linux_elf,
            .base_address = 0x400000,
            .page_size = info.page_size,
            .default_entry = info.default_entry,
            .default_output = info.default_output,
            .preferred_sections = &linux_sections,
        },
        .coff => .{
            .kind = .windows_pe,
            .base_address = if (info.arch.pointerWidth() == 64) 0x140000000 else 0x400000,
            .page_size = info.page_size,
            .default_entry = info.default_entry,
            .default_output = info.default_output,
            .preferred_sections = &windows_sections,
        },
        .macho => .{
            .kind = .macos_macho,
            .base_address = 0x100000000,
            .page_size = info.page_size,
            .default_entry = info.default_entry,
            .default_output = info.default_output,
            .preferred_sections = &macos_sections,
        },
    };
}

/// Apply the template's base address and page size to a layout.
///
/// Call this before `Layout.computeAddresses`. Existing pins from Phase 9.2
/// still take precedence for the sections they name.
pub fn applyBase(l: *layout.Layout, tmpl: Template) void {
    l.base_address = tmpl.base_address;
    l.page_size = if (tmpl.page_size == 0) 4096 else tmpl.page_size;
}

/// Virtual address of the first byte of a named output section, or null
/// if the section is absent or not allocated.
pub fn sectionStart(l: *const layout.Layout, name: []const u8) ?u64 {
    const sec = l.get(name) orelse return null;
    if (!sec.is_alloc) return null;
    return sec.virtual_address;
}

/// Virtual address one past the last byte of a named output section, or
/// null if the section is absent or not allocated.
pub fn sectionEnd(l: *const layout.Layout, name: []const u8) ?u64 {
    const sec = l.get(name) orelse return null;
    if (!sec.is_alloc) return null;
    return sec.virtual_address + sec.size;
}

/// Highest allocated virtual address in the layout (end of the last
/// ALLOC section), or the base address if nothing is allocated.
pub fn imageEnd(l: *const layout.Layout) u64 {
    var end = l.base_address;
    for (l.sections.items) |sec| {
        if (sec.is_alloc) {
            const sec_end = sec.virtual_address + sec.size;
            if (sec_end > end) end = sec_end;
        }
    }
    return end;
}

/// Insert a strong absolute symbol only if the name is not already defined.
///
/// Existing definitions (from input objects or earlier `--defsym`) win.
/// Undefined references are replaced by the provided absolute value.
fn provideIfAbsent(table: *symbol.SymbolTable, name: []const u8, value: u64) !void {
    if (table.get(name)) |existing| {
        if (existing.isDefined()) return;
    }
    try table.add(.{
        .name = name,
        .binding = .global,
        .kind = .absolute,
        .value = value,
        .visibility = .default,
    });
}

/// After `computeAddresses`, define the standard boundary symbols for the
/// template if they are not already defined.
///
/// Symbols provided (when the corresponding section exists):
/// - `__executable_start` — image base
/// - `etext`, `_etext` — end of `.text`
/// - `edata`, `_edata` — end of `.data` (falls back to end of `.rodata` or `.text`)
/// - `__bss_start` — start of `.bss`
/// - `end`, `_end` — end of the image (highest allocated address)
///
/// These are absolute symbols so Phase 9.1 entry resolution and later
/// relocation can use them without a holding section.
pub fn provideBoundarySymbols(
    table: *symbol.SymbolTable,
    l: *const layout.Layout,
    tmpl: Template,
) Error!void {
    _ = tmpl;

    try provideIfAbsent(table, "__executable_start", l.base_address);

    if (sectionEnd(l, ".text")) |addr| {
        try provideIfAbsent(table, "etext", addr);
        try provideIfAbsent(table, "_etext", addr);
    }

    const edata_addr = sectionEnd(l, ".data") orelse
        sectionEnd(l, ".rdata") orelse
        sectionEnd(l, ".rodata") orelse
        sectionEnd(l, ".text");
    if (edata_addr) |addr| {
        try provideIfAbsent(table, "edata", addr);
        try provideIfAbsent(table, "_edata", addr);
    }

    if (sectionStart(l, ".bss")) |addr| {
        try provideIfAbsent(table, "__bss_start", addr);
    }

    const end_addr = imageEnd(l);
    try provideIfAbsent(table, "end", end_addr);
    try provideIfAbsent(table, "_end", end_addr);
}

/// Errors from template helpers. Compatible with `SymbolTable.add`.
pub const Error = error{
    OutOfMemory,
    EmptyName,
    DuplicateStrongDefinition,
    UnresolvedSymbols,
};

// === Unit Tests ===

test "forTarget selects linux ELF defaults" {
    const info = target.TargetInfo{
        .arch = .x86_64,
        .format = .elf,
        .endian = .little,
        .page_size = 4096,
        .default_entry = "_start",
        .default_output = "a.out",
    };
    const tmpl = forTarget(info, false);
    try std.testing.expect(tmpl.kind == .linux_elf);
    try std.testing.expectEqual(@as(u64, 0x400000), tmpl.base_address);
    try std.testing.expectEqual(@as(u64, 4096), tmpl.page_size);
    try std.testing.expectEqualStrings("_start", tmpl.default_entry);
    try std.testing.expectEqualStrings("a.out", tmpl.default_output);
    try std.testing.expectEqual(@as(usize, 4), tmpl.preferred_sections.len);
    try std.testing.expectEqualStrings(".text", tmpl.preferred_sections[0]);
}

test "forTarget selects 64-bit Windows PE base" {
    const info = target.TargetInfo{
        .arch = .x86_64,
        .format = .coff,
        .endian = .little,
        .page_size = 4096,
        .default_entry = "mainCRTStartup",
        .default_output = "a.exe",
    };
    const tmpl = forTarget(info, false);
    try std.testing.expect(tmpl.kind == .windows_pe);
    try std.testing.expectEqual(@as(u64, 0x140000000), tmpl.base_address);
    try std.testing.expectEqualStrings("mainCRTStartup", tmpl.default_entry);
    try std.testing.expectEqualStrings("a.exe", tmpl.default_output);
}

test "forTarget selects 32-bit Windows PE base" {
    const info = target.TargetInfo{
        .arch = .x86,
        .format = .coff,
        .endian = .little,
        .page_size = 4096,
        .default_entry = "mainCRTStartup",
        .default_output = "a.exe",
    };
    const tmpl = forTarget(info, false);
    try std.testing.expectEqual(@as(u64, 0x400000), tmpl.base_address);
}

test "forTarget selects macOS Mach-O base" {
    const info = target.TargetInfo{
        .arch = .aarch64,
        .format = .macho,
        .endian = .little,
        .page_size = 16384,
        .default_entry = "_main",
        .default_output = "a.out",
    };
    const tmpl = forTarget(info, false);
    try std.testing.expect(tmpl.kind == .macos_macho);
    try std.testing.expectEqual(@as(u64, 0x100000000), tmpl.base_address);
    try std.testing.expectEqual(@as(u64, 16384), tmpl.page_size);
    try std.testing.expectEqualStrings("_main", tmpl.default_entry);
}

test "forTarget selects bare-metal when requested" {
    const info = target.TargetInfo{
        .arch = .x86_64,
        .format = .elf,
        .endian = .little,
        .page_size = 4096,
        .default_entry = "_start",
        .default_output = "a.out",
    };
    const tmpl = forTarget(info, true);
    try std.testing.expect(tmpl.kind == .bare_metal);
    try std.testing.expectEqual(@as(u64, 0), tmpl.base_address);
    try std.testing.expectEqualStrings("_start", tmpl.default_entry);
}

test "applyBase writes base and page size" {
    var l = layout.Layout.init(std.testing.allocator, 0, 1);
    defer l.deinit();

    const tmpl = Template{
        .kind = .linux_elf,
        .base_address = 0x400000,
        .page_size = 4096,
        .default_entry = "_start",
        .default_output = "a.out",
        .preferred_sections = &linux_sections,
    };
    applyBase(&l, tmpl);
    try std.testing.expectEqual(@as(u64, 0x400000), l.base_address);
    try std.testing.expectEqual(@as(u64, 4096), l.page_size);
}

test "provideBoundarySymbols defines etext edata end from layout" {
    var l = layout.Layout.init(std.testing.allocator, 0x400000, 4096);
    defer l.deinit();

    try l.addInput(.{
        .name = ".text",
        .data = "0123456789abcdef",
        .alignment = 16,
        .is_alloc = true,
        .is_writable = false,
        .is_executable = true,
        .is_nobits = false,
        .file_index = 0,
        .section_index = 1,
    });
    try l.addInput(.{
        .name = ".data",
        .data = "01234567",
        .alignment = 8,
        .is_alloc = true,
        .is_writable = true,
        .is_executable = false,
        .is_nobits = false,
        .file_index = 0,
        .section_index = 2,
    });
    try l.addInput(.{
        .name = ".bss",
        .data = &[_]u8{},
        .alignment = 8,
        .is_alloc = true,
        .is_writable = true,
        .is_executable = false,
        .is_nobits = true,
        .file_index = 0,
        .section_index = 3,
    });
    // Force a non-zero size for the NOBITS section by giving it data length
    // of 0; size accounting uses member data length. Set a synthetic size
    // by adding a second empty-looking member is unnecessary: size is
    // computed from data.len. Use a zero-length data slice and accept
    // size 0, then verify the symbols still land at the section VAs.

    l.computeAddresses();

    var table = symbol.SymbolTable.init(std.testing.allocator);
    defer table.deinit();

    const info = target.TargetInfo{
        .arch = .x86_64,
        .format = .elf,
        .endian = .little,
        .page_size = 4096,
        .default_entry = "_start",
        .default_output = "a.out",
    };
    const tmpl = forTarget(info, false);
    try provideBoundarySymbols(&table, &l, tmpl);

    try std.testing.expectEqual(@as(u64, 0x400000), table.get("__executable_start").?.value);

    const text_end = sectionEnd(&l, ".text").?;
    try std.testing.expectEqual(text_end, table.get("etext").?.value);
    try std.testing.expectEqual(text_end, table.get("_etext").?.value);
    try std.testing.expect(table.get("etext").?.kind == .absolute);

    const data_end = sectionEnd(&l, ".data").?;
    try std.testing.expectEqual(data_end, table.get("edata").?.value);
    try std.testing.expectEqual(data_end, table.get("_edata").?.value);

    const bss_start = sectionStart(&l, ".bss").?;
    try std.testing.expectEqual(bss_start, table.get("__bss_start").?.value);

    const end_addr = imageEnd(&l);
    try std.testing.expectEqual(end_addr, table.get("end").?.value);
    try std.testing.expectEqual(end_addr, table.get("_end").?.value);
}

test "provideBoundarySymbols does not override existing definitions" {
    var l = layout.Layout.init(std.testing.allocator, 0x400000, 4096);
    defer l.deinit();

    try l.addInput(.{
        .name = ".text",
        .data = "0123456789abcdef0123456789abcdef",
        .alignment = 1,
        .is_alloc = true,
        .is_writable = false,
        .is_executable = true,
        .is_nobits = false,
        .file_index = 0,
        .section_index = 1,
    });
    l.computeAddresses();

    var table = symbol.SymbolTable.init(std.testing.allocator);
    defer table.deinit();

    try table.add(.{
        .name = "etext",
        .binding = .global,
        .kind = .absolute,
        .value = 0xDEAD,
    });

    const info = target.TargetInfo{
        .arch = .x86_64,
        .format = .elf,
        .endian = .little,
        .page_size = 4096,
        .default_entry = "_start",
        .default_output = "a.out",
    };
    try provideBoundarySymbols(&table, &l, forTarget(info, false));

    try std.testing.expectEqual(@as(u64, 0xDEAD), table.get("etext").?.value);
    // _etext was not predefined, so it receives the real section end.
    try std.testing.expectEqual(sectionEnd(&l, ".text").?, table.get("_etext").?.value);
}

test "provideBoundarySymbols replaces an undefined reference" {
    var l = layout.Layout.init(std.testing.allocator, 0x400000, 4096);
    defer l.deinit();
    l.computeAddresses();

    var table = symbol.SymbolTable.init(std.testing.allocator);
    defer table.deinit();

    try table.add(.{
        .name = "end",
        .binding = .global,
        .kind = .undefined,
    });

    const info = target.TargetInfo{
        .arch = .x86_64,
        .format = .elf,
        .endian = .little,
        .page_size = 4096,
        .default_entry = "_start",
        .default_output = "a.out",
    };
    try provideBoundarySymbols(&table, &l, forTarget(info, false));

    const end_sym = table.get("end").?;
    try std.testing.expect(end_sym.isDefined());
    try std.testing.expect(end_sym.kind == .absolute);
    try std.testing.expectEqual(imageEnd(&l), end_sym.value);
}

test "sectionStart and sectionEnd return null for missing sections" {
    var l = layout.Layout.init(std.testing.allocator, 0x400000, 4096);
    defer l.deinit();
    try std.testing.expectEqual(@as(?u64, null), sectionStart(&l, ".text"));
    try std.testing.expectEqual(@as(?u64, null), sectionEnd(&l, ".text"));
    try std.testing.expectEqual(@as(u64, 0x400000), imageEnd(&l));
}
