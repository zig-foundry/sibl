//! Phase 9.1: Entry Point Setup.
//!
//! Finds the program entry symbol (like `_start` or `mainCRTStartup`) and
//! computes its final virtual address from the Phase 6 symbol table and the
//! Phase 7 layout. Rules:
//! - The entry name must resolve to a defined symbol (`_start` by default,
//!   overridable with `-e` / `--entry`)
//! - Absolute symbols resolve to their stored value directly
//! - Section-relative symbols resolve to
//!   `output.virtual_address + member_offset + symbol.value`
//!   where member_offset replays the exact merge order of `computeAddresses`

const std = @import("std");
const symbol = @import("symbol.zig");
const layout = @import("layout.zig");

/// Errors that can occur while resolving the entry point.
pub const Error = error{
    OutOfMemory,
    /// The entry name does not exist in the symbol table.
    EntrySymbolNotFound,
    /// The entry name exists but is still undefined.
    EntrySymbolUndefined,
    /// The symbol is defined but its section never made it into the layout
    /// (for example a non-alloc section like `.comment` or a debug section).
    EntryNotInSection,
};

/// Entry symbol candidates tried when no explicit `-e` / `--entry` was given.
/// Order follows the common targets: ELF, PE, Mach-O, then a last-resort `main`.
pub const default_candidates = [_][]const u8{ "_start", "mainCRTStartup", "_main", "main" };

/// A resolved program entry point.
pub const Entry = struct {
    /// Symbol name (owned by the symbol table).
    name: []const u8,
    /// Final virtual address of the entry.
    address: u64,
    /// Input file that defined the entry symbol.
    file_index: u32,
    /// Section index inside the defining object.
    section_index: u32,
    /// Canonical name of the output section holding the entry.
    /// Empty for absolute symbols (they need no holding section).
    section_name: []const u8,
    /// True when the holding output section is executable.
    /// Always false for absolute symbols.
    is_executable: bool,
};

/// Look up `name` in the table and return the symbol if it is defined.
pub fn findSymbol(table: *const symbol.SymbolTable, name: []const u8) Error!symbol.Symbol {
    const sym = table.get(name) orelse return error.EntrySymbolNotFound;
    if (sym.isUndefined()) return error.EntrySymbolUndefined;
    return sym;
}

/// Compute the final virtual address of a defined symbol.
///
/// Absolute symbols resolve to their stored value directly. All other
/// symbols are section-relative: the function replays the merge order of
/// the output section holding them and adds the symbol's value.
pub fn symbolAddress(sym: symbol.Symbol, l: *const layout.Layout) Error!u64 {
    if (sym.kind == .absolute) return sym.value;
    const ep = try locate(sym, l);
    return ep.address;
}

/// Resolve `entry_name` to a final entry point address.
///
/// Errors:
/// - `error.EntrySymbolNotFound` when no symbol with that name exists
/// - `error.EntrySymbolUndefined` when the symbol is still undefined
/// - `error.EntryNotInSection` when the symbol is defined outside the
///   loadable layout (its section was never added with `Layout.addInput`)
pub fn resolve(table: *const symbol.SymbolTable, l: *const layout.Layout, entry_name: []const u8) Error!Entry {
    const sym = try findSymbol(table, entry_name);

    if (sym.kind == .absolute) {
        return .{
            .name = sym.name,
            .address = sym.value,
            .file_index = sym.file_index,
            .section_index = sym.section_index,
            .section_name = "",
            .is_executable = false,
        };
    }

    for (l.sections.items) |*out| {
        if (memberOffsetOf(sym, out)) |off| {
            return .{
                .name = sym.name,
                .address = out.virtual_address + off + sym.value,
                .file_index = sym.file_index,
                .section_index = sym.section_index,
                .section_name = out.name,
                .is_executable = out.is_executable,
            };
        }
    }

    return error.EntryNotInSection;
}

/// Resolve the first symbol from `candidates` that is defined.
/// Useful when the caller has a list of per-target default names.
/// If every candidate fails, the last candidate's error is returned
/// (or `error.EntrySymbolNotFound` for an empty list).
pub fn resolveCandidates(
    table: *const symbol.SymbolTable,
    l: *const layout.Layout,
    candidates: []const []const u8,
) Error!Entry {
    var first_err: Error = error.EntrySymbolNotFound;
    for (candidates) |name| {
        if (resolve(table, l, name)) |ep| {
            return ep;
        } else |err| {
            first_err = err;
        }
    }
    return first_err;
}

/// Replay the merge order of `out` (mirroring `Layout.computeAddresses`) and
/// return the byte offset of the member that `sym` was defined in. Members are
/// matched by input file index and original section index. Returns null when
/// `sym` was defined in a section that is not part of `out`.
fn memberOffsetOf(sym: symbol.Symbol, out: *const layout.OutputSection) ?u64 {
    var cursor: u64 = 0;
    for (out.members.items) |mem| {
        const aligned = layout.alignTo(cursor, @max(mem.alignment, 1));
        if (mem.file_index == sym.file_index and mem.section_index == sym.section_index) {
            return aligned;
        }
        cursor = aligned + mem.data.len;
    }
    return null;
}

/// Walk the layout once on behalf of `symbolAddress`.
fn locate(sym: symbol.Symbol, l: *const layout.Layout) Error!Entry {
    for (l.sections.items) |*out| {
        if (memberOffsetOf(sym, out)) |off| {
            return .{
                .name = sym.name,
                .address = out.virtual_address + off + sym.value,
                .file_index = sym.file_index,
                .section_index = sym.section_index,
                .section_name = out.name,
                .is_executable = out.is_executable,
            };
        }
    }
    return error.EntryNotInSection;
}

// === Unit Tests ===

const testing = std.testing;

test "resolve computes the final address from member replay and symbol value" {
    var table = symbol.SymbolTable.init(testing.allocator);
    defer table.deinit();
    try table.add(.{
        .name = "_start",
        .binding = .global,
        .kind = .defined,
        .value = 2,
        .file_index = 0,
        .section_index = 1,
    });

    var l = layout.Layout.init(testing.allocator, 0x400000, 4096);
    defer l.deinit();
    try l.addInput(.{
        .name = ".text",
        .data = "12345678",
        .alignment = 4,
        .is_alloc = true,
        .is_executable = true,
        .file_index = 0,
        .section_index = 0,
        .is_writable = false,
        .is_nobits = false,
    });
    try l.addInput(.{
        .name = ".text",
        .data = "1234",
        .alignment = 1,
        .is_alloc = true,
        .is_executable = true,
        .file_index = 0,
        .section_index = 1,
        .is_writable = false,
        .is_nobits = false,
    });
    l.computeAddresses();

    const ep = try resolve(&table, &l, "_start");

    // Member 0: 8 bytes at align 4. Member 1 starts at offset 8, symbol at +2.
    try testing.expectEqual(@as(u64, 0x400000 + 8 + 2), ep.address);
    try testing.expectEqualStrings(".text", ep.section_name);
    try testing.expect(ep.is_executable);
    try testing.expectEqual(@as(u32, 0), ep.file_index);
    try testing.expectEqual(@as(u32, 1), ep.section_index);
}

test "resolve uses the correct output section after a protection change" {
    var table = symbol.SymbolTable.init(testing.allocator);
    defer table.deinit();
    try table.add(.{ .name = "data_start", .binding = .global, .kind = .defined, .value = 1, .file_index = 0, .section_index = 1 });

    var l = layout.Layout.init(testing.allocator, 0x400000, 4096);
    defer l.deinit();
    try l.addInput(.{
        .name = ".text",
        .data = "abcd",
        .alignment = 1,
        .is_alloc = true,
        .is_executable = true,
        .file_index = 0,
        .section_index = 0,
        .is_writable = false,
        .is_nobits = false,
    });
    try l.addInput(.{
        .name = ".data",
        .data = "1234",
        .alignment = 1,
        .is_alloc = true,
        .is_writable = true,
        .file_index = 0,
        .section_index = 1,
        .is_executable = false,
        .is_nobits = false,
    });
    l.computeAddresses();

    const ep = try resolve(&table, &l, "data_start");
    const data_va = l.get(".data").?.virtual_address;
    try testing.expectEqual(data_va + 1, ep.address);
    try testing.expectEqualStrings(".data", ep.section_name);
    // The protection change page-aligns .data, so it moves past .text.
    try testing.expect(data_va > 0x400000);
}

test "member offsets replay computeAddresses exactly" {
    var l = layout.Layout.init(testing.allocator, 0x400000, 4096);
    defer l.deinit();
    try l.addInput(.{
        .name = ".text",
        .data = "abc",
        .alignment = 8,
        .is_alloc = true,
        .is_executable = true,
        .file_index = 0,
        .section_index = 0,
        .is_writable = false,
        .is_nobits = false,
    });
    try l.addInput(.{
        .name = ".text",
        .data = "defgh",
        .alignment = 1,
        .is_alloc = true,
        .is_executable = true,
        .file_index = 0,
        .section_index = 1,
        .is_writable = false,
        .is_nobits = false,
    });
    try l.addInput(.{
        .name = ".text",
        .data = "ij",
        .alignment = 16,
        .is_alloc = true,
        .is_executable = true,
        .file_index = 0,
        .section_index = 2,
        .is_writable = false,
        .is_nobits = false,
    });
    l.computeAddresses();

    const out = l.get(".text").?;
    // 0 + "abc"(3) -> cursor 3; member 1 at 3, +(5) -> 8; member 2 aligned to
    // 16, +(2) -> 18.
    try testing.expectEqual(@as(u64, 18), out.size);

    // Symbol inside member 2 sits at the aligned offset 16.
    try testing.expectEqual(@as(u64, 16), memberOffsetOf(
        .{ .name = "x", .binding = .global, .kind = .defined, .file_index = 0, .section_index = 2 },
        out,
    ).?);
    // Symbol inside member 1 sits at 3.
    try testing.expectEqual(@as(u64, 3), memberOffsetOf(
        .{ .name = "x", .binding = .global, .kind = .defined, .file_index = 0, .section_index = 1 },
        out,
    ).?);
}

test "resolve works for symbols inside a NOBITS (.bss) member" {
    var table = symbol.SymbolTable.init(testing.allocator);
    defer table.deinit();
    try table.add(.{ .name = "_start", .binding = .global, .kind = .defined, .value = 12, .file_index = 0, .section_index = 1 });

    var l = layout.Layout.init(testing.allocator, 0x400000, 4096);
    defer l.deinit();
    try l.addInput(.{
        .name = ".text",
        .data = "T",
        .alignment = 1,
        .is_alloc = true,
        .is_executable = true,
        .file_index = 0,
        .section_index = 0,
        .is_writable = false,
        .is_nobits = false,
    });
    try l.addInput(.{
        .name = ".bss",
        .data = "",
        .alignment = 8,
        .is_alloc = true,
        .is_writable = true,
        .is_nobits = true,
        .file_index = 0,
        .section_index = 1,
        .is_executable = false,
    });
    l.computeAddresses();

    const ep = try resolve(&table, &l, "_start");
    const bss_va = l.get(".bss").?.virtual_address;
    try testing.expectEqual(bss_va + 12, ep.address);
    try testing.expectEqualStrings(".bss", ep.section_name);
    try testing.expect(!ep.is_executable);
}

test "absolute symbol resolves to its stored value" {
    var table = symbol.SymbolTable.init(testing.allocator);
    defer table.deinit();
    try table.add(.{ .name = "entry", .binding = .global, .kind = .absolute, .value = 0x12345678, .file_index = 0, .section_index = 0xfff1 });

    var l = layout.Layout.init(testing.allocator, 0x400000, 4096);
    defer l.deinit();

    // No members at all: absolute symbols never need the layout.
    const ep = try resolve(&table, &l, "entry");
    try testing.expectEqual(@as(u64, 0x12345678), ep.address);
    try testing.expectEqualStrings("", ep.section_name);
    try testing.expect(!ep.is_executable);
}

test "missing entry symbol returns EntrySymbolNotFound" {
    var table = symbol.SymbolTable.init(testing.allocator);
    defer table.deinit();
    var l = layout.Layout.init(testing.allocator, 0x400000, 4096);
    defer l.deinit();

    try testing.expectError(error.EntrySymbolNotFound, resolve(&table, &l, "_start"));
}

test "undefined entry symbol returns EntrySymbolUndefined" {
    var table = symbol.SymbolTable.init(testing.allocator);
    defer table.deinit();
    try table.add(.{ .name = "_start", .binding = .global, .kind = .undefined });

    var l = layout.Layout.init(testing.allocator, 0x400000, 4096);
    defer l.deinit();

    try testing.expectError(error.EntrySymbolUndefined, resolve(&table, &l, "_start"));
}

test "symbol in a section absent from the layout returns EntryNotInSection" {
    var table = symbol.SymbolTable.init(testing.allocator);
    defer table.deinit();
    try table.add(.{ .name = "_start", .binding = .global, .kind = .defined, .value = 0, .file_index = 0, .section_index = 7 });

    var l = layout.Layout.init(testing.allocator, 0x400000, 4096);
    defer l.deinit();
    try l.addInput(.{
        .name = ".text",
        .data = "abc",
        .alignment = 1,
        .is_alloc = true,
        .is_executable = true,
        .file_index = 0,
        .section_index = 0,
        .is_writable = false,
        .is_nobits = false,
    });
    l.computeAddresses();

    // The entry definition lives in section 7, which was never added.
    try testing.expectError(error.EntryNotInSection, resolve(&table, &l, "_start"));

    // Same story when the section exists but belongs to another input file.
    _ = table.remove("_start");
    try table.add(.{ .name = "_start", .binding = .global, .kind = .defined, .value = 0, .file_index = 1, .section_index = 0 });
    try testing.expectError(error.EntryNotInSection, resolve(&table, &l, "_start"));
}

test "symbolAddress handles absolute and section-relative symbols" {
    var table = symbol.SymbolTable.init(testing.allocator);
    defer table.deinit();
    try table.add(.{ .name = "abs", .binding = .global, .kind = .absolute, .value = 0xdeadbeef });
    try table.add(.{ .name = "rel", .binding = .global, .kind = .defined, .value = 4, .file_index = 0, .section_index = 0 });

    var l = layout.Layout.init(testing.allocator, 0x400000, 4096);
    defer l.deinit();
    try l.addInput(.{
        .name = ".text",
        .data = "abcdef",
        .alignment = 1,
        .is_alloc = true,
        .is_executable = true,
        .file_index = 0,
        .section_index = 0,
        .is_writable = false,
        .is_nobits = false,
    });
    l.computeAddresses();

    const abs_sym = table.get("abs") orelse return error.TestExpectedSymbol;
    try testing.expectEqual(@as(u64, 0xdeadbeef), try symbolAddress(abs_sym, &l));

    const rel_sym = table.get("rel") orelse return error.TestExpectedSymbol;
    try testing.expectEqual(@as(u64, 0x400004), try symbolAddress(rel_sym, &l));
}

test "resolveCandidates picks the first defined candidate" {
    var table = symbol.SymbolTable.init(testing.allocator);
    defer table.deinit();
    try table.add(.{ .name = "_main", .binding = .global, .kind = .defined, .value = 0, .file_index = 0, .section_index = 0 });

    var l = layout.Layout.init(testing.allocator, 0x400000, 4096);
    defer l.deinit();
    try l.addInput(.{
        .name = ".text",
        .data = "xyz",
        .alignment = 1,
        .is_alloc = true,
        .is_executable = true,
        .file_index = 0,
        .section_index = 0,
        .is_writable = false,
        .is_nobits = false,
    });
    l.computeAddresses();

    const candidates = [_][]const u8{ "_start", "mainCRTStartup", "_main" };
    const ep = try resolveCandidates(&table, &l, &candidates);
    try testing.expectEqualStrings("_main", ep.name);
}

test "resolveCandidates returns the last error when nothing matches" {
    var table = symbol.SymbolTable.init(testing.allocator);
    defer table.deinit();
    var l = layout.Layout.init(testing.allocator, 0x400000, 4096);
    defer l.deinit();

    // `_missing` is undefined (present but not defined), so the final error
    // should be EntrySymbolUndefined from the last candidate.
    try table.add(.{ .name = "_missing", .binding = .global, .kind = .undefined });

    const candidates = [_][]const u8{ "_start", "_missing" };
    const result = resolveCandidates(&table, &l, &candidates);
    try testing.expectError(error.EntrySymbolUndefined, result);

    // With no candidates at all, the fallback is EntrySymbolNotFound.
    const empty = [_][]const u8{};
    try testing.expectError(error.EntrySymbolNotFound, resolveCandidates(&table, &l, &empty));
}

test "resolve works with symbols from two different input files" {
    var table = symbol.SymbolTable.init(testing.allocator);
    defer table.deinit();
    try table.add(.{ .name = "_start", .binding = .global, .kind = .defined, .value = 1, .file_index = 1, .section_index = 0 });

    var l = layout.Layout.init(testing.allocator, 0x400000, 4096);
    defer l.deinit();
    try l.addInput(.{
        .name = ".text",
        .data = "AAAA",
        .alignment = 1,
        .is_alloc = true,
        .is_executable = true,
        .file_index = 0,
        .section_index = 0,
        .is_writable = false,
        .is_nobits = false,
    });
    try l.addInput(.{
        .name = ".text",
        .data = "BBB",
        .alignment = 2,
        .is_alloc = true,
        .is_executable = true,
        .file_index = 1,
        .section_index = 0,
        .is_writable = false,
        .is_nobits = false,
    });
    l.computeAddresses();

    const ep = try resolve(&table, &l, "_start");
    // Member from file 1 starts at offset 4 (mismatched file_index prevents
    // matching the first member), aligned to 2 stays 4. Symbol at +1.
    try testing.expectEqual(@as(u64, 0x400000 + 4 + 1), ep.address);
}

test "default_candidates order covers common targets" {
    try testing.expectEqualStrings("_start", default_candidates[0]);
    try testing.expectEqualStrings("mainCRTStartup", default_candidates[1]);
    try testing.expectEqualStrings("_main", default_candidates[2]);
    try testing.expectEqualStrings("main", default_candidates[3]);
}
