//! Phase 6.1–6.5: Global Symbol Table, Binding, Duplicates, Undefined Tracking,
//! and Visibility Rules.
//!
//! Provides a format-agnostic symbol representation and a central hash map
//! that stores every defined and undefined symbol collected from input
//! objects and archives. Strong definitions override weak ones; multiple
//! strong definitions for the same symbol are reported as errors. Visibility
//! is resolved so the most restrictive rule wins, and only exportable symbols
//! are candidates for the dynamic symbol table.

const std = @import("std");
const elf = @import("elf.zig");
const coff = @import("coff.zig");
const macho = @import("macho.zig");

/// Symbol binding strength (independent of source format).
pub const Binding = enum {
    /// Local / static symbol (not exported).
    local,
    /// Strong global definition or reference.
    global,
    /// Weak definition or weak reference.
    weak,

    /// Return a human-readable name for this Binding.
    pub fn name(self: Binding) []const u8 {
        return switch (self) {
            .local => "local",
            .global => "global",
            .weak => "weak",
        };
    }

    /// Return true if this binding is strong (non-weak global).
    pub fn isStrong(self: Binding) bool {
        return self == .global;
    }
};

/// High-level kind of a symbol after normalization.
pub const Kind = enum {
    /// Defined in a regular section.
    defined,
    /// Referenced but not yet defined.
    undefined,
    /// Absolute value (not relative to a section).
    absolute,
    /// Common / tentative definition.
    common,

    /// Return a human-readable name for this Kind.
    pub fn name(self: Kind) []const u8 {
        return switch (self) {
            .defined => "defined",
            .undefined => "undefined",
            .absolute => "absolute",
            .common => "common",
        };
    }

    /// Return true if this kind represents a definition (not a pure reference).
    pub fn isDefinition(self: Kind) bool {
        return self != .undefined;
    }
};

/// Format-agnostic symbol used by the linker.
///
/// The name is owned by the `SymbolTable` that stores the symbol.
pub const Symbol = struct {
    /// Interned symbol name (owned by the table).
    name: []const u8,
    binding: Binding,
    kind: Kind,
    /// Value / address / alignment (interpretation depends on `kind`).
    value: u64 = 0,
    /// Size in bytes (0 if unknown).
    size: u64 = 0,
    /// Section index inside the originating object (0 = none / special).
    section_index: u32 = 0,
    /// Index of the input file that contributed this symbol.
    file_index: u32 = 0,
    /// Visibility (default / hidden / protected / internal).
    visibility: elf.SymbolVisibility = .default,

    /// Return true if the symbol has a definition (defined, absolute, or common).
    pub fn isDefined(self: Symbol) bool {
        return self.kind.isDefinition();
    }

    /// Return true if the symbol is a pure reference (undefined).
    pub fn isUndefined(self: Symbol) bool {
        return self.kind == .undefined;
    }

    /// Return true if this is a strong (global) definition.
    pub fn isStrong(self: Symbol) bool {
        return self.binding.isStrong() and self.isDefined();
    }

    /// Return true if this is a weak definition.
    pub fn isWeak(self: Symbol) bool {
        return self.binding == .weak and self.isDefined();
    }

    /// Return true if the symbol is hidden or internal (not visible outside).
    pub fn isHidden(self: Symbol) bool {
        return self.visibility == .hidden or self.visibility == .internal;
    }

    /// Return true if this symbol should appear in a dynamic symbol table.
    /// Local symbols and hidden/internal symbols are never exported.
    pub fn isExportable(self: Symbol) bool {
        if (self.binding == .local) return false;
        if (self.isHidden()) return false;
        if (!self.isDefined()) return false;
        return true;
    }

    /// Return a short visibility name.
    pub fn visibilityName(self: Symbol) []const u8 {
        return self.visibility.name();
    }
};

/// Return the more restrictive of two visibility values.
/// Order (most → least restrictive): internal/hidden > protected > default.
pub fn moreRestrictiveVisibility(a: elf.SymbolVisibility, b: elf.SymbolVisibility) elf.SymbolVisibility {
    const rank = struct {
        fn r(v: elf.SymbolVisibility) u8 {
            return switch (v) {
                .internal, .hidden => 3,
                .protected => 2,
                .default => 1,
            };
        }
    };
    return if (rank.r(a) >= rank.r(b)) a else b;
}

/// Errors that can occur while building or querying the symbol table.
pub const Error = error{
    OutOfMemory,
    EmptyName,
    /// Two or more strong definitions exist for the same symbol.
    DuplicateStrongDefinition,
    /// One or more symbols remain undefined after all inputs are processed.
    UnresolvedSymbols,
};

/// Central hash map of all symbols seen so far.
///
/// Implements Phase 6.2 binding rules (strong overrides weak),
/// Phase 6.3 duplicate detection (error on multiple strong definitions),
/// Phase 6.4 undefined symbol tracking, and Phase 6.5 visibility rules
/// (more restrictive visibility wins; only exportable symbols are candidates
/// for the dynamic symbol table).
pub const SymbolTable = struct {
    /// Maps symbol name → Symbol. Names are owned by this table.
    map: std.StringHashMapUnmanaged(Symbol),
    allocator: std.mem.Allocator,

    /// Initialize an empty symbol table using the given allocator.
    /// The table owns all stored symbol names.
    pub fn init(allocator: std.mem.Allocator) SymbolTable {
        return .{
            .map = .empty,
            .allocator = allocator,
        };
    }

    /// Free all owned names and the internal map.
    pub fn deinit(self: *SymbolTable) void {
        var it = self.map.iterator();
        while (it.next()) |entry| {
            self.allocator.free(entry.key_ptr.*);
        }
        self.map.deinit(self.allocator);
        self.* = undefined;
    }

    /// Number of unique symbol names currently stored.
    pub fn count(self: *const SymbolTable) usize {
        return self.map.count();
    }

    /// Look up a symbol by name. Returns null if not present.
    pub fn get(self: *const SymbolTable, name: []const u8) ?Symbol {
        return self.map.get(name);
    }

    /// Insert a symbol, applying binding and visibility rules.
    ///
    /// Resolution order:
    /// - Undefined is replaced by any definition.
    /// - Weak definition is replaced by a strong definition.
    /// - Strong definition is kept; a second strong definition returns
    ///   `error.DuplicateStrongDefinition`.
    /// - A second weak definition is ignored (first one wins).
    /// - Local symbols are stored but do not participate in strong/weak
    ///   conflict detection with global symbols of the same name.
    /// - Visibility: the more restrictive of the two wins (hidden/internal
    ///   > protected > default).
    pub fn add(self: *SymbolTable, symbol: Symbol) Error!void {
        if (symbol.name.len == 0) return error.EmptyName;

        if (self.map.getPtr(symbol.name)) |existing| {
            // Apply more restrictive visibility even if we keep the existing symbol.
            const merged_vis = moreRestrictiveVisibility(existing.visibility, symbol.visibility);

            // Local symbols never conflict with anything already present.
            if (symbol.binding == .local or existing.binding == .local) {
                // Prefer the non-local symbol if one exists.
                if (existing.binding == .local and symbol.binding != .local) {
                    // Replace local with global/weak, but keep stricter visibility.
                } else {
                    existing.visibility = merged_vis;
                    return; // keep existing
                }
            } else {
                const existing_is_def = existing.isDefined();
                const new_is_def = symbol.isDefined();
                const existing_strong = existing.isStrong();
                const new_strong = symbol.isStrong();

                if (existing_strong and new_strong) {
                    return error.DuplicateStrongDefinition;
                }

                // Strong definition always wins over weak or undefined.
                if (new_strong and !existing_strong) {
                    // fall through to replace
                } else if (existing_strong) {
                    existing.visibility = merged_vis;
                    return; // keep strong
                } else if (existing_is_def and existing.binding == .weak and new_is_def and symbol.binding == .weak) {
                    existing.visibility = merged_vis;
                    return; // first weak wins
                } else if (!new_is_def) {
                    existing.visibility = merged_vis;
                    return; // pure undefined does not override a definition
                }
                // else: new definition replaces existing (e.g. def over undef, strong over weak)
            }
        }

        const owned_name = try self.allocator.dupe(u8, symbol.name);
        errdefer self.allocator.free(owned_name);

        const gop = try self.map.getOrPut(self.allocator, owned_name);
        if (gop.found_existing) {
            self.allocator.free(gop.key_ptr.*);
            gop.key_ptr.* = owned_name;
        }

        // Preserve stricter visibility if we are replacing.
        const final_vis = if (gop.found_existing)
            moreRestrictiveVisibility(gop.value_ptr.visibility, symbol.visibility)
        else
            symbol.visibility;

        gop.value_ptr.* = .{
            .name = owned_name,
            .binding = symbol.binding,
            .kind = symbol.kind,
            .value = symbol.value,
            .size = symbol.size,
            .section_index = symbol.section_index,
            .file_index = symbol.file_index,
            .visibility = final_vis,
        };
    }

    /// Remove a symbol by name. Returns true if it existed.
    pub fn remove(self: *SymbolTable, name: []const u8) bool {
        if (self.map.fetchRemove(name)) |kv| {
            self.allocator.free(kv.key);
            return true;
        }
        return false;
    }

    /// Return an iterator over all stored symbols.
    pub fn iterator(self: *const SymbolTable) std.StringHashMapUnmanaged(Symbol).Iterator {
        return self.map.iterator();
    }

    /// Return the number of currently undefined symbols.
    pub fn undefinedCount(self: *const SymbolTable) usize {
        var n: usize = 0;
        var it = self.map.iterator();
        while (it.next()) |entry| {
            if (entry.value_ptr.isUndefined()) n += 1;
        }
        return n;
    }

    /// Collect the names of all currently undefined symbols into a new slice.
    /// The caller owns the returned slice (names themselves are still owned by the table).
    pub fn collectUndefined(self: *const SymbolTable, allocator: std.mem.Allocator) ![]const []const u8 {
        const n = self.undefinedCount();
        const names = try allocator.alloc([]const u8, n);
        errdefer allocator.free(names);

        var i: usize = 0;
        var it = self.map.iterator();
        while (it.next()) |entry| {
            if (entry.value_ptr.isUndefined()) {
                names[i] = entry.value_ptr.name;
                i += 1;
            }
        }
        return names;
    }

    /// Return an error if any symbols remain undefined.
    /// Used at the end of the link to ensure every needed symbol was found.
    pub fn checkResolved(self: *const SymbolTable) Error!void {
        if (self.undefinedCount() > 0) {
            return error.UnresolvedSymbols;
        }
    }

    /// Count symbols that are eligible for export (dynamic symbol table).
    pub fn exportableCount(self: *const SymbolTable) usize {
        var n: usize = 0;
        var it = self.map.iterator();
        while (it.next()) |entry| {
            if (entry.value_ptr.isExportable()) n += 1;
        }
        return n;
    }

    /// Collect names of symbols that should be exported.
    /// Caller owns the returned slice.
    pub fn collectExportable(self: *const SymbolTable, allocator: std.mem.Allocator) ![]const []const u8 {
        const n = self.exportableCount();
        const names = try allocator.alloc([]const u8, n);
        errdefer allocator.free(names);

        var i: usize = 0;
        var it = self.map.iterator();
        while (it.next()) |entry| {
            if (entry.value_ptr.isExportable()) {
                names[i] = entry.value_ptr.name;
                i += 1;
            }
        }
        return names;
    }

    // === Format-specific ingestion helpers ===

    /// Convert and add an ELF symbol.
    pub fn addElf(
        self: *SymbolTable,
        elf_sym: elf.Symbol,
        strtab_bytes: []const u8,
        file_index: u32,
    ) !void {
        const name = elf_sym.getName(strtab_bytes) catch return;
        if (name.len == 0) return;

        const kind: Kind = if (elf_sym.isUndefined())
            .undefined
        else if (elf_sym.isAbsolute())
            .absolute
        else if (elf_sym.shndx == elf.SpecialSectionIndex.COMMON)
            .common
        else
            .defined;

        const binding: Binding = switch (elf_sym.binding) {
            .local => .local,
            .weak => .weak,
            else => .global,
        };

        try self.add(.{
            .name = name,
            .binding = binding,
            .kind = kind,
            .value = elf_sym.value,
            .size = elf_sym.size,
            .section_index = elf_sym.shndx,
            .file_index = file_index,
            .visibility = elf_sym.visibility,
        });
    }

    /// Convert and add a COFF symbol.
    pub fn addCoff(
        self: *SymbolTable,
        coff_sym: coff.Symbol,
        strtab_bytes: []const u8,
        file_index: u32,
    ) !void {
        const name = coff_sym.getName(strtab_bytes) catch return;
        if (name.len == 0) return;

        const kind: Kind = if (coff_sym.isUndefined())
            .undefined
        else if (coff_sym.isAbsolute())
            .absolute
        else if (coff_sym.isCommon())
            .common
        else
            .defined;

        const binding: Binding = if (coff_sym.isStatic())
            .local
        else if (coff_sym.storage_class == .weak_external)
            .weak
        else
            .global;

        try self.add(.{
            .name = name,
            .binding = binding,
            .kind = kind,
            .value = coff_sym.value,
            .size = 0,
            .section_index = if (coff_sym.section_number > 0) @intCast(coff_sym.section_number) else 0,
            .file_index = file_index,
            .visibility = .default,
        });
    }

    /// Convert and add a Mach-O nlist_64 entry.
    pub fn addMacho(
        self: *SymbolTable,
        nlist: macho.Nlist64,
        strtab_bytes: []const u8,
        file_index: u32,
    ) !void {
        if (nlist.isStab()) return;

        const name = nlist.getName(strtab_bytes) catch return;
        if (name.len == 0) return;

        const kind: Kind = if (nlist.isUndefined())
            .undefined
        else if (nlist.isAbsolute())
            .absolute
        else if (nlist.isCommon())
            .common
        else
            .defined;

        const binding: Binding = if (nlist.isWeakDef() or nlist.isWeakRef())
            .weak
        else if (nlist.isExternal())
            .global
        else
            .local;

        try self.add(.{
            .name = name,
            .binding = binding,
            .kind = kind,
            .value = nlist.value,
            .size = 0,
            .section_index = nlist.sect,
            .file_index = file_index,
            .visibility = .default,
        });
    }
};

// === Unit Tests ===

test "symbol table init, add, get, and count" {
    var table = SymbolTable.init(std.testing.allocator);
    defer table.deinit();

    try table.add(.{
        .name = "main",
        .binding = .global,
        .kind = .defined,
        .value = 0x1000,
        .size = 64,
        .file_index = 0,
    });

    try table.add(.{
        .name = "printf",
        .binding = .global,
        .kind = .undefined,
        .file_index = 0,
    });

    try std.testing.expectEqual(@as(usize, 2), table.count());

    const main_sym = table.get("main") orelse return error.TestExpectedSymbol;
    try std.testing.expectEqualStrings("main", main_sym.name);
    try std.testing.expect(main_sym.isDefined());
    try std.testing.expectEqual(@as(u64, 0x1000), main_sym.value);
    try std.testing.expectEqual(Binding.global, main_sym.binding);

    const printf_sym = table.get("printf") orelse return error.TestExpectedSymbol;
    try std.testing.expect(printf_sym.isUndefined());
    try std.testing.expectEqual(Kind.undefined, printf_sym.kind);

    try std.testing.expect(table.get("missing") == null);
}

test "strong definition overrides weak definition" {
    var table = SymbolTable.init(std.testing.allocator);
    defer table.deinit();

    try table.add(.{
        .name = "foo",
        .binding = .weak,
        .kind = .defined,
        .value = 1,
        .file_index = 0,
    });

    try table.add(.{
        .name = "foo",
        .binding = .global,
        .kind = .defined,
        .value = 42,
        .file_index = 1,
    });

    try std.testing.expectEqual(@as(usize, 1), table.count());
    const sym = table.get("foo") orelse return error.TestExpectedSymbol;
    try std.testing.expectEqual(Binding.global, sym.binding);
    try std.testing.expectEqual(@as(u64, 42), sym.value);
    try std.testing.expectEqual(@as(u32, 1), sym.file_index);
}

test "weak definition does not override strong definition" {
    var table = SymbolTable.init(std.testing.allocator);
    defer table.deinit();

    try table.add(.{
        .name = "bar",
        .binding = .global,
        .kind = .defined,
        .value = 100,
        .file_index = 0,
    });

    try table.add(.{
        .name = "bar",
        .binding = .weak,
        .kind = .defined,
        .value = 999,
        .file_index = 1,
    });

    const sym = table.get("bar") orelse return error.TestExpectedSymbol;
    try std.testing.expectEqual(Binding.global, sym.binding);
    try std.testing.expectEqual(@as(u64, 100), sym.value);
    try std.testing.expectEqual(@as(u32, 0), sym.file_index);
}

test "definition replaces undefined" {
    var table = SymbolTable.init(std.testing.allocator);
    defer table.deinit();

    try table.add(.{
        .name = "puts",
        .binding = .global,
        .kind = .undefined,
        .file_index = 0,
    });

    try table.add(.{
        .name = "puts",
        .binding = .global,
        .kind = .defined,
        .value = 0x4000,
        .file_index = 1,
    });

    const sym = table.get("puts") orelse return error.TestExpectedSymbol;
    try std.testing.expect(sym.isDefined());
    try std.testing.expectEqual(@as(u64, 0x4000), sym.value);
    try std.testing.expectEqual(@as(usize, 0), table.undefinedCount());
}

test "duplicate strong definitions are rejected" {
    var table = SymbolTable.init(std.testing.allocator);
    defer table.deinit();

    try table.add(.{
        .name = "main",
        .binding = .global,
        .kind = .defined,
        .value = 0x1000,
        .file_index = 0,
    });

    const result = table.add(.{
        .name = "main",
        .binding = .global,
        .kind = .defined,
        .value = 0x2000,
        .file_index = 1,
    });

    try std.testing.expectError(error.DuplicateStrongDefinition, result);

    // Original strong definition must still be present.
    const sym = table.get("main") orelse return error.TestExpectedSymbol;
    try std.testing.expectEqual(@as(u64, 0x1000), sym.value);
    try std.testing.expectEqual(@as(u32, 0), sym.file_index);
}

test "second weak definition is ignored" {
    var table = SymbolTable.init(std.testing.allocator);
    defer table.deinit();

    try table.add(.{
        .name = "weakfn",
        .binding = .weak,
        .kind = .defined,
        .value = 10,
        .file_index = 0,
    });

    try table.add(.{
        .name = "weakfn",
        .binding = .weak,
        .kind = .defined,
        .value = 20,
        .file_index = 1,
    });

    const sym = table.get("weakfn") orelse return error.TestExpectedSymbol;
    try std.testing.expectEqual(@as(u64, 10), sym.value);
    try std.testing.expectEqual(@as(u32, 0), sym.file_index);
}

test "symbol table rejects empty name" {
    var table = SymbolTable.init(std.testing.allocator);
    defer table.deinit();

    const result = table.add(.{
        .name = "",
        .binding = .global,
        .kind = .defined,
    });
    try std.testing.expectError(error.EmptyName, result);
    try std.testing.expectEqual(@as(usize, 0), table.count());
}

test "symbol table remove" {
    var table = SymbolTable.init(std.testing.allocator);
    defer table.deinit();

    try table.add(.{ .name = "bar", .binding = .local, .kind = .defined });
    try std.testing.expect(table.remove("bar"));
    try std.testing.expectEqual(@as(usize, 0), table.count());
    try std.testing.expect(!table.remove("bar"));
}

test "addElf helper normalizes binding and kind" {
    var table = SymbolTable.init(std.testing.allocator);
    defer table.deinit();

    // Synthetic string table: "\0main\0printf\0"
    const strtab = "\x00main\x00printf\x00";

    const defined = elf.Symbol{
        .name_offset = 1,
        .value = 0x2000,
        .size = 32,
        .binding = .global,
        .sym_type = .func,
        .visibility = .default,
        .shndx = 1,
    };
    try table.addElf(defined, strtab, 0);

    const undef = elf.Symbol{
        .name_offset = 6,
        .value = 0,
        .size = 0,
        .binding = .global,
        .sym_type = .notype,
        .visibility = .default,
        .shndx = elf.SpecialSectionIndex.UNDEF,
    };
    try table.addElf(undef, strtab, 0);

    try std.testing.expectEqual(@as(usize, 2), table.count());

    const main_sym = table.get("main") orelse return error.TestExpectedSymbol;
    try std.testing.expectEqual(Kind.defined, main_sym.kind);
    try std.testing.expectEqual(@as(u64, 0x2000), main_sym.value);
    try std.testing.expectEqual(Binding.global, main_sym.binding);

    const printf_sym = table.get("printf") orelse return error.TestExpectedSymbol;
    try std.testing.expectEqual(Kind.undefined, printf_sym.kind);
}

test "iterator visits every symbol" {
    var table = SymbolTable.init(std.testing.allocator);
    defer table.deinit();

    try table.add(.{ .name = "a", .binding = .global, .kind = .defined });
    try table.add(.{ .name = "b", .binding = .global, .kind = .undefined });
    try table.add(.{ .name = "c", .binding = .weak, .kind = .common });

    var seen: usize = 0;
    var it = table.iterator();
    while (it.next()) |_| {
        seen += 1;
    }
    try std.testing.expectEqual(@as(usize, 3), seen);
}

test "undefinedCount tracks unresolved symbols" {
    var table = SymbolTable.init(std.testing.allocator);
    defer table.deinit();

    try table.add(.{ .name = "main", .binding = .global, .kind = .defined });
    try table.add(.{ .name = "printf", .binding = .global, .kind = .undefined });
    try table.add(.{ .name = "malloc", .binding = .global, .kind = .undefined });

    try std.testing.expectEqual(@as(usize, 2), table.undefinedCount());
}

test "collectUndefined returns all unresolved names" {
    var table = SymbolTable.init(std.testing.allocator);
    defer table.deinit();

    try table.add(.{ .name = "main", .binding = .global, .kind = .defined });
    try table.add(.{ .name = "puts", .binding = .global, .kind = .undefined });
    try table.add(.{ .name = "exit", .binding = .global, .kind = .undefined });

    const names = try table.collectUndefined(std.testing.allocator);
    defer std.testing.allocator.free(names);

    try std.testing.expectEqual(@as(usize, 2), names.len);

    var found_puts = false;
    var found_exit = false;
    for (names) |n| {
        if (std.mem.eql(u8, n, "puts")) found_puts = true;
        if (std.mem.eql(u8, n, "exit")) found_exit = true;
    }
    try std.testing.expect(found_puts);
    try std.testing.expect(found_exit);
}

test "checkResolved succeeds when all symbols are defined" {
    var table = SymbolTable.init(std.testing.allocator);
    defer table.deinit();

    try table.add(.{ .name = "main", .binding = .global, .kind = .defined });
    try table.add(.{ .name = "_start", .binding = .global, .kind = .defined });

    try table.checkResolved();
}

test "checkResolved fails when symbols remain undefined" {
    var table = SymbolTable.init(std.testing.allocator);
    defer table.deinit();

    try table.add(.{ .name = "main", .binding = .global, .kind = .defined });
    try table.add(.{ .name = "printf", .binding = .global, .kind = .undefined });

    try std.testing.expectError(error.UnresolvedSymbols, table.checkResolved());
}

test "definition clears previously undefined symbol" {
    var table = SymbolTable.init(std.testing.allocator);
    defer table.deinit();

    try table.add(.{ .name = "foo", .binding = .global, .kind = .undefined });
    try std.testing.expectError(error.UnresolvedSymbols, table.checkResolved());

    try table.add(.{ .name = "foo", .binding = .global, .kind = .defined, .value = 1 });
    try table.checkResolved();
    try std.testing.expectEqual(@as(usize, 0), table.undefinedCount());
}

test "hidden symbol is not exportable" {
    var table = SymbolTable.init(std.testing.allocator);
    defer table.deinit();

    try table.add(.{
        .name = "internal_fn",
        .binding = .global,
        .kind = .defined,
        .visibility = .hidden,
    });

    try table.add(.{
        .name = "public_fn",
        .binding = .global,
        .kind = .defined,
        .visibility = .default,
    });

    try table.add(.{
        .name = "local_fn",
        .binding = .local,
        .kind = .defined,
        .visibility = .default,
    });

    const hidden = table.get("internal_fn") orelse return error.TestExpectedSymbol;
    try std.testing.expect(hidden.isHidden());
    try std.testing.expect(!hidden.isExportable());

    const public = table.get("public_fn") orelse return error.TestExpectedSymbol;
    try std.testing.expect(public.isExportable());

    const local = table.get("local_fn") orelse return error.TestExpectedSymbol;
    try std.testing.expect(!local.isExportable());

    try std.testing.expectEqual(@as(usize, 1), table.exportableCount());
}

test "more restrictive visibility wins" {
    var table = SymbolTable.init(std.testing.allocator);
    defer table.deinit();

    try table.add(.{
        .name = "shared",
        .binding = .global,
        .kind = .defined,
        .visibility = .default,
        .value = 1,
    });

    try table.add(.{
        .name = "shared",
        .binding = .weak,
        .kind = .defined,
        .visibility = .hidden,
        .value = 2,
    });

    const sym = table.get("shared") orelse return error.TestExpectedSymbol;
    // Strong definition kept, but visibility became hidden.
    try std.testing.expectEqual(Binding.global, sym.binding);
    try std.testing.expectEqual(@as(u64, 1), sym.value);
    try std.testing.expectEqual(elf.SymbolVisibility.hidden, sym.visibility);
    try std.testing.expect(!sym.isExportable());
}

test "protected is exportable but hidden is not" {
    var table = SymbolTable.init(std.testing.allocator);
    defer table.deinit();

    try table.add(.{
        .name = "prot",
        .binding = .global,
        .kind = .defined,
        .visibility = .protected,
    });

    try table.add(.{
        .name = "hid",
        .binding = .global,
        .kind = .defined,
        .visibility = .hidden,
    });

    try std.testing.expect((table.get("prot") orelse return error.TestExpectedSymbol).isExportable());
    try std.testing.expect(!(table.get("hid") orelse return error.TestExpectedSymbol).isExportable());
}

test "collectExportable returns only exportable names" {
    var table = SymbolTable.init(std.testing.allocator);
    defer table.deinit();

    try table.add(.{ .name = "main", .binding = .global, .kind = .defined, .visibility = .default });
    try table.add(.{ .name = "hidden_main", .binding = .global, .kind = .defined, .visibility = .hidden });
    try table.add(.{ .name = "static_fn", .binding = .local, .kind = .defined });
    try table.add(.{ .name = "printf", .binding = .global, .kind = .undefined });

    const names = try table.collectExportable(std.testing.allocator);
    defer std.testing.allocator.free(names);

    try std.testing.expectEqual(@as(usize, 1), names.len);
    try std.testing.expectEqualStrings("main", names[0]);
}
