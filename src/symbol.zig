//! Phase 6.1: Global Symbol Table Creation.
//!
//! Provides a format-agnostic symbol representation and a central hash map
//! that stores every defined and undefined symbol collected from input
//! objects and archives. Later phases (binding rules, duplicate detection,
//! visibility) build on top of this table.

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

    pub fn name(self: Binding) []const u8 {
        return switch (self) {
            .local => "local",
            .global => "global",
            .weak => "weak",
        };
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

    pub fn name(self: Kind) []const u8 {
        return switch (self) {
            .defined => "defined",
            .undefined => "undefined",
            .absolute => "absolute",
            .common => "common",
        };
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

    pub fn isDefined(self: Symbol) bool {
        return self.kind == .defined or self.kind == .absolute or self.kind == .common;
    }

    pub fn isUndefined(self: Symbol) bool {
        return self.kind == .undefined;
    }
};

/// Errors that can occur while building or querying the symbol table.
pub const Error = error{
    OutOfMemory,
    EmptyName,
};

/// Central hash map of all symbols seen so far.
///
/// Phase 6.1 only stores symbols. Conflict resolution (weak vs strong,
/// duplicate strong definitions, etc.) is handled in later sub-phases.
pub const SymbolTable = struct {
    /// Maps symbol name → Symbol. Names are owned by this table.
    map: std.StringHashMapUnmanaged(Symbol),
    allocator: std.mem.Allocator,

    pub fn init(allocator: std.mem.Allocator) SymbolTable {
        return .{
            .map = .empty,
            .allocator = allocator,
        };
    }

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

    /// Insert or replace a symbol.
    ///
    /// The name is duplicated so the table owns it. If a symbol with the
    /// same name already exists it is overwritten (Phase 6.2 will refine
    /// this behaviour).
    pub fn add(self: *SymbolTable, symbol: Symbol) Error!void {
        if (symbol.name.len == 0) return error.EmptyName;

        const owned_name = try self.allocator.dupe(u8, symbol.name);
        errdefer self.allocator.free(owned_name);

        const gop = try self.map.getOrPut(self.allocator, owned_name);
        if (gop.found_existing) {
            // Free the previous owned key; the map still holds the old key pointer
            // until we replace it.
            self.allocator.free(gop.key_ptr.*);
            gop.key_ptr.* = owned_name;
        }

        gop.value_ptr.* = .{
            .name = owned_name,
            .binding = symbol.binding,
            .kind = symbol.kind,
            .value = symbol.value,
            .size = symbol.size,
            .section_index = symbol.section_index,
            .file_index = symbol.file_index,
            .visibility = symbol.visibility,
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

test "symbol table overwrites existing name" {
    var table = SymbolTable.init(std.testing.allocator);
    defer table.deinit();

    try table.add(.{
        .name = "foo",
        .binding = .weak,
        .kind = .defined,
        .value = 1,
    });

    try table.add(.{
        .name = "foo",
        .binding = .global,
        .kind = .defined,
        .value = 42,
    });

    try std.testing.expectEqual(@as(usize, 1), table.count());
    const sym = table.get("foo") orelse return error.TestExpectedSymbol;
    try std.testing.expectEqual(Binding.global, sym.binding);
    try std.testing.expectEqual(@as(u64, 42), sym.value);
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
