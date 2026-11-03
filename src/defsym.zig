//! Phase 9.3: Symbol Assignment from CLI flags (`--defsym`).
//!
//! Parses `--defsym SYMBOL=EXPRESSION` and inserts absolute symbols into
//! the Phase 6 symbol table. Expressions follow the limited arithmetic
//! supported by GNU ld's `--defsym`:
//! - numeric constants (`0x1000`, `0b1000`, `4096`)
//! - the name of an existing symbol
//! - `+` and `-` combining constants and symbols (no whitespace)
//!
//! The resulting symbol is a strong absolute definition. A second strong
//! definition for the same name is reported as `DuplicateStrongDefinition`
//! by the symbol table. Expressions are evaluated against the symbol table
//! as it exists at the moment of the call, so `--defsym` is applied after
//! all input objects have been ingested.

const std = @import("std");
const symbol = @import("symbol.zig");

/// Errors that can occur while parsing or applying `--defsym` specs.
pub const Error = error{
    OutOfMemory,
    /// Spec does not contain `=` or has an empty name or expression.
    InvalidSpec,
    /// Expression contains unexpected tokens, an unknown symbol, or an
    /// empty operand.
    InvalidExpression,
    /// Two or more strong definitions exist for the same symbol
    /// (re-exported from the symbol table so callers can handle it).
    DuplicateStrongDefinition,
    EmptyName,
    /// Present so the error set is compatible with `SymbolTable.add`.
    UnresolvedSymbols,
};

/// A parsed `--defsym` specification.
pub const Spec = struct {
    /// Symbol name to define (borrowed from the input string).
    name: []const u8,
    /// Expression text (borrowed from the input string).
    expression: []const u8,
};

/// Split a raw `--defsym` argument into a name and an expression.
///
/// Accepts `SYMBOL=EXPRESSION` with no surrounding whitespace. Both sides
/// must be non-empty.
pub fn parseSpec(spec: []const u8) Error!Spec {
    const eq = std.mem.indexOfScalar(u8, spec, '=') orelse return error.InvalidSpec;
    const name = spec[0..eq];
    const expression = spec[eq + 1 ..];
    if (name.len == 0 or expression.len == 0) return error.InvalidSpec;
    return .{ .name = name, .expression = expression };
}

/// Evaluate a limited expression against the current symbol table.
///
/// Supported forms (no whitespace):
/// - `0x1000`, `4096`, `0b1000` — numeric constants (`std.fmt.parseInt` base 0)
/// - `existing_symbol` — the absolute value of a defined symbol, or the
///   stored value of an absolute symbol
/// - `a+0x10`, `b-4`, `0x2000+sym`, `sym1+sym2-0x8` — left-associative
///   addition and subtraction of the above
///
/// Undefined symbols and empty operands return `error.InvalidExpression`.
pub fn evaluate(table: *const symbol.SymbolTable, expr: []const u8) Error!u64 {
    if (expr.len == 0) return error.InvalidExpression;

    var result: u64 = 0;
    var pending_op: enum { none, add, sub } = .none;
    var seen_term = false;
    var i: usize = 0;

    while (i < expr.len) {
        // Operator between terms. A leading operator is invalid.
        if (expr[i] == '+' or expr[i] == '-') {
            if (!seen_term or pending_op != .none) return error.InvalidExpression;
            pending_op = if (expr[i] == '+') .add else .sub;
            i += 1;
            continue;
        }

        // Scan a term: either a number or a symbol name.
        const start = i;
        while (i < expr.len and expr[i] != '+' and expr[i] != '-') : (i += 1) {}
        const term = expr[start..i];
        if (term.len == 0) return error.InvalidExpression;

        const term_value = try evalTerm(table, term);

        switch (pending_op) {
            .none => {
                // First term.
                result = term_value;
            },
            .add => {
                result +%= term_value;
            },
            .sub => {
                result -%= term_value;
            },
        }
        pending_op = .none;
        seen_term = true;
    }

    if (!seen_term or pending_op != .none) return error.InvalidExpression;
    return result;
}

fn evalTerm(table: *const symbol.SymbolTable, term: []const u8) Error!u64 {
    // Prefer a numeric parse. Base 0 accepts `0x`, `0b`, and decimal.
    if (std.fmt.parseInt(u64, term, 0)) |n| {
        return n;
    } else |_| {}

    // Otherwise treat as a symbol name. Absolute symbols contribute their
    // stored value; section-relative symbols contribute their stored
    // section-relative value (callers that need the final VA should resolve
    // after layout). `--defsym` is applied before address assignment, so
    // only absolute values or previously defined absolute symbols are
    // meaningful here. Defined non-absolute symbols are accepted as their
    // stored `value` (the symbol's section-relative offset), matching the
    // limited GNU ld form for early evaluation.
    const sym = table.get(term) orelse return error.InvalidExpression;
    if (sym.isUndefined()) return error.InvalidExpression;
    return sym.value;
}

/// Apply a list of `--defsym` specs to the symbol table.
///
/// Each spec is evaluated in order. Later specs may reference symbols
/// defined by earlier specs in the same list. The inserted symbol is a
/// strong absolute global definition. If a strong definition of the same
/// name already exists, `error.DuplicateStrongDefinition` is returned.
pub fn apply(table: *symbol.SymbolTable, specs: []const []const u8) Error!void {
    for (specs) |raw| {
        const spec = try parseSpec(raw);
        const value = try evaluate(table, spec.expression);
        try table.add(.{
            .name = spec.name,
            .binding = .global,
            .kind = .absolute,
            .value = value,
            .visibility = .default,
        });
    }
}

// === Unit Tests ===

test "parseSpec splits name and expression" {
    const s = try parseSpec("FOO=0x1000");
    try std.testing.expectEqualStrings("FOO", s.name);
    try std.testing.expectEqualStrings("0x1000", s.expression);

    const s2 = try parseSpec("_start=main+0x10");
    try std.testing.expectEqualStrings("_start", s2.name);
    try std.testing.expectEqualStrings("main+0x10", s2.expression);
}

test "parseSpec rejects empty sides and missing equals" {
    try std.testing.expectError(error.InvalidSpec, parseSpec("NOEQUALS"));
    try std.testing.expectError(error.InvalidSpec, parseSpec("=0x1"));
    try std.testing.expectError(error.InvalidSpec, parseSpec("NAME="));
    try std.testing.expectError(error.InvalidSpec, parseSpec(""));
}

test "evaluate numeric constants" {
    var table = symbol.SymbolTable.init(std.testing.allocator);
    defer table.deinit();

    try std.testing.expectEqual(@as(u64, 0x1000), try evaluate(&table, "0x1000"));
    try std.testing.expectEqual(@as(u64, 4096), try evaluate(&table, "4096"));
    try std.testing.expectEqual(@as(u64, 0b1010), try evaluate(&table, "0b1010"));
    try std.testing.expectEqual(@as(u64, 0), try evaluate(&table, "0"));
}

test "evaluate addition and subtraction of constants" {
    var table = symbol.SymbolTable.init(std.testing.allocator);
    defer table.deinit();

    try std.testing.expectEqual(@as(u64, 0x1010), try evaluate(&table, "0x1000+0x10"));
    try std.testing.expectEqual(@as(u64, 0xFF0), try evaluate(&table, "0x1000-0x10"));
    try std.testing.expectEqual(@as(u64, 100), try evaluate(&table, "50+60-10"));
    try std.testing.expectEqual(@as(u64, 0), try evaluate(&table, "0x10-0x10"));
}

test "evaluate uses existing absolute symbols" {
    var table = symbol.SymbolTable.init(std.testing.allocator);
    defer table.deinit();

    try table.add(.{
        .name = "base",
        .binding = .global,
        .kind = .absolute,
        .value = 0x400000,
    });
    try table.add(.{
        .name = "offset",
        .binding = .global,
        .kind = .absolute,
        .value = 0x100,
    });

    try std.testing.expectEqual(@as(u64, 0x400000), try evaluate(&table, "base"));
    try std.testing.expectEqual(@as(u64, 0x400100), try evaluate(&table, "base+0x100"));
    try std.testing.expectEqual(@as(u64, 0x400100), try evaluate(&table, "base+offset"));
    try std.testing.expectEqual(@as(u64, 0x3FFF00), try evaluate(&table, "base-offset"));
}

test "evaluate rejects unknown and undefined symbols" {
    var table = symbol.SymbolTable.init(std.testing.allocator);
    defer table.deinit();

    try std.testing.expectError(error.InvalidExpression, evaluate(&table, "missing"));
    try std.testing.expectError(error.InvalidExpression, evaluate(&table, ""));
    try std.testing.expectError(error.InvalidExpression, evaluate(&table, "0x10+"));
    try std.testing.expectError(error.InvalidExpression, evaluate(&table, "+0x10"));

    try table.add(.{
        .name = "undef",
        .binding = .global,
        .kind = .undefined,
    });
    try std.testing.expectError(error.InvalidExpression, evaluate(&table, "undef"));
    try std.testing.expectError(error.InvalidExpression, evaluate(&table, "0x10+undef"));
}

test "apply inserts absolute symbols and chains" {
    var table = symbol.SymbolTable.init(std.testing.allocator);
    defer table.deinit();

    try apply(&table, &.{
        "FOO=0x1000",
        "BAR=FOO+0x20",
        "BAZ=BAR-0x10",
    });

    const foo = table.get("FOO").?;
    try std.testing.expect(foo.kind == .absolute);
    try std.testing.expect(foo.binding == .global);
    try std.testing.expectEqual(@as(u64, 0x1000), foo.value);

    const bar = table.get("BAR").?;
    try std.testing.expectEqual(@as(u64, 0x1020), bar.value);

    const baz = table.get("BAZ").?;
    try std.testing.expectEqual(@as(u64, 0x1010), baz.value);
}

test "apply reports duplicate strong definitions" {
    var table = symbol.SymbolTable.init(std.testing.allocator);
    defer table.deinit();

    try table.add(.{
        .name = "FOO",
        .binding = .global,
        .kind = .absolute,
        .value = 1,
    });

    try std.testing.expectError(error.DuplicateStrongDefinition, apply(&table, &.{"FOO=0x1000"}));
}

test "apply rejects invalid specs and expressions" {
    var table = symbol.SymbolTable.init(std.testing.allocator);
    defer table.deinit();

    try std.testing.expectError(error.InvalidSpec, apply(&table, &.{"NOEQUALS"}));
    try std.testing.expectError(error.InvalidExpression, apply(&table, &.{"X=missing"}));
}
