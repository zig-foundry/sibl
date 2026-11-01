//! Phase 8: Relocation Engine.
//!
//! Resolves relocation records against final symbol addresses, applies
//! architecture-specific formulas (x86_64 and AArch64), checks ranges, and
//! patches the result directly into an output buffer.
//!
//! Formulas follow the ELF psABI:
//! - S = symbol address
//! - A = addend
//! - P = address of the place being relocated
//!
//! Supported:
//! - x86_64: NONE, 64, PC32, 32, 32S, PC64
//! - AArch64: ABS64, ADR_PREL_PG_HI21, ADD_ABS_LO12_NC, JUMP26, CALL26

const std = @import("std");

/// Target architecture for relocation application.
pub const Arch = enum {
    x86_64,
    aarch64,

    pub fn name(self: Arch) []const u8 {
        return switch (self) {
            .x86_64 => "x86_64",
            .aarch64 => "aarch64",
        };
    }
};

/// x86_64 relocation type codes (AMD64 ABI).
pub const X86_64 = struct {
    pub const NONE: u32 = 0;
    pub const @"64": u32 = 1;
    pub const PC32: u32 = 2;
    pub const @"32": u32 = 10;
    pub const @"32S": u32 = 11;
    pub const PC64: u32 = 24;
};

/// AArch64 relocation type codes (AAELF64).
pub const AArch64 = struct {
    pub const NONE: u32 = 0;
    pub const ABS64: u32 = 257;
    pub const ADR_PREL_PG_HI21: u32 = 275;
    pub const ADD_ABS_LO12_NC: u32 = 277;
    pub const JUMP26: u32 = 282;
    pub const CALL26: u32 = 283;
};

/// A single relocation to apply.
pub const Reloc = struct {
    /// Byte offset of the place within the section buffer.
    offset: u64,
    /// Architecture-specific type code.
    type_id: u32,
    /// Resolved symbol address (S). 0 if none.
    symbol_address: u64,
    /// Explicit addend (A). For REL (not RELA) the caller must extract it.
    addend: i64,
    /// Virtual address of the place (P).
    place_address: u64,
};

/// Errors produced while applying relocations.
pub const Error = error{
    /// Relocation offset is outside the output buffer.
    OutOfBounds,
    /// Relocation type is not implemented for this architecture.
    UnsupportedType,
    /// Computed value does not fit in the target field.
    Overflow,
    /// Buffer is too small for the write width.
    Truncated,
    /// Symbol name was not found in the address table.
    UnresolvedSymbol,
};

/// Result of a single successful relocation.
pub const Applied = struct {
    offset: u64,
    type_id: u32,
    value: i64,
    bytes_written: u8,
};

/// Apply one relocation in place.
///
/// Writes the computed value directly into `buffer` at `reloc.offset`.
pub fn apply(arch: Arch, buffer: []u8, reloc: Reloc) Error!Applied {
    if (reloc.offset >= buffer.len) return error.OutOfBounds;

    const S: i64 = @bitCast(reloc.symbol_address);
    const A: i64 = reloc.addend;
    const P: i64 = @bitCast(reloc.place_address);

    return switch (arch) {
        .x86_64 => applyX86_64(buffer, reloc, S, A, P),
        .aarch64 => applyAArch64(buffer, reloc, S, A, P),
    };
}

/// Apply a list of relocations. Stops on the first error.
pub fn applyAll(arch: Arch, buffer: []u8, relocs: []const Reloc) Error!usize {
    var n: usize = 0;
    for (relocs) |r| {
        _ = try apply(arch, buffer, r);
        n += 1;
    }
    return n;
}

fn applyX86_64(buffer: []u8, reloc: Reloc, S: i64, A: i64, P: i64) Error!Applied {
    switch (reloc.type_id) {
        X86_64.NONE => return .{
            .offset = reloc.offset,
            .type_id = reloc.type_id,
            .value = 0,
            .bytes_written = 0,
        },
        X86_64.@"64" => {
            // S + A
            const value = S +% A;
            try writeU64(buffer, reloc.offset, @bitCast(value));
            return .{ .offset = reloc.offset, .type_id = reloc.type_id, .value = value, .bytes_written = 8 };
        },
        X86_64.PC32 => {
            // S + A - P  (signed 32-bit)
            const value = S +% A -% P;
            try checkSigned(value, 32);
            try writeU32(buffer, reloc.offset, @truncate(@as(u64, @bitCast(value))));
            return .{ .offset = reloc.offset, .type_id = reloc.type_id, .value = value, .bytes_written = 4 };
        },
        X86_64.@"32" => {
            // S + A  (zero-extended 32-bit)
            const value = S +% A;
            if (value < 0 or value > 0xFFFFFFFF) return error.Overflow;
            try writeU32(buffer, reloc.offset, @intCast(value));
            return .{ .offset = reloc.offset, .type_id = reloc.type_id, .value = value, .bytes_written = 4 };
        },
        X86_64.@"32S" => {
            // S + A  (sign-extended 32-bit)
            const value = S +% A;
            try checkSigned(value, 32);
            try writeU32(buffer, reloc.offset, @truncate(@as(u64, @bitCast(value))));
            return .{ .offset = reloc.offset, .type_id = reloc.type_id, .value = value, .bytes_written = 4 };
        },
        X86_64.PC64 => {
            // S + A - P
            const value = S +% A -% P;
            try writeU64(buffer, reloc.offset, @bitCast(value));
            return .{ .offset = reloc.offset, .type_id = reloc.type_id, .value = value, .bytes_written = 8 };
        },
        else => return error.UnsupportedType,
    }
}

fn applyAArch64(buffer: []u8, reloc: Reloc, S: i64, A: i64, P: i64) Error!Applied {
    switch (reloc.type_id) {
        AArch64.NONE => return .{
            .offset = reloc.offset,
            .type_id = reloc.type_id,
            .value = 0,
            .bytes_written = 0,
        },
        AArch64.ABS64 => {
            // S + A
            const value = S +% A;
            try writeU64(buffer, reloc.offset, @bitCast(value));
            return .{ .offset = reloc.offset, .type_id = reloc.type_id, .value = value, .bytes_written = 8 };
        },
        AArch64.ADR_PREL_PG_HI21 => {
            // X = Page(S+A) - Page(P). Encode X>>12 into the ADRP immediate.
            const page_s = page(S +% A);
            const page_p = page(P);
            const value = page_s -% page_p;
            // AAELF: -2^32 <= X < 2^32
            try checkSigned(value, 33);
            try patchAdrp(buffer, reloc.offset, value >> 12);
            return .{ .offset = reloc.offset, .type_id = reloc.type_id, .value = value, .bytes_written = 4 };
        },
        AArch64.ADD_ABS_LO12_NC => {
            // Low 12 bits of S+A into ADD immediate. No overflow check.
            const value = S +% A;
            try patchAddImm12(buffer, reloc.offset, @as(u64, @bitCast(value)));
            return .{ .offset = reloc.offset, .type_id = reloc.type_id, .value = value, .bytes_written = 4 };
        },
        AArch64.JUMP26, AArch64.CALL26 => {
            // (S + A - P) >> 2 into 26-bit branch immediate.
            const delta = S +% A -% P;
            if (@mod(delta, 4) != 0) return error.Overflow;
            const imm = @divTrunc(delta, 4);
            try checkSigned(imm, 26);
            try patchBranch26(buffer, reloc.offset, imm);
            return .{ .offset = reloc.offset, .type_id = reloc.type_id, .value = delta, .bytes_written = 4 };
        },
        else => return error.UnsupportedType,
    }
}

/// Align an address down to a 4 KiB page.
pub fn page(addr: i64) i64 {
    const u: u64 = @bitCast(addr);
    return @bitCast(u & ~@as(u64, 0xFFF));
}

/// Check that `value` fits in a signed field of `bits` width.
pub fn checkSigned(value: i64, bits: u6) Error!void {
    if (bits >= 64) return;
    const min = -(@as(i64, 1) << (bits - 1));
    const max = (@as(i64, 1) << (bits - 1)) - 1;
    if (value < min or value > max) return error.Overflow;
}

fn writeU64(buffer: []u8, offset: u64, value: u64) Error!void {
    const start: usize = @intCast(offset);
    if (start + 8 > buffer.len) return error.Truncated;
    std.mem.writeInt(u64, buffer[start..][0..8], value, .little);
}

fn writeU32(buffer: []u8, offset: u64, value: u32) Error!void {
    const start: usize = @intCast(offset);
    if (start + 4 > buffer.len) return error.Truncated;
    std.mem.writeInt(u32, buffer[start..][0..4], value, .little);
}

fn readU32(buffer: []const u8, offset: u64) Error!u32 {
    const start: usize = @intCast(offset);
    if (start + 4 > buffer.len) return error.Truncated;
    return std.mem.readInt(u32, buffer[start..][0..4], .little);
}

/// Patch an ADRP instruction's 21-bit page immediate.
/// ADRP encoding: immhi[23:5] | immlo[30:29], value is in pages.
fn patchAdrp(buffer: []u8, offset: u64, page_delta: i64) Error!void {
    var inst = try readU32(buffer, offset);
    // Clear existing immediate bits.
    inst &= ~@as(u32, 0x00FFFFE0); // immhi
    inst &= ~@as(u32, 0x60000000); // immlo

    const pages: u64 = @bitCast(page_delta);
    const immlo: u32 = @truncate((pages & 0x3) << 29);
    const immhi: u32 = @truncate(((pages >> 2) & 0x7FFFF) << 5);
    inst |= immlo | immhi;
    try writeU32(buffer, offset, inst);
}

/// Patch an ADD (immediate) instruction's 12-bit immediate (bits [21:10]).
fn patchAddImm12(buffer: []u8, offset: u64, value: u64) Error!void {
    var inst = try readU32(buffer, offset);
    inst &= ~@as(u32, 0x003FFC00);
    const imm12: u32 = @truncate((value & 0xFFF) << 10);
    inst |= imm12;
    try writeU32(buffer, offset, inst);
}

/// Patch a B / BL 26-bit branch immediate (bits [25:0], in instructions).
fn patchBranch26(buffer: []u8, offset: u64, imm26: i64) Error!void {
    var inst = try readU32(buffer, offset);
    inst &= ~@as(u32, 0x03FFFFFF);
    const bits: u32 = @truncate(@as(u64, @bitCast(imm26)) & 0x03FFFFFF);
    inst |= bits;
    try writeU32(buffer, offset, inst);
}

/// Human-readable name for a relocation type.
pub fn typeName(arch: Arch, type_id: u32) []const u8 {
    return switch (arch) {
        .x86_64 => switch (type_id) {
            X86_64.NONE => "NONE",
            X86_64.@"64" => "64",
            X86_64.PC32 => "PC32",
            X86_64.@"32" => "32",
            X86_64.@"32S" => "32S",
            X86_64.PC64 => "PC64",
            else => "UNKNOWN",
        },
        .aarch64 => switch (type_id) {
            AArch64.NONE => "NONE",
            AArch64.ABS64 => "ABS64",
            AArch64.ADR_PREL_PG_HI21 => "ADR_PREL_PG_HI21",
            AArch64.ADD_ABS_LO12_NC => "ADD_ABS_LO12_NC",
            AArch64.JUMP26 => "JUMP26",
            AArch64.CALL26 => "CALL26",
            else => "UNKNOWN",
        },
    };
}

/// Unresolved relocation waiting for a symbol address (Phase 8.1).
pub const PendingReloc = struct {
    offset: u64,
    type_id: u32,
    /// Name of the symbol to resolve.
    symbol_name: []const u8,
    addend: i64,
    place_address: u64,
};

/// Resolve a pending relocation against a symbol address table.
///
/// `symbols` is a slice of name/address pairs. Returns `error.UnresolvedSymbol`
/// if the name is not found.
pub fn resolve(pending: PendingReloc, symbols: []const SymbolAddr) Error!Reloc {
    for (symbols) |sym| {
        if (std.mem.eql(u8, sym.name, pending.symbol_name)) {
            return .{
                .offset = pending.offset,
                .type_id = pending.type_id,
                .symbol_address = sym.address,
                .addend = pending.addend,
                .place_address = pending.place_address,
            };
        }
    }
    return error.UnresolvedSymbol;
}

/// Name + final address pair used by `resolve`.
pub const SymbolAddr = struct {
    name: []const u8,
    address: u64,
};

/// Resolve and apply a list of pending relocations.
pub fn resolveAndApply(arch: Arch, buffer: []u8, pending: []const PendingReloc, symbols: []const SymbolAddr) Error!usize {
    var n: usize = 0;
    for (pending) |p| {
        const r = try resolve(p, symbols);
        _ = try apply(arch, buffer, r);
        n += 1;
    }
    return n;
}

// === Unit Tests ===

test "x86_64 R_X86_64_64 absolute" {
    var buf: [16]u8 = undefined;
    @memset(&buf, 0);

    const applied = try apply(.x86_64, &buf, .{
        .offset = 0,
        .type_id = X86_64.@"64",
        .symbol_address = 0x400000,
        .addend = 8,
        .place_address = 0x401000,
    });

    try std.testing.expectEqual(@as(u8, 8), applied.bytes_written);
    const got = std.mem.readInt(u64, buf[0..8], .little);
    try std.testing.expectEqual(@as(u64, 0x400008), got);
}

test "x86_64 R_X86_64_PC32 relative" {
    var buf: [8]u8 = undefined;
    @memset(&buf, 0);

    // S=0x401000, P=0x400000, A=0 → 0x1000
    _ = try apply(.x86_64, &buf, .{
        .offset = 0,
        .type_id = X86_64.PC32,
        .symbol_address = 0x401000,
        .addend = 0,
        .place_address = 0x400000,
    });

    const got = std.mem.readInt(u32, buf[0..4], .little);
    try std.testing.expectEqual(@as(u32, 0x1000), got);
}

test "x86_64 PC32 overflow is rejected" {
    var buf: [8]u8 = undefined;
    @memset(&buf, 0);

    const result = apply(.x86_64, &buf, .{
        .offset = 0,
        .type_id = X86_64.PC32,
        .symbol_address = 0x1_0000_0000,
        .addend = 0,
        .place_address = 0,
    });
    try std.testing.expectError(error.Overflow, result);
}

test "x86_64 R_X86_64_32 zero-extended" {
    var buf: [8]u8 = undefined;
    @memset(&buf, 0);

    _ = try apply(.x86_64, &buf, .{
        .offset = 0,
        .type_id = X86_64.@"32",
        .symbol_address = 0x1234,
        .addend = 1,
        .place_address = 0,
    });

    const got = std.mem.readInt(u32, buf[0..4], .little);
    try std.testing.expectEqual(@as(u32, 0x1235), got);
}

test "x86_64 R_X86_64_32 rejects high bits" {
    var buf: [8]u8 = undefined;
    @memset(&buf, 0);

    const result = apply(.x86_64, &buf, .{
        .offset = 0,
        .type_id = X86_64.@"32",
        .symbol_address = 0x1_0000_0000,
        .addend = 0,
        .place_address = 0,
    });
    try std.testing.expectError(error.Overflow, result);
}

test "x86_64 R_X86_64_32S accepts negative" {
    var buf: [8]u8 = undefined;
    @memset(&buf, 0);

    // True 64-bit representation of -2 (fits in signed 32).
    _ = try apply(.x86_64, &buf, .{
        .offset = 0,
        .type_id = X86_64.@"32S",
        .symbol_address = @as(u64, @bitCast(@as(i64, -2))),
        .addend = 0,
        .place_address = 0,
    });

    const got = std.mem.readInt(i32, buf[0..4], .little);
    try std.testing.expectEqual(@as(i32, -2), got);
}

test "x86_64 R_X86_64_PC64" {
    var buf: [16]u8 = undefined;
    @memset(&buf, 0);

    _ = try apply(.x86_64, &buf, .{
        .offset = 0,
        .type_id = X86_64.PC64,
        .symbol_address = 0x5000,
        .addend = 4,
        .place_address = 0x1000,
    });

    const got = std.mem.readInt(u64, buf[0..8], .little);
    try std.testing.expectEqual(@as(u64, 0x4004), got);
}

test "x86_64 NONE writes nothing" {
    var buf = [_]u8{ 0xAA, 0xBB, 0xCC, 0xDD };
    _ = try apply(.x86_64, &buf, .{
        .offset = 0,
        .type_id = X86_64.NONE,
        .symbol_address = 0x1234,
        .addend = 0,
        .place_address = 0,
    });
    try std.testing.expectEqual(@as(u8, 0xAA), buf[0]);
}

test "x86_64 unsupported type" {
    var buf: [8]u8 = undefined;
    const result = apply(.x86_64, &buf, .{
        .offset = 0,
        .type_id = 99,
        .symbol_address = 0,
        .addend = 0,
        .place_address = 0,
    });
    try std.testing.expectError(error.UnsupportedType, result);
}

test "out of bounds offset" {
    var buf: [4]u8 = undefined;
    const result = apply(.x86_64, &buf, .{
        .offset = 4,
        .type_id = X86_64.@"64",
        .symbol_address = 0,
        .addend = 0,
        .place_address = 0,
    });
    try std.testing.expectError(error.OutOfBounds, result);
}

test "truncated write" {
    var buf: [4]u8 = undefined;
    const result = apply(.x86_64, &buf, .{
        .offset = 0,
        .type_id = X86_64.@"64",
        .symbol_address = 1,
        .addend = 0,
        .place_address = 0,
    });
    try std.testing.expectError(error.Truncated, result);
}

test "aarch64 ABS64" {
    var buf: [16]u8 = undefined;
    @memset(&buf, 0);

    _ = try apply(.aarch64, &buf, .{
        .offset = 0,
        .type_id = AArch64.ABS64,
        .symbol_address = 0x8000,
        .addend = 16,
        .place_address = 0,
    });

    const got = std.mem.readInt(u64, buf[0..8], .little);
    try std.testing.expectEqual(@as(u64, 0x8010), got);
}

test "aarch64 ADR_PREL_PG_HI21 patches ADRP" {
    // ADRP x0, #0  → 0x90000000
    var buf = [_]u8{ 0x00, 0x00, 0x00, 0x90 };
    // S = 0x5000, P = 0x1000 → page delta = 0x4000 = 4 pages
    _ = try apply(.aarch64, &buf, .{
        .offset = 0,
        .type_id = AArch64.ADR_PREL_PG_HI21,
        .symbol_address = 0x5000,
        .addend = 0,
        .place_address = 0x1000,
    });

    const inst = std.mem.readInt(u32, &buf, .little);
    // ADRP opcode: bit 31 set, bits [28:24] == 10000.
    try std.testing.expectEqual(@as(u32, 1), (inst >> 31) & 1);
    try std.testing.expectEqual(@as(u32, 0x10), (inst >> 24) & 0x1F);
    // immlo (bits 30:29) should be 0 for 4 pages (4 & 3 == 0).
    try std.testing.expectEqual(@as(u32, 0), (inst >> 29) & 0x3);
    // immhi (bits 23:5) should be 1 (4 >> 2).
    try std.testing.expectEqual(@as(u32, 1), (inst >> 5) & 0x7FFFF);
}

test "aarch64 ADD_ABS_LO12_NC patches immediate" {
    // ADD x0, x0, #0 → 0x91000000
    var buf = [_]u8{ 0x00, 0x00, 0x00, 0x91 };
    _ = try apply(.aarch64, &buf, .{
        .offset = 0,
        .type_id = AArch64.ADD_ABS_LO12_NC,
        .symbol_address = 0x123,
        .addend = 0,
        .place_address = 0,
    });

    const inst = std.mem.readInt(u32, &buf, .little);
    const imm12 = (inst >> 10) & 0xFFF;
    try std.testing.expectEqual(@as(u32, 0x123), imm12);
}

test "aarch64 JUMP26 in range" {
    // B #0 → 0x14000000
    var buf = [_]u8{ 0x00, 0x00, 0x00, 0x14 };
    // delta = 16 bytes = 4 instructions
    _ = try apply(.aarch64, &buf, .{
        .offset = 0,
        .type_id = AArch64.JUMP26,
        .symbol_address = 0x1010,
        .addend = 0,
        .place_address = 0x1000,
    });

    const inst = std.mem.readInt(u32, &buf, .little);
    try std.testing.expectEqual(@as(u32, 4), inst & 0x03FFFFFF);
}

test "aarch64 CALL26 unaligned rejected" {
    var buf = [_]u8{ 0x00, 0x00, 0x00, 0x94 };
    const result = apply(.aarch64, &buf, .{
        .offset = 0,
        .type_id = AArch64.CALL26,
        .symbol_address = 0x1002,
        .addend = 0,
        .place_address = 0x1000,
    });
    try std.testing.expectError(error.Overflow, result);
}

test "aarch64 ADRP overflow" {
    var buf = [_]u8{ 0x00, 0x00, 0x00, 0x90 };
    const result = apply(.aarch64, &buf, .{
        .offset = 0,
        .type_id = AArch64.ADR_PREL_PG_HI21,
        .symbol_address = 0x2_0000_0000,
        .addend = 0,
        .place_address = 0,
    });
    try std.testing.expectError(error.Overflow, result);
}

test "applyAll processes multiple" {
    var buf: [32]u8 = undefined;
    @memset(&buf, 0);

    const relocs = [_]Reloc{
        .{ .offset = 0, .type_id = X86_64.@"64", .symbol_address = 0x100, .addend = 0, .place_address = 0 },
        .{ .offset = 8, .type_id = X86_64.PC32, .symbol_address = 0x200, .addend = 0, .place_address = 0x100 },
    };
    const n = try applyAll(.x86_64, &buf, &relocs);
    try std.testing.expectEqual(@as(usize, 2), n);

    const a = std.mem.readInt(u64, buf[0..8], .little);
    try std.testing.expectEqual(@as(u64, 0x100), a);
}

test "typeName coverage" {
    try std.testing.expectEqualStrings("PC32", typeName(.x86_64, X86_64.PC32));
    try std.testing.expectEqualStrings("ADR_PREL_PG_HI21", typeName(.aarch64, AArch64.ADR_PREL_PG_HI21));
    try std.testing.expectEqualStrings("UNKNOWN", typeName(.x86_64, 999));
}

test "checkSigned boundaries" {
    try checkSigned(0, 32);
    try checkSigned(0x7FFFFFFF, 32);
    try checkSigned(-0x80000000, 32);
    try std.testing.expectError(error.Overflow, checkSigned(0x80000000, 32));
    try std.testing.expectError(error.Overflow, checkSigned(-0x80000001, 32));
}

test "page alignment" {
    try std.testing.expectEqual(@as(i64, 0x1000), page(0x1234));
    try std.testing.expectEqual(@as(i64, 0x2000), page(0x2FFF));
    try std.testing.expectEqual(@as(i64, 0), page(0x0FFF));
}

// === Additional Phase 8 tests (40) ===

test "resolve finds symbol address" {
    const syms = [_]SymbolAddr{.{ .name = "main", .address = 0x401000 }};
    const r = try resolve(.{
        .offset = 0,
        .type_id = X86_64.@"64",
        .symbol_name = "main",
        .addend = 0,
        .place_address = 0x400000,
    }, &syms);
    try std.testing.expectEqual(@as(u64, 0x401000), r.symbol_address);
}

test "resolve missing symbol" {
    const syms = [_]SymbolAddr{.{ .name = "foo", .address = 1 }};
    const result = resolve(.{
        .offset = 0,
        .type_id = X86_64.@"64",
        .symbol_name = "bar",
        .addend = 0,
        .place_address = 0,
    }, &syms);
    try std.testing.expectError(error.UnresolvedSymbol, result);
}

test "resolveAndApply patches buffer" {
    var buf: [16]u8 = undefined;
    @memset(&buf, 0);
    const syms = [_]SymbolAddr{.{ .name = "val", .address = 0x42 }};
    const pending = [_]PendingReloc{.{
        .offset = 0,
        .type_id = X86_64.@"64",
        .symbol_name = "val",
        .addend = 1,
        .place_address = 0,
    }};
    const n = try resolveAndApply(.x86_64, &buf, &pending, &syms);
    try std.testing.expectEqual(@as(usize, 1), n);
    try std.testing.expectEqual(@as(u64, 0x43), std.mem.readInt(u64, buf[0..8], .little));
}

test "x86_64 64 with negative addend" {
    var buf: [8]u8 = undefined;
    @memset(&buf, 0);
    _ = try apply(.x86_64, &buf, .{ .offset = 0, .type_id = X86_64.@"64", .symbol_address = 100, .addend = -10, .place_address = 0 });
    try std.testing.expectEqual(@as(u64, 90), std.mem.readInt(u64, buf[0..8], .little));
}

test "x86_64 PC32 negative displacement" {
    var buf: [4]u8 = undefined;
    @memset(&buf, 0);
    _ = try apply(.x86_64, &buf, .{ .offset = 0, .type_id = X86_64.PC32, .symbol_address = 0x1000, .addend = 0, .place_address = 0x2000 });
    const got = std.mem.readInt(i32, &buf, .little);
    try std.testing.expectEqual(@as(i32, -0x1000), got);
}

test "x86_64 PC32 max positive" {
    var buf: [4]u8 = undefined;
    @memset(&buf, 0);
    _ = try apply(.x86_64, &buf, .{ .offset = 0, .type_id = X86_64.PC32, .symbol_address = 0x7FFFFFFF, .addend = 0, .place_address = 0 });
    try std.testing.expectEqual(@as(u32, 0x7FFFFFFF), std.mem.readInt(u32, &buf, .little));
}

test "x86_64 PC32 min negative" {
    var buf: [4]u8 = undefined;
    @memset(&buf, 0);
    _ = try apply(.x86_64, &buf, .{ .offset = 0, .type_id = X86_64.PC32, .symbol_address = 0, .addend = 0, .place_address = 0x80000000 });
    const got = std.mem.readInt(i32, &buf, .little);
    try std.testing.expectEqual(@as(i32, -0x80000000), got);
}

test "x86_64 32S overflow high" {
    var buf: [4]u8 = undefined;
    const result = apply(.x86_64, &buf, .{ .offset = 0, .type_id = X86_64.@"32S", .symbol_address = 0x80000000, .addend = 0, .place_address = 0 });
    try std.testing.expectError(error.Overflow, result);
}

test "x86_64 32 accepts zero" {
    var buf: [4]u8 = undefined;
    @memset(&buf, 0);
    _ = try apply(.x86_64, &buf, .{ .offset = 0, .type_id = X86_64.@"32", .symbol_address = 0, .addend = 0, .place_address = 0 });
    try std.testing.expectEqual(@as(u32, 0), std.mem.readInt(u32, &buf, .little));
}

test "x86_64 32 rejects negative" {
    var buf: [4]u8 = undefined;
    const result = apply(.x86_64, &buf, .{ .offset = 0, .type_id = X86_64.@"32", .symbol_address = 0, .addend = -1, .place_address = 0 });
    try std.testing.expectError(error.Overflow, result);
}

test "x86_64 write at non-zero offset" {
    var buf: [16]u8 = undefined;
    @memset(&buf, 0xFF);
    _ = try apply(.x86_64, &buf, .{ .offset = 4, .type_id = X86_64.@"32", .symbol_address = 0xABCD, .addend = 0, .place_address = 0 });
    try std.testing.expectEqual(@as(u8, 0xFF), buf[0]);
    try std.testing.expectEqual(@as(u32, 0xABCD), std.mem.readInt(u32, buf[4..8], .little));
}

test "x86_64 PC64 large positive" {
    var buf: [8]u8 = undefined;
    @memset(&buf, 0);
    _ = try apply(.x86_64, &buf, .{ .offset = 0, .type_id = X86_64.PC64, .symbol_address = 0xFFFF_FFFF_FFFF_0000, .addend = 0, .place_address = 0x1000 });
    const got = std.mem.readInt(u64, &buf, .little);
    try std.testing.expect(got > 0xFFFF_0000);
}

test "aarch64 ABS64 with addend" {
    var buf: [8]u8 = undefined;
    @memset(&buf, 0);
    _ = try apply(.aarch64, &buf, .{ .offset = 0, .type_id = AArch64.ABS64, .symbol_address = 0x1000, .addend = -8, .place_address = 0 });
    try std.testing.expectEqual(@as(u64, 0xFF8), std.mem.readInt(u64, &buf, .little));
}

test "aarch64 ADD lo12 wraps modulo 4096" {
    var buf = [_]u8{ 0x00, 0x00, 0x00, 0x91 };
    _ = try apply(.aarch64, &buf, .{ .offset = 0, .type_id = AArch64.ADD_ABS_LO12_NC, .symbol_address = 0x1FFF, .addend = 0, .place_address = 0 });
    const imm12 = (std.mem.readInt(u32, &buf, .little) >> 10) & 0xFFF;
    try std.testing.expectEqual(@as(u32, 0xFFF), imm12);
}

test "aarch64 JUMP26 zero delta" {
    var buf = [_]u8{ 0x00, 0x00, 0x00, 0x14 };
    _ = try apply(.aarch64, &buf, .{ .offset = 0, .type_id = AArch64.JUMP26, .symbol_address = 0x2000, .addend = 0, .place_address = 0x2000 });
    try std.testing.expectEqual(@as(u32, 0), std.mem.readInt(u32, &buf, .little) & 0x03FFFFFF);
}

test "aarch64 CALL26 positive" {
    var buf = [_]u8{ 0x00, 0x00, 0x00, 0x94 };
    _ = try apply(.aarch64, &buf, .{ .offset = 0, .type_id = AArch64.CALL26, .symbol_address = 0x1020, .addend = 0, .place_address = 0x1000 });
    try std.testing.expectEqual(@as(u32, 8), std.mem.readInt(u32, &buf, .little) & 0x03FFFFFF);
}

test "aarch64 JUMP26 overflow large" {
    var buf = [_]u8{ 0x00, 0x00, 0x00, 0x14 };
    const result = apply(.aarch64, &buf, .{ .offset = 0, .type_id = AArch64.JUMP26, .symbol_address = 0x1000_0000, .addend = 0, .place_address = 0 });
    try std.testing.expectError(error.Overflow, result);
}

test "aarch64 ADRP same page is zero" {
    var buf = [_]u8{ 0x00, 0x00, 0x00, 0x90 };
    _ = try apply(.aarch64, &buf, .{ .offset = 0, .type_id = AArch64.ADR_PREL_PG_HI21, .symbol_address = 0x1ABC, .addend = 0, .place_address = 0x1000 });
    // Page delta 0 → immediate bits stay 0.
    const inst = std.mem.readInt(u32, &buf, .little);
    try std.testing.expectEqual(@as(u32, 0), (inst >> 5) & 0x7FFFF);
}

test "aarch64 NONE preserves bytes" {
    var buf = [_]u8{ 1, 2, 3, 4 };
    _ = try apply(.aarch64, &buf, .{ .offset = 0, .type_id = AArch64.NONE, .symbol_address = 99, .addend = 0, .place_address = 0 });
    try std.testing.expectEqual(@as(u8, 1), buf[0]);
}

test "aarch64 unsupported" {
    var buf: [8]u8 = undefined;
    const result = apply(.aarch64, &buf, .{ .offset = 0, .type_id = 300, .symbol_address = 0, .addend = 0, .place_address = 0 });
    try std.testing.expectError(error.UnsupportedType, result);
}

test "applyAll stops on first error" {
    var buf: [16]u8 = undefined;
    @memset(&buf, 0);
    const relocs = [_]Reloc{
        .{ .offset = 0, .type_id = X86_64.@"64", .symbol_address = 1, .addend = 0, .place_address = 0 },
        .{ .offset = 8, .type_id = 99, .symbol_address = 0, .addend = 0, .place_address = 0 },
    };
    const result = applyAll(.x86_64, &buf, &relocs);
    try std.testing.expectError(error.UnsupportedType, result);
}

test "typeName all x86_64" {
    try std.testing.expectEqualStrings("NONE", typeName(.x86_64, 0));
    try std.testing.expectEqualStrings("64", typeName(.x86_64, 1));
    try std.testing.expectEqualStrings("32", typeName(.x86_64, 10));
    try std.testing.expectEqualStrings("32S", typeName(.x86_64, 11));
    try std.testing.expectEqualStrings("PC64", typeName(.x86_64, 24));
}

test "typeName all aarch64" {
    try std.testing.expectEqualStrings("ABS64", typeName(.aarch64, 257));
    try std.testing.expectEqualStrings("ADD_ABS_LO12_NC", typeName(.aarch64, 277));
    try std.testing.expectEqualStrings("JUMP26", typeName(.aarch64, 282));
    try std.testing.expectEqualStrings("CALL26", typeName(.aarch64, 283));
}

test "checkSigned 8-bit" {
    try checkSigned(127, 8);
    try checkSigned(-128, 8);
    try std.testing.expectError(error.Overflow, checkSigned(128, 8));
}

test "checkSigned 16-bit" {
    try checkSigned(32767, 16);
    try std.testing.expectError(error.Overflow, checkSigned(32768, 16));
}

test "checkSigned 26-bit" {
    try checkSigned((1 << 25) - 1, 26);
    try std.testing.expectError(error.Overflow, checkSigned(1 << 25, 26));
}

test "page of negative" {
    try std.testing.expectEqual(@as(i64, -0x1000), page(-1));
}

test "resolve empty symbol list" {
    const result = resolve(.{ .offset = 0, .type_id = 1, .symbol_name = "x", .addend = 0, .place_address = 0 }, &.{});
    try std.testing.expectError(error.UnresolvedSymbol, result);
}

test "resolve picks correct among many" {
    const syms = [_]SymbolAddr{
        .{ .name = "a", .address = 1 },
        .{ .name = "b", .address = 2 },
        .{ .name = "c", .address = 3 },
    };
    const r = try resolve(.{ .offset = 0, .type_id = 1, .symbol_name = "b", .addend = 0, .place_address = 0 }, &syms);
    try std.testing.expectEqual(@as(u64, 2), r.symbol_address);
}

test "x86_64 64 preserves surrounding bytes" {
    var buf = [_]u8{ 0x11, 0x22, 0x33, 0x44, 0, 0, 0, 0, 0, 0, 0, 0, 0x55, 0x66 };
    _ = try apply(.x86_64, &buf, .{ .offset = 4, .type_id = X86_64.@"64", .symbol_address = 0x01020304, .addend = 0, .place_address = 0 });
    try std.testing.expectEqual(@as(u8, 0x11), buf[0]);
    try std.testing.expectEqual(@as(u8, 0x55), buf[12]);
}

test "aarch64 ADD preserves opcode" {
    var buf = [_]u8{ 0x00, 0x00, 0x00, 0x91 };
    _ = try apply(.aarch64, &buf, .{ .offset = 0, .type_id = AArch64.ADD_ABS_LO12_NC, .symbol_address = 1, .addend = 0, .place_address = 0 });
    try std.testing.expectEqual(@as(u8, 0x91), buf[3]);
}

test "aarch64 JUMP26 preserves opcode" {
    var buf = [_]u8{ 0x00, 0x00, 0x00, 0x14 };
    _ = try apply(.aarch64, &buf, .{ .offset = 0, .type_id = AArch64.JUMP26, .symbol_address = 0x1004, .addend = 0, .place_address = 0x1000 });
    try std.testing.expectEqual(@as(u8, 0x14), buf[3]);
}

test "multiple pending resolveAndApply" {
    var buf: [32]u8 = undefined;
    @memset(&buf, 0);
    const syms = [_]SymbolAddr{
        .{ .name = "a", .address = 10 },
        .{ .name = "b", .address = 20 },
    };
    const pending = [_]PendingReloc{
        .{ .offset = 0, .type_id = X86_64.@"64", .symbol_name = "a", .addend = 0, .place_address = 0 },
        .{ .offset = 8, .type_id = X86_64.@"64", .symbol_name = "b", .addend = 5, .place_address = 0 },
    };
    const n = try resolveAndApply(.x86_64, &buf, &pending, &syms);
    try std.testing.expectEqual(@as(usize, 2), n);
    try std.testing.expectEqual(@as(u64, 10), std.mem.readInt(u64, buf[0..8], .little));
    try std.testing.expectEqual(@as(u64, 25), std.mem.readInt(u64, buf[8..16], .little));
}

test "x86_64 PC32 with addend" {
    var buf: [4]u8 = undefined;
    @memset(&buf, 0);
    _ = try apply(.x86_64, &buf, .{ .offset = 0, .type_id = X86_64.PC32, .symbol_address = 0x2000, .addend = 4, .place_address = 0x1000 });
    try std.testing.expectEqual(@as(u32, 0x1004), std.mem.readInt(u32, &buf, .little));
}

test "arch name" {
    try std.testing.expectEqualStrings("x86_64", Arch.x86_64.name());
    try std.testing.expectEqualStrings("aarch64", Arch.aarch64.name());
}

test "Applied fields populated" {
    var buf: [8]u8 = undefined;
    @memset(&buf, 0);
    const a = try apply(.x86_64, &buf, .{ .offset = 2, .type_id = X86_64.@"32", .symbol_address = 7, .addend = 0, .place_address = 0 });
    try std.testing.expectEqual(@as(u64, 2), a.offset);
    try std.testing.expectEqual(@as(u32, 10), a.type_id);
    try std.testing.expectEqual(@as(u8, 4), a.bytes_written);
}

test "truncated at offset near end" {
    var buf: [6]u8 = undefined;
    const result = apply(.x86_64, &buf, .{ .offset = 4, .type_id = X86_64.@"32", .symbol_address = 1, .addend = 0, .place_address = 0 });
    try std.testing.expectError(error.Truncated, result);
}

test "aarch64 ADRP one page forward" {
    var buf = [_]u8{ 0x00, 0x00, 0x00, 0x90 };
    _ = try apply(.aarch64, &buf, .{ .offset = 0, .type_id = AArch64.ADR_PREL_PG_HI21, .symbol_address = 0x2000, .addend = 0, .place_address = 0x1000 });
    const inst = std.mem.readInt(u32, &buf, .little);
    // immlo should be 1 (page delta = 1).
    try std.testing.expectEqual(@as(u32, 1), (inst >> 29) & 0x3);
}
