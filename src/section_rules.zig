//! Phase 9.2: Custom Section Placement Rules.
//!
//! Supports basic placement rules for embedded or custom memory maps:
//! - `--place PATTERN=DEST` moves matching input sections into the output
//!   section `DEST`, or into a named memory region when `DEST` matches a
//!   region added earlier (first rule wins)
//! - `--pin PATTERN=ADDR` pins the holding output section at an exact
//!   virtual address
//! - `--region NAME=ADDR:SIZE` defines a memory region (RAM, FLASH, ...)
//!   that sequentially allocates the sections assigned to it
//!
//! Patterns match the original input section name: exact text, a prefix
//! followed by `*` (`.text.*`), or a single `*` as catch-all. Rules are
//! checked in the order they were added.

const std = @import("std");
const layout = @import("layout.zig");

/// Errors that can occur while building or applying placement rules.
pub const Error = error{
    OutOfMemory,
    /// A rule spec does not follow the documented `--place` / `--pin` /
    /// `--region` syntax.
    InvalidSpec,
    /// A region rule references a region name that was never defined.
    UnknownRegion,
    /// The target region ran out of space for the assigned section.
    RegionFull,
};

/// What a matching rule does with an input section.
pub const Action = union(enum) {
    /// Move the input into an output section with this name.
    output_name: []const u8,
    /// Pin the holding output section at this exact virtual address.
    address: u64,
    /// Allocate the input inside the named memory region.
    region: []const u8,
};

/// One placement rule: a name pattern plus its action.
pub const Rule = struct {
    /// Input section name pattern (exact, `prefix*`, or catch-all `*`).
    pattern: []const u8,
    action: Action,
};

/// A named memory region for embedded memory maps. The cursor tracks
/// allocation as region rules are applied.
pub const MemoryRegion = struct {
    /// Region name (owned by the rule set).
    name: []const u8,
    /// First byte address of the region.
    address: u64,
    /// Total size in bytes.
    size: u64,
    /// Next free byte address (starts at `address`).
    cursor: u64 = 0,

    /// Bytes still free in the region.
    pub fn freeBytes(self: MemoryRegion) u64 {
        return self.address + self.size - self.cursor;
    }

    /// True once anything was allocated in the region.
    pub fn isUsed(self: MemoryRegion) bool {
        return self.cursor > self.address;
    }
};

/// Result of applying the rules to one input section.
pub const Placement = struct {
    /// Pinned virtual address for the holding output section
    /// (address or region rules), or null for move rules / no match.
    address: ?u64 = null,
};

/// Collection of placement rules and memory regions.
pub const RuleSet = struct {
    rules: std.ArrayListUnmanaged(Rule),
    regions: std.ArrayListUnmanaged(MemoryRegion),
    allocator: std.mem.Allocator,

    pub fn init(allocator: std.mem.Allocator) RuleSet {
        return .{
            .rules = .empty,
            .regions = .empty,
            .allocator = allocator,
        };
    }

    pub fn deinit(self: *RuleSet) void {
        // Rule strings are borrowed from the caller; only region names are owned.
        self.rules.deinit(self.allocator);
        for (self.regions.items) |*region| {
            self.allocator.free(region.name);
        }
        self.regions.deinit(self.allocator);
        self.* = undefined;
    }

    /// Number of rules added so far.
    pub fn ruleCount(self: *const RuleSet) usize {
        return self.rules.items.len;
    }

    /// Number of memory regions defined so far.
    pub fn regionCount(self: *const RuleSet) usize {
        return self.regions.items.len;
    }

    /// Add a rule directly.
    pub fn addRule(self: *RuleSet, pattern: []const u8, action: Action) Error!void {
        try self.rules.append(self.allocator, .{ .pattern = pattern, .action = action });
    }

    /// Look up or create a named region. When created, `cursor` starts at
    /// `address`. Returns the index of the region inside `self.regions`.
    pub fn addRegion(self: *RuleSet, name: []const u8, address: u64, size: u64) Error!void {
        for (self.regions.items) |*region| {
            if (std.mem.eql(u8, region.name, name)) {
                // Redefinition: update the extent and reset the cursor.
                region.address = address;
                region.size = size;
                region.cursor = address;
                return;
            }
        }
        const owned = try self.allocator.dupe(u8, name);
        errdefer self.allocator.free(owned);
        try self.regions.append(self.allocator, .{
            .name = owned,
            .address = address,
            .size = size,
            .cursor = address,
        });
    }

    fn findRegion(self: *const RuleSet, name: []const u8) ?*MemoryRegion {
        for (self.regions.items) |*region| {
            if (std.mem.eql(u8, region.name, name)) return region;
        }
        return null;
    }

    /// Parse a `--place PATTERN=DEST` spec.
    ///
    /// When `DEST` matches a previously defined region the rule allocates
    /// inside that region; otherwise it moves matching inputs into the
    /// output section named `DEST`.
    pub fn addMoveSpec(self: *RuleSet, spec: []const u8) Error!void {
        const eq = std.mem.indexOfScalar(u8, spec, '=') orelse return error.InvalidSpec;
        const pattern = spec[0..eq];
        const dest = spec[eq + 1 ..];
        if (pattern.len == 0 or dest.len == 0) return error.InvalidSpec;
        if (self.findRegion(dest)) |_| {
            try self.addRule(pattern, .{ .region = dest });
        } else {
            try self.addRule(pattern, .{ .output_name = dest });
        }
    }

    /// Parse a `--pin PATTERN=ADDR` spec: pin the holding output section at
    /// an exact virtual address. Accepts decimal, `0x` hex, and `0b` binary.
    pub fn addPinSpec(self: *RuleSet, spec: []const u8) Error!void {
        const eq = std.mem.indexOfScalar(u8, spec, '=') orelse return error.InvalidSpec;
        const pattern = spec[0..eq];
        const addr_text = spec[eq + 1 ..];
        if (pattern.len == 0 or addr_text.len == 0) return error.InvalidSpec;
        const address = std.fmt.parseInt(u64, addr_text, 0) catch return error.InvalidSpec;
        try self.addRule(pattern, .{ .address = address });
    }

    /// Parse a `--region NAME=ADDR:SIZE` spec.
    pub fn addRegionSpec(self: *RuleSet, spec: []const u8) Error!void {
        const eq = std.mem.indexOfScalar(u8, spec, '=') orelse return error.InvalidSpec;
        const name = spec[0..eq];
        const rest = spec[eq + 1 ..];
        const colon = std.mem.indexOfScalar(u8, rest, ':') orelse return error.InvalidSpec;
        const addr_text = rest[0..colon];
        const size_text = rest[colon + 1 ..];
        if (name.len == 0 or addr_text.len == 0 or size_text.len == 0) return error.InvalidSpec;
        const address = std.fmt.parseInt(u64, addr_text, 0) catch return error.InvalidSpec;
        const size = std.fmt.parseInt(u64, size_text, 0) catch return error.InvalidSpec;
        try self.addRegion(name, address, size);
    }

    /// Apply the rules to one input section before `Layout.addInput`.
    ///
    /// A move rule renames `input.name` so the section groups under the
    /// rule's output section (parent allocation through `Layout.addInput`
    /// stays unchanged). An address or region rule returns the pinned
    /// virtual address; region rules advance the region cursor by
    /// `input.data.len`, aligned up to `input.alignment`, and fail with
    /// `error.RegionFull` when the region cannot hold the input.
    ///
    /// Rules are evaluated in insertion order; the first match wins.
    pub fn apply(self: *RuleSet, input: *layout.InputSection) Error!Placement {
        for (self.rules.items) |rule| {
            if (!matches(rule.pattern, input.name)) continue;
            switch (rule.action) {
                .output_name => |name| {
                    input.name = name;
                    return .{ .address = null };
                },
                .address => |addr| {
                    return .{ .address = addr };
                },
                .region => |region_name| {
                    const region = self.findRegion(region_name) orelse return error.UnknownRegion;
                    const start = layout.alignTo(region.cursor, @max(input.alignment, 1));
                    const end = start + input.data.len;
                    if (end > region.address + region.size) return error.RegionFull;
                    region.cursor = end;
                    return .{ .address = start };
                },
            }
        }
        return .{};
    }
};

/// Return true when `name` matches `pattern`.
///
/// - `*` matches every name (catch-all)
/// - a pattern ending with `*` matches by prefix (`.text.*`)
/// - anything else must compare equal byte for byte
pub fn matches(pattern: []const u8, name: []const u8) bool {
    if (std.mem.eql(u8, pattern, "*")) return true;
    if (pattern.len > 0 and pattern[pattern.len - 1] == '*') {
        return std.mem.startsWith(u8, name, pattern[0 .. pattern.len - 1]);
    }
    return std.mem.eql(u8, pattern, name);
}

// === Unit Tests ===

const testing = std.testing;

test "matches handles exact, prefix, and catch-all patterns" {
    try testing.expect(matches(".text", ".text"));
    try testing.expect(!matches(".text", ".text.foo"));
    try testing.expect(matches(".text.*", ".text.foo"));
    try testing.expect(!matches(".text.*", ".data.foo"));
    try testing.expect(matches("*", ".anything"));
    try testing.expect(matches("", ""));
    try testing.expect(!matches("", "x"));
}

const filler = "AAAAAAAAAAAAAAAA";

fn testInput(name: []const u8, size: usize) layout.InputSection {
    return .{
        .name = name,
        .data = filler[0..size],
        .alignment = 1,
        .is_alloc = true,
        .is_writable = false,
        .is_executable = false,
        .is_nobits = false,
        .file_index = 0,
    };
}

test "move rule renames the input section" {
    var rules = RuleSet.init(testing.allocator);
    defer rules.deinit();
    try rules.addMoveSpec(".hot=.fast_text");

    var input = testInput(".hot", 4);
    const placement = try rules.apply(&input);
    try testing.expectEqual(@as(?u64, null), placement.address);
    try testing.expectEqualStrings(".fast_text", input.name);
}

test "first matching rule wins" {
    var rules = RuleSet.init(testing.allocator);
    defer rules.deinit();
    try rules.addRule("*", .{ .output_name = ".catch_all" });

    var input = testInput(".weird", 2);
    const placement = try rules.apply(&input);
    try testing.expectEqual(@as(?u64, null), placement.address);
    try testing.expectEqualStrings(".catch_all", input.name);
}

test "pin rule returns the exact address" {
    var rules = RuleSet.init(testing.allocator);
    defer rules.deinit();
    try rules.addPinSpec(".isr_vector=0x08000000");

    var input = testInput(".isr_vector", 16);
    const placement = try rules.apply(&input);
    try testing.expectEqual(@as(?u64, 0x08000000), placement.address);
    try testing.expectEqualStrings(".isr_vector", input.name);
}

test "region rule allocates consecutively with alignment" {
    var rules = RuleSet.init(testing.allocator);
    defer rules.deinit();
    try rules.addRegion("FLASH", 0x08000000, 0x10000);
    try rules.addRule(".vector", .{ .region = "FLASH" });
    try rules.addRule(".text.*", .{ .region = "FLASH" });
    try rules.addRule("*", .{ .region = "FLASH" });

    var a = testInput(".vector", 4);
    a.alignment = 8;
    const pa = try rules.apply(&a);
    try testing.expectEqual(@as(?u64, 0x08000000), pa.address);
    // Cursor advanced by 4; the next section needs an 8-byte alignment gap.

    var b = testInput(".text.foo", 6);
    b.alignment = 8;
    const pb = try rules.apply(&b);
    try testing.expectEqual(@as(?u64, 0x08000008), pb.address);

    var c = testInput(".more", 2);
    // Cursor sits at 0x0800000E after the 6 bytes of member B.
    const pc = try rules.apply(&c);
    try testing.expectEqual(@as(?u64, 0x0800000E), pc.address);
}

test "region rule reports RegionFull when out of space" {
    var rules = RuleSet.init(testing.allocator);
    defer rules.deinit();
    try rules.addRegion("RAM", 0x20000000, 8);
    try rules.addRule("*", .{ .region = "RAM" });

    var a = testInput(".data.a", 6);
    const ra = try rules.apply(&a);
    try testing.expectEqual(@as(?u64, 0x20000000), ra.address);

    var b = testInput(".data.b", 3);
    try testing.expectError(error.RegionFull, rules.apply(&b));
}

test "region rule fails with UnknownRegion when undefined" {
    var rules = RuleSet.init(testing.allocator);
    defer rules.deinit();
    // Region defined after the rule, but only if addRegion ran; here it
    // never runs, so the region lookup fails at apply time.
    try rules.addRule(".fast_local", .{ .region = "TCM" });

    var input = testInput(".fast_local", 4);
    try testing.expectError(error.UnknownRegion, rules.apply(&input));
}

test "place spec targets a region when the name matches" {
    var rules = RuleSet.init(testing.allocator);
    defer rules.deinit();
    try rules.addRegionSpec("FLASH=0x08000000:0x10000");
    try rules.addMoveSpec(".isr_hash=FLASH");

    var input = testInput(".isr_hash", 12);
    const placement = try rules.apply(&input);
    try testing.expectEqual(@as(?u64, 0x08000000), placement.address);
}

test "rule specs parse decimal, hex, and binary numbers" {
    var rules = RuleSet.init(testing.allocator);
    defer rules.deinit();
    try rules.addRegionSpec("RAM=0x20000000:4096");
    try rules.addPinSpec(".entry=4096");
    try rules.addPinSpec(".code=0b10000000000000");
    try rules.addRule(".entry", .{ .address = 4096 });
    try rules.addRule(".code", .{ .address = 0b10000000000000 });

    // Decimal spec pins .entry at 4096.
    var entry_input = testInput(".entry", 1);
    const entry_placement = try rules.apply(&entry_input);
    try testing.expectEqual(@as(?u64, 4096), entry_placement.address);

    // Binary spec pins .code at 2^13 = 0x2000.
    var code_input = testInput(".code", 1);
    const placement = try rules.apply(&code_input);
    try testing.expectEqual(@as(?u64, 0x2000), placement.address);
}

test "invalid specs return InvalidSpec" {
    var rules = RuleSet.init(testing.allocator);
    defer rules.deinit();
    try testing.expectError(error.InvalidSpec, rules.addMoveSpec(".no_equals"));
    try testing.expectError(error.InvalidSpec, rules.addMoveSpec("=.dest"));
    try testing.expectError(error.InvalidSpec, rules.addMoveSpec(".src="));
    try testing.expectError(error.InvalidSpec, rules.addPinSpec(".pin=0xzz"));
    try testing.expectError(error.InvalidSpec, rules.addPinSpec(".pin="));
    try testing.expectError(error.InvalidSpec, rules.addRegionSpec("R=0x100"));
    try testing.expectError(error.InvalidSpec, rules.addRegionSpec("R=0x100:"));
    try testing.expectError(error.InvalidSpec, rules.addRegionSpec("R=zzz:0x10"));
}

test "region redefinition resets the cursor" {
    var rules = RuleSet.init(testing.allocator);
    defer rules.deinit();
    try rules.addRegion("RAM", 0x20000000, 16);
    var a = testInput(".x", 4);
    _ = try rules.apply(&a);

    try rules.addRegion("RAM", 0x20001000, 16);
    for (rules.regions.items) |*r| {
        if (std.mem.eql(u8, r.name, "RAM")) {
            try testing.expectEqual(@as(u64, 0x20001000), r.cursor);
            try testing.expectEqual(@as(u64, 0x20001000), r.address);
        }
    }
}

test "freeBytes and isUsed track region state" {
    var rules = RuleSet.init(testing.allocator);
    defer rules.deinit();
    try rules.addRegion("RAM", 0x20000000, 16);
    try rules.addRule("*", .{ .region = "RAM" });
    const region = rules.findRegion("RAM").?;
    try testing.expectEqual(@as(u64, 16), region.freeBytes());
    try testing.expect(!region.isUsed());

    var a = testInput(".x", 4);
    _ = try rules.apply(&a);
    try testing.expectEqual(@as(u64, 12), region.freeBytes());
    try testing.expect(region.isUsed());
}

test "region cursor flows into layout pinning end to end" {
    var rules = RuleSet.init(testing.allocator);
    defer rules.deinit();
    try rules.addRegion("FLASH", 0x08000000, 0x1000);
    try rules.addMoveSpec(".isr*=FLASH");

    var l = layout.Layout.init(testing.allocator, 0x400000, 4096);
    defer l.deinit();

    var input = testInput(".isr_vector", 16);
    const placement = try rules.apply(&input);
    try l.addInput(input);
    if (placement.address) |pin| {
        try l.pinOutput(layout.canonicalizeName(input.name), pin);
    }
    l.computeAddresses();

    const va = l.get(".isr_vector").?.virtual_address;
    try testing.expectEqual(@as(u64, 0x08000000), va);
}
