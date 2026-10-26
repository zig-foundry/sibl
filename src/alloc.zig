//! Phase 1.2: Memory Allocator Setup for sibl.
//!
//! Provides an Arena Allocator for fast bulk allocations and a
//! stack buffer for small string formatting.

const std = @import("std");

/// Central allocator wrapper used throughout sibl linking phases.
pub const LinkerAllocators = struct {
    /// Arena allocator that frees all memory in one call at the end
    arena_state: std.heap.ArenaAllocator,
    /// Backing allocator used for dynamic structures that need manual resizing
    base_allocator: std.mem.Allocator,

    /// Initialize the arena using an existing backing allocator.
    pub fn init(base: std.mem.Allocator) LinkerAllocators {
        return .{
            .arena_state = std.heap.ArenaAllocator.init(base),
            .base_allocator = base,
        };
    }

    /// Free all memory held inside the arena.
    pub fn deinit(self: *LinkerAllocators) void {
        self.arena_state.deinit();
    }

    /// Fast allocator for symbols, strings, and parsed object data.
    pub fn arena(self: *LinkerAllocators) std.mem.Allocator {
        return self.arena_state.allocator();
    }

    /// General purpose allocator for structures that need manual resizing or freeing.
    pub fn gpa(self: *LinkerAllocators) std.mem.Allocator {
        return self.base_allocator;
    }
};

/// A fixed 4 KB stack buffer for assembling file paths and short messages.
pub const ScratchBuffer = struct {
    buffer: [4096]u8 = undefined,

    pub fn fixedBufferAllocator(self: *ScratchBuffer) std.heap.FixedBufferAllocator {
        return std.heap.FixedBufferAllocator.init(&self.buffer);
    }
};

// === Unit Tests ===

test "allocators initialization and arena bulk free" {
    var allocs = LinkerAllocators.init(std.testing.allocator);
    defer allocs.deinit();

    const a = allocs.arena();
    const slice = try a.alloc(u8, 1024);
    try std.testing.expectEqual(@as(usize, 1024), slice.len);
}

test "arena allocates multiple buffers in sequence" {
    var allocs = LinkerAllocators.init(std.testing.allocator);
    defer allocs.deinit();

    const a = allocs.arena();
    const buf1 = try a.alloc(u8, 64);
    const buf2 = try a.alloc(u8, 128);
    const buf3 = try a.alloc(u8, 256);

    try std.testing.expectEqual(@as(usize, 64), buf1.len);
    try std.testing.expectEqual(@as(usize, 128), buf2.len);
    try std.testing.expectEqual(@as(usize, 256), buf3.len);
}

test "scratch buffer formats text within limit" {
    var scratch = ScratchBuffer{};
    var fba = scratch.fixedBufferAllocator();
    const a = fba.allocator();

    const msg = try std.fmt.allocPrint(a, "output_{s}_{d}.bin", .{ "test", 42 });
    try std.testing.expectEqualStrings("output_test_42.bin", msg);
}

test "scratch buffer fails on overflow exceeding buffer size" {
    var scratch = ScratchBuffer{};
    var fba = scratch.fixedBufferAllocator();
    const a = fba.allocator();

    // 5000 bytes exceeds the 4096-byte fixed buffer size
    try std.testing.expectError(error.OutOfMemory, a.alloc(u8, 5000));
}

test "gpa allocator works for manual allocation and free" {
    var allocs = LinkerAllocators.init(std.testing.allocator);
    defer allocs.deinit();

    const g = allocs.gpa();
    const slice = try g.alloc(u32, 16);
    defer g.free(slice);

    slice[0] = 0xDEADBEEF;
    try std.testing.expectEqual(@as(u32, 0xDEADBEEF), slice[0]);
}

test "arena handles zero-byte allocation cleanly" {
    var allocs = LinkerAllocators.init(std.testing.allocator);
    defer allocs.deinit();

    const a = allocs.arena();
    const zero = try a.alloc(u8, 0);
    try std.testing.expectEqual(@as(usize, 0), zero.len);
}
