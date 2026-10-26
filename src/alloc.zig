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

test "allocators initialization and arena bulk free" {
    // Uses the test runner allocator so there are no dangling pointers or hangs
    var allocs = LinkerAllocators.init(std.testing.allocator);
    defer allocs.deinit();

    const a = allocs.arena();
    const slice = try a.alloc(u8, 1024);
    try std.testing.expectEqual(@as(usize, 1024), slice.len);
}
