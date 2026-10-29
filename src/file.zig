//! Phase 1.5: File Reader and Memory Mapping for sibl.
//!
//! Maps input files directly into virtual memory for zero-copy slice access.
//! Handles both absolute and relative paths and gracefully treats empty files.

const std = @import("std");

/// A file mapped into memory for fast, read-only slice access.
pub const MappedFile = struct {
    data: []const u8,
    size: usize,
    map: ?std.Io.File.MemoryMap,

    /// Errors that can occur while opening or mapping a file.
    pub const OpenError = error{
        FileTooBig,
        FileNotFound,
        AccessDenied,
        OutOfMemory,
        SystemResources,
        Unexpected,
    };

    /// Open and memory-map a file for zero-copy read access.
    /// Empty files are handled specially and return an empty slice with no mapping.
    pub fn open(io: std.Io, file_path: []const u8) !MappedFile {
        var file = if (std.fs.path.isAbsolute(file_path))
            try std.Io.Dir.openFileAbsolute(io, file_path, .{ .mode = .read_only })
        else
            try std.Io.Dir.cwd().openFile(io, file_path, .{ .mode = .read_only });
        defer file.close(io);

        const raw_len = try file.length(io);
        const file_size = std.math.cast(usize, raw_len) orelse return error.FileTooBig;

        if (file_size == 0) {
            return .{
                .data = &.{},
                .size = 0,
                .map = null,
            };
        }

        const mapping = try file.createMemoryMap(io, .{
            .len = file_size,
            .protection = .{ .read = true },
        });

        return .{
            .data = mapping.memory,
            .size = file_size,
            .map = mapping,
        };
    }

    /// Unmap the file and clear the data slice.
    /// Safe to call even if the mapping was never created.
    pub fn deinit(self: *MappedFile, io: std.Io) void {
        if (self.map) |*m| {
            m.destroy(io);
            self.map = null;
        }
        self.data = &.{};
        self.size = 0;
    }
};

// === Unit Tests ===

test "open and memory map a file" {
    const io = std.testing.io;
    const test_path = "sibl_test_file.tmp";

    {
        var f = try std.Io.Dir.cwd().createFile(io, test_path, .{});
        defer f.close(io);
        try f.writeStreamingAll(io, "sibl linker test file content");
    }
    defer std.Io.Dir.cwd().deleteFile(io, test_path) catch {};

    var mf = try MappedFile.open(io, test_path);
    defer mf.deinit(io);

    try std.testing.expectEqualStrings("sibl linker test file content", mf.data);
    try std.testing.expectEqual(@as(usize, 29), mf.size);
}

test "open empty file without mmap failure" {
    const io = std.testing.io;
    const test_path = "sibl_empty_file.tmp";

    {
        var f = try std.Io.Dir.cwd().createFile(io, test_path, .{});
        defer f.close(io);
    }
    defer std.Io.Dir.cwd().deleteFile(io, test_path) catch {};

    var mf = try MappedFile.open(io, test_path);
    defer mf.deinit(io);

    try std.testing.expectEqual(@as(usize, 0), mf.size);
    try std.testing.expectEqual(@as(usize, 0), mf.data.len);
}

test "open non-existent file returns FileNotFound error" {
    const io = std.testing.io;
    const result = MappedFile.open(io, "this_file_does_not_exist_at_all.tmp");
    try std.testing.expectError(error.FileNotFound, result);
}

test "mapped file preserves exact binary bytes and slices" {
    const io = std.testing.io;
    const test_path = "sibl_binary_test.tmp";
    const binary_data = [_]u8{ 0x7F, 'E', 'L', 'F', 0x02, 0x01, 0x01, 0x00, 0xAA, 0xBB, 0xCC, 0xDD };

    {
        var f = try std.Io.Dir.cwd().createFile(io, test_path, .{});
        defer f.close(io);
        try f.writeStreamingAll(io, &binary_data);
    }
    defer std.Io.Dir.cwd().deleteFile(io, test_path) catch {};

    var mf = try MappedFile.open(io, test_path);
    defer mf.deinit(io);

    try std.testing.expectEqual(@as(usize, binary_data.len), mf.size);
    try std.testing.expectEqualSlices(u8, &binary_data, mf.data);
}

test "multiple files can be mapped and read concurrently" {
    const io = std.testing.io;
    const path1 = "sibl_multi_1.tmp";
    const path2 = "sibl_multi_2.tmp";

    {
        var f1 = try std.Io.Dir.cwd().createFile(io, path1, .{});
        defer f1.close(io);
        try f1.writeStreamingAll(io, "first object payload");

        var f2 = try std.Io.Dir.cwd().createFile(io, path2, .{});
        defer f2.close(io);
        try f2.writeStreamingAll(io, "second object payload");
    }
    defer {
        std.Io.Dir.cwd().deleteFile(io, path1) catch {};
        std.Io.Dir.cwd().deleteFile(io, path2) catch {};
    }

    var mf1 = try MappedFile.open(io, path1);
    defer mf1.deinit(io);

    var mf2 = try MappedFile.open(io, path2);
    defer mf2.deinit(io);

    try std.testing.expectEqualStrings("first object payload", mf1.data);
    try std.testing.expectEqualStrings("second object payload", mf2.data);
}
