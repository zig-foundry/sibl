//! Phase 2.4: String Table Decoder and Builder for sibl.
//!
//! Provides zero-copy reading for input string tables (.strtab, .shstrtab, .dynstr)
//! and a deduplicating string table builder for generating output binaries.

const std = @import("std");

// === String Table Reader ===

/// Zero-copy reader for ELF string tables.
pub const StringTableReader = struct {
    /// Raw slice of the string table section
    data: []const u8,

    pub const ReadError = error{
        OutOfBounds,
        MissingNullTerminator,
    };

    /// Initialize reader with the raw section bytes.
    pub fn init(data: []const u8) StringTableReader {
        return .{ .data = data };
    }

    /// Look up a null-terminated string at the given byte offset.
    pub fn get(self: StringTableReader, offset: u32) ReadError![:0]const u8 {
        if (offset >= self.data.len) {
            return error.OutOfBounds;
        }

        const slice = self.data[offset..];
        const len = std.mem.indexOfScalar(u8, slice, 0) orelse return error.MissingNullTerminator;
        return slice[0..len :0];
    }

    /// Check if offset points to an empty string.
    pub fn isEmptyAt(self: StringTableReader, offset: u32) bool {
        if (offset >= self.data.len) return true;
        return self.data[offset] == 0;
    }

    /// Return an iterator over all strings inside the table.
    pub fn iterator(self: StringTableReader) Iterator {
        return .{
            .data = self.data,
            .offset = 0,
        };
    }

    // --- Reader Iterator ---

    pub const Iterator = struct {
        data: []const u8,
        offset: usize,

        pub const Entry = struct {
            offset: u32,
            string: [:0]const u8,
        };

        /// Returns the next valid string entry, or null when finished.
        pub fn next(self: *Iterator) ?Entry {
            // Skip leading null bytes
            while (self.offset < self.data.len and self.data[self.offset] == 0) {
                self.offset += 1;
            }

            if (self.offset >= self.data.len) return null;

            const current_offset: u32 = @intCast(self.offset);
            const remaining = self.data[self.offset..];
            const len = std.mem.indexOfScalar(u8, remaining, 0) orelse {
                self.offset = self.data.len;
                return null;
            };

            const str = remaining[0..len :0];
            self.offset += len + 1;

            return .{
                .offset = current_offset,
                .string = str,
            };
        }
    };
};

// === String Table Builder ===

/// Deduplicating string table builder for generating output ELF binaries.
pub const StringTableBuilder = struct {
    /// Contiguous byte buffer storing null-terminated strings
    buffer: std.ArrayListUnmanaged(u8) = .empty,
    /// Map storing string slice to existing offset in buffer
    lookup: std.StringHashMapUnmanaged(u32) = .empty,

    /// Initialize a new string table builder.
    /// In ELF format, offset 0 must always be an empty string (\0).
    pub fn init(allocator: std.mem.Allocator) !StringTableBuilder {
        var self = StringTableBuilder{};
        errdefer self.deinit(allocator);

        // Byte 0 is always null
        try self.buffer.append(allocator, 0);
        try self.lookup.put(allocator, "", 0);

        return self;
    }

    /// Free resources held by the builder.
    pub fn deinit(self: *StringTableBuilder, allocator: std.mem.Allocator) void {
        self.buffer.deinit(allocator);
        self.lookup.deinit(allocator);
    }

    /// Insert a string into the table and return its byte offset.
    /// If the string was already added, returns the existing offset.
    pub fn insert(self: *StringTableBuilder, allocator: std.mem.Allocator, str: []const u8) !u32 {
        if (str.len == 0) return 0;

        // Check if string already exists
        if (self.lookup.get(str)) |existing_offset| {
            return existing_offset;
        }

        const offset: u32 = @intCast(self.buffer.items.len);

        // Append string bytes and null terminator
        try self.buffer.appendSlice(allocator, str);
        try self.buffer.append(allocator, 0);

        // Track in map using stable buffer slice
        const stored_slice = self.buffer.items[offset .. offset + str.len];
        try self.lookup.put(allocator, stored_slice, offset);

        return offset;
    }

    /// Get raw bytes of the string table.
    pub fn getBytes(self: StringTableBuilder) []const u8 {
        return self.buffer.items;
    }

    /// Total byte size of the string table.
    pub fn size(self: StringTableBuilder) usize {
        return self.buffer.items.len;
    }
};

// === Unit Tests ===

test "string table reader looks up strings by offset" {
    const raw_table = "\x00.text\x00.data\x00main\x00";
    const reader = StringTableReader.init(raw_table);

    try std.testing.expectEqualStrings("", try reader.get(0));
    try std.testing.expectEqualStrings(".text", try reader.get(1));
    try std.testing.expectEqualStrings(".data", try reader.get(7));
    try std.testing.expectEqualStrings("main", try reader.get(13));
}

test "string table reader handles bounds errors cleanly" {
    const raw_table = "\x00symbol\x00";
    const reader = StringTableReader.init(raw_table);

    try std.testing.expectError(error.OutOfBounds, reader.get(20));

    // Unterminated slice
    const bad_table = "unterminated";
    const bad_reader = StringTableReader.init(bad_table);
    try std.testing.expectError(error.MissingNullTerminator, bad_reader.get(0));
}

test "string table reader iterator returns all entries" {
    const raw_table = "\x00puts\x00free\x00malloc\x00";
    const reader = StringTableReader.init(raw_table);
    var iter = reader.iterator();

    const entry1 = iter.next().?;
    try std.testing.expectEqual(@as(u32, 1), entry1.offset);
    try std.testing.expectEqualStrings("puts", entry1.string);

    const entry2 = iter.next().?;
    try std.testing.expectEqual(@as(u32, 6), entry2.offset);
    try std.testing.expectEqualStrings("free", entry2.string);

    const entry3 = iter.next().?;
    try std.testing.expectEqual(@as(u32, 11), entry3.offset);
    try std.testing.expectEqualStrings("malloc", entry3.string);

    try std.testing.expect(iter.next() == null);
}

test "string table builder starts with null at offset 0" {
    var builder = try StringTableBuilder.init(std.testing.allocator);
    defer builder.deinit(std.testing.allocator);

    try std.testing.expectEqual(@as(usize, 1), builder.size());
    try std.testing.expectEqual(@as(u8, 0), builder.getBytes()[0]);
    try std.testing.expectEqual(@as(u32, 0), try builder.insert(std.testing.allocator, ""));
}

test "string table builder deduplicates identical strings" {
    var builder = try StringTableBuilder.init(std.testing.allocator);
    defer builder.deinit(std.testing.allocator);

    const off1 = try builder.insert(std.testing.allocator, ".text");
    const off2 = try builder.insert(std.testing.allocator, ".data");
    const off3 = try builder.insert(std.testing.allocator, ".text"); // Duplicate

    try std.testing.expectEqual(@as(u32, 1), off1);
    try std.testing.expectEqual(@as(u32, 7), off2);
    try std.testing.expectEqual(off1, off3); // Must reuse off1

    const bytes = builder.getBytes();
    const reader = StringTableReader.init(bytes);

    try std.testing.expectEqualStrings(".text", try reader.get(off1));
    try std.testing.expectEqualStrings(".data", try reader.get(off2));
}
