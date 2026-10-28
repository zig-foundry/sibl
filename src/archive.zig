//! Phase 5.1 & 5.2: Static Archive Header Validation, Member Parser, and Symbol Index.
//!
//! Provides zero-copy parsing for Unix static archives (.a) and Windows
//! import/static libraries (.lib), supporting GNU ('/') and BSD ('__.SYMDEF') symbol indices.

const std = @import("std");

// === Constants and Signatures ===

/// Standard 8-byte archive global magic header ("!<arch>\n").
pub const ARMAG = "!<arch>\n";

/// GNU thin archive 8-byte global magic header ("!<thin>\n").
pub const THIN_ARMAG = "!<thin>\n";

/// Fixed 2-byte member header trailer magic ("`\n").
pub const ARFMAG = "`\n";

// === Error Sets ===

pub const Error = error{
    TruncatedArchive,
    InvalidArchiveMagic,
    TruncatedMemberHeader,
    InvalidTrailerMagic,
    InvalidDecimalField,
    InvalidOctalField,
    InvalidMemberSize,
    StringTableOutOfBounds,
    TruncatedSymbolTable,
    InvalidSymbolTable,
};

// === Helper Numeric Parsers ===

fn parseDecimal(comptime T: type, raw: []const u8) Error!T {
    const trimmed = std.mem.trim(u8, raw, " \t\r\n");
    if (trimmed.len == 0) return 0;
    return std.fmt.parseInt(T, trimmed, 10) catch error.InvalidDecimalField;
}

fn parseOctal(comptime T: type, raw: []const u8) Error!T {
    const trimmed = std.mem.trim(u8, raw, " \t\r\n");
    if (trimmed.len == 0) return 0;
    return std.fmt.parseInt(T, trimmed, 8) catch error.InvalidOctalField;
}

// === Archive Symbol Representation ===

/// Normalized symbol mapping an exported identifier to its defining member header offset.
pub const ArchiveSymbol = struct {
    name: []const u8,
    /// Byte offset in the archive file where the defining member's 60-byte header begins.
    member_offset: usize,
};

// === Decoded Member Header ===

/// Normalized representation for a 60-byte archive member header.
pub const MemberHeader = struct {
    raw_name: [16]u8,
    date: u64,
    uid: u32,
    gid: u32,
    mode: u32,
    size: u64,

    /// Byte offset in archive file where this 60-byte header starts.
    header_offset: usize,
    /// Byte offset in archive file where the member payload starts.
    data_offset: usize,

    /// Returns true if this member is the GNU/SysV symbol table ("/").
    pub fn isGnuSymbolTable(self: *const MemberHeader) bool {
        const trimmed = std.mem.trim(u8, &self.raw_name, " ");
        return std.mem.eql(u8, trimmed, "/");
    }

    /// Returns true if this member is the GNU/Windows long filenames string table ("//").
    pub fn isGnuStringTable(self: *const MemberHeader) bool {
        const trimmed = std.mem.trim(u8, &self.raw_name, " ");
        return std.mem.eql(u8, trimmed, "//");
    }

    /// Returns true if this member is a BSD symbol table ("__.SYMDEF" or "__.SYMDEF SORTED").
    pub fn isBsdSymbolTable(self: *const MemberHeader, file_bytes: []const u8) bool {
        const name = self.getName(file_bytes, null) catch return false;
        return std.mem.startsWith(u8, name, "__.SYMDEF");
    }

    /// Returns true if this member uses BSD extended filename encoding ("#1/<len>").
    pub fn isBsdExtendedName(self: *const MemberHeader) bool {
        return std.mem.startsWith(u8, &self.raw_name, "#1/");
    }

    /// Returns true if this member uses GNU long filename offset reference ("/<offset>").
    pub fn isGnuLongName(self: *const MemberHeader) bool {
        return self.raw_name[0] == '/' and self.raw_name[1] >= '0' and self.raw_name[1] <= '9';
    }

    /// Resolve the clean filename for this member across standard, GNU, and BSD conventions.
    pub fn getName(
        self: *const MemberHeader,
        file_bytes: []const u8,
        gnu_strtab: ?[]const u8,
    ) Error![]const u8 {
        // 1. BSD extended filename: #1/<len>
        if (self.isBsdExtendedName()) {
            const trimmed = std.mem.trim(u8, self.raw_name[3..], " ");
            const name_len = std.fmt.parseInt(usize, trimmed, 10) catch return error.InvalidDecimalField;

            if (self.data_offset + name_len > file_bytes.len or name_len > self.size) {
                return error.InvalidMemberSize;
            }

            const raw_bsd_name = file_bytes[self.data_offset .. self.data_offset + name_len];
            const term_len = std.mem.indexOfScalar(u8, raw_bsd_name, 0) orelse raw_bsd_name.len;
            return std.mem.trim(u8, raw_bsd_name[0..term_len], " ");
        }

        // 2. GNU long name: /<offset>
        if (self.isGnuLongName()) {
            const trimmed = std.mem.trim(u8, self.raw_name[1..], " ");
            const offset = std.fmt.parseInt(usize, trimmed, 10) catch return error.InvalidDecimalField;

            const strtab = gnu_strtab orelse return error.StringTableOutOfBounds;
            if (offset >= strtab.len) return error.StringTableOutOfBounds;

            const slice = strtab[offset..];
            var end_idx: usize = 0;
            while (end_idx < slice.len) : (end_idx += 1) {
                const c = slice[end_idx];
                if (c == '/' or c == '\n' or c == 0) break;
            }
            return slice[0..end_idx];
        }

        // 3. Special tables ("/ " or "//")
        const trimmed = std.mem.trim(u8, &self.raw_name, " ");
        if (std.mem.eql(u8, trimmed, "/") or std.mem.eql(u8, trimmed, "//")) {
            return trimmed;
        }

        // 4. Standard name: trim trailing slash and space padding
        var name = trimmed;
        if (std.mem.endsWith(u8, name, "/")) {
            name = name[0 .. name.len - 1];
        }
        return name;
    }

    /// Returns the raw data slice for this member's payload.
    /// For BSD extended names, the payload automatically skips the embedded filename prefix.
    pub fn getData(self: *const MemberHeader, file_bytes: []const u8) Error![]const u8 {
        var start = self.data_offset;
        const end = std.math.add(usize, start, @as(usize, @intCast(self.size))) catch return error.InvalidMemberSize;
        if (end > file_bytes.len) return error.InvalidMemberSize;

        if (self.isBsdExtendedName()) {
            const trimmed = std.mem.trim(u8, self.raw_name[3..], " ");
            const name_len = std.fmt.parseInt(usize, trimmed, 10) catch return error.InvalidDecimalField;
            if (name_len > self.size) return error.InvalidMemberSize;
            start += name_len;
        }

        return file_bytes[start..end];
    }
};

// === Member Iterator ===

/// Iterator to sequentially traverse all members in an archive file.
pub const MemberIterator = struct {
    file_bytes: []const u8,
    cursor: usize,

    pub fn next(self: *MemberIterator) Error!?MemberHeader {
        // All archive members must start on an even 2-byte boundary
        self.cursor += (self.cursor & 1);

        if (self.cursor >= self.file_bytes.len) {
            return null;
        }

        if (self.cursor + 60 > self.file_bytes.len) {
            return error.TruncatedMemberHeader;
        }

        const hdr_bytes = self.file_bytes[self.cursor .. self.cursor + 60];

        // Verify the 2-byte trailer magic "`\n"
        if (!std.mem.eql(u8, hdr_bytes[58..60], ARFMAG)) {
            return error.InvalidTrailerMagic;
        }

        var name_buf: [16]u8 = undefined;
        @memcpy(&name_buf, hdr_bytes[0..16]);

        const date = try parseDecimal(u64, hdr_bytes[16..28]);
        const uid = try parseDecimal(u32, hdr_bytes[28..34]);
        const gid = try parseDecimal(u32, hdr_bytes[34..40]);
        const mode = try parseOctal(u32, hdr_bytes[40..48]);
        const size = try parseDecimal(u64, hdr_bytes[48..58]);

        const header_offset = self.cursor;
        const data_offset = self.cursor + 60;

        const end_offset = std.math.add(usize, data_offset, @as(usize, @intCast(size))) catch return error.InvalidMemberSize;
        if (end_offset > self.file_bytes.len) {
            return error.InvalidMemberSize;
        }

        self.cursor = end_offset;

        return .{
            .raw_name = name_buf,
            .date = date,
            .uid = uid,
            .gid = gid,
            .mode = mode,
            .size = size,
            .header_offset = header_offset,
            .data_offset = data_offset,
        };
    }
};

// === Symbol Table Iterator ===

/// Zero-allocation streaming iterator across all symbols in an archive symbol index.
pub const SymbolIterator = struct {
    kind: SymbolIndex.Kind,
    data: []const u8,
    symbol_count: usize,
    current_index: usize,
    gnu_str_cursor: usize,
    bsd_strtab_start: usize,

    pub fn next(self: *SymbolIterator) Error!?ArchiveSymbol {
        if (self.current_index >= self.symbol_count) return null;

        switch (self.kind) {
            .gnu => {
                const off_pos = 4 + (self.current_index * 4);
                if (off_pos + 4 > self.data.len) return error.TruncatedSymbolTable;
                const member_offset = std.mem.readInt(u32, self.data[off_pos..][0..4], .big);

                if (self.gnu_str_cursor >= self.data.len) return error.TruncatedSymbolTable;
                const slice = self.data[self.gnu_str_cursor..];
                const term_len = std.mem.indexOfScalar(u8, slice, 0) orelse return error.TruncatedSymbolTable;
                const name = slice[0..term_len];

                self.gnu_str_cursor += term_len + 1;
                self.current_index += 1;

                return .{
                    .name = name,
                    .member_offset = member_offset,
                };
            },
            .bsd => {
                const ran_pos = 4 + (self.current_index * 8);
                if (ran_pos + 8 > self.data.len) return error.TruncatedSymbolTable;
                const ran_strx = std.mem.readInt(u32, self.data[ran_pos..][0..4], .little);
                const ran_off = std.mem.readInt(u32, self.data[ran_pos + 4 ..][0..4], .little);

                const str_pos = self.bsd_strtab_start + ran_strx;
                if (str_pos >= self.data.len) return error.StringTableOutOfBounds;

                const slice = self.data[str_pos..];
                const term_len = std.mem.indexOfScalar(u8, slice, 0) orelse return error.TruncatedSymbolTable;
                const name = slice[0..term_len];

                self.current_index += 1;

                return .{
                    .name = name,
                    .member_offset = ran_off,
                };
            },
        }
    }
};

// === Decoded Symbol Index ===

/// Normalized representation for an archive's symbol index table.
pub const SymbolIndex = struct {
    pub const Kind = enum {
        gnu,
        bsd,
    };

    kind: Kind,
    data: []const u8,
    symbol_count: usize,
    strtab_offset: usize,

    /// Parse a raw member data slice as a symbol table index.
    pub fn parse(data: []const u8, kind: Kind) Error!SymbolIndex {
        switch (kind) {
            .gnu => {
                if (data.len < 4) return error.TruncatedSymbolTable;
                const nsyms = std.mem.readInt(u32, data[0..4], .big);
                const table_bytes = std.math.mul(usize, @as(usize, nsyms), 4) catch return error.InvalidSymbolTable;
                const strtab_start = std.math.add(usize, 4, table_bytes) catch return error.InvalidSymbolTable;
                if (strtab_start > data.len) return error.TruncatedSymbolTable;

                return .{
                    .kind = .gnu,
                    .data = data,
                    .symbol_count = nsyms,
                    .strtab_offset = strtab_start,
                };
            },
            .bsd => {
                if (data.len < 4) return error.TruncatedSymbolTable;
                const ran_size = std.mem.readInt(u32, data[0..4], .little);
                if (ran_size % 8 != 0) return error.InvalidSymbolTable;
                const ran_count = ran_size / 8;

                const strsize_offset = std.math.add(usize, 4, @as(usize, ran_size)) catch return error.InvalidSymbolTable;
                if (strsize_offset + 4 > data.len) return error.TruncatedSymbolTable;

                const strsize = std.mem.readInt(u32, data[strsize_offset..][0..4], .little);
                const strtab_start = strsize_offset + 4;
                const expected_end = std.math.add(usize, strtab_start, @as(usize, strsize)) catch return error.InvalidSymbolTable;
                if (expected_end > data.len) return error.TruncatedSymbolTable;

                return .{
                    .kind = .bsd,
                    .data = data,
                    .symbol_count = ran_count,
                    .strtab_offset = strtab_start,
                };
            },
        }
    }

    /// Return an iterator over all archive symbols.
    pub fn iterator(self: *const SymbolIndex) SymbolIterator {
        return .{
            .kind = self.kind,
            .data = self.data,
            .symbol_count = self.symbol_count,
            .current_index = 0,
            .gnu_str_cursor = self.strtab_offset,
            .bsd_strtab_start = self.strtab_offset,
        };
    }

    /// Parse all symbols into an allocated slice.
    pub fn parseAllSymbols(
        self: *const SymbolIndex,
        allocator: std.mem.Allocator,
    ) (Error || std.mem.Allocator.Error)![]ArchiveSymbol {
        const syms = try allocator.alloc(ArchiveSymbol, self.symbol_count);
        errdefer allocator.free(syms);

        var iter = self.iterator();
        var i: usize = 0;
        while (try iter.next()) |s| : (i += 1) {
            syms[i] = s;
        }
        return syms;
    }

    /// Search the symbol index for a specific symbol name.
    /// Returns the file offset of the defining member header if found.
    pub fn findSymbol(self: *const SymbolIndex, name: []const u8) Error!?usize {
        var iter = self.iterator();
        while (try iter.next()) |s| {
            if (std.mem.eql(u8, s.name, name)) {
                return s.member_offset;
            }
        }
        return null;
    }
};

// === Archive Container ===

/// Normalized representation for a static library archive.
pub const Archive = struct {
    file_bytes: []const u8,
    is_thin: bool,
    gnu_strtab: ?[]const u8,

    pub fn parse(file_bytes: []const u8) Error!Archive {
        if (file_bytes.len < 8) return error.TruncatedArchive;

        var is_thin = false;
        if (std.mem.eql(u8, file_bytes[0..8], ARMAG)) {
            is_thin = false;
        } else if (std.mem.eql(u8, file_bytes[0..8], THIN_ARMAG)) {
            is_thin = true;
        } else {
            return error.InvalidArchiveMagic;
        }

        var ar = Archive{
            .file_bytes = file_bytes,
            .is_thin = is_thin,
            .gnu_strtab = null,
        };

        // Pre-scan for GNU long filenames string table ("//")
        ar.gnu_strtab = ar.findGnuStringTable();

        return ar;
    }

    fn findGnuStringTable(self: *const Archive) ?[]const u8 {
        var iter = self.iterator();
        while (iter.next() catch null) |member| {
            if (member.isGnuStringTable()) {
                const start = member.data_offset;
                const end = start + @as(usize, @intCast(member.size));
                if (end <= self.file_bytes.len) {
                    return self.file_bytes[start..end];
                }
            }
        }
        return null;
    }

    /// Find and parse the archive's central symbol index (GNU '/' or BSD '__.SYMDEF').
    pub fn getSymbolIndex(self: *const Archive) Error!?SymbolIndex {
        var iter = self.iterator();
        while (try iter.next()) |member| {
            if (member.isGnuSymbolTable()) {
                const data = try member.getData(self.file_bytes);
                return try SymbolIndex.parse(data, .gnu);
            } else if (member.isBsdSymbolTable(self.file_bytes)) {
                const data = try member.getData(self.file_bytes);
                return try SymbolIndex.parse(data, .bsd);
            }
        }
        return null;
    }

    pub fn iterator(self: *const Archive) MemberIterator {
        return .{
            .file_bytes = self.file_bytes,
            .cursor = 8,
        };
    }
};

// === Unit Tests ===

test "reject archive shorter than 8 bytes" {
    const short_buf = "!<arc";
    try std.testing.expectError(error.TruncatedArchive, Archive.parse(short_buf));
}

test "reject archive with invalid magic signature" {
    const bad_buf = "BADMAGIC";
    try std.testing.expectError(error.InvalidArchiveMagic, Archive.parse(bad_buf));
}

test "parse standard and thin archive magic" {
    const ar_std = try Archive.parse(ARMAG);
    try std.testing.expect(!ar_std.is_thin);
    try std.testing.expect(ar_std.gnu_strtab == null);

    const ar_thin = try Archive.parse(THIN_ARMAG);
    try std.testing.expect(ar_thin.is_thin);
}

test "parse 60-byte member header with decimal and octal fields" {
    var file_buf: [68]u8 = undefined;
    @memcpy(file_buf[0..8], ARMAG);

    var hdr = file_buf[8..68];
    @memset(hdr, ' ');
    @memcpy(hdr[0..6], "foo.o/");
    @memcpy(hdr[16..26], "1700000000");
    @memcpy(hdr[28..32], "1001");
    @memcpy(hdr[34..38], "1002");
    @memcpy(hdr[40..46], "100644");
    @memcpy(hdr[48..49], "0");
    @memcpy(hdr[58..60], ARFMAG);

    const ar = try Archive.parse(&file_buf);
    var iter = ar.iterator();

    const member = (try iter.next()).?;
    try std.testing.expectEqualStrings("foo.o", try member.getName(&file_buf, null));
    try std.testing.expectEqual(@as(u64, 1700000000), member.date);
    try std.testing.expectEqual(@as(u32, 1001), member.uid);
    try std.testing.expectEqual(@as(u32, 1002), member.gid);
    try std.testing.expectEqual(@as(u32, 0o100644), member.mode);
    try std.testing.expectEqual(@as(u64, 0), member.size);
    try std.testing.expectEqual(@as(usize, 68), member.data_offset);
}

test "reject member header with invalid trailer magic" {
    var file_buf: [68]u8 = undefined;
    @memcpy(file_buf[0..8], ARMAG);

    var hdr = file_buf[8..68];
    @memset(hdr, ' ');
    @memcpy(hdr[0..6], "bar.o/");
    @memcpy(hdr[48..49], "0");
    @memcpy(hdr[58..60], "XX");

    const ar = try Archive.parse(&file_buf);
    var iter = ar.iterator();
    try std.testing.expectError(error.InvalidTrailerMagic, iter.next());
}

test "resolve GNU long member name from string table" {
    var buf: [164]u8 = undefined;
    @memset(&buf, ' ');
    @memcpy(buf[0..8], ARMAG);

    // 1. String table member header at 8
    @memcpy(buf[8..10], "//");
    @memcpy(buf[56..58], "32");
    @memcpy(buf[66..68], ARFMAG);
    @memcpy(buf[68..94], "my_very_long_file_name.o/\n");

    // 2. Member 2 header at 100
    @memcpy(buf[100..102], "/0");
    @memcpy(buf[148..149], "4");
    @memcpy(buf[158..160], ARFMAG);
    @memcpy(buf[160..164], "DATA");

    const ar = try Archive.parse(&buf);
    try std.testing.expect(ar.gnu_strtab != null);

    var iter = ar.iterator();
    const m1 = (try iter.next()).?;
    try std.testing.expect(m1.isGnuStringTable());

    const m2 = (try iter.next()).?;
    try std.testing.expect(m2.isGnuLongName());
    try std.testing.expectEqualStrings("my_very_long_file_name.o", try m2.getName(&buf, ar.gnu_strtab));
    try std.testing.expectEqualStrings("DATA", try m2.getData(&buf));
}

test "resolve BSD extended member name embedded in payload" {
    var buf: [96]u8 = undefined;
    @memset(&buf, ' ');
    @memcpy(buf[0..8], ARMAG);

    @memcpy(buf[8..13], "#1/20");
    @memcpy(buf[56..58], "28");
    @memcpy(buf[66..68], ARFMAG);
    @memcpy(buf[68..88], "apple_long_object.o\x00");
    @memcpy(buf[88..96], "DATA1234");

    const ar = try Archive.parse(&buf);
    var iter = ar.iterator();

    const m = (try iter.next()).?;
    try std.testing.expect(m.isBsdExtendedName());
    try std.testing.expectEqualStrings("apple_long_object.o", try m.getName(&buf, null));
    try std.testing.expectEqualStrings("DATA1234", try m.getData(&buf));
}

test "handle 2-byte alignment padding for odd-sized members" {
    var buf: [136]u8 = undefined;
    @memset(&buf, ' ');
    @memcpy(buf[0..8], ARMAG);

    // Member 1 (size = 3)
    @memcpy(buf[8..14], "odd.o/");
    @memcpy(buf[56..57], "3");
    @memcpy(buf[66..68], ARFMAG);
    @memcpy(buf[68..71], "ODD");
    buf[71] = '\n';

    // Member 2 (size = 4)
    @memcpy(buf[72..79], "even.o/");
    @memcpy(buf[120..121], "4");
    @memcpy(buf[130..132], ARFMAG);
    @memcpy(buf[132..136], "EVEN");

    const ar = try Archive.parse(&buf);
    var iter = ar.iterator();

    const m1 = (try iter.next()).?;
    try std.testing.expectEqualStrings("odd.o", try m1.getName(&buf, null));
    try std.testing.expectEqualStrings("ODD", try m1.getData(&buf));
    try std.testing.expectEqual(@as(usize, 68), m1.data_offset);

    const m2 = (try iter.next()).?;
    try std.testing.expectEqualStrings("even.o", try m2.getName(&buf, null));
    try std.testing.expectEqualStrings("EVEN", try m2.getData(&buf));
    try std.testing.expectEqual(@as(usize, 132), m2.data_offset);

    try std.testing.expect((try iter.next()) == null);
}

test "parse GNU symbol table with multiple big-endian symbols" {
    // Layout:
    // 0..4: nsyms = 2 (big-endian)
    // 4..8: offset[0] = 0x200 (big-endian)
    // 8..12: offset[1] = 0x400 (big-endian)
    // 12..30: "func_one\x00func_two\x00" (18 bytes)
    var symtab_buf: [30]u8 = undefined;
    @memset(&symtab_buf, 0);

    std.mem.writeInt(u32, symtab_buf[0..4], 2, .big);
    std.mem.writeInt(u32, symtab_buf[4..8], 0x200, .big);
    std.mem.writeInt(u32, symtab_buf[8..12], 0x400, .big);
    @memcpy(symtab_buf[12..30], "func_one\x00func_two\x00");

    const index = try SymbolIndex.parse(&symtab_buf, .gnu);
    try std.testing.expectEqual(@as(usize, 2), index.symbol_count);

    var iter = index.iterator();

    const s1 = (try iter.next()).?;
    try std.testing.expectEqualStrings("func_one", s1.name);
    try std.testing.expectEqual(@as(usize, 0x200), s1.member_offset);

    const s2 = (try iter.next()).?;
    try std.testing.expectEqualStrings("func_two", s2.name);
    try std.testing.expectEqual(@as(usize, 0x400), s2.member_offset);

    try std.testing.expect((try iter.next()) == null);

    // Lookup functions
    try std.testing.expectEqual(@as(usize, 0x400), (try index.findSymbol("func_two")).?);
    try std.testing.expect((try index.findSymbol("nonexistent")) == null);
}

test "parse BSD __.SYMDEF symbol table" {
    // Layout:
    // 0..4: ranlib_size = 16 (2 entries * 8 bytes, little-endian)
    // 4..8: ran_strx[0] = 0
    // 8..12: ran_off[0] = 0x120
    // 12..16: ran_strx[1] = 10
    // 16..20: ran_off[1] = 0x240
    // 20..24: strsize = 20 (little-endian)
    // 24..44: "apple_one\x00apple_two\x00" (20 bytes)
    var bsd_buf: [44]u8 = undefined;
    @memset(&bsd_buf, 0);

    std.mem.writeInt(u32, bsd_buf[0..4], 16, .little);
    std.mem.writeInt(u32, bsd_buf[4..8], 0, .little);
    std.mem.writeInt(u32, bsd_buf[8..12], 0x120, .little);
    std.mem.writeInt(u32, bsd_buf[12..16], 10, .little);
    std.mem.writeInt(u32, bsd_buf[16..20], 0x240, .little);

    std.mem.writeInt(u32, bsd_buf[20..24], 20, .little);
    @memcpy(bsd_buf[24..44], "apple_one\x00apple_two\x00");

    const index = try SymbolIndex.parse(&bsd_buf, .bsd);
    try std.testing.expectEqual(@as(usize, 2), index.symbol_count);

    var iter = index.iterator();

    const s1 = (try iter.next()).?;
    try std.testing.expectEqualStrings("apple_one", s1.name);
    try std.testing.expectEqual(@as(usize, 0x120), s1.member_offset);

    const s2 = (try iter.next()).?;
    try std.testing.expectEqualStrings("apple_two", s2.name);
    try std.testing.expectEqual(@as(usize, 0x240), s2.member_offset);

    try std.testing.expect((try iter.next()) == null);

    try std.testing.expectEqual(@as(usize, 0x120), (try index.findSymbol("apple_one")).?);
}

test "reject truncated archive symbol table" {
    var bad_gnu: [6]u8 = undefined;
    std.mem.writeInt(u32, bad_gnu[0..4], 10, .big); // claims 10 symbols, but buffer is only 6 bytes
    try std.testing.expectError(error.TruncatedSymbolTable, SymbolIndex.parse(&bad_gnu, .gnu));

    var bad_bsd: [6]u8 = undefined;
    std.mem.writeInt(u32, bad_bsd[0..4], 7, .little); // not a multiple of 8
    try std.testing.expectError(error.InvalidSymbolTable, SymbolIndex.parse(&bad_bsd, .bsd));
}
