//! Phase 5.1: Static Archive Header Validation and Member Parser for sibl.
//!
//! Provides zero-copy parsing for Unix static archives (.a) and Windows
//! import/static libraries (.lib), supporting standard, thin, GNU, and BSD variants.

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

    // Member header at offset 8 (60 bytes)
    var hdr = file_buf[8..68];
    @memset(hdr, ' ');
    @memcpy(hdr[0..6], "foo.o/");
    @memcpy(hdr[16..26], "1700000000"); // date
    @memcpy(hdr[28..32], "1001"); // uid
    @memcpy(hdr[34..38], "1002"); // gid
    @memcpy(hdr[40..46], "100644"); // mode (octal)
    @memcpy(hdr[48..49], "0"); // size = 0
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
    @memcpy(hdr[58..60], "XX"); // Corrupted trailer

    const ar = try Archive.parse(&file_buf);
    var iter = ar.iterator();
    try std.testing.expectError(error.InvalidTrailerMagic, iter.next());
}

test "resolve GNU long member name from string table" {
    // Layout:
    // 0..8: ARMAG
    // 8..68: Member 1 ("//") -> size 32
    // 68..100: string table payload: "my_very_long_file_name.o/\n\x00"
    // 100..160: Member 2 ("/0") -> size 4
    // 160..164: payload: "DATA"
    var buf: [164]u8 = undefined;
    @memset(&buf, ' ');
    @memcpy(buf[0..8], ARMAG);

    // 1. String table member header at 8
    @memcpy(buf[8..10], "//");
    @memcpy(buf[56..58], "32");
    @memcpy(buf[66..68], ARFMAG);
    @memcpy(buf[68..94], "my_very_long_file_name.o/\n");

    // 2. Member 2 header at 100
    @memcpy(buf[100..102], "/0"); // references offset 0 in string table
    @memcpy(buf[148..149], "4"); // size = 4
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
    // Layout:
    // 0..8: ARMAG
    // 8..68: Header with name "#1/20" and size 28 (20 bytes name + 8 bytes data)
    // 68..88: "apple_long_object.o\x00" (20 bytes)
    // 88..96: "DATA1234" (8 bytes actual data)
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
    // Member 1 has size = 3 (odd). A padding newline must be skipped before Member 2.
    // 0..8: ARMAG
    // 8..68: Member 1 header (size = 3)
    // 68..71: "ODD"
    // 71..72: "\n" (padding byte)
    // 72..132: Member 2 header (size = 4)
    // 132..136: "EVEN"
    var buf: [136]u8 = undefined;
    @memset(&buf, ' ');
    @memcpy(buf[0..8], ARMAG);

    // Member 1
    @memcpy(buf[8..14], "odd.o/");
    @memcpy(buf[56..57], "3");
    @memcpy(buf[66..68], ARFMAG);
    @memcpy(buf[68..71], "ODD");
    buf[71] = '\n';

    // Member 2
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
