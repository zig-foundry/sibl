//! Phase 5.1 - 5.4: Static Archive Header Validation, Member Parser, Symbol Index,
//! Selective Member Extraction, and Thin Archive Support.
//!
//! Provides zero-copy parsing for Unix static archives (.a) and Windows
//! import/static libraries (.lib), supporting GNU ('/'), BSD ('__.SYMDEF'),
//! deduplicated selective extraction, and external thin archive references.

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
    MemberNotFound,
    ExternalFileNotFound,
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

// === Extracted Member Representation ===

/// An extracted object file member ready for parsing (ELF, COFF, or Mach-O).
pub const ExtractedMember = struct {
    name: []const u8,
    header: MemberHeader,
    data: []const u8,
    is_external: bool,
    allocated_data: ?[]const u8 = null,
    allocated_path: ?[]const u8 = null,

    pub fn deinit(self: *ExtractedMember, allocator: std.mem.Allocator) void {
        if (self.allocated_data) |d| allocator.free(d);
        if (self.allocated_path) |p| allocator.free(p);
    }
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

    /// Returns true if this member is a special non-object table ('/', '//', or '__.SYMDEF').
    pub fn isSpecialTable(self: *const MemberHeader, file_bytes: []const u8) bool {
        if (self.isGnuSymbolTable() or self.isGnuStringTable()) return true;
        return self.isBsdSymbolTable(file_bytes);
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

    /// Returns the raw data slice for this member's payload in standard archives.
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
    is_thin: bool = false,

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

        // In a thin archive, ordinary object members have 0 bytes of payload in the archive file.
        // Special members ('/' symbol table and '//' string table) do contain actual payload in the archive.
        const trimmed_name = std.mem.trim(u8, &name_buf, " ");
        const is_special = std.mem.eql(u8, trimmed_name, "/") or std.mem.eql(u8, trimmed_name, "//") or std.mem.startsWith(u8, trimmed_name, "__.SYMDEF");

        const archive_payload_size: usize = if (self.is_thin and !is_special)
            0
        else
            @intCast(size);

        const end_offset = std.math.add(usize, data_offset, archive_payload_size) catch return error.InvalidMemberSize;
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

    /// Parse a static archive from its raw bytes.
    /// Supports standard GNU archives, BSD-style symbol indexes, and thin archives.
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

    /// Parse a single 60-byte member header directly at a specified archive byte offset.
    pub fn getMemberAtOffset(self: *const Archive, offset: usize) Error!MemberHeader {
        if (offset >= self.file_bytes.len) return error.TruncatedMemberHeader;
        if (offset + 60 > self.file_bytes.len) return error.TruncatedMemberHeader;

        const hdr_bytes = self.file_bytes[offset .. offset + 60];
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

        return .{
            .raw_name = name_buf,
            .date = date,
            .uid = uid,
            .gid = gid,
            .mode = mode,
            .size = size,
            .header_offset = offset,
            .data_offset = offset + 60,
        };
    }

    /// Look up a symbol in the index and return the member header defining it.
    pub fn findMemberDefiningSymbol(self: *const Archive, symbol_name: []const u8) Error!?MemberHeader {
        const sym_index = (try self.getSymbolIndex()) orelse return null;
        const offset = (try sym_index.findSymbol(symbol_name)) orelse return null;
        return try self.getMemberAtOffset(offset);
    }

    /// Resolve the filesystem path of a member file, handling relative paths for thin archives.
    pub fn resolveMemberPath(
        self: *const Archive,
        allocator: std.mem.Allocator,
        member: *const MemberHeader,
        archive_path: ?[]const u8,
    ) (Error || std.mem.Allocator.Error)![]u8 {
        const name = try member.getName(self.file_bytes, self.gnu_strtab);

        if (!self.is_thin) {
            return allocator.dupe(u8, name);
        }

        if (std.fs.path.isAbsolute(name)) {
            return allocator.dupe(u8, name);
        }

        if (archive_path) |ap| {
            if (std.fs.path.dirname(ap)) |dir| {
                return std.fs.path.join(allocator, &.{ dir, name });
            }
        }

        return allocator.dupe(u8, name);
    }

    /// Safely close an OS file descriptor across Zig versions.
    fn closeFd(fd: std.posix.fd_t) void {
        if (comptime @hasDecl(std.posix, "close")) {
            std.posix.close(fd);
        } else if (comptime @hasDecl(std.posix.system, "close")) {
            _ = std.posix.system.close(fd);
        } else if (comptime @hasDecl(std, "os") and @hasDecl(std.os, "linux") and @hasDecl(std.os.linux, "close")) {
            _ = std.os.linux.close(fd);
        }
    }

    /// Read an external file from disk for thin archive members using POSIX openat.
    fn readExternalFile(allocator: std.mem.Allocator, path: []const u8) (Error || std.mem.Allocator.Error)![]const u8 {
        const fd = std.posix.openat(std.posix.AT.FDCWD, path, .{}, 0) catch return error.ExternalFileNotFound;
        defer closeFd(fd);

        var list = std.ArrayListUnmanaged(u8).empty;
        errdefer list.deinit(allocator);

        var chunk: [8192]u8 = undefined;
        while (true) {
            const n = std.posix.read(fd, &chunk) catch return error.ExternalFileNotFound;
            if (n == 0) break;
            try list.appendSlice(allocator, chunk[0..n]);
        }

        return try list.toOwnedSlice(allocator);
    }

    /// Extract an archive member.
    /// In standard archives, returns a zero-copy slice of memory.
    /// In thin archives, reads the external file from disk.
    pub fn extractMember(
        self: *const Archive,
        allocator: std.mem.Allocator,
        member: *const MemberHeader,
        archive_path: ?[]const u8,
    ) (Error || std.mem.Allocator.Error)!ExtractedMember {
        const name = try member.getName(self.file_bytes, self.gnu_strtab);

        if (!self.is_thin) {
            const data = try member.getData(self.file_bytes);
            return .{
                .name = name,
                .header = member.*,
                .data = data,
                .is_external = false,
                .allocated_data = null,
                .allocated_path = null,
            };
        } else {
            const full_path = try self.resolveMemberPath(allocator, member, archive_path);
            errdefer allocator.free(full_path);

            const data = try readExternalFile(allocator, full_path);

            return .{
                .name = name,
                .header = member.*,
                .data = data,
                .is_external = true,
                .allocated_data = data,
                .allocated_path = full_path,
            };
        }
    }

    pub fn iterator(self: *const Archive) MemberIterator {
        return .{
            .file_bytes = self.file_bytes,
            .cursor = 8,
            .is_thin = self.is_thin,
        };
    }
};

// === Selective Extractor ===

/// Tracks and manages deduplicated selective member extraction during linking.
pub const SelectiveExtractor = struct {
    allocator: std.mem.Allocator,
    archive: *const Archive,
    archive_path: ?[]const u8,
    extracted_offsets: std.AutoHashMap(usize, void),
    extracted_members: std.ArrayListUnmanaged(ExtractedMember),

    pub fn init(allocator: std.mem.Allocator, ar: *const Archive, archive_path: ?[]const u8) SelectiveExtractor {
        return .{
            .allocator = allocator,
            .archive = ar,
            .archive_path = archive_path,
            .extracted_offsets = std.AutoHashMap(usize, void).init(allocator),
            .extracted_members = .empty,
        };
    }

    pub fn deinit(self: *SelectiveExtractor) void {
        for (self.extracted_members.items) |*m| {
            m.deinit(self.allocator);
        }
        self.extracted_members.deinit(self.allocator);
        self.extracted_offsets.deinit();
    }

    /// Extract the member that defines `symbol_name` if present and not yet extracted.
    pub fn extractSymbol(self: *SelectiveExtractor, symbol_name: []const u8) !?*const ExtractedMember {
        const sym_index = (try self.archive.getSymbolIndex()) orelse return null;
        const offset = (try sym_index.findSymbol(symbol_name)) orelse return null;

        if (self.extracted_offsets.contains(offset)) {
            return null; // Already extracted
        }

        try self.extracted_offsets.put(offset, {});
        const member_hdr = try self.archive.getMemberAtOffset(offset);
        const extracted = try self.archive.extractMember(self.allocator, &member_hdr, self.archive_path);
        try self.extracted_members.append(self.allocator, extracted);

        return &self.extracted_members.items[self.extracted_members.items.len - 1];
    }

    /// Iterates across a slice of undefined symbol names, extracting all needed members.
    /// Returns the number of newly extracted members.
    pub fn extractUndefined(self: *SelectiveExtractor, undefined_symbols: []const []const u8) !usize {
        var count: usize = 0;
        for (undefined_symbols) |sym| {
            if (try self.extractSymbol(sym)) |_| {
                count += 1;
            }
        }
        return count;
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

    try std.testing.expectEqual(@as(usize, 0x400), (try index.findSymbol("func_two")).?);
    try std.testing.expect((try index.findSymbol("nonexistent")) == null);
}

test "parse BSD __.SYMDEF symbol table" {
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

test "selective member extraction by symbol lookup" {
    // Layout:
    // 0..8: ARMAG
    // 8..68: Member 0: GNU symbol table ("/") with size 16 (1 symbol -> member at 68)
    // 68..72: nsyms = 1 (big-endian)
    // 72..76: offset = 84 (big-endian, pointing to Member 1 header)
    // 76..84: "my_func\x00"
    // 84..144: Member 1: header ("obj.o/") with size 11
    // 144..155: "OBJ_PAYLOAD" (11 bytes)
    var ar_buf: [155]u8 = undefined;
    @memset(&ar_buf, ' ');
    @memcpy(ar_buf[0..8], ARMAG);

    // Symbol table header
    @memcpy(ar_buf[8..10], "/ ");
    @memcpy(ar_buf[56..58], "16");
    @memcpy(ar_buf[66..68], ARFMAG);

    // Symbol table data at 68
    std.mem.writeInt(u32, ar_buf[68..72], 1, .big);
    std.mem.writeInt(u32, ar_buf[72..76], 84, .big); // points to offset 84
    @memcpy(ar_buf[76..84], "my_func\x00");

    // Member 1 header at 84
    @memcpy(ar_buf[84..90], "obj.o/");
    @memcpy(ar_buf[132..134], "11");
    @memcpy(ar_buf[142..144], ARFMAG);
    @memcpy(ar_buf[144..155], "OBJ_PAYLOAD");

    const ar = try Archive.parse(&ar_buf);
    const sym_index = (try ar.getSymbolIndex()).?;
    try std.testing.expectEqual(@as(usize, 84), (try sym_index.findSymbol("my_func")).?);

    // Direct lookup of defining member
    const member_hdr = (try ar.findMemberDefiningSymbol("my_func")).?;
    try std.testing.expectEqualStrings("obj.o", try member_hdr.getName(&ar_buf, null));

    // Selective extraction
    var extractor = SelectiveExtractor.init(std.testing.allocator, &ar, null);
    defer extractor.deinit();

    const undefined_syms = [_][]const u8{ "my_func", "unused_func" };
    const newly_extracted = try extractor.extractUndefined(&undefined_syms);
    try std.testing.expectEqual(@as(usize, 1), newly_extracted);

    const m = &extractor.extracted_members.items[0];
    try std.testing.expectEqualStrings("obj.o", m.name);
    try std.testing.expectEqualStrings("OBJ_PAYLOAD", m.data);
    try std.testing.expect(!m.is_external);

    // Deduplication: extract again, returns 0 newly extracted
    const second_run = try extractor.extractUndefined(&undefined_syms);
    try std.testing.expectEqual(@as(usize, 0), second_run);
}

test "thin archive relative path resolution and header traversal" {
    // In a thin archive, members do not contain payload in the archive file.
    // Member 1 at offset 8 (60 bytes)
    // Member 2 at offset 68 (60 bytes)
    var thin_buf: [128]u8 = undefined;
    @memset(&thin_buf, ' ');
    @memcpy(thin_buf[0..8], THIN_ARMAG);

    // Member 1: "src/foo.o/"
    @memcpy(thin_buf[8..18], "src/foo.o/");
    @memcpy(thin_buf[56..58], "48"); // original file size, but 0 in archive
    @memcpy(thin_buf[66..68], ARFMAG);

    // Member 2: "bar.o/"
    @memcpy(thin_buf[68..74], "bar.o/");
    @memcpy(thin_buf[116..118], "96");
    @memcpy(thin_buf[126..128], ARFMAG);

    const ar = try Archive.parse(&thin_buf);
    try std.testing.expect(ar.is_thin);

    var iter = ar.iterator();
    const m1 = (try iter.next()).?;
    try std.testing.expectEqualStrings("src/foo.o", try m1.getName(&thin_buf, null));
    try std.testing.expectEqual(@as(usize, 8), m1.header_offset);

    const m2 = (try iter.next()).?;
    try std.testing.expectEqualStrings("bar.o", try m2.getName(&thin_buf, null));
    try std.testing.expectEqual(@as(usize, 68), m2.header_offset);

    try std.testing.expect((try iter.next()) == null);

    // Path resolution relative to archive directory
    const resolved_path = try ar.resolveMemberPath(std.testing.allocator, &m1, "libs/sub/libtest.a");
    defer std.testing.allocator.free(resolved_path);

    try std.testing.expect(std.mem.endsWith(u8, resolved_path, "src/foo.o"));
}
