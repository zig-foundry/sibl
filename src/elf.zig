//! Phase 2.1 - 2.5: ELF Header, Sections, Symbols, and Relocations.
//!
//! Provides zero-copy parsing for headers, section tables, symbol tables,
//! and relocation entries across 32-bit and 64-bit ELF binaries.

const std = @import("std");

// === Constants and Types ===

/// The 4-byte magic signature present at the start of every valid ELF binary.
pub const MAGIC = [4]u8{ 0x7F, 'E', 'L', 'F' };

/// ELF architecture width (EI_CLASS).
pub const Class = enum(u8) {
    none = 0,
    elf32 = 1,
    elf64 = 2,

    /// Return a human-readable name for this Class.
    pub fn name(self: Class) []const u8 {
        return switch (self) {
            .none => "none",
            .elf32 => "elf32",
            .elf64 => "elf64",
        };
    }
};

/// ELF data byte order encoding (EI_DATA).
pub const DataEncoding = enum(u8) {
    none = 0,
    lsb = 1, // Little-endian
    msb = 2, // Big-endian
};

/// ELF file type (e_type).
pub const FileType = enum(u16) {
    none = 0,
    rel = 1, // Relocatable object (.o)
    exec = 2, // Executable binary
    dyn = 3, // Shared library (.so) or PIE executable
    core = 4, // Core dump
    _,

    /// Return a human-readable name for this FileType.
    pub fn name(self: FileType) []const u8 {
        return switch (self) {
            .none => "none",
            .rel => "rel",
            .exec => "exec",
            .dyn => "dyn",
            .core => "core",
            _ => "unknown",
        };
    }
};

/// Target processor architecture (e_machine).
pub const Machine = enum(u16) {
    none = 0,
    x86 = 3,
    arm = 40,
    x86_64 = 62,
    aarch64 = 183,
    riscv = 243,
    _,

    /// Return a human-readable name for this Machine.
    pub fn name(self: Machine) []const u8 {
        return switch (self) {
            .none => "none",
            .x86 => "x86",
            .arm => "arm",
            .x86_64 => "x86_64",
            .aarch64 => "aarch64",
            .riscv => "riscv",
            _ => "unknown",
        };
    }
};

/// Operating System and ABI identifier (EI_OSABI).
pub const OsAbi = enum(u8) {
    sysv = 0,
    hpux = 1,
    netbsd = 2,
    linux = 3,
    solaris = 6,
    freebsd = 9,
    openbsd = 12,
    arm_aeabi = 64,
    standalone = 255,
    _,
};

/// Section type identifying section contents and semantics (sh_type).
pub const SectionType = enum(u32) {
    null = 0,
    progbits = 1,
    symtab = 2,
    strtab = 3,
    rela = 4,
    hash = 5,
    dynamic = 6,
    note = 7,
    nobits = 8,
    rel = 9,
    shlib = 10,
    dynsym = 11,
    init_array = 14,
    fini_array = 15,
    preinit_array = 16,
    group = 17,
    symtab_shndx = 18,
    relr = 19,

    // Android-specific sections
    android_rel = 0x60000001,
    android_rela = 0x60000002,

    // GNU extension sections
    gnu_attributes = 0x6ffffff5,
    gnu_hash = 0x6ffffff6,
    gnu_verdef = 0x6ffffffd,
    gnu_verneed = 0x6ffffffe,
    gnu_versym = 0x6fffffff,

    // Processor-specific (ARM / AArch64)
    arm_exidx = 0x70000001,
    arm_preemptmap = 0x70000002,
    arm_attributes = 0x70000003,

    _,

    /// Return a human-readable name for this SectionType.
    pub fn name(self: SectionType) []const u8 {
        return switch (self) {
            .null => "null",
            .progbits => "progbits",
            .symtab => "symtab",
            .strtab => "strtab",
            .rela => "rela",
            .hash => "hash",
            .dynamic => "dynamic",
            .note => "note",
            .nobits => "nobits",
            .rel => "rel",
            .shlib => "shlib",
            .dynsym => "dynsym",
            .init_array => "init_array",
            .fini_array => "fini_array",
            .preinit_array => "preinit_array",
            .group => "group",
            .symtab_shndx => "symtab_shndx",
            .relr => "relr",
            .android_rel => "android_rel",
            .android_rela => "android_rela",
            .gnu_attributes => "gnu_attributes",
            .gnu_hash => "gnu_hash",
            .gnu_verdef => "gnu_verdef",
            .gnu_verneed => "gnu_verneed",
            .gnu_versym => "gnu_versym",
            .arm_exidx => "arm_exidx",
            .arm_preemptmap => "arm_preemptmap",
            .arm_attributes => "arm_attributes",
            _ => "unknown",
        };
    }
};

/// Section attribute flags (sh_flags bitmask).
pub const flags = struct {
    /// Section is writable.
    pub const WRITE: u64 = 1 << 0;
    /// Section occupies memory during execution.
    pub const ALLOC: u64 = 1 << 1;
    /// Section contains executable instructions.
    pub const EXECINSTR: u64 = 1 << 2;
    /// Section may be merged with others of the same type.
    pub const MERGE: u64 = 1 << 4;
    /// Section contains null-terminated strings.
    pub const STRINGS: u64 = 1 << 5;
    /// sh_info field contains a section header index.
    pub const INFO_LINK: u64 = 1 << 6;
    /// Section must be ordered relative to another section.
    pub const LINK_ORDER: u64 = 1 << 7;
    /// Section requires special OS-specific handling.
    pub const OS_NONCONFORMING: u64 = 1 << 8;
    /// Section is a member of a section group.
    pub const GROUP: u64 = 1 << 9;
    /// Section holds thread-local storage.
    pub const TLS: u64 = 1 << 10;
};

// === Symbol Table Enums and Types ===

/// Symbol binding rules (STB_*).
pub const SymbolBinding = enum(u4) {
    local = 0,
    global = 1,
    weak = 2,
    _,

    /// Return a human-readable name for this SymbolBinding.
    pub fn name(self: SymbolBinding) []const u8 {
        return switch (self) {
            .local => "LOCAL",
            .global => "GLOBAL",
            .weak => "WEAK",
            _ => "UNKNOWN",
        };
    }
};

/// Symbol type category (STT_*).
pub const SymbolType = enum(u4) {
    notype = 0,
    object = 1,
    func = 2,
    section = 3,
    file = 4,
    common = 5,
    tls = 6,
    gnu_ifunc = 10,
    _,

    /// Return a human-readable name for this SymbolType.
    pub fn name(self: SymbolType) []const u8 {
        return switch (self) {
            .notype => "NOTYPE",
            .object => "OBJECT",
            .func => "FUNC",
            .section => "SECTION",
            .file => "FILE",
            .common => "COMMON",
            .tls => "TLS",
            .gnu_ifunc => "IFUNC",
            _ => "UNKNOWN",
        };
    }
};

/// Symbol visibility flags (STV_*).
pub const SymbolVisibility = enum(u2) {
    default = 0,
    internal = 1,
    hidden = 2,
    protected = 3,

    /// Return a human-readable name for this SymbolVisibility.
    pub fn name(self: SymbolVisibility) []const u8 {
        return switch (self) {
            .default => "DEFAULT",
            .internal => "INTERNAL",
            .hidden => "HIDDEN",
            .protected => "PROTECTED",
        };
    }
};

/// Special section indices reserved for symbol definitions (SHN_*).
pub const SpecialSectionIndex = struct {
    /// Undefined section (SHN_UNDEF).
    pub const UNDEF: u16 = 0;
    /// Start of reserved section index range.
    pub const LORESERVE: u16 = 0xff00;
    /// Absolute symbol (SHN_ABS).
    pub const ABS: u16 = 0xfff1;
    /// Common symbol (SHN_COMMON).
    pub const COMMON: u16 = 0xfff2;
    /// Extended section index (SHN_XINDEX).
    pub const XINDEX: u16 = 0xffff;
};

/// Normalized symbol representation for both 32-bit and 64-bit ELF symbols.
pub const Symbol = struct {
    name_offset: u32,
    value: u64,
    size: u64,
    binding: SymbolBinding,
    sym_type: SymbolType,
    visibility: SymbolVisibility,
    shndx: u16,

    /// Returns true if the symbol is undefined (SHN_UNDEF).
    pub fn isUndefined(self: Symbol) bool {
        return self.shndx == SpecialSectionIndex.UNDEF;
    }

    /// Returns true if the symbol is absolute (SHN_ABS).
    pub fn isAbsolute(self: Symbol) bool {
        return self.shndx == SpecialSectionIndex.ABS;
    }

    /// Resolve the symbol name from the associated string table.
    pub fn getName(self: Symbol, strtab_bytes: []const u8) SectionError![:0]const u8 {
        if (self.name_offset >= strtab_bytes.len) {
            return error.StringTableOutOfBounds;
        }

        const slice = strtab_bytes[self.name_offset..];
        const len = std.mem.indexOfScalar(u8, slice, 0) orelse return error.StringTableOutOfBounds;
        return slice[0..len :0];
    }
};

// === Relocation Types and Helpers ===

/// Normalized relocation record for both .rel and .rela entries.
pub const Relocation = struct {
    /// Byte offset within the target section where the relocation is applied
    offset: u64,
    /// Symbol table index referenced by this relocation
    symbol_index: u32,
    /// Architecture-specific relocation type identifier
    type_id: u32,
    /// Explicit addend value (0 if this entry came from a .rel section)
    addend: i64,
    /// True if the entry has an explicit addend (.rela)
    has_explicit_addend: bool,

    /// Return readable name of the relocation type for common architectures.
    pub fn typeName(self: Relocation, machine: Machine) []const u8 {
        return switch (machine) {
            .aarch64 => switch (self.type_id) {
                0 => "NONE",
                257 => "ABS64",
                258 => "ABS32",
                261 => "PREL32",
                275 => "ADR_PREL_PG_HI21",
                277 => "ADD_ABS_LO12_NC",
                282 => "JUMP26",
                283 => "CALL26",
                1025 => "GLOB_DAT",
                1026 => "JUMP_SLOT",
                1027 => "RELATIVE",
                else => "AARCH64_RELOC",
            },
            .x86_64 => switch (self.type_id) {
                0 => "NONE",
                1 => "64",
                2 => "PC32",
                3 => "GOT32",
                4 => "PLT32",
                5 => "COPY",
                6 => "GLOB_DAT",
                7 => "JUMP_SLOT",
                8 => "RELATIVE",
                10 => "32",
                11 => "32S",
                24 => "PC64",
                else => "X86_64_RELOC",
            },
            .arm => switch (self.type_id) {
                0 => "NONE",
                2 => "ABS32",
                3 => "REL32",
                28 => "CALL",
                29 => "JUMP24",
                else => "ARM_RELOC",
            },
            .riscv => switch (self.type_id) {
                0 => "NONE",
                1 => "32",
                2 => "64",
                18 => "BRANCH",
                19 => "JAL",
                else => "RISCV_RELOC",
            },
            else => "RELOC",
        };
    }
};

// === Error Sets ===

/// Errors that can occur while parsing an ELF header.
pub const HeaderError = error{
    TruncatedHeader,
    InvalidMagic,
    InvalidClass,
    InvalidEndian,
    InvalidVersion,
};

/// Errors that can occur while parsing section headers or section data.
pub const SectionError = error{
    TruncatedSectionTable,
    InvalidSectionIndex,
    InvalidSectionSize,
    StringTableOutOfBounds,
};

/// Errors that can occur while parsing symbol table entries.
pub const SymbolError = error{
    TruncatedSymbolTable,
    InvalidSymbolIndex,
    InvalidSymbolEntrySize,
    StringTableOutOfBounds,
};

/// Errors that can occur while parsing relocation entries.
pub const RelocationError = error{
    TruncatedRelocationTable,
    InvalidRelocationIndex,
    InvalidRelocationEntrySize,
    UnsupportedRelocationFormat,
};

// === Section Header Representation ===

/// Normalized section header representation for 32-bit and 64-bit ELF sections.
pub const SectionHeader = struct {
    name_offset: u32,
    sh_type: SectionType,
    sh_flags: u64,
    addr: u64,
    offset: u64,
    size: u64,
    link: u32, // Points to symtab for relocations and symbol tables
    info: u32, // Points to target section being patched for relocations
    addralign: u64,
    entsize: u64,

    /// Return true if the section has the ALLOC flag set.
    pub fn isAlloc(self: SectionHeader) bool {
        return (self.sh_flags & flags.ALLOC) != 0;
    }

    /// Return true if the section has the WRITE flag set.
    pub fn isWritable(self: SectionHeader) bool {
        return (self.sh_flags & flags.WRITE) != 0;
    }

    /// Return true if the section has the EXECINSTR flag set.
    pub fn isExecutable(self: SectionHeader) bool {
        return (self.sh_flags & flags.EXECINSTR) != 0;
    }

    /// Return the raw bytes of this section from the file.
    pub fn getData(self: SectionHeader, file_bytes: []const u8) SectionError![]const u8 {
        if (self.sh_type == .nobits or self.size == 0) {
            return &.{};
        }

        const end_offset = std.math.add(u64, self.offset, self.size) catch {
            return error.InvalidSectionSize;
        };

        if (end_offset > file_bytes.len) {
            return error.InvalidSectionSize;
        }

        const start: usize = @intCast(self.offset);
        const end: usize = @intCast(end_offset);
        return file_bytes[start..end];
    }

    /// Resolve the section name from the section header string table.
    pub fn getName(self: SectionHeader, shstrtab_data: []const u8) SectionError![:0]const u8 {
        if (self.name_offset >= shstrtab_data.len) {
            return error.StringTableOutOfBounds;
        }

        const slice = shstrtab_data[self.name_offset..];
        const len = std.mem.indexOfScalar(u8, slice, 0) orelse return error.StringTableOutOfBounds;
        return slice[0..len :0];
    }

    /// Return the number of symbols in this section (for SHT_SYMTAB / SHT_DYNSYM).
    pub fn getSymbolCount(self: SectionHeader, class: Class) SymbolError!usize {
        const expected_entry_size: u64 = switch (class) {
            .elf64 => 24,
            .elf32 => 16,
            .none => return error.InvalidSymbolEntrySize,
        };

        const entry_size = if (self.entsize != 0) self.entsize else expected_entry_size;
        if (entry_size != expected_entry_size) {
            return error.InvalidSymbolEntrySize;
        }

        return @intCast(self.size / entry_size);
    }

    /// Parse a single symbol at the given index from this section.
    pub fn parseSymbol(
        self: SectionHeader,
        file_bytes: []const u8,
        class: Class,
        endian: std.builtin.Endian,
        sym_index: usize,
    ) SymbolError!Symbol {
        const count = try self.getSymbolCount(class);
        if (sym_index >= count) {
            return error.InvalidSymbolIndex;
        }

        const entry_size: usize = if (class == .elf64) 24 else 16;
        const sym_offset = self.offset + (@as(u64, sym_index) * entry_size);
        const sym_end = sym_offset + entry_size;

        if (sym_end > file_bytes.len) {
            return error.TruncatedSymbolTable;
        }

        const start: usize = @intCast(sym_offset);
        const end: usize = @intCast(sym_end);
        const bytes = file_bytes[start..end];

        return switch (class) {
            .elf64 => parseSymbol64(bytes, endian),
            .elf32 => parseSymbol32(bytes, endian),
            .none => error.InvalidSymbolEntrySize,
        };
    }

    /// Parse every symbol in this section into a newly allocated slice.
    pub fn parseAllSymbols(
        self: SectionHeader,
        allocator: std.mem.Allocator,
        file_bytes: []const u8,
        class: Class,
        endian: std.builtin.Endian,
    ) (SymbolError || std.mem.Allocator.Error)![]Symbol {
        const count = try self.getSymbolCount(class);
        const symbols = try allocator.alloc(Symbol, count);
        errdefer allocator.free(symbols);

        var i: usize = 0;
        while (i < count) : (i += 1) {
            symbols[i] = try self.parseSymbol(file_bytes, class, endian, i);
        }

        return symbols;
    }

    // --- Relocation Methods ---

    /// Calculate how many relocation entries exist in this section.
    pub fn getRelocationCount(self: SectionHeader, class: Class) RelocationError!usize {
        const is_rela = (self.sh_type == .rela or self.sh_type == .android_rela);
        const is_rel = (self.sh_type == .rel or self.sh_type == .android_rel);

        if (!is_rela and !is_rel) {
            return error.UnsupportedRelocationFormat;
        }

        const expected_entry_size: u64 = switch (class) {
            .elf64 => if (is_rela) 24 else 16,
            .elf32 => if (is_rela) 12 else 8,
            .none => return error.InvalidRelocationEntrySize,
        };

        const entry_size = if (self.entsize != 0) self.entsize else expected_entry_size;
        if (entry_size != expected_entry_size) {
            return error.InvalidRelocationEntrySize;
        }

        return @intCast(self.size / entry_size);
    }

    /// Parse a single relocation entry by index.
    pub fn parseRelocation(
        self: SectionHeader,
        file_bytes: []const u8,
        class: Class,
        endian: std.builtin.Endian,
        reloc_index: usize,
    ) RelocationError!Relocation {
        const count = try self.getRelocationCount(class);
        if (reloc_index >= count) {
            return error.InvalidRelocationIndex;
        }

        const is_rela = (self.sh_type == .rela or self.sh_type == .android_rela);
        const entry_size: usize = switch (class) {
            .elf64 => if (is_rela) 24 else 16,
            .elf32 => if (is_rela) 12 else 8,
            .none => return error.InvalidRelocationEntrySize,
        };

        const rel_offset = self.offset + (@as(u64, reloc_index) * entry_size);
        const rel_end = rel_offset + entry_size;

        if (rel_end > file_bytes.len) {
            return error.TruncatedRelocationTable;
        }

        const start: usize = @intCast(rel_offset);
        const end: usize = @intCast(rel_end);
        const bytes = file_bytes[start..end];

        return switch (class) {
            .elf64 => parseRelocation64(bytes, endian, is_rela),
            .elf32 => parseRelocation32(bytes, endian, is_rela),
            .none => error.InvalidRelocationEntrySize,
        };
    }

    /// Parse all relocation entries in this section into an allocated slice.
    pub fn parseAllRelocations(
        self: SectionHeader,
        allocator: std.mem.Allocator,
        file_bytes: []const u8,
        class: Class,
        endian: std.builtin.Endian,
    ) (RelocationError || std.mem.Allocator.Error)![]Relocation {
        const count = try self.getRelocationCount(class);
        const relocs = try allocator.alloc(Relocation, count);
        errdefer allocator.free(relocs);

        var i: usize = 0;
        while (i < count) : (i += 1) {
            relocs[i] = try self.parseRelocation(file_bytes, class, endian, i);
        }

        return relocs;
    }
};

// === ELF Header Structure ===

/// Normalized ELF header representation for both 32-bit and 64-bit objects.
pub const Header = struct {
    class: Class,
    endian: std.builtin.Endian,
    os_abi: OsAbi,
    abi_version: u8,
    file_type: FileType,
    machine: Machine,
    entry: u64,
    phoff: u64,
    shoff: u64,
    flags: u32,
    ehsize: u16,
    phentsize: u16,
    phnum: u16,
    shentsize: u16,
    shnum: u16,
    shstrndx: u16,

    /// Parse an ELF header from the start of a file or object.
    /// Supports both 32-bit and 64-bit little- and big-endian encodings.
    pub fn parse(bytes: []const u8) HeaderError!Header {
        if (bytes.len < 16) return error.TruncatedHeader;

        if (!std.mem.eql(u8, bytes[0..4], &MAGIC)) {
            return error.InvalidMagic;
        }

        const class: Class = switch (bytes[4]) {
            1 => .elf32,
            2 => .elf64,
            else => return error.InvalidClass,
        };

        const endian: std.builtin.Endian = switch (bytes[5]) {
            1 => .little,
            2 => .big,
            else => return error.InvalidEndian,
        };

        if (bytes[6] != 1) {
            return error.InvalidVersion;
        }

        const os_abi: OsAbi = @fromBackingInt(@intCast(bytes[7]));
        const abi_version = bytes[8];

        return switch (class) {
            .elf64 => parseElf64(bytes, endian, os_abi, abi_version),
            .elf32 => parseElf32(bytes, endian, os_abi, abi_version),
            .none => error.InvalidClass,
        };
    }

    /// Parse the section header at the given index.
    pub fn parseSectionHeader(self: Header, bytes: []const u8, index: usize) SectionError!SectionHeader {
        if (index >= self.shnum) {
            return error.InvalidSectionIndex;
        }

        const entry_size: u64 = self.shentsize;
        const entry_offset = std.math.add(u64, self.shoff, @as(u64, index) * entry_size) catch {
            return error.TruncatedSectionTable;
        };

        const end_offset = std.math.add(u64, entry_offset, entry_size) catch {
            return error.TruncatedSectionTable;
        };

        if (end_offset > bytes.len) {
            return error.TruncatedSectionTable;
        }

        const start: usize = @intCast(entry_offset);
        const end: usize = @intCast(end_offset);
        const entry_bytes = bytes[start..end];

        return switch (self.class) {
            .elf64 => parseSectionHeader64(entry_bytes, self.endian),
            .elf32 => parseSectionHeader32(entry_bytes, self.endian),
            .none => error.TruncatedSectionTable,
        };
    }

    /// Parse every section header in the file into a newly allocated slice.
    pub fn parseAllSectionHeaders(
        self: Header,
        allocator: std.mem.Allocator,
        bytes: []const u8,
    ) (SectionError || std.mem.Allocator.Error)![]SectionHeader {
        const sections = try allocator.alloc(SectionHeader, self.shnum);
        errdefer allocator.free(sections);

        var i: usize = 0;
        while (i < self.shnum) : (i += 1) {
            sections[i] = try self.parseSectionHeader(bytes, i);
        }

        return sections;
    }

    /// Return the raw bytes of the section header string table (.shstrtab).
    pub fn getSectionStringTable(self: Header, bytes: []const u8) SectionError![]const u8 {
        if (self.shstrndx >= self.shnum) {
            return error.InvalidSectionIndex;
        }

        const shstr_header = try self.parseSectionHeader(bytes, self.shstrndx);
        return shstr_header.getData(bytes);
    }

    // --- Private Helper Parsers ---

    fn parseElf64(
        bytes: []const u8,
        endian: std.builtin.Endian,
        os_abi: OsAbi,
        abi_version: u8,
    ) HeaderError!Header {
        if (bytes.len < 64) return error.TruncatedHeader;

        const raw_type = std.mem.readInt(u16, bytes[16..18], endian);
        const raw_machine = std.mem.readInt(u16, bytes[18..20], endian);
        const version = std.mem.readInt(u32, bytes[20..24], endian);
        if (version != 1) return error.InvalidVersion;

        return .{
            .class = .elf64,
            .endian = endian,
            .os_abi = os_abi,
            .abi_version = abi_version,
            .file_type = @fromBackingInt(@intCast(raw_type)),
            .machine = @fromBackingInt(@intCast(raw_machine)),
            .entry = std.mem.readInt(u64, bytes[24..32], endian),
            .phoff = std.mem.readInt(u64, bytes[32..40], endian),
            .shoff = std.mem.readInt(u64, bytes[40..48], endian),
            .flags = std.mem.readInt(u32, bytes[48..52], endian),
            .ehsize = std.mem.readInt(u16, bytes[52..54], endian),
            .phentsize = std.mem.readInt(u16, bytes[54..56], endian),
            .phnum = std.mem.readInt(u16, bytes[56..58], endian),
            .shentsize = std.mem.readInt(u16, bytes[58..60], endian),
            .shnum = std.mem.readInt(u16, bytes[60..62], endian),
            .shstrndx = std.mem.readInt(u16, bytes[62..64], endian),
        };
    }

    fn parseElf32(
        bytes: []const u8,
        endian: std.builtin.Endian,
        os_abi: OsAbi,
        abi_version: u8,
    ) HeaderError!Header {
        if (bytes.len < 52) return error.TruncatedHeader;

        const raw_type = std.mem.readInt(u16, bytes[16..18], endian);
        const raw_machine = std.mem.readInt(u16, bytes[18..20], endian);
        const version = std.mem.readInt(u32, bytes[20..24], endian);
        if (version != 1) return error.InvalidVersion;

        return .{
            .class = .elf32,
            .endian = endian,
            .os_abi = os_abi,
            .abi_version = abi_version,
            .file_type = @fromBackingInt(@intCast(raw_type)),
            .machine = @fromBackingInt(@intCast(raw_machine)),
            .entry = std.mem.readInt(u32, bytes[24..28], endian),
            .phoff = std.mem.readInt(u32, bytes[28..32], endian),
            .shoff = std.mem.readInt(u32, bytes[32..36], endian),
            .flags = std.mem.readInt(u32, bytes[36..40], endian),
            .ehsize = std.mem.readInt(u16, bytes[40..42], endian),
            .phentsize = std.mem.readInt(u16, bytes[42..44], endian),
            .phnum = std.mem.readInt(u16, bytes[44..46], endian),
            .shentsize = std.mem.readInt(u16, bytes[46..48], endian),
            .shnum = std.mem.readInt(u16, bytes[48..50], endian),
            .shstrndx = std.mem.readInt(u16, bytes[50..52], endian),
        };
    }

    fn parseSectionHeader64(bytes: []const u8, endian: std.builtin.Endian) SectionError!SectionHeader {
        if (bytes.len < 64) return error.TruncatedSectionTable;

        const raw_type = std.mem.readInt(u32, bytes[4..8], endian);

        return .{
            .name_offset = std.mem.readInt(u32, bytes[0..4], endian),
            .sh_type = @fromBackingInt(@intCast(raw_type)),
            .sh_flags = std.mem.readInt(u64, bytes[8..16], endian),
            .addr = std.mem.readInt(u64, bytes[16..24], endian),
            .offset = std.mem.readInt(u64, bytes[24..32], endian),
            .size = std.mem.readInt(u64, bytes[32..40], endian),
            .link = std.mem.readInt(u32, bytes[40..44], endian),
            .info = std.mem.readInt(u32, bytes[44..48], endian),
            .addralign = std.mem.readInt(u64, bytes[48..56], endian),
            .entsize = std.mem.readInt(u64, bytes[56..64], endian),
        };
    }

    fn parseSectionHeader32(bytes: []const u8, endian: std.builtin.Endian) SectionError!SectionHeader {
        if (bytes.len < 40) return error.TruncatedSectionTable;

        const raw_type = std.mem.readInt(u32, bytes[4..8], endian);

        return .{
            .name_offset = std.mem.readInt(u32, bytes[0..4], endian),
            .sh_type = @fromBackingInt(@intCast(raw_type)),
            .sh_flags = std.mem.readInt(u32, bytes[8..12], endian),
            .addr = std.mem.readInt(u32, bytes[12..16], endian),
            .offset = std.mem.readInt(u32, bytes[16..20], endian),
            .size = std.mem.readInt(u32, bytes[20..24], endian),
            .link = std.mem.readInt(u32, bytes[24..28], endian),
            .info = std.mem.readInt(u32, bytes[28..32], endian),
            .addralign = std.mem.readInt(u32, bytes[32..36], endian),
            .entsize = std.mem.readInt(u32, bytes[36..40], endian),
        };
    }
};

// --- Symbol Parser Helpers ---

fn parseSymbol64(bytes: []const u8, endian: std.builtin.Endian) SymbolError!Symbol {
    if (bytes.len < 24) return error.TruncatedSymbolTable;

    const info_byte = bytes[4];
    const other_byte = bytes[5];

    return .{
        .name_offset = std.mem.readInt(u32, bytes[0..4], endian),
        .binding = @fromBackingInt(@intCast(@as(u4, @truncate(info_byte >> 4)))),
        .sym_type = @fromBackingInt(@intCast(@as(u4, @truncate(info_byte & 0x0F)))),
        .visibility = @fromBackingInt(@intCast(@as(u2, @truncate(other_byte & 0x03)))),
        .shndx = std.mem.readInt(u16, bytes[6..8], endian),
        .value = std.mem.readInt(u64, bytes[8..16], endian),
        .size = std.mem.readInt(u64, bytes[16..24], endian),
    };
}

fn parseSymbol32(bytes: []const u8, endian: std.builtin.Endian) SymbolError!Symbol {
    if (bytes.len < 16) return error.TruncatedSymbolTable;

    const info_byte = bytes[12];
    const other_byte = bytes[13];

    return .{
        .name_offset = std.mem.readInt(u32, bytes[0..4], endian),
        .value = std.mem.readInt(u32, bytes[4..8], endian),
        .size = std.mem.readInt(u32, bytes[8..12], endian),
        .binding = @fromBackingInt(@intCast(@as(u4, @truncate(info_byte >> 4)))),
        .sym_type = @fromBackingInt(@intCast(@as(u4, @truncate(info_byte & 0x0F)))),
        .visibility = @fromBackingInt(@intCast(@as(u2, @truncate(other_byte & 0x03)))),
        .shndx = std.mem.readInt(u16, bytes[14..16], endian),
    };
}

// --- Relocation Parser Helpers ---

fn parseRelocation64(bytes: []const u8, endian: std.builtin.Endian, is_rela: bool) RelocationError!Relocation {
    if (is_rela and bytes.len < 24) return error.TruncatedRelocationTable;
    if (!is_rela and bytes.len < 16) return error.TruncatedRelocationTable;

    const offset = std.mem.readInt(u64, bytes[0..8], endian);
    const r_info = std.mem.readInt(u64, bytes[8..16], endian);
    const sym_index: u32 = @intCast(r_info >> 32);
    const type_id: u32 = @intCast(r_info & 0xFFFFFFFF);

    const addend: i64 = if (is_rela)
        std.mem.readInt(i64, bytes[16..24], endian)
    else
        0;

    return .{
        .offset = offset,
        .symbol_index = sym_index,
        .type_id = type_id,
        .addend = addend,
        .has_explicit_addend = is_rela,
    };
}

fn parseRelocation32(bytes: []const u8, endian: std.builtin.Endian, is_rela: bool) RelocationError!Relocation {
    if (is_rela and bytes.len < 12) return error.TruncatedRelocationTable;
    if (!is_rela and bytes.len < 8) return error.TruncatedRelocationTable;

    const offset = std.mem.readInt(u32, bytes[0..4], endian);
    const r_info = std.mem.readInt(u32, bytes[4..8], endian);
    const sym_index: u32 = r_info >> 8;
    const type_id: u32 = r_info & 0xFF;

    const addend: i64 = if (is_rela)
        @as(i64, std.mem.readInt(i32, bytes[8..12], endian))
    else
        0;

    return .{
        .offset = offset,
        .symbol_index = sym_index,
        .type_id = type_id,
        .addend = addend,
        .has_explicit_addend = is_rela,
    };
}

// === Unit Tests ===

test "reject file with invalid magic bytes" {
    var invalid_bytes: [64]u8 = undefined;
    @memset(&invalid_bytes, 0);
    @memcpy(invalid_bytes[0..8], &[_]u8{ 'N', 'O', 'P', 'E', 2, 1, 1, 0 });
    try std.testing.expectError(error.InvalidMagic, Header.parse(&invalid_bytes));
}

test "reject file shorter than minimum identification bytes" {
    const short_bytes = [_]u8{ 0x7F, 'E', 'L' };
    try std.testing.expectError(error.TruncatedHeader, Header.parse(&short_bytes));
}

test "reject invalid class and endianness codes" {
    var bad_class: [64]u8 = undefined;
    @memset(&bad_class, 0);
    @memcpy(bad_class[0..8], &[_]u8{ 0x7F, 'E', 'L', 'F', 99, 1, 1, 0 });
    try std.testing.expectError(error.InvalidClass, Header.parse(&bad_class));

    var bad_endian: [64]u8 = undefined;
    @memset(&bad_endian, 0);
    @memcpy(bad_endian[0..8], &[_]u8{ 0x7F, 'E', 'L', 'F', 2, 99, 1, 0 });
    try std.testing.expectError(error.InvalidEndian, Header.parse(&bad_endian));
}

test "parse 64-bit little-endian ELF relocatable header" {
    var hdr_buf: [64]u8 = undefined;
    @memset(&hdr_buf, 0);

    @memcpy(hdr_buf[0..4], &MAGIC);
    hdr_buf[4] = 2; // ELFCLASS64
    hdr_buf[5] = 1; // ELFDATA2LSB (little-endian)
    hdr_buf[6] = 1; // EV_CURRENT
    hdr_buf[7] = 0; // System V
    hdr_buf[8] = 0; // ABI version

    std.mem.writeInt(u16, hdr_buf[16..18], 1, .little);
    std.mem.writeInt(u16, hdr_buf[18..20], 183, .little);
    std.mem.writeInt(u32, hdr_buf[20..24], 1, .little);
    std.mem.writeInt(u64, hdr_buf[24..32], 0, .little);
    std.mem.writeInt(u64, hdr_buf[32..40], 0, .little);
    std.mem.writeInt(u64, hdr_buf[40..48], 0x1000, .little);
    std.mem.writeInt(u32, hdr_buf[48..52], 0, .little);
    std.mem.writeInt(u16, hdr_buf[52..54], 64, .little);
    std.mem.writeInt(u16, hdr_buf[54..56], 0, .little);
    std.mem.writeInt(u16, hdr_buf[56..58], 0, .little);
    std.mem.writeInt(u16, hdr_buf[58..60], 64, .little);
    std.mem.writeInt(u16, hdr_buf[60..62], 12, .little);
    std.mem.writeInt(u16, hdr_buf[62..64], 11, .little);

    const parsed = try Header.parse(&hdr_buf);

    try std.testing.expectEqual(Class.elf64, parsed.class);
    try std.testing.expectEqual(std.builtin.Endian.little, parsed.endian);
    try std.testing.expectEqual(FileType.rel, parsed.file_type);
    try std.testing.expectEqual(Machine.aarch64, parsed.machine);
    try std.testing.expectEqual(@as(u64, 0x1000), parsed.shoff);
    try std.testing.expectEqual(@as(u16, 64), parsed.ehsize);
    try std.testing.expectEqual(@as(u16, 64), parsed.shentsize);
    try std.testing.expectEqual(@as(u16, 12), parsed.shnum);
    try std.testing.expectEqual(@as(u16, 11), parsed.shstrndx);
}

test "parse 32-bit big-endian ELF header" {
    var hdr_buf: [52]u8 = undefined;
    @memset(&hdr_buf, 0);

    @memcpy(hdr_buf[0..4], &MAGIC);
    hdr_buf[4] = 1; // ELFCLASS32
    hdr_buf[5] = 2; // ELFDATA2MSB (big-endian)
    hdr_buf[6] = 1; // EV_CURRENT

    std.mem.writeInt(u16, hdr_buf[16..18], 2, .big);
    std.mem.writeInt(u16, hdr_buf[18..20], 40, .big);
    std.mem.writeInt(u32, hdr_buf[20..24], 1, .big);
    std.mem.writeInt(u32, hdr_buf[24..28], 0x8000, .big);
    std.mem.writeInt(u32, hdr_buf[28..32], 0x34, .big);
    std.mem.writeInt(u32, hdr_buf[32..36], 0x2000, .big);
    std.mem.writeInt(u32, hdr_buf[36..40], 0x05000000, .big);
    std.mem.writeInt(u16, hdr_buf[40..42], 52, .big);
    std.mem.writeInt(u16, hdr_buf[42..44], 32, .big);
    std.mem.writeInt(u16, hdr_buf[44..46], 2, .big);
    std.mem.writeInt(u16, hdr_buf[46..48], 40, .big);
    std.mem.writeInt(u16, hdr_buf[48..50], 8, .big);
    std.mem.writeInt(u16, hdr_buf[50..52], 7, .big);

    const parsed = try Header.parse(&hdr_buf);

    try std.testing.expectEqual(Class.elf32, parsed.class);
    try std.testing.expectEqual(std.builtin.Endian.big, parsed.endian);
    try std.testing.expectEqual(FileType.exec, parsed.file_type);
    try std.testing.expectEqual(Machine.arm, parsed.machine);
    try std.testing.expectEqual(@as(u64, 0x8000), parsed.entry);
    try std.testing.expectEqual(@as(u64, 0x2000), parsed.shoff);
    try std.testing.expectEqual(@as(u16, 52), parsed.ehsize);
    try std.testing.expectEqual(@as(u16, 40), parsed.shentsize);
    try std.testing.expectEqual(@as(u16, 8), parsed.shnum);
    try std.testing.expectEqual(@as(u16, 7), parsed.shstrndx);
}

test "parse 64-bit ELF section header" {
    var sh_buf: [64]u8 = undefined;
    @memset(&sh_buf, 0);

    std.mem.writeInt(u32, sh_buf[0..4], 12, .little);
    std.mem.writeInt(u32, sh_buf[4..8], 1, .little);
    std.mem.writeInt(u64, sh_buf[8..16], flags.ALLOC | flags.EXECINSTR, .little);
    std.mem.writeInt(u64, sh_buf[16..24], 0x400000, .little);
    std.mem.writeInt(u64, sh_buf[24..32], 0x100, .little);
    std.mem.writeInt(u64, sh_buf[32..40], 0x48, .little);
    std.mem.writeInt(u32, sh_buf[40..44], 0, .little);
    std.mem.writeInt(u32, sh_buf[44..48], 0, .little);
    std.mem.writeInt(u64, sh_buf[48..56], 16, .little);
    std.mem.writeInt(u64, sh_buf[56..64], 0, .little);

    var hdr: Header = undefined;
    hdr.class = .elf64;
    hdr.endian = .little;
    hdr.shoff = 0;
    hdr.shentsize = 64;
    hdr.shnum = 1;

    const sh = try hdr.parseSectionHeader(&sh_buf, 0);

    try std.testing.expectEqual(@as(u32, 12), sh.name_offset);
    try std.testing.expectEqual(SectionType.progbits, sh.sh_type);
    try std.testing.expect(sh.isAlloc());
    try std.testing.expect(sh.isExecutable());
    try std.testing.expect(!sh.isWritable());
    try std.testing.expectEqual(@as(u64, 0x400000), sh.addr);
    try std.testing.expectEqual(@as(u64, 0x100), sh.offset);
    try std.testing.expectEqual(@as(u64, 0x48), sh.size);
    try std.testing.expectEqual(@as(u64, 16), sh.addralign);
}

test "parse 32-bit ELF section header" {
    var sh_buf: [40]u8 = undefined;
    @memset(&sh_buf, 0);

    std.mem.writeInt(u32, sh_buf[0..4], 5, .big);
    std.mem.writeInt(u32, sh_buf[4..8], 8, .big);
    std.mem.writeInt(u32, sh_buf[8..12], @as(u32, @truncate(flags.ALLOC | flags.WRITE)), .big);
    std.mem.writeInt(u32, sh_buf[12..16], 0x20000, .big);
    std.mem.writeInt(u32, sh_buf[16..20], 0x80, .big);
    std.mem.writeInt(u32, sh_buf[20..24], 0x20, .big);
    std.mem.writeInt(u32, sh_buf[24..28], 0, .big);
    std.mem.writeInt(u32, sh_buf[28..32], 0, .big);
    std.mem.writeInt(u32, sh_buf[32..36], 4, .big);
    std.mem.writeInt(u32, sh_buf[36..40], 0, .big);

    var hdr: Header = undefined;
    hdr.class = .elf32;
    hdr.endian = .big;
    hdr.shoff = 0;
    hdr.shentsize = 40;
    hdr.shnum = 1;

    const sh = try hdr.parseSectionHeader(&sh_buf, 0);

    try std.testing.expectEqual(@as(u32, 5), sh.name_offset);
    try std.testing.expectEqual(SectionType.nobits, sh.sh_type);
    try std.testing.expect(sh.isAlloc());
    try std.testing.expect(sh.isWritable());
    try std.testing.expect(!sh.isExecutable());
    try std.testing.expectEqual(@as(u64, 0x20000), sh.addr);
    try std.testing.expectEqual(@as(u64, 0x20), sh.size);
}

test "section data slice retrieval and nobits empty return" {
    var file_mock: [256]u8 = undefined;
    @memset(&file_mock, 0);
    @memcpy(file_mock[64..80], "embedded payload");

    const progbits_sh = SectionHeader{
        .name_offset = 0,
        .sh_type = .progbits,
        .sh_flags = flags.ALLOC,
        .addr = 0,
        .offset = 64,
        .size = 16,
        .link = 0,
        .info = 0,
        .addralign = 8,
        .entsize = 0,
    };

    const data = try progbits_sh.getData(&file_mock);
    try std.testing.expectEqualStrings("embedded payload", data);

    const nobits_sh = SectionHeader{
        .name_offset = 0,
        .sh_type = .nobits,
        .sh_flags = flags.ALLOC | flags.WRITE,
        .addr = 0,
        .offset = 64,
        .size = 1024,
        .link = 0,
        .info = 0,
        .addralign = 8,
        .entsize = 0,
    };

    const nobits_data = try nobits_sh.getData(&file_mock);
    try std.testing.expectEqual(@as(usize, 0), nobits_data.len);
}

test "section name lookup from string table" {
    const shstrtab = "\x00.text\x00.data\x00.bss\x00.shstrtab\x00";

    const text_sh = SectionHeader{
        .name_offset = 1,
        .sh_type = .progbits,
        .sh_flags = flags.ALLOC | flags.EXECINSTR,
        .addr = 0,
        .offset = 0,
        .size = 0,
        .link = 0,
        .info = 0,
        .addralign = 4,
        .entsize = 0,
    };

    const name = try text_sh.getName(shstrtab);
    try std.testing.expectEqualStrings(".text", name);

    const data_sh = SectionHeader{
        .name_offset = 7,
        .sh_type = .progbits,
        .sh_flags = flags.ALLOC | flags.WRITE,
        .addr = 0,
        .offset = 0,
        .size = 0,
        .link = 0,
        .info = 0,
        .addralign = 4,
        .entsize = 0,
    };

    const data_name = try data_sh.getName(shstrtab);
    try std.testing.expectEqualStrings(".data", data_name);
}

test "section parsing reports out of bounds errors cleanly" {
    var short_buf: [30]u8 = undefined;
    @memset(&short_buf, 0);

    var hdr: Header = undefined;
    hdr.class = .elf64;
    hdr.endian = .little;
    hdr.shoff = 100;
    hdr.shentsize = 64;
    hdr.shnum = 2;

    try std.testing.expectError(error.TruncatedSectionTable, hdr.parseSectionHeader(&short_buf, 0));
    try std.testing.expectError(error.InvalidSectionIndex, hdr.parseSectionHeader(&short_buf, 5));
}

test "section type name handles custom and unknown integer values without panicking" {
    const custom_sec: SectionType = @fromBackingInt(@intCast(0x6ffffff6));
    try std.testing.expectEqualStrings("gnu_hash", custom_sec.name());

    const unknown_sec: SectionType = @fromBackingInt(@intCast(0x12345678));
    try std.testing.expectEqualStrings("unknown", unknown_sec.name());
}

test "parse 64-bit ELF symbol entry" {
    var sym_buf: [24]u8 = undefined;
    @memset(&sym_buf, 0);

    std.mem.writeInt(u32, sym_buf[0..4], 14, .little);
    sym_buf[4] = (1 << 4) | 2;
    sym_buf[5] = 0;
    std.mem.writeInt(u16, sym_buf[6..8], 1, .little);
    std.mem.writeInt(u64, sym_buf[8..16], 0x401000, .little);
    std.mem.writeInt(u64, sym_buf[16..24], 128, .little);

    const sym = try parseSymbol64(&sym_buf, .little);

    try std.testing.expectEqual(@as(u32, 14), sym.name_offset);
    try std.testing.expectEqual(SymbolBinding.global, sym.binding);
    try std.testing.expectEqual(SymbolType.func, sym.sym_type);
    try std.testing.expectEqual(SymbolVisibility.default, sym.visibility);
    try std.testing.expectEqual(@as(u16, 1), sym.shndx);
    try std.testing.expectEqual(@as(u64, 0x401000), sym.value);
    try std.testing.expectEqual(@as(u64, 128), sym.size);
    try std.testing.expect(!sym.isUndefined());
    try std.testing.expect(!sym.isAbsolute());
}

test "parse 32-bit ELF symbol entry" {
    var sym_buf: [16]u8 = undefined;
    @memset(&sym_buf, 0);

    std.mem.writeInt(u32, sym_buf[0..4], 8, .big);
    std.mem.writeInt(u32, sym_buf[4..8], 0x20004, .big);
    std.mem.writeInt(u32, sym_buf[8..12], 4, .big);
    sym_buf[12] = (2 << 4) | 1;
    sym_buf[13] = 2;
    std.mem.writeInt(u16, sym_buf[14..16], SpecialSectionIndex.UNDEF, .big);

    const sym = try parseSymbol32(&sym_buf, .big);

    try std.testing.expectEqual(@as(u32, 8), sym.name_offset);
    try std.testing.expectEqual(@as(u64, 0x20004), sym.value);
    try std.testing.expectEqual(@as(u64, 4), sym.size);
    try std.testing.expectEqual(SymbolBinding.weak, sym.binding);
    try std.testing.expectEqual(SymbolType.object, sym.sym_type);
    try std.testing.expectEqual(SymbolVisibility.hidden, sym.visibility);
    try std.testing.expect(sym.isUndefined());
}

test "symbol name extraction from strtab bytes" {
    const strtab_mock = "\x00main\x00printf\x00global_counter\x00";

    const sym_main = Symbol{
        .name_offset = 1,
        .value = 0x4000,
        .size = 32,
        .binding = .global,
        .sym_type = .func,
        .visibility = .default,
        .shndx = 1,
    };

    const sym_printf = Symbol{
        .name_offset = 6,
        .value = 0,
        .size = 0,
        .binding = .global,
        .sym_type = .func,
        .visibility = .default,
        .shndx = SpecialSectionIndex.UNDEF,
    };

    try std.testing.expectEqualStrings("main", try sym_main.getName(strtab_mock));
    try std.testing.expectEqualStrings("printf", try sym_printf.getName(strtab_mock));
}

test "parse 64-bit ELF rela entry" {
    var rela_buf: [24]u8 = undefined;
    @memset(&rela_buf, 0);

    std.mem.writeInt(u64, rela_buf[0..8], 0x1024, .little); // r_offset
    // r_info: symbol index 5, type 275 (R_AARCH64_ADR_PREL_PG_HI21)
    const r_info: u64 = (@as(u64, 5) << 32) | @as(u64, 275);
    std.mem.writeInt(u64, rela_buf[8..16], r_info, .little);
    std.mem.writeInt(i64, rela_buf[16..24], -4, .little); // r_addend

    const rel = try parseRelocation64(&rela_buf, .little, true);

    try std.testing.expectEqual(@as(u64, 0x1024), rel.offset);
    try std.testing.expectEqual(@as(u32, 5), rel.symbol_index);
    try std.testing.expectEqual(@as(u32, 275), rel.type_id);
    try std.testing.expectEqual(@as(i64, -4), rel.addend);
    try std.testing.expect(rel.has_explicit_addend);
    try std.testing.expectEqualStrings("ADR_PREL_PG_HI21", rel.typeName(.aarch64));
}

test "parse 64-bit ELF rel entry without addend" {
    var rel_buf: [16]u8 = undefined;
    @memset(&rel_buf, 0);

    std.mem.writeInt(u64, rel_buf[0..8], 0x2000, .little);
    const r_info: u64 = (@as(u64, 12) << 32) | @as(u64, 7); // R_X86_64_JUMP_SLOT
    std.mem.writeInt(u64, rel_buf[8..16], r_info, .little);

    const rel = try parseRelocation64(&rel_buf, .little, false);

    try std.testing.expectEqual(@as(u64, 0x2000), rel.offset);
    try std.testing.expectEqual(@as(u32, 12), rel.symbol_index);
    try std.testing.expectEqual(@as(u32, 7), rel.type_id);
    try std.testing.expectEqual(@as(i64, 0), rel.addend);
    try std.testing.expect(!rel.has_explicit_addend);
    try std.testing.expectEqualStrings("JUMP_SLOT", rel.typeName(.x86_64));
}

test "parse 32-bit ELF rela and rel entries" {
    // 32-bit Rela (12 bytes)
    var rela32_buf: [12]u8 = undefined;
    @memset(&rela32_buf, 0);

    std.mem.writeInt(u32, rela32_buf[0..4], 0x400, .big);
    const r_info32: u32 = (@as(u32, 3) << 8) | @as(u32, 2); // sym 3, type 2
    std.mem.writeInt(u32, rela32_buf[4..8], r_info32, .big);
    std.mem.writeInt(i32, rela32_buf[8..12], 16, .big);

    const rela = try parseRelocation32(&rela32_buf, .big, true);
    try std.testing.expectEqual(@as(u64, 0x400), rela.offset);
    try std.testing.expectEqual(@as(u32, 3), rela.symbol_index);
    try std.testing.expectEqual(@as(u32, 2), rela.type_id);
    try std.testing.expectEqual(@as(i64, 16), rela.addend);
    try std.testing.expect(rela.has_explicit_addend);

    // 32-bit Rel (8 bytes)
    var rel32_buf: [8]u8 = undefined;
    @memset(&rel32_buf, 0);

    std.mem.writeInt(u32, rel32_buf[0..4], 0x800, .big);
    std.mem.writeInt(u32, rel32_buf[4..8], r_info32, .big);

    const rel = try parseRelocation32(&rel32_buf, .big, false);
    try std.testing.expectEqual(@as(u64, 0x800), rel.offset);
    try std.testing.expectEqual(@as(u32, 3), rel.symbol_index);
    try std.testing.expectEqual(@as(i64, 0), rel.addend);
    try std.testing.expect(!rel.has_explicit_addend);
}
