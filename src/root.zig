//! sibl - Something is Better Linker
//!
//! A fast, lightweight, zero-dependency static and dynamic linker written in Zig.
//! This root module re-exports all core parsing, allocation, and target utilities
//! so consumers can import a single namespace.
//!
//! Supported object formats:
//! - ELF (Linux, FreeBSD, and other Unix systems)
//! - PE/COFF (Windows)
//! - Mach-O (macOS and Apple Silicon)
//! - Static archives (.a / .lib)
//!
//! The library is organized by implementation phase. Each phase module is
//! independently importable and heavily unit-tested.

const std = @import("std");

// === Core Modules ===

/// Memory allocation utilities and arena management (Phase 1.2).
/// Provides `LinkerAllocators` for bulk arena allocation and a fixed
/// scratch buffer for short-lived formatting.
pub const alloc = @import("alloc.zig");

/// Command-line argument parsing and flag types (Phase 1.3).
/// Handles common linker flags (`-o`, `-L`, `-l`, `-shared`, `--entry`, etc.)
/// and target format / emulation selection.
pub const args = @import("args.zig");

/// Target architecture, binary format detection, and page size rules (Phase 1.4).
/// Resolves host or explicit target into a `TargetInfo` used by later stages.
pub const target = @import("target.zig");

/// Zero-copy memory-mapped file reader (Phase 1.5).
/// Maps input object files into virtual memory for efficient slice access.
pub const file = @import("file.zig");

/// ELF parsing and format inspection (Phase 2.1 – 2.5).
/// Zero-copy readers for ELF headers, section headers, symbol tables,
/// string tables, and relocation entries (32-bit and 64-bit).
pub const elf = @import("elf.zig");

/// String table reader and deduplicating builder (Phase 2.4).
/// Supports zero-copy lookup of existing string tables and construction
/// of new deduplicated tables for output binaries.
pub const strtab = @import("strtab.zig");

/// PE and COFF parsing for Windows targets (Phase 3.1 – 3.5).
/// Parses DOS stubs, COFF headers, section tables, symbols, relocations,
/// and section characteristic flags.
pub const coff = @import("coff.zig");

/// Mach-O parsing for macOS and Apple Silicon targets (Phase 4.1 – 4.5).
/// Decodes Mach-O headers, load commands, sections, nlist symbols, and
/// relocation entries.
pub const macho = @import("macho.zig");

/// Static archive (.a and .lib) parsing (Phase 5.1 – 5.4).
/// Supports GNU and BSD-style symbol indexes, selective member extraction,
/// and thin archives.
pub const archive = @import("archive.zig");

// === Re-exported Types and Functions ===

// Allocator types
/// Central allocator wrapper used throughout sibl linking phases.
pub const LinkerAllocators = alloc.LinkerAllocators;
/// Fixed 4 KB stack buffer for assembling short paths and messages.
pub const ScratchBuffer = alloc.ScratchBuffer;

// Argument parser types and helpers
/// Fully parsed command-line options.
pub const Options = args.Options;
/// Explicit output format requested by the user.
pub const TargetFormat = args.TargetFormat;
/// Emulation mode (e.g. elf_x86_64, coff_x86_64).
pub const Emulation = args.Emulation;
/// Errors that can occur while parsing arguments.
pub const ParseError = args.ParseError;
/// Parse raw process arguments into an `Options` value.
pub const parseArgs = args.parse;
/// Print the sibl usage help text to stderr.
pub const printHelp = args.printHelp;

// Target and platform types
/// Supported CPU architectures.
pub const Arch = target.Arch;
/// Supported binary container formats.
pub const BinaryFormat = target.BinaryFormat;
/// Complete target specification (arch, format, endian, page size, defaults).
pub const TargetInfo = target.TargetInfo;

// File reader types
/// A file mapped into memory for fast, read-only slice access.
pub const MappedFile = file.MappedFile;

// ELF types
/// Parsed ELF file header (32-bit or 64-bit).
pub const ElfHeader = elf.Header;
/// ELF class (32-bit vs 64-bit).
pub const ElfClass = elf.Class;
/// ELF machine architecture identifier.
pub const ElfMachine = elf.Machine;
/// ELF file type (REL, EXEC, DYN, CORE).
pub const ElfFileType = elf.FileType;
/// ELF section header.
pub const ElfSectionHeader = elf.SectionHeader;
/// ELF section type.
pub const ElfSectionType = elf.SectionType;
/// ELF section flag constants.
pub const elf_flags = elf.flags;

// ELF Symbol types
/// ELF symbol table entry.
pub const ElfSymbol = elf.Symbol;
/// Symbol binding (local, global, weak).
pub const ElfSymbolBinding = elf.SymbolBinding;
/// Symbol type (function, object, section, etc.).
pub const ElfSymbolType = elf.SymbolType;
/// Symbol visibility.
pub const ElfSymbolVisibility = elf.SymbolVisibility;
/// Special section index values (UNDEF, ABS, COMMON, …).
pub const SpecialSectionIndex = elf.SpecialSectionIndex;

// ELF Relocation types
/// ELF relocation entry (Rel or Rela).
pub const ElfRelocation = elf.Relocation;
/// Errors that can occur while parsing relocations.
pub const RelocationError = elf.RelocationError;

// String table types
/// Zero-copy reader for an existing string table section.
pub const StringTableReader = strtab.StringTableReader;
/// Builder that constructs a deduplicated string table.
pub const StringTableBuilder = strtab.StringTableBuilder;

// COFF / PE types
/// Parsed COFF / PE header.
pub const CoffHeader = coff.Header;
/// COFF machine type.
pub const CoffMachine = coff.Machine;
/// PE optional header.
pub const CoffOptionalHeader = coff.OptionalHeader;
/// PE subsystem.
pub const CoffSubsystem = coff.Subsystem;
/// PE data directory entry.
pub const CoffDataDirectory = coff.DataDirectory;
/// COFF section header.
pub const CoffSectionHeader = coff.SectionHeader;
/// COFF symbol table entry.
pub const CoffSymbol = coff.Symbol;
/// COFF symbol storage class.
pub const CoffStorageClass = coff.StorageClass;
/// Special COFF section indices.
pub const CoffSpecialSection = coff.SpecialSection;
/// COFF relocation entry.
pub const CoffRelocation = coff.Relocation;
/// Errors that can occur while parsing COFF relocations.
pub const CoffRelocationError = coff.RelocationError;
/// COMDAT selection criteria.
pub const CoffComdatSelection = coff.ComdatSelection;
/// Classified section kind (code, data, bss, …).
pub const CoffSectionKind = coff.SectionKind;
/// Mapped section permissions.
pub const CoffSectionPermissions = coff.SectionPermissions;
/// COFF file characteristic flags.
pub const coff_characteristics = coff.characteristics;
/// COFF section characteristic flags.
pub const coff_section_flags = coff.section_flags;

// Mach-O types
/// Parsed Mach-O header.
pub const MachoHeader = macho.Header;
/// Mach-O CPU type.
pub const MachoCpuType = macho.CpuType;
/// Mach-O file type.
pub const MachoFileType = macho.FileType;
/// Mach-O load command type.
pub const MachoCommandType = macho.CommandType;
/// Generic load command header.
pub const MachoLoadCommand = macho.LoadCommand;
/// Iterator over load commands in a Mach-O file.
pub const MachoLoadCommandIterator = macho.LoadCommandIterator;
/// 64-bit segment load command.
pub const MachoSegment64Command = macho.Segment64Command;
/// 64-bit section descriptor.
pub const MachoSection64 = macho.Section64;
/// Mach-O section type.
pub const MachoSectionType = macho.SectionType;
/// Symbol table load command.
pub const MachoSymtabCommand = macho.SymtabCommand;
/// Dynamic symbol table load command.
pub const MachoDysymtabCommand = macho.DysymtabCommand;
/// Entry point load command.
pub const MachoMainCommand = macho.MainCommand;
/// Dynamic library load command.
pub const MachoDylibCommand = macho.DylibCommand;
/// Build version load command.
pub const MachoBuildVersionCommand = macho.BuildVersionCommand;
/// 64-bit nlist symbol entry.
pub const MachoNlist64 = macho.Nlist64;
/// Errors that can occur while reading Mach-O symbols.
pub const MachoSymbolError = macho.SymbolError;
/// Mach-O relocation entry.
pub const MachoRelocation = macho.Relocation;
/// Errors that can occur while parsing Mach-O relocations.
pub const MachoRelocationError = macho.RelocationError;
/// Mach-O header flag constants.
pub const macho_flags = macho.flags;
/// Mach-O virtual memory protection constants.
pub const macho_vm_prot = macho.vm_prot;
/// Mach-O section attribute constants.
pub const macho_section_attributes = macho.section_attributes;
/// nlist descriptor masks.
pub const macho_nlist_masks = macho.nlist_masks;
/// nlist type constants.
pub const macho_nlist_type = macho.nlist_type;
/// nlist descriptor flags.
pub const macho_nlist_desc = macho.nlist_desc;
/// Relocation-related constants.
pub const macho_reloc_constants = macho.reloc_constants;

// Archive types
/// Parsed static archive.
pub const Archive = archive.Archive;
/// Archive member header.
pub const ArchiveMemberHeader = archive.MemberHeader;
/// Iterator over archive members.
pub const ArchiveMemberIterator = archive.MemberIterator;
/// Symbol defined by an archive member.
pub const ArchiveSymbol = archive.ArchiveSymbol;
/// Symbol index inside an archive.
pub const ArchiveSymbolIndex = archive.SymbolIndex;
/// Iterator over archive symbols.
pub const ArchiveSymbolIterator = archive.SymbolIterator;
/// Extracted archive member data.
pub const ArchiveExtractedMember = archive.ExtractedMember;
/// Selective extractor that pulls only needed members.
pub const ArchiveSelectiveExtractor = archive.SelectiveExtractor;
/// Errors that can occur while parsing archives.
pub const ArchiveError = archive.Error;
/// Standard archive magic (`!<arch>\n`).
pub const archive_magic = archive.ARMAG;
/// Thin archive magic (`!<thin>\n`).
pub const archive_thin_magic = archive.THIN_ARMAG;
/// Member trailer magic (`` `\n ``).
pub const archive_trailer_magic = archive.ARFMAG;

// === Test Suite Runner ===

test {
    _ = alloc;
    _ = args;
    _ = target;
    _ = file;
    _ = elf;
    _ = strtab;
    _ = coff;
    _ = macho;
    _ = archive;
}
