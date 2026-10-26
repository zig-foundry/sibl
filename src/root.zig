//! sibl - Something is Better Linker
//!
//! Root package library file.
//! Re-exports all core modules and data types.

const std = @import("std");

// === Core Modules ===

/// Memory allocation utilities and arena management (Phase 1.2).
pub const alloc = @import("alloc.zig");

/// Command-line argument parsing and flag types (Phase 1.3).
pub const args = @import("args.zig");

/// Target architecture, format detection, and page rules (Phase 1.4).
pub const target = @import("target.zig");

/// Zero-copy memory mapped file reader (Phase 1.5).
pub const file = @import("file.zig");

/// ELF parsing and format inspection (Phase 2.1).
pub const elf = @import("elf.zig");

// === Re-exported Types and Functions ===

// Allocator types
pub const LinkerAllocators = alloc.LinkerAllocators;
pub const ScratchBuffer = alloc.ScratchBuffer;

// Argument parser types and helpers
pub const Options = args.Options;
pub const TargetFormat = args.TargetFormat;
pub const Emulation = args.Emulation;
pub const ParseError = args.ParseError;
pub const parseArgs = args.parse;
pub const printHelp = args.printHelp;

// Target and platform types
pub const Arch = target.Arch;
pub const BinaryFormat = target.BinaryFormat;
pub const TargetInfo = target.TargetInfo;

// File reader types
pub const MappedFile = file.MappedFile;

// ELF types
pub const ElfHeader = elf.Header;
pub const ElfClass = elf.Class;
pub const ElfMachine = elf.Machine;
pub const ElfFileType = elf.FileType;

// === Test Suite Runner ===

test {
    _ = alloc;
    _ = args;
    _ = target;
    _ = file;
    _ = elf;
}
