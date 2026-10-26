//! sibl - Something is Better Linker
//!
//! Root package library file.
//! This file exposes the public API for sibl so other programs
//! or internal files can use it as a package (`@import("sibl")`).

const std = @import("std");

// Core Modules

/// Memory allocation utilities and arena management (Phase 1.2).
pub const alloc = @import("alloc.zig");

/// Command-line argument parsing and flag types (Phase 1.3).
pub const args = @import("args.zig");

/// Target architecture, format detection, and page rules (Phase 1.4).
pub const target = @import("target.zig");

// Re-exported Common Types and Functions

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

// Test Suite Runner

// Running `zig build test` against root.zig will automatically run
// all unit tests inside each sub-module.
test {
    _ = alloc;
    _ = args;
    _ = target;
}
