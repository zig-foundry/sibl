//! Phase 1.4: Target Detection for sibl.
//!
//! Identifies the target CPU architecture, binary container format,
//! byte order, and virtual memory page alignment.

const std = @import("std");
const builtin = @import("builtin");
const args = @import("args.zig");

/// Supported CPU architectures.
pub const Arch = enum {
    x86_64,
    aarch64,
    riscv64,
    x86,
    arm,

    pub fn pointerWidth(self: Arch) u8 {
        return switch (self) {
            .x86_64, .aarch64, .riscv64 => 64,
            .x86, .arm => 32,
        };
    }
};

/// Supported binary object and executable formats.
pub const BinaryFormat = enum {
    elf,
    coff,
    macho,
};

/// Target machine specification used across all linking stages.
pub const TargetInfo = struct {
    /// Target CPU architecture
    arch: Arch,
    /// Output file container format
    format: BinaryFormat,
    /// Byte ordering (little-endian or big-endian)
    endian: std.builtin.Endian,
    /// Virtual memory page alignment size in bytes
    page_size: usize,
    /// Default program entry point symbol name
    default_entry: []const u8,
    /// Default output binary filename
    default_output: []const u8,

    /// Detect target machine settings from CLI options and host system fallbacks.
    pub fn detect(opts: args.Options) TargetInfo {
        // 1. Check if user specified emulation via -m
        if (opts.emulation != .unspecified) {
            return fromEmulation(opts.emulation);
        }

        // 2. Check if user explicitly passed --format
        if (opts.target_format != .auto) {
            return fromExplicitFormat(opts.target_format);
        }

        // 3. Fall back to host system defaults
        return fromHost();
    }

    /// Construct target configuration from standard GNU ld emulation strings.
    fn fromEmulation(emu: args.Emulation) TargetInfo {
        return switch (emu) {
            .elf_x86_64 => .{
                .arch = .x86_64,
                .format = .elf,
                .endian = .little,
                .page_size = 4096,
                .default_entry = "_start",
                .default_output = "a.out",
            },
            .elf_aarch64 => .{
                .arch = .aarch64,
                .format = .elf,
                .endian = .little,
                .page_size = 65536,
                .default_entry = "_start",
                .default_output = "a.out",
            },
            .elf_riscv64 => .{
                .arch = .riscv64,
                .format = .elf,
                .endian = .little,
                .page_size = 4096,
                .default_entry = "_start",
                .default_output = "a.out",
            },
            .pe_x86_64 => .{
                .arch = .x86_64,
                .format = .coff,
                .endian = .little,
                .page_size = 4096,
                .default_entry = "mainCRTStartup",
                .default_output = "a.exe",
            },
            .pe_aarch64 => .{
                .arch = .aarch64,
                .format = .coff,
                .endian = .little,
                .page_size = 4096,
                .default_entry = "mainCRTStartup",
                .default_output = "a.exe",
            },
            .unspecified => fromHost(),
        };
    }

    /// Construct target configuration when only the format is provided.
    fn fromExplicitFormat(fmt: args.TargetFormat) TargetInfo {
        const host = fromHost();
        return switch (fmt) {
            .elf => .{
                .arch = host.arch,
                .format = .elf,
                .endian = host.endian,
                .page_size = host.page_size,
                .default_entry = "_start",
                .default_output = "a.out",
            },
            .coff => .{
                .arch = host.arch,
                .format = .coff,
                .endian = .little,
                .page_size = 4096,
                .default_entry = "mainCRTStartup",
                .default_output = "a.exe",
            },
            .macho => .{
                .arch = host.arch,
                .format = .macho,
                .endian = host.endian,
                .page_size = if (host.arch == .aarch64) 16384 else 4096,
                .default_entry = "_main",
                .default_output = "a.out",
            },
            .auto => host,
        };
    }

    /// Read host machine architecture and OS using builtin reflection.
    fn fromHost() TargetInfo {
        const host_arch: Arch = switch (builtin.target.cpu.arch) {
            .x86_64 => .x86_64,
            .aarch64 => .aarch64,
            .riscv64 => .riscv64,
            .x86 => .x86,
            .arm, .armeb => .arm,
            else => .x86_64,
        };

        const host_format: BinaryFormat = switch (builtin.target.os.tag) {
            .windows => .coff,
            .macos, .ios, .tvos, .watchos, .visionos => .macho,
            else => .elf,
        };

        const page_size: usize = switch (host_arch) {
            .aarch64 => if (host_format == .macho) 16384 else 65536,
            else => 4096,
        };

        const entry: []const u8 = switch (host_format) {
            .elf => "_start",
            .coff => "mainCRTStartup",
            .macho => "_main",
        };

        const output: []const u8 = switch (host_format) {
            .coff => "a.exe",
            else => "a.out",
        };

        return .{
            .arch = host_arch,
            .format = host_format,
            .endian = builtin.target.cpu.arch.endian(),
            .page_size = page_size,
            .default_entry = entry,
            .default_output = output,
        };
    }
};

test "target detection from emulation flag" {
    const opts = args.Options{
        .emulation = .elf_x86_64,
    };
    const target = TargetInfo.detect(opts);

    try std.testing.expectEqual(Arch.x86_64, target.arch);
    try std.testing.expectEqual(BinaryFormat.elf, target.format);
    try std.testing.expectEqual(@as(usize, 4096), target.page_size);
    try std.testing.expectEqualStrings("_start", target.default_entry);
}

test "target detection for windows pe" {
    const opts = args.Options{
        .emulation = .pe_x86_64,
    };
    const target = TargetInfo.detect(opts);

    try std.testing.expectEqual(BinaryFormat.coff, target.format);
    try std.testing.expectEqualStrings("a.exe", target.default_output);
    try std.testing.expectEqualStrings("mainCRTStartup", target.default_entry);
}
