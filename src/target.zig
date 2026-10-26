//! Phase 1.4: Target Detection for sibl.
//!
//! Identifies target CPU architecture, binary container format,
//! byte order, and page alignment.

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

/// Supported binary formats.
pub const BinaryFormat = enum {
    elf,
    coff,
    macho,
};

/// Target machine specification used across linking stages.
pub const TargetInfo = struct {
    arch: Arch,
    format: BinaryFormat,
    endian: std.builtin.Endian,
    page_size: usize,
    default_entry: []const u8,
    default_output: []const u8,

    pub fn detect(opts: args.Options) TargetInfo {
        if (opts.emulation != .unspecified) {
            return fromEmulation(opts.emulation);
        }

        if (opts.target_format != .auto) {
            return fromExplicitFormat(opts.target_format);
        }

        return fromHost();
    }

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

// === Unit Tests ===

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

test "pointer width returns correct size for 32-bit and 64-bit architectures" {
    try std.testing.expectEqual(@as(u8, 64), Arch.x86_64.pointerWidth());
    try std.testing.expectEqual(@as(u8, 64), Arch.aarch64.pointerWidth());
    try std.testing.expectEqual(@as(u8, 64), Arch.riscv64.pointerWidth());
    try std.testing.expectEqual(@as(u8, 32), Arch.x86.pointerWidth());
    try std.testing.expectEqual(@as(u8, 32), Arch.arm.pointerWidth());
}

test "target detection for elf riscv64" {
    const opts = args.Options{
        .emulation = .elf_riscv64,
    };
    const target_info = TargetInfo.detect(opts);

    try std.testing.expectEqual(Arch.riscv64, target_info.arch);
    try std.testing.expectEqual(BinaryFormat.elf, target_info.format);
    try std.testing.expectEqual(@as(usize, 4096), target_info.page_size);
    try std.testing.expectEqualStrings("_start", target_info.default_entry);
    try std.testing.expectEqualStrings("a.out", target_info.default_output);
}

test "target detection for elf aarch64" {
    const opts = args.Options{
        .emulation = .elf_aarch64,
    };
    const target_info = TargetInfo.detect(opts);

    try std.testing.expectEqual(Arch.aarch64, target_info.arch);
    try std.testing.expectEqual(BinaryFormat.elf, target_info.format);
    try std.testing.expectEqual(@as(usize, 65536), target_info.page_size);
}

test "target detection for explicit macho format" {
    const opts = args.Options{
        .target_format = .macho,
    };
    const target_info = TargetInfo.detect(opts);

    try std.testing.expectEqual(BinaryFormat.macho, target_info.format);
    try std.testing.expectEqualStrings("_main", target_info.default_entry);
}
