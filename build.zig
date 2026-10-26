//! sibl (Something is Better Linker) build configuration.
//! Configured for Zig 0.17.0 using the module-based build system.

const std = @import("std");

pub fn build(b: *std.Build) void {
    // Standard target and optimization options passed via CLI (-Dtarget, -Doptimize)
    const target = b.standardTargetOptions(.{});
    const optimize = b.standardOptimizeOption(.{});

    // Root module for the linker binary
    const sibl_mod = b.createModule(.{
        .root_source_file = b.path("src/main.zig"),
        .target = target,
        .optimize = optimize,
    });

    // Executable artifact
    const exe = b.addExecutable(.{
        .name = "sibl",
        .root_module = sibl_mod,
    });

    b.installArtifact(exe);

    // Convenience step: `zig build run -- [args]`
    const run_cmd = b.addRunArtifact(exe);
    run_cmd.step.dependOn(b.getInstallStep());
    if (b.args) |args| {
        run_cmd.addArgs(args);
    }

    const run_step = b.step("run", "Run the sibl linker");
    run_step.dependOn(&run_cmd.step);

    // Unit test step: `zig build test`
    const unit_tests = b.addTest(.{
        .root_module = b.createModule(.{
            .root_source_file = b.path("src/main.zig"),
            .target = target,
            .optimize = optimize,
        }),
    });

    const run_unit_tests = b.addRunArtifact(unit_tests);
    const test_step = b.step("test", "Run sibl unit tests");
    test_step.dependOn(&run_unit_tests.step);
}
