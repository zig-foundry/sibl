//! sibl (Something is Better Linker) build script.
//!
//! Configured for Zig 0.17.0.
//! Sets up the sibl library module, the main executable, and test runners.
//! The library is exported so other projects can import it as a dependency.

const std = @import("std");

pub fn build(b: *std.Build) void {
    // Standard target options allow cross-compilation via -Dtarget
    const target = b.standardTargetOptions(.{});

    // Standard optimization options allow -Doptimize (Debug, ReleaseFast, ReleaseSafe, ReleaseSmall)
    const optimize = b.standardOptimizeOption(.{});

    // Step 1: Reusable sibl library module
    // We create a named module from root.zig so other projects can import it.
    const sibl_mod = b.addModule("sibl", .{
        .root_source_file = b.path("src/root.zig"),
        .target = target,
        .optimize = optimize,
    });

    // Allow internal source files to do: const sibl = @import("sibl");
    sibl_mod.addImport("sibl", sibl_mod);

    // Step 2: Main executable binary
    // The executable compiles src/main.zig and imports the sibl library module.
    const exe_mod = b.createModule(.{
        .root_source_file = b.path("src/main.zig"),
        .target = target,
        .optimize = optimize,
        .imports = &.{
            .{ .name = "sibl", .module = sibl_mod },
        },
    });

    const exe = b.addExecutable(.{
        .name = "sibl",
        .root_module = exe_mod,
    });

    // Place the final compiled binary into zig-out/bin/
    b.installArtifact(exe);

    // Step 3: Run step (`zig build run -- [args]`)
    const run_cmd = b.addRunArtifact(exe);
    run_cmd.step.dependOn(b.getInstallStep());

    // In Zig 0.17, addPassthruArgs() passes all CLI flags after `--` to sibl
    run_cmd.addPassthruArgs();

    const run_step = b.step("run", "Run the sibl linker");
    run_step.dependOn(&run_cmd.step);

    // Step 4: Unit test runner (`zig build test`)
    //
    // Compiles and runs all tests referenced inside src/root.zig
    const unit_tests = b.addTest(.{
        .root_module = sibl_mod,
    });

    const run_unit_tests = b.addRunArtifact(unit_tests);
    const test_step = b.step("test", "Run all sibl unit tests");
    test_step.dependOn(&run_unit_tests.step);
}
