//! sibl main entry point.
//! Combines Phase 1.1 (build), 1.2 (allocators), and 1.3 (CLI parser).

const std = @import("std");
pub const alloc = @import("alloc.zig");
pub const args = @import("args.zig");

pub fn main(init: std.process.Init) !void {
    // Keep DebugAllocator in main's stack frame so its pointer stays valid
    var debug_alloc = std.heap.DebugAllocator(.{}){};
    defer {
        const check = debug_alloc.deinit();
        if (check == .leak) {
            std.debug.print("sibl: warning: memory leak detected\n", .{});
        }
    }

    // Phase 1.2: Initialize arena using the debug allocator
    var allocs = alloc.LinkerAllocators.init(debug_alloc.allocator());
    defer allocs.deinit();

    // In Zig 0.17, read CLI arguments through init.minimal.args
    const raw_args = init.minimal.args.toSlice(allocs.arena()) catch |err| {
        std.debug.print("sibl: failed to retrieve CLI arguments: {s}\n", .{@errorName(err)});
        std.process.exit(1);
    };

    // Phase 1.3: Parse arguments
    var options = args.parse(allocs.arena(), raw_args) catch |err| {
        switch (err) {
            error.MissingValue => std.debug.print("sibl: error: missing value for flag\n", .{}),
            error.InvalidFormat => std.debug.print("sibl: error: invalid target format (use elf, coff, or macho)\n", .{}),
            error.InvalidEmulation => std.debug.print("sibl: error: unsupported emulation mode\n", .{}),
            error.UnknownOption => {},
            error.OutOfMemory => std.debug.print("sibl: error: out of memory during argument parse\n", .{}),
        }
        std.process.exit(1);
    };
    defer options.deinit(allocs.arena());

    // Make sure at least one input file was provided
    if (options.input_files.items.len == 0) {
        std.debug.print("sibl: error: no input files provided\n", .{});
        args.printHelp();
        std.process.exit(1);
    }

    // Print parsed summary
    std.debug.print("sibl: Target Format : {s}\n", .{@tagName(options.target_format)});
    std.debug.print("sibl: Output Binary : {s}\n", .{options.output_path});
    std.debug.print("sibl: Entry Point   : {s}\n", .{options.entry_symbol});
    std.debug.print("sibl: Shared Build  : {}\n", .{options.is_shared});
    std.debug.print("sibl: Static Build  : {}\n", .{options.is_static});

    std.debug.print("sibl: Input Files ({d}):\n", .{options.input_files.items.len});
    for (options.input_files.items) |file| {
        std.debug.print("  - {s}\n", .{file});
    }

    if (options.lib_dirs.items.len > 0) {
        std.debug.print("sibl: Library Dirs ({d}):\n", .{options.lib_dirs.items.len});
        for (options.lib_dirs.items) |dir| {
            std.debug.print("  - {s}\n", .{dir});
        }
    }

    if (options.libs.items.len > 0) {
        std.debug.print("sibl: Libraries ({d}):\n", .{options.libs.items.len});
        for (options.libs.items) |lib| {
            std.debug.print("  - -l{s}\n", .{lib});
        }
    }
}

// Ensure zig build test runs tests from all submodules
test {
    _ = alloc;
    _ = args;
}
