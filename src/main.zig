//! sibl main entry point.

const std = @import("std");
const sibl = @import("sibl");

pub fn main(init: std.process.Init) !void {
    // Keep DebugAllocator on main stack frame
    var debug_alloc = std.heap.DebugAllocator(.{}){};
    defer {
        const check = debug_alloc.deinit();
        if (check == .leak) {
            std.debug.print("sibl: warning: memory leak detected\n", .{});
        }
    }

    // Initialize arena allocator
    var allocs = sibl.LinkerAllocators.init(debug_alloc.allocator());
    defer allocs.deinit();

    // Read CLI arguments
    const raw_args = init.minimal.args.toSlice(allocs.arena()) catch |err| {
        std.debug.print("sibl: failed to read CLI arguments: {s}\n", .{@errorName(err)});
        std.process.exit(1);
    };

    // Parse options
    var options = sibl.parseArgs(allocs.arena(), raw_args) catch |err| {
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

    if (options.input_files.items.len == 0) {
        std.debug.print("sibl: error: no input files provided\n", .{});
        sibl.printHelp();
        std.process.exit(1);
    }

    // Detect target configuration
    const target_info = sibl.TargetInfo.detect(options);

    const final_output = if (std.mem.eql(u8, options.output_path, "a.out") and target_info.format == .coff)
        target_info.default_output
    else
        options.output_path;

    const final_entry = if (std.mem.eql(u8, options.entry_symbol, "_start"))
        target_info.default_entry
    else
        options.entry_symbol;

    std.debug.print("sibl configuration:\n", .{});
    std.debug.print("  Target Arch   : {s} ({d}-bit, {s})\n", .{
        @tagName(target_info.arch),
        target_info.arch.pointerWidth(),
        @tagName(target_info.endian),
    });
    std.debug.print("  Binary Format : {s}\n", .{@tagName(target_info.format)});
    std.debug.print("  Page Size     : {d} bytes\n", .{target_info.page_size});
    std.debug.print("  Output File   : {s}\n", .{final_output});
    std.debug.print("  Entry Point   : {s}\n", .{final_entry});
    std.debug.print("  Shared Mode   : {}\n", .{options.is_shared});

    std.debug.print("  Input Files ({d}):\n", .{options.input_files.items.len});
    for (options.input_files.items) |file| {
        std.debug.print("    - {s}\n", .{file});
    }
}
