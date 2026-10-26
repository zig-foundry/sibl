//! sibl main entry point.
//!
//! Uses Zig 0.17 juicy main (`std.process.Init`) for pre-configured
//! allocators and I/O interfaces.

const std = @import("std");
const sibl = @import("sibl");

pub fn main(init: std.process.Init) !void {
    // In Zig 0.17, juicy main gives us pre-configured handles:
    // - init.io: standard I/O interface
    // - init.arena: permanent process arena allocator
    // - init.gpa: thread-safe general purpose allocator with leak checks
    const io = init.io;
    const arena = init.arena.allocator();

    // Read process command line arguments
    const raw_args = init.minimal.args.toSlice(arena) catch |err| {
        std.debug.print("sibl: failed to read CLI arguments: {s}\n", .{@errorName(err)});
        std.process.exit(1);
    };

    // Phase 1.3: Parse CLI options
    var options = sibl.parseArgs(arena, raw_args) catch |err| {
        switch (err) {
            error.MissingValue => std.debug.print("sibl: error: missing value for flag\n", .{}),
            error.InvalidFormat => std.debug.print("sibl: error: invalid target format (use elf, coff, or macho)\n", .{}),
            error.InvalidEmulation => std.debug.print("sibl: error: unsupported emulation mode\n", .{}),
            error.UnknownOption => {},
            error.OutOfMemory => std.debug.print("sibl: error: out of memory during argument parse\n", .{}),
        }
        std.process.exit(1);
    };
    defer options.deinit(arena);

    if (options.input_files.items.len == 0) {
        std.debug.print("sibl: error: no input files provided\n", .{});
        sibl.printHelp();
        std.process.exit(1);
    }

    // Phase 1.4: Detect target architecture and binary format
    const target_info = sibl.TargetInfo.detect(options);

    const final_output = if (std.mem.eql(u8, options.output_path, "a.out") and target_info.format == .coff)
        target_info.default_output
    else
        options.output_path;

    const final_entry = if (std.mem.eql(u8, options.entry_symbol, "_start"))
        target_info.default_entry
    else
        options.entry_symbol;

    // Print linker settings
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

    // Phase 1.5: Read and memory-map all input files
    std.debug.print("  Input Files ({d}):\n", .{options.input_files.items.len});
    for (options.input_files.items) |file_path| {
        var mapped = sibl.MappedFile.open(io, file_path) catch |err| {
            std.debug.print("sibl: error: could not open '{s}': {s}\n", .{ file_path, @errorName(err) });
            std.process.exit(1);
        };
        defer mapped.deinit(io);

        std.debug.print("    - {s} ({d} bytes mapped)\n", .{ file_path, mapped.size });
    }
}
