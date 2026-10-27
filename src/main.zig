//! sibl main entry point.
//!
//! Uses Zig 0.17 juicy main (`std.process.Init`).

const std = @import("std");
const sibl = @import("sibl");

pub fn main(init: std.process.Init) !void {
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

    // Process input files
    std.debug.print("  Input Files ({d}):\n", .{options.input_files.items.len});
    for (options.input_files.items) |file_path| {
        var mapped = sibl.MappedFile.open(io, file_path) catch |err| {
            std.debug.print("sibl: error: could not open '{s}': {s}\n", .{ file_path, @errorName(err) });
            std.process.exit(1);
        };
        defer mapped.deinit(io);

        // Check if file is ELF format
        if (mapped.data.len >= 4 and std.mem.eql(u8, mapped.data[0..4], &sibl.elf.MAGIC)) {
            const elf_hdr = sibl.elf.Header.parse(mapped.data) catch |err| {
                std.debug.print("sibl: error: failed to parse ELF header for '{s}': {s}\n", .{ file_path, @errorName(err) });
                continue;
            };

            std.debug.print("    - {s} [ELF {s} {s} {s}] ({d} sections at 0x{x})\n", .{
                file_path,
                elf_hdr.class.name(),
                elf_hdr.machine.name(),
                elf_hdr.file_type.name(),
                elf_hdr.shnum,
                elf_hdr.shoff,
            });

            const shstrtab = elf_hdr.getSectionStringTable(mapped.data) catch &.{};
            const sections = elf_hdr.parseAllSectionHeaders(arena, mapped.data) catch continue;

            for (sections, 0..) |sh, idx| {
                if (sh.sh_type == .null) continue;
                const name = sh.getName(shstrtab) catch "<unnamed>";
                std.debug.print("      [{d:2}] {s:<24} type={s:<14} size=0x{x:<6} align={d:<2} flags={s}{s}{s}\n", .{
                    idx,
                    name,
                    sh.sh_type.name(),
                    sh.size,
                    sh.addralign,
                    if (sh.isAlloc()) "A" else "",
                    if (sh.isWritable()) "W" else "",
                    if (sh.isExecutable()) "X" else "",
                });
            }
        }
        // Check if file is PE / COFF format
        else if (sibl.coff.Header.parse(mapped.data)) |coff_hdr| {
            if (coff_hdr.is_pe) {
                const opt = coff_hdr.optional_header.?;
                std.debug.print("    - {s} [PE {s} {s}] ({d} sections, entry=0x{x}, base=0x{x}, {s})\n", .{
                    file_path,
                    if (opt.is_64bit) "64-bit" else "32-bit",
                    coff_hdr.machine.name(),
                    coff_hdr.section_count,
                    opt.address_of_entry_point,
                    opt.image_base,
                    opt.subsystem.name(),
                });
            } else {
                std.debug.print("    - {s} [COFF OBJ {s}] ({d} sections, {d} symbols)\n", .{
                    file_path,
                    coff_hdr.machine.name(),
                    coff_hdr.section_count,
                    coff_hdr.symbol_count,
                });
            }
        } else |_| {
            std.debug.print("    - {s} ({d} bytes mapped, non-binary/unknown)\n", .{ file_path, mapped.size });
        }
    }
}
