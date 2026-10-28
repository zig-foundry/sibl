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

        // 1. Check if file is ELF format
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
        // 2. Check if file is PE / COFF format
        else if (sibl.coff.Header.parse(mapped.data) catch null) |coff_hdr| {
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

            const strtab_bytes = coff_hdr.getStringTable(mapped.data);
            const coff_sections = coff_hdr.parseAllSectionHeaders(arena, mapped.data) catch continue;

            for (coff_sections, 0..) |csh, idx| {
                const name = csh.getName(strtab_bytes) catch "<unnamed>";
                const rel_count = csh.getRelocationCount(mapped.data) catch 0;
                const kind = csh.getNormalizedKind(name);
                const perm = csh.getPermissions();
                const perm_str = perm.toChars();
                const sort_key = sibl.CoffSectionHeader.getSortKey(name);

                if (sort_key) |key| {
                    const base = sibl.CoffSectionHeader.getBaseName(name);
                    std.debug.print("      [{d:2}] {s:<18} -> group={s:<8} sort={s:<6} kind={s:<7} {s} relocs={d}\n", .{
                        idx,
                        name,
                        base,
                        key,
                        kind.name(),
                        perm_str,
                        rel_count,
                    });
                } else {
                    std.debug.print("      [{d:2}] {s:<24} kind={s:<7} perm={s} align={d:<4} relocs={d}\n", .{
                        idx,
                        name,
                        kind.name(),
                        perm_str,
                        csh.getAlignment(),
                        rel_count,
                    });
                }
            }
        }
        // 3. Check if file is Mach-O format
        else if (sibl.macho.Header.parse(mapped.data) catch null) |macho_hdr| {
            std.debug.print("    - {s} [Mach-O {s} {s} {s}] ({d} load commands, {d} bytes, pie={})\n", .{
                file_path,
                if (macho_hdr.is_64bit) "64-bit" else "32-bit",
                macho_hdr.cpu_type.name(),
                macho_hdr.file_type.name(),
                macho_hdr.ncmds,
                macho_hdr.sizeofcmds,
                macho_hdr.isPie(),
            });

            // Decode load commands
            if (macho_hdr.loadCommands(mapped.data)) |mut_iter| {
                var iter = mut_iter;
                var cmd_idx: usize = 0;
                while (iter.next() catch null) |lc| : (cmd_idx += 1) {
                    switch (lc.cmd) {
                        .segment_64 => {
                            if (lc.asSegment64(macho_hdr.endian)) |seg| {
                                const seg_name = seg.getName();
                                std.debug.print("      [{d:2}] {s:<14} {s:<16} vmaddr=0x{x:<9} vmsz=0x{x:<7} nsects={d}\n", .{
                                    cmd_idx,
                                    lc.cmd.name(),
                                    if (seg_name.len == 0) "<unnamed>" else seg_name,
                                    seg.vmaddr,
                                    seg.vmsize,
                                    seg.nsects,
                                });

                                var s_idx: usize = 0;
                                while (s_idx < seg.nsects) : (s_idx += 1) {
                                    const sec = seg.parseSection(macho_hdr.endian, s_idx) catch continue;
                                    std.debug.print("          [{d:2}] {s:<16} addr=0x{x:<9} size=0x{x:<7} align={d:<3} type={s:<14} relocs={d}\n", .{
                                        s_idx,
                                        sec.getSectName(),
                                        sec.addr,
                                        sec.size,
                                        sec.getAlignment(),
                                        sec.getType().name(),
                                        sec.nreloc,
                                    });
                                }
                            } else |_| {}
                        },
                        .symtab => {
                            if (lc.asSymtab(macho_hdr.endian)) |sym_cmd| {
                                std.debug.print("      [{d:2}] {s:<14} symoff=0x{x:<8} nsyms={d:<6} stroff=0x{x:<8} strsz=0x{x}\n", .{
                                    cmd_idx,
                                    lc.cmd.name(),
                                    sym_cmd.symoff,
                                    sym_cmd.nsyms,
                                    sym_cmd.stroff,
                                    sym_cmd.strsize,
                                });

                                // Phase 4.4: Read and print nlist_64 symbols
                                const strtab = sym_cmd.getStringTable(mapped.data);
                                const print_limit = @min(sym_cmd.nsyms, 8);
                                var sym_idx: usize = 0;
                                while (sym_idx < print_limit) : (sym_idx += 1) {
                                    const sym = sym_cmd.parseSymbol(mapped.data, macho_hdr.endian, sym_idx) catch break;
                                    const name = sym.getName(strtab) catch "<unnamed>";

                                    std.debug.print("          -> ({d:2}) {s:<28} val=0x{x:<8} sec={d:<2} type={s:<6} {s}{s}{s}\n", .{
                                        sym_idx,
                                        if (name.len == 0) "<empty>" else name,
                                        sym.value,
                                        sym.sect,
                                        sym.typeName(),
                                        if (sym.isExternal()) "EXT " else "",
                                        if (sym.isPrivateExternal()) "PEXT " else "",
                                        if (sym.isWeakDef()) "WEAK_DEF" else if (sym.isWeakRef()) "WEAK_REF" else "",
                                    });
                                }

                                if (sym_cmd.nsyms > print_limit) {
                                    std.debug.print("          -> ... and {d} more symbols\n", .{sym_cmd.nsyms - print_limit});
                                }
                            } else |_| {}
                        },
                        .dysymtab => {
                            if (lc.asDysymtab(macho_hdr.endian)) |dysym| {
                                std.debug.print("      [{d:2}] {s:<14} locals={d} extdef={d} undef={d} indirect={d}\n", .{
                                    cmd_idx,
                                    lc.cmd.name(),
                                    dysym.nlocalsym,
                                    dysym.nextdefsym,
                                    dysym.nundefsym,
                                    dysym.nindirectsyms,
                                });
                            } else |_| {}
                        },
                        .main => {
                            if (lc.asMain(macho_hdr.endian)) |m| {
                                std.debug.print("      [{d:2}] {s:<14} entryoff=0x{x} stacksize=0x{x}\n", .{
                                    cmd_idx,
                                    lc.cmd.name(),
                                    m.entryoff,
                                    m.stacksize,
                                });
                            } else |_| {}
                        },
                        .load_dylib, .load_weak_dylib, .id_dylib => {
                            if (lc.asDylib(macho_hdr.endian)) |dyl| {
                                const dyl_name = dyl.getName() orelse "<unknown>";
                                std.debug.print("      [{d:2}] {s:<14} dylib={s}\n", .{
                                    cmd_idx,
                                    lc.cmd.name(),
                                    dyl_name,
                                });
                            } else |_| {}
                        },
                        .build_version => {
                            if (lc.asBuildVersion(macho_hdr.endian)) |bv| {
                                std.debug.print("      [{d:2}] {s:<14} platform={s} minos=0x{x} sdk=0x{x}\n", .{
                                    cmd_idx,
                                    lc.cmd.name(),
                                    bv.platformName(),
                                    bv.minos,
                                    bv.sdk,
                                });
                            } else |_| {}
                        },
                        else => {},
                    }
                }
            } else |_| {}
        } else {
            std.debug.print("    - {s} ({d} bytes mapped, non-binary/unknown)\n", .{ file_path, mapped.size });
        }
    }
}
