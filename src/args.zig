//! Phase 1.3: Command-Line Interface Argument Parser.
//!
//! Parses common linker flags (`-o`, `-L`, `-l`, `-e`, `-shared`, `-static`,
//! `-s`, `-S`, `--format`, `-m`) without external dependencies. All string
//! data is owned by the caller; the parser only stores slices.

const std = @import("std");

/// Target binary format that sibl will generate.
pub const TargetFormat = enum {
    auto,
    elf,
    coff,
    macho,

    /// Parse a format name ("elf", "coff", "pe", "macho", "auto") into a TargetFormat.
    /// Returns null if the string is not recognized.
    pub fn fromString(str: []const u8) ?TargetFormat {
        if (std.mem.eql(u8, str, "elf")) return .elf;
        if (std.mem.eql(u8, str, "coff") or std.mem.eql(u8, str, "pe")) return .coff;
        if (std.mem.eql(u8, str, "macho")) return .macho;
        if (std.mem.eql(u8, str, "auto")) return .auto;
        return null;
    }
};

/// Emulation architecture passed via -m flag (like GNU ld).
pub const Emulation = enum {
    unspecified,
    elf_x86_64,
    elf_aarch64,
    elf_riscv64,
    pe_x86_64,
    pe_aarch64,

    /// Parse an emulation string (e.g. "elf_x86_64", "aarch64elf", "i386pep") into an Emulation.
    /// Returns null if the string is not recognized.
    pub fn fromString(str: []const u8) ?Emulation {
        if (std.mem.eql(u8, str, "elf_x86_64")) return .elf_x86_64;
        if (std.mem.eql(u8, str, "aarch64elf") or std.mem.eql(u8, str, "elf_aarch64")) return .elf_aarch64;
        if (std.mem.eql(u8, str, "elf64lriscv")) return .elf_riscv64;
        if (std.mem.eql(u8, str, "i386pep")) return .pe_x86_64;
        return null;
    }
};

/// All collected CLI configuration options.
pub const Options = struct {
    /// Final binary output path (-o)
    output_path: []const u8 = "a.out",
    /// Entry symbol name (-e, default: _start)
    entry_symbol: []const u8 = "_start",
    /// Selected binary file format
    target_format: TargetFormat = .auto,
    /// Target emulation
    emulation: Emulation = .unspecified,
    /// Build a shared library instead of an executable (-shared)
    is_shared: bool = false,
    /// Static linking mode (-static)
    is_static: bool = false,
    /// Strip all symbols from final output (-s)
    strip_all: bool = false,
    /// Strip debug sections only (-S)
    strip_debug: bool = false,

    /// List of input object files (.o, .obj) and archives (.a, .lib)
    input_files: std.ArrayListUnmanaged([]const u8) = .empty,
    /// List of library lookup directories (-L<dir>)
    lib_dirs: std.ArrayListUnmanaged([]const u8) = .empty,
    /// List of library names to link (-l<name>)
    libs: std.ArrayListUnmanaged([]const u8) = .empty,
    /// Raw placement spec strings (--place PATTERN=DEST, Phase 9.2): move
    /// matching sections into an output section, or a region when DEST
    /// names one.
    place_specs: std.ArrayListUnmanaged([]const u8) = .empty,
    /// Raw pin spec strings (--pin PATTERN=ADDR, Phase 9.2): pin the
    /// holding output section at an exact virtual address.
    pin_specs: std.ArrayListUnmanaged([]const u8) = .empty,
    /// Raw region spec strings (--region NAME=ADDR:SIZE, Phase 9.2):
    /// memory regions for embedded or custom memory maps.
    region_specs: std.ArrayListUnmanaged([]const u8) = .empty,
    /// Raw `--defsym SYMBOL=EXPRESSION` specs (Phase 9.3). Expressions are
    /// evaluated after input symbols are collected and inserted as absolute
    /// symbols. See `defsym.zig`.
    defsym_specs: std.ArrayListUnmanaged([]const u8) = .empty,

    /// Free the ArrayLists that own the input file, library, and search-path lists.
    pub fn deinit(self: *Options, allocator: std.mem.Allocator) void {
        self.input_files.deinit(allocator);
        self.lib_dirs.deinit(allocator);
        self.libs.deinit(allocator);
        self.place_specs.deinit(allocator);
        self.pin_specs.deinit(allocator);
        self.region_specs.deinit(allocator);
        self.defsym_specs.deinit(allocator);
    }
};

/// Errors that can be returned while parsing command-line arguments.
pub const ParseError = error{
    MissingValue,
    UnknownOption,
    InvalidFormat,
    InvalidEmulation,
    OutOfMemory,
};

/// Parse an array of command line argument strings into an `Options` struct.
pub fn parse(allocator: std.mem.Allocator, raw_args: []const []const u8) ParseError!Options {
    var opts = Options{};
    errdefer opts.deinit(allocator);

    var i: usize = 1; // Skip argv[0]
    while (i < raw_args.len) : (i += 1) {
        const arg = raw_args[i];

        // Stop processing options if user gives "--"
        if (std.mem.eql(u8, arg, "--")) {
            i += 1;
            while (i < raw_args.len) : (i += 1) {
                try opts.input_files.append(allocator, raw_args[i]);
            }
            break;
        }

        // Help flag
        if (std.mem.eql(u8, arg, "-h") or std.mem.eql(u8, arg, "--help")) {
            printHelp();
            std.process.exit(0);
        }

        // Output file: -o <path> or -o<path>
        if (std.mem.eql(u8, arg, "-o") or std.mem.eql(u8, arg, "--output")) {
            i += 1;
            if (i >= raw_args.len) return error.MissingValue;
            opts.output_path = raw_args[i];
            continue;
        }
        if (std.mem.startsWith(u8, arg, "-o") and arg.len > 2) {
            opts.output_path = arg[2..];
            continue;
        }

        // Library search directory: -L <path> or -L<path>
        if (std.mem.eql(u8, arg, "-L")) {
            i += 1;
            if (i >= raw_args.len) return error.MissingValue;
            try opts.lib_dirs.append(allocator, raw_args[i]);
            continue;
        }
        if (std.mem.startsWith(u8, arg, "-L") and arg.len > 2) {
            try opts.lib_dirs.append(allocator, arg[2..]);
            continue;
        }

        // Library name: -l <name> or -l<name>
        if (std.mem.eql(u8, arg, "-l")) {
            i += 1;
            if (i >= raw_args.len) return error.MissingValue;
            try opts.libs.append(allocator, raw_args[i]);
            continue;
        }
        if (std.mem.startsWith(u8, arg, "-l") and arg.len > 2) {
            try opts.libs.append(allocator, arg[2..]);
            continue;
        }

        // Entry point: -e <symbol> or --entry=<symbol>
        if (std.mem.eql(u8, arg, "-e") or std.mem.eql(u8, arg, "--entry")) {
            i += 1;
            if (i >= raw_args.len) return error.MissingValue;
            opts.entry_symbol = raw_args[i];
            continue;
        }
        if (std.mem.startsWith(u8, arg, "--entry=")) {
            opts.entry_symbol = arg["--entry=".len..];
            continue;
        }

        // Placement rules (Phase 9.2): --place / --pin / --region
        if (std.mem.eql(u8, arg, "--place")) {
            i += 1;
            if (i >= raw_args.len) return error.MissingValue;
            try opts.place_specs.append(allocator, raw_args[i]);
            continue;
        }
        if (std.mem.startsWith(u8, arg, "--place=")) {
            try opts.place_specs.append(allocator, arg["--place=".len..]);
            continue;
        }
        if (std.mem.eql(u8, arg, "--pin")) {
            i += 1;
            if (i >= raw_args.len) return error.MissingValue;
            try opts.pin_specs.append(allocator, raw_args[i]);
            continue;
        }
        if (std.mem.startsWith(u8, arg, "--pin=")) {
            try opts.pin_specs.append(allocator, arg["--pin=".len..]);
            continue;
        }
        if (std.mem.eql(u8, arg, "--region")) {
            i += 1;
            if (i >= raw_args.len) return error.MissingValue;
            try opts.region_specs.append(allocator, raw_args[i]);
            continue;
        }
        if (std.mem.startsWith(u8, arg, "--region=")) {
            try opts.region_specs.append(allocator, arg["--region=".len..]);
            continue;
        }

        // Symbol assignment (Phase 9.3): --defsym SYMBOL=EXPRESSION
        if (std.mem.eql(u8, arg, "--defsym")) {
            i += 1;
            if (i >= raw_args.len) return error.MissingValue;
            try opts.defsym_specs.append(allocator, raw_args[i]);
            continue;
        }
        if (std.mem.startsWith(u8, arg, "--defsym=")) {
            try opts.defsym_specs.append(allocator, arg["--defsym=".len..]);
            continue;
        }

        // Emulation flag: -m <emulation>
        if (std.mem.eql(u8, arg, "-m")) {
            i += 1;
            if (i >= raw_args.len) return error.MissingValue;
            opts.emulation = Emulation.fromString(raw_args[i]) orelse return error.InvalidEmulation;
            continue;
        }

        // Target output format: --format <elf|coff|macho|auto>
        if (std.mem.eql(u8, arg, "--format")) {
            i += 1;
            if (i >= raw_args.len) return error.MissingValue;
            opts.target_format = TargetFormat.fromString(raw_args[i]) orelse return error.InvalidFormat;
            continue;
        }

        // Boolean mode flags
        if (std.mem.eql(u8, arg, "-shared") or std.mem.eql(u8, arg, "--shared")) {
            opts.is_shared = true;
            continue;
        }
        if (std.mem.eql(u8, arg, "-static") or std.mem.eql(u8, arg, "--static")) {
            opts.is_static = true;
            continue;
        }
        if (std.mem.eql(u8, arg, "-s") or std.mem.eql(u8, arg, "--strip-all")) {
            opts.strip_all = true;
            continue;
        }
        if (std.mem.eql(u8, arg, "-S") or std.mem.eql(u8, arg, "--strip-debug")) {
            opts.strip_debug = true;
            continue;
        }

        // Unknown options
        if (std.mem.startsWith(u8, arg, "-")) {
            std.debug.print("sibl: unrecognized option '{s}'\n", .{arg});
            return error.UnknownOption;
        }

        // Positional argument
        try opts.input_files.append(allocator, arg);
    }

    return opts;
}

/// Print the sibl usage help text to stderr and exit.
pub fn printHelp() void {
    const help_msg =
        \\sibl - Something is Better Linker
        \\
        \\Usage:
        \\  sibl [options] <input-files...>
        \\
        \\Options:
        \\  -o <file>             Set output binary name (default: a.out)
        \\  -e <symbol>           Set entry point symbol (default: _start)
        \\  -m <emulation>        Set emulation (elf_x86_64, elf_aarch64, etc.)
        \\  -L <dir>              Add directory to library search path
        \\  -l <lib>              Link with library name
        \\  -shared               Generate dynamic shared library (.so / .dll / .dylib)
        \\  -static               Produce a static executable
        \\  -s, --strip-all       Omit all symbol tables from output
        \\  -S, --strip-debug     Omit debug sections from output
        \\  --format <fmt>        Set format explicitly: auto, elf, coff, macho
        \\  --region N=A:Z        Define memory region NAME=ADDR:SIZE (Phase 9.2)
        \\  --place P=D           Place section PATTERN into DEST: an output
        \\                        section name, or a region defined earlier
        \\  --pin S=A             Pin the section's output at ADDR (embedded maps)
        \\  --defsym SYM=EXPR     Define an absolute symbol (Phase 9.3). EXPR is a
        \\                        constant (0x.. / decimal), an existing symbol,
        \\                        or a + / - combination of those (no spaces)
        \\  -h, --help            Show this help text
        \\
    ;
    std.debug.print("{s}", .{help_msg});
}

// === Unit Tests ===

test "parse combined short flags and positional inputs" {
    const testing = std.testing;
    const test_argv = [_][]const u8{
        "sibl",
        "-ooutput.elf",
        "-L/usr/lib",
        "-L",
        "/custom/lib",
        "-lc",
        "-shared",
        "-s",
        "foo.o",
        "bar.o",
    };

    var opts = try parse(testing.allocator, &test_argv);
    defer opts.deinit(testing.allocator);

    try testing.expectEqualStrings("output.elf", opts.output_path);
    try testing.expect(opts.is_shared);
    try testing.expect(opts.strip_all);
    try testing.expectEqual(@as(usize, 2), opts.lib_dirs.items.len);
    try testing.expectEqualStrings("/usr/lib", opts.lib_dirs.items[0]);
    try testing.expectEqualStrings("/custom/lib", opts.lib_dirs.items[1]);
    try testing.expectEqual(@as(usize, 1), opts.libs.items.len);
    try testing.expectEqualStrings("c", opts.libs.items[0]);
    try testing.expectEqual(@as(usize, 2), opts.input_files.items.len);
    try testing.expectEqualStrings("foo.o", opts.input_files.items[0]);
    try testing.expectEqualStrings("bar.o", opts.input_files.items[1]);
}

test "parse attached flags for -o -L and -l" {
    const test_argv = [_][]const u8{
        "sibl",
        "-oapp.exe",
        "-L/opt/lib",
        "-lm",
        "start.o",
    };

    var opts = try parse(std.testing.allocator, &test_argv);
    defer opts.deinit(std.testing.allocator);

    try std.testing.expectEqualStrings("app.exe", opts.output_path);
    try std.testing.expectEqual(@as(usize, 1), opts.lib_dirs.items.len);
    try std.testing.expectEqualStrings("/opt/lib", opts.lib_dirs.items[0]);
    try std.testing.expectEqual(@as(usize, 1), opts.libs.items.len);
    try std.testing.expectEqualStrings("m", opts.libs.items[0]);
    try std.testing.expectEqual(@as(usize, 1), opts.input_files.items.len);
    try std.testing.expectEqualStrings("start.o", opts.input_files.items[0]);
}

test "double dash stops flag parsing and treats remaining as input files" {
    const test_argv = [_][]const u8{
        "sibl",
        "-o",
        "final.out",
        "--",
        "-not-a-flag.o",
        "regular.o",
    };

    var opts = try parse(std.testing.allocator, &test_argv);
    defer opts.deinit(std.testing.allocator);

    try std.testing.expectEqualStrings("final.out", opts.output_path);
    try std.testing.expectEqual(@as(usize, 2), opts.input_files.items.len);
    try std.testing.expectEqualStrings("-not-a-flag.o", opts.input_files.items[0]);
    try std.testing.expectEqualStrings("regular.o", opts.input_files.items[1]);
}

test "parse --entry with equals sign" {
    const test_argv = [_][]const u8{
        "sibl",
        "--entry=custom_kernel_entry",
        "kernel.o",
    };

    var opts = try parse(std.testing.allocator, &test_argv);
    defer opts.deinit(std.testing.allocator);

    try std.testing.expectEqualStrings("custom_kernel_entry", opts.entry_symbol);
}

test "parse static linking flags" {
    const test_argv = [_][]const u8{
        "sibl",
        "-static",
        "main.o",
    };

    var opts = try parse(std.testing.allocator, &test_argv);
    defer opts.deinit(std.testing.allocator);

    try std.testing.expect(opts.is_static);
}

test "parse strip debug flag" {
    const test_argv = [_][]const u8{
        "sibl",
        "-S",
        "main.o",
    };

    var opts = try parse(std.testing.allocator, &test_argv);
    defer opts.deinit(std.testing.allocator);

    try std.testing.expect(opts.strip_debug);
    try std.testing.expect(!opts.strip_all);
}

test "error when flag value is missing" {
    const test_argv = [_][]const u8{
        "sibl",
        "-o",
    };

    try std.testing.expectError(error.MissingValue, parse(std.testing.allocator, &test_argv));
}

test "error on unknown flag option" {
    const test_argv = [_][]const u8{
        "sibl",
        "--non-existent-option",
        "main.o",
    };

    try std.testing.expectError(error.UnknownOption, parse(std.testing.allocator, &test_argv));
}

test "error on invalid target format and invalid emulation" {
    const bad_fmt_argv = [_][]const u8{
        "sibl",
        "--format",
        "unknown_format",
        "main.o",
    };
    try std.testing.expectError(error.InvalidFormat, parse(std.testing.allocator, &bad_fmt_argv));

    const bad_emu_argv = [_][]const u8{
        "sibl",
        "-m",
        "unknown_emulation",
        "main.o",
    };
    try std.testing.expectError(error.InvalidEmulation, parse(std.testing.allocator, &bad_emu_argv));
}

test "parse placement rule flags in both argument forms" {
    const test_argv = [_][]const u8{
        "sibl",
        "--region",
        "FLASH=0x08000000:0x10000",
        "--place",
        ".isr*=FLASH",
        "--place=.hot=.fast_text",
        "--pin",
        ".isr_hash=0x08000000",
        "--pin=.reset=4096",
        "main.o",
    };

    var opts = try parse(std.testing.allocator, &test_argv);
    defer opts.deinit(std.testing.allocator);

    try std.testing.expectEqual(@as(usize, 1), opts.region_specs.items.len);
    try std.testing.expectEqualStrings("FLASH=0x08000000:0x10000", opts.region_specs.items[0]);
    try std.testing.expectEqual(@as(usize, 2), opts.place_specs.items.len);
    try std.testing.expectEqualStrings(".isr*=FLASH", opts.place_specs.items[0]);
    try std.testing.expectEqualStrings(".hot=.fast_text", opts.place_specs.items[1]);
    try std.testing.expectEqual(@as(usize, 2), opts.pin_specs.items.len);
    try std.testing.expectEqualStrings(".isr_hash=0x08000000", opts.pin_specs.items[0]);
    try std.testing.expectEqualStrings(".reset=4096", opts.pin_specs.items[1]);
    try std.testing.expectEqual(@as(usize, 1), opts.input_files.items.len);
}

test "missing value for placement flags" {
    for ([_][]const u8{ "--place", "--pin", "--region", "--defsym" }) |flag| {
        const test_argv = [_][]const u8{ "sibl", flag };
        try std.testing.expectError(error.MissingValue, parse(std.testing.allocator, &test_argv));
    }
}

test "parse --defsym in both argument forms" {
    const test_argv = [_][]const u8{
        "sibl",
        "--defsym",
        "FOO=0x1000",
        "--defsym=BAR=main+0x10",
        "--defsym=ZERO=0",
        "main.o",
    };

    var opts = try parse(std.testing.allocator, &test_argv);
    defer opts.deinit(std.testing.allocator);

    try std.testing.expectEqual(@as(usize, 3), opts.defsym_specs.items.len);
    try std.testing.expectEqualStrings("FOO=0x1000", opts.defsym_specs.items[0]);
    try std.testing.expectEqualStrings("BAR=main+0x10", opts.defsym_specs.items[1]);
    try std.testing.expectEqualStrings("ZERO=0", opts.defsym_specs.items[2]);
    try std.testing.expectEqual(@as(usize, 1), opts.input_files.items.len);
}
