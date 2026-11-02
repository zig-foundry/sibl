# sibl (Something is Better Linker)

A fast, lightweight, zero-dependency static and dynamic linker written in Zig 0.17.0.

sibl parses ELF, PE/COFF, Mach-O, and static archives with a zero-copy design, resolves symbols, lays out sections and segments, and applies relocations. Binary emission is the next major phase.

## Features

- Zero-copy parsing of ELF, PE/COFF, Mach-O, and static archives (including thin archives)
- Arena-based memory management
- Cross-platform target detection and page-size handling
- Global symbol resolution with strong/weak binding rules
- Duplicate strong definition detection
- Undefined symbol tracking and a final resolution check
- Visibility rules (default / hidden / protected / internal) with export filtering
- Section grouping (`.text.*` → `.text`) and address/alignment layout
- PT_LOAD-style segment layout with page-congruent offsets
- Per-segment file and memory size accounting (`p_filesz` / `p_memsz`)
- Relocation engine for x86_64 and AArch64 (absolute, PC-relative, ADRP, branch)
- Range checking and in-place patching
- Entry point resolution: `-e` / `--entry` (default `_start`) resolved to a final virtual address
- Custom section placement rules: `--place`, `--pin`, and named `--region` memory areas for embedded maps
- Unit-tested parsing, resolution, layout, relocation, and entry resolution

## Building

Requires Zig 0.17.0.

```sh
zig build              # Build the sibl executable
zig build run -- --help
zig build test         # Run the full test suite
```

## Quick Test

```sh
# Compile a minimal Zig object (no system libc needed)
zig build-obj hello.zig -femit-bin=hello.o

# Inspect symbols, sections, and segments
./zig-out/bin/sibl hello.o
```

Expected output includes resolved symbols, a section layout (virtual addresses from `0x400000`), a segment list with `filesz` / `memsz`, and the resolved entry point:

```
  Entry Point '_start':
    Address       : 0x401000
    Section       : .text
    Executable    : true
```

Override the entry symbol with `-e <name>` / `--entry <name>`.

### Placement Rules (Phase 9.2)

For embedded or custom memory maps:

```sh
# Sections land higher if they match a rule pattern.
# Patterns: exact name, prefix + `*`, or a single `*` catch-all.

# Define memory regions (NAME=ADDR:SIZE)
sibl --region FLASH=0x08000000:0x10000 \
     --region RAM=0x20000000:0x8000 \
     --place .isr*=FLASH \       # allocate matching sections in FLASH
     --place .hot=.fast_text \   # merge .hot.* sections under .fast_text
     --pin .vector=0x08000040 \  # pin the holding section at an exact VA
     crt.o main.o driver.o
```

- `--place PATTERN=DEST` merges matching inputs into the output section
  `DEST`, or allocates them inside `DEST` when it names a region defined
  earlier. First matching rule wins, so put catch-all `*` rules last.
- `--pin PATTERN=ADDR` fixes the holding output section's virtual address.
- `--region NAME=ADDR:SIZE` defines a region; assigned sections allocate
  sequentially with alignment until the region runs out (`RegionFull`).

## Using sibl as a Library

Import the root module:

```zig
const sibl = @import("sibl");

var table = sibl.SymbolTable.init(allocator);
defer table.deinit();

var layout = sibl.Layout.init(allocator, 0x400000, 4096);
defer layout.deinit();

// ... add symbols and sections ...
layout.computeAddresses();
const ep = sibl.resolveEntry(&table, &layout, "_start");
// ep.address is the final virtual address of the entry point
```

Public types are re-exported from `src/root.zig`. HTML docs:

```sh
zig build-lib src/root.zig -femit-docs
```

## Project Layout

```
src/
├── alloc.zig     Phase 1.2  — arena and scratch allocators
├── args.zig      Phase 1.3  — CLI argument parser
├── target.zig    Phase 1.4  — target detection and page size
├── file.zig      Phase 1.5  — memory-mapped file reader
├── elf.zig       Phase 2    — ELF parsing
├── strtab.zig    Phase 2.4  — string table reader and builder
├── coff.zig      Phase 3    — PE/COFF parsing
├── macho.zig     Phase 4    — Mach-O parsing
├── archive.zig   Phase 5    — static archive (.a / .lib) parsing
├── symbol.zig    Phase 6    — global symbol table and resolution
├── layout.zig    Phase 7    — section grouping, segments, size accounting
├── reloc.zig     Phase 8    — relocation engine (x86_64, AArch64)
├── entry.zig     Phase 9.1  — entry point resolution
├── section_rules.zig Phase 9.2 — placement rules and memory regions
├── root.zig      Public re-exports
└── main.zig      Linker executable entry point
```

See `ROADMAP.md` for the full phase plan and what is still ahead.

## For Contributors

- Keep the zero-copy and arena style used in existing modules.
- Add a module-level `//!` comment that names the phase and the contract.
- Document every public type, function, and error.
- Add unit tests next to the code. Prefer real formulas over stubs.
- Mark completed items in `ROADMAP.md`.
- Run `zig build test` before sending changes.

## Status

Phases 1–8, Phase 9.1 (entry point setup), and Phase 9.2 (custom section
placement rules) are implemented and tested. Phase 9 continues with
`--defsym` support (9.3) and default layout templates (9.4). Binary
emission of a runnable binary is Phase 13.
