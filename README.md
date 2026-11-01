# sibl (Something is Better Linker)

A fast, lightweight, zero-dependency static and dynamic linker written in Zig 0.17.0.

## Features

- Zero-copy parsing of ELF, PE/COFF, Mach-O, and static archives
- Arena-based memory management for high throughput
- Clean public API with full documentation comments
- Cross-platform target detection and page-size handling
- Unit-tested parsing for all supported formats
- Global symbol resolution with strong/weak binding rules
- Duplicate strong definition detection
- Undefined symbol tracking and final resolution check
- Visibility rules (default / hidden / protected / internal) with export filtering
- Section grouping (`.text.*` → `.text`) and address/alignment layout
- Section grouping (`.text.*` → `.text`) and address/alignment layout

## Building

Requires Zig 0.17.0.

```sh
zig build          # Build the sibl executable
zig build run -- --help
zig build test     # Run the test suite
```

## Quick Test

```sh
# Compile a minimal Zig object (no system libc needed)
zig build-obj hello.zig -femit-bin=hello.o

# Inspect and resolve symbols
./zig-out/bin/sibl hello.o
```

## Documentation

HTML documentation can be generated with:

```sh
zig build-lib src/root.zig -femit-docs
```

The generated `docs/` directory contains browsable documentation for the entire public API.

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
├── layout.zig    Phase 7    — section grouping and address layout
├── root.zig      Public re-exports
└── main.zig      Linker executable entry point
```

See `ROADMAP.md` for the full phase plan.
