# sibl (Something is Better Linker)

A fast, lightweight, zero-dependency static and dynamic linker written in Zig 0.17.0.

## Features

- Zero-copy parsing of ELF, PE/COFF, Mach-O, and static archives
- Arena-based memory management for high throughput
- Clean public API with full documentation comments
- Cross-platform target detection and page-size handling
- Unit-tested parsing for all supported formats

## Building

Requires Zig 0.17.0.

```sh
zig build          # Build the sibl executable
zig build run -- --help
zig build test     # Run the test suite
```

## Documentation

HTML documentation can be generated with:

```sh
zig build-lib src/root.zig -femit-docs
```

The generated `docs/` directory contains browsable documentation for the entire public API.
