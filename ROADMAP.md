# sibl (Something is Better Linker) - Roadmap

A fast, lightweight, and zero-dependency static and dynamic linker written in Zig 0.17.0.

## Phase 1: Project Setup and CLI Core
- [x] **1.1 Build Configuration:** Set up `build.zig` for Zig 0.17.0, target options, and release modes.
- [x] **1.2 Memory Allocators:** Set up fast arena allocators and fixed scratch buffers using `std.mem.Allocator`.
- [x] **1.3 CLI Argument Parser:** Parse common linker flags like `-o`, `-L`, `-l`, `-shared`, and target options.
- [x] **1.4 Target Detection:** Detect host and target CPU architectures and default binary formats (ELF, PE, Mach-O).
- [x] **1.5 File Reader and Memory Mapping:** Open files and map them into memory with OS handles for zero-copy reads.

## Phase 2: ELF Object Parsing
- [x] **2.1 Header Parsing:** Read 32-bit and 64-bit ELF headers and verify magic bytes.
- [x] **2.2 Section Header Table:** Read section headers to get section names, sizes, flags, and file offsets.
- [x] **2.3 Symbol Table Reader:** Read `.symtab` and `.dynsym` tables to extract symbol names, bindings, and types.
- [x] **2.4 String Table Decoder:** Load `.strtab` and `.shstrtab` string tables and deduplicate strings for output.
- [x] **2.5 Relocation Table Parsing:** Parse `.rel` and `.rela` sections and read target symbols and addends.

## Phase 3: PE/COFF Object Parsing
- [x] **3.1 DOS and COFF Headers:** Parse the DOS stub, PE signature, and COFF header for Windows targets.
- [x] **3.2 Section Table Reader:** Read section headers, sizes, and memory flags like read, write, and execute.
- [x] **3.3 COFF Symbol Table:** Read 18-byte symbols, storage classes, and string table offsets.
- [x] **3.4 Relocation Reader:** Parse 10-byte relocations for x86_64 and ARM64, and handle 16-bit overflow tables.
- [x] **3.5 Section Flags Mapping:** Group sections using the `$` rule, classify section kinds, and map permissions.

## Phase 4: Mach-O Object Parsing
- [x] **4.1 Mach Header Parser:** Read 64-bit Mach-O headers and detect CPU architecture.
- [x] **4.2 Load Commands Decoder:** Parse `LC_SEGMENT_64`, `LC_SYMTAB`, and `LC_DYSYMTAB` commands.
- [x] **4.3 Section Parsing:** Read Mach-O sections inside segments and track their alignment and offsets.
- [x] **4.4 Nlist Symbol Reader:** Read Mach-O symbol tables and extract external, local, and undefined symbols.
- [x] **4.5 Relocation Info:** Parse standard and scattered relocation entries for macOS targets.

## Phase 5: Static Archive Parsing (.a and .lib)
- [ ] **5.1 Archive Header Validation:** Check the `!<arch>\n` magic bytes and read member headers.
- [ ] **5.2 Symbol Index Parsing:** Parse symbol tables (like GNU `/` or BSD `__.SYMDEF`) to map symbols to member files.
- [ ] **5.3 Member Extraction:** Extract only the object files that define symbols currently marked as undefined.
- [ ] **5.4 Thin Archives:** Support thin archives by reading file paths and loading external objects directly.

## Phase 6: Global Symbol Resolution
- [ ] **6.1 Symbol Table Creation:** Build a central hash map to store all defined and undefined symbols.
- [ ] **6.2 Binding Rules:** Resolve conflicts between weak symbols and strong symbols properly.
- [ ] **6.3 Duplicate Detection:** Report clear errors when multiple strong definitions exist for the same symbol.
- [ ] **6.4 Undefined Symbol Tracking:** Track missing symbols and ensure every needed symbol is found before linking stops.
- [ ] **6.5 Visibility Rules:** Handle local, hidden, and default visibility rules.

## Phase 7: Section Merging and Memory Layout
- [ ] **7.1 Section Grouping:** Group matching input sections together (like `.text`, `.rodata`, `.data`, and `.bss`).
- [ ] **7.2 Address and Alignment Calculation:** Calculate base addresses and align each section based on target page sizes.
- [ ] **7.3 Memory Map Layout:** Lay out program headers and segments in order so the operating system can load them cleanly.
- [ ] **7.4 Size Accounting:** Compute the final virtual memory size and raw file size for each segment.

## Phase 8: Relocation Engine
- [ ] **8.1 Relocation Resolver:** Match relocation records to final resolved symbol addresses.
- [ ] **8.2 x86_64 Relocations:** Implement PC-relative (like `R_X86_64_PC32`) and absolute relocations (`R_X86_64_64`).
- [ ] **8.3 AArch64 Relocations:** Implement branch offsets and page-based relocations (like `ADR_PREL_PG_HI21`).
- [ ] **8.4 Range Checking:** Check for 32-bit overflow errors on relative jumps and report error details.
- [ ] **8.5 In-Place Patching:** Write the computed target addresses directly into the output byte buffer.

## Phase 9: Linker Script and Entry Rules
- [ ] **9.1 Entry Point Setup:** Find and set the program entry point (like `_start` or `mainCRTStartup`).
- [ ] **9.2 Custom Section Rules:** Support basic placement rules for embedded or custom memory maps.
- [ ] **9.3 Symbol Assignment:** Allow defining basic symbols from CLI flags (like `--defsym`).
- [ ] **9.4 Default Layout Templates:** Provide built-in standard layouts for Linux, Windows, macOS, and bare-metal targets.

## Phase 10: Dynamic Linking Infrastructure
- [ ] **10.1 Global Offset Table (GOT):** Create and populate GOT entries for position-independent code (PIC).
- [ ] **10.2 Procedure Linkage Table (PLT):** Build PLT jump stubs so shared library functions can be called cleanly.
- [ ] **10.3 Dynamic Section Construction:** Build `.dynamic` tag arrays for `DT_NEEDED`, `DT_INIT`, `DT_FINI`, and table offsets.
- [ ] **10.4 Dynamic Symbol and String Tables:** Write `.dynsym` and `.dynstr` sections for runtime symbol lookups.
- [ ] **10.5 Symbol Hash Tables:** Generate standard SysV `.hash` and fast `.gnu.hash` tables for fast dynamic loading.

## Phase 11: Shared Library and Import/Export Writers
- [ ] **11.1 Linux Shared Objects (.so):** Emit shared ELF libraries with soname tags and PIC relocations.
- [ ] **11.2 Windows DLLs (.dll):** Build Export Address Tables (EAT) and Import Address Tables (IAT).
- [ ] **11.3 Import Library Generation:** Emit `.lib` stub files alongside Windows DLLs for linking against.
- [ ] **11.4 macOS Dynamic Libraries (.dylib):** Build `LC_ID_DYLIB` and `LC_LOAD_DYLIB` load commands.
- [ ] **11.5 Runtime Search Paths:** Handle `-rpath` options and write paths into executable headers.

## Phase 12: Debug Info and Strip Support
- [ ] **12.1 Section Passing:** Pass through DWARF (`.debug_*`) sections directly to the output without touching them.
- [ ] **12.2 Strip All (`-s`):** Remove all symbol tables and debug sections to make small binaries.
- [ ] **12.3 Strip Debug (`-S`):** Drop only debug sections while keeping regular symbols for backtraces.
- [ ] **12.4 Build ID Generation:** Create unique build ID hashes inside note sections.

## Phase 13: Binary Output Emission
- [ ] **13.1 Buffered File Writer:** Write final files using buffered file I/O to avoid small write calls.
- [ ] **13.2 Header and Table Emission:** Write the file header, program headers, and section headers in exact order.
- [ ] **13.3 Content Streaming:** Stream merged section bytes into the output file.
- [ ] **13.4 File Permissions:** Set executable permissions (`chmod +x` on Unix) after writing finishes.
- [ ] **13.5 File Padding:** Ensure file sizes match exact byte boundaries and pad correctly.

## Phase 14: Speed and Parallel Optimization
- [ ] **14.1 Multi-Threaded File Parsing:** Use `std.Thread.Pool` to parse multiple input object files at the same time.
- [ ] **14.2 Parallel Relocation Processing:** Split relocations across sections into batches run by worker threads.
- [ ] **14.3 Fast String Hashing:** Use simple, fast hash functions (like FNV-1a or Wyhash) for symbol lookup.
- [ ] **14.4 Zero-Copy Buffer Slices:** Pass slices into memory-mapped buffers instead of making data copies.

## Phase 15: Cross-Platform Testing and Validation
- [ ] **15.1 Hello World Linking:** Link simple Zig and C programs into working static binaries on Linux, Windows, and macOS.
- [ ] **15.2 Format Verifier:** Verify output binaries using tools like `readelf`, `objdump`, and `dumpbin`.
- [ ] **15.3 Shared Library Tests:** Run integration tests linking against shared libraries like `libc.so` and `kernel32.dll`.
- [ ] **15.4 Self-Hosting Test:** Use `sibl` to link its own compiled object files into a working executable.
- [ ] **15.5 Performance Benchmark:** Measure link times against system linkers (like `ld.bfd`, `lld`, and `mold`).
