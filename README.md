# CodeBreak

A native binary analysis suite for Windows. CodeBreak loads compiled files — EXE, DLL, APK, JAR, DEX, ELF, Mach-O, Java classes, ZIP archives — and shows what is actually inside them: machine-code structure, metadata, hashes, entropy, strings, and raw bytes. Nothing is guessed or faked; every field is parsed from the file itself.

The GUI is a native Win32 application hosting Microsoft Edge WebView2. The parsing engine is dependency-free C++17 and also builds as a standalone CLI on Linux and Windows.

## The GUI

Run `CodeBreak.exe`, drop a file anywhere on the window (or press `Ctrl+O`) and the analysis appears in milliseconds: a full parse of `/bin/ls` takes ~4 ms, and a 2.2 MB `libc.so.6` — 17,299 extracted strings included — analyzes in ~45 ms. Files up to 4 GB load through a memory-mapped pipeline.

- **Overview** — file identity, format detection with confidence, SHA-256/SHA-1/MD5/CRC32, overall and per-16-KB entropy graph, and a live security-indicator list (packer detection, signing state, TLS callbacks, entropy warnings, manifest flags).
- **PE / APK / ZIP / ELF / Mach-O / Java class tabs** — appear only when the format is present: imports and exports, rich header history, debug PDB paths, version info, TLS, Authenticode state; Android manifest (decoded from binary AXML), permissions, activities, services, DEX class map, signing schemes, native libraries; full archive trees, APK v2/v3 signature blocks; ELF sections/segments/interpreter/dynamic imports; Mach-O load commands; constant pool, fields and methods for `.class` files.
- **Strings** — virtualized list over up to 2 million extracted strings, ASCII + UTF-16 wide detection, live filter box, minimum-length control, jump-to-offset.
- **Hex** — responsive hex viewer with offset jumping synced from the strings tab.

## Building

### Windows GUI (Visual Studio 2022)

Requirements: Visual Studio 2022 with the *Desktop development with C++* workload (CMake ships with it). From the repository root:

```bat
build.bat
```

Output: `build\Release\CodeBreak.exe` and `build\Release\codebreak-cli.exe`. `WebView2Loader.dll` is copied next to the executable automatically. The WebView2 headers and loader in `third_party/webview2` are from the official `Microsoft.Web.WebView2` 1.0.2651.64 package, so no NuGet step is needed. Running the app requires the Edge WebView2 Runtime, which is preinstalled on Windows 11 and current Windows 10; the app tells you where to get it if it is missing.

Equivalent manual commands:

```bat
cmake -S . -B build -A x64
cmake --build build --config Release
```

MinGW-w64 (UCRT x64) also works: `cmake -S . -B build-mingw -G "MinGW Makefiles" -DCMAKE_BUILD_TYPE=Release` then `cmake --build build-mingw -j`.

### CLI only (Linux / Windows)

```sh
./build.sh          # Linux: plain g++, no dependencies
```

## CLI usage

```sh
codebreak-cli <file>                 # everything as one JSON document
codebreak-cli <file> --section overview
codebreak-cli <file> --strings --filter kernel32 --min-length 6
codebreak-cli <file> --strings --kind wide
codebreak-cli <file> --hex --offset 0x400 --length 512
```

`--section` accepts `overview | indicators | pe | apk | zip | elf | macho | javaclass | strings`. Exit code 0 on success, 1 on error (message on stderr). All output is UTF-8 JSON, suitable for piping into `jq`.

## What is parsed

| Format | Detection | Details extracted |
|---|---|---|
| PE (EXE/DLL/SYS) | `MZ` + `PE\0\0` | machine, timestamp, sections, entry point, imports per DLL, exports, rich header, debug directory + PDB GUID/age, resources, version info, TLS callbacks, Authenticode presence, .NET detection |
| APK / AAB / JAR | ZIP with expected layout | package, version, min/target SDK, permissions, activities/services/receivers with export flags, binary AXML manifest decode, DEX header + classes, native libs per ABI, v1/v2/v3 signing, zip alignment |
| ZIP | `PK` structures | entry tree, compression per entry, encrypted entries, zip64 |
| ELF | `\x7fELF` | class, endianness, machine, type, sections, program segments, interpreter, dynamic symbols, soname |
| Mach-O | magic `FEEDFACF`/`FEEDFACE`/`CAFEBABE` (big-endian variants) | load commands, segments and sections, entry point, linked dylibs |
| Java class | `CAFEBABE` | version, constant pool, fields, methods with descriptors |
| DEX | `dex\n` | header, checksum + SHA-1 validation, string/type/proto/field/class/method counts |
| Anything else | — | hashes, entropy profile, strings, hex |

Entropy is computed over 16 KB blocks with Shannon's formula; the overall figure is the weighted mean. Strings extraction recognizes ASCII (CP437-safe printable run) and UTF-16LE/BE.

## Architecture

```
src/
  analyze.cpp      format detection + orchestration, one JSON document out
  pe.cpp elf.cpp zipfmt.cpp dex.cpp axml.cpp otherfmts.cpp
                   format parsers (PE/COFF, ELF, ZIP/APK/JAR, DEX, binary AXML,
                   Mach-O, Java class)
  hashes.cpp       SHA-256, SHA-1, MD5, CRC32, entropy
  util.cpp         file IO, string building, wide-string decode, formatting
  jsonw.h jsonr.h  minimal JSON writer (engine) and parser (host)
  cli/main_cli.cpp command line front end
  host/main.cpp    Win32 + WebView2 application host
  host/app.html    the entire UI (single file, no external assets)
tests/
  run_tests.py     52-assertion suite; builds fixtures and checks real output
  make_fixtures.py generates PE, APK, DEX, ELF, Mach-O, class, ZIP fixtures
third_party/webview2  official WebView2 SDK headers + loader (1.0.2651.64)
```

The host and the UI talk over `window.chrome.webview.postMessage` with request/response envelopes (`{id, cmd, ...}` in, `{id, ok, data|error}` out). Heavy work (file reads, parsing, string indexing) runs on worker threads so the window never blocks; the UI thread only renders and dispatches.

To regenerate the application icon after editing `tools/make_icon.py`, run `python tools/make_icon.py` and rebuild.

## Testing

```sh
python3 tests/make_fixtures.py     # builds every fixture from scratch
CB_CLI=build-cli/codebreak-cli python3 tests/run_tests.py
```

The suite builds a real PE image (sections, imports, exports, rich header, debug directory, TLS, version info, certificate table), a real signed APK (ZIP + binary AXML manifest + DEX with valid SHA-1/Adler-32 + v1/v2 signature blocks), an ELF shared object, a Mach-O image and a Java class — then asserts dozens of parsed fields against known ground truth, plus checksum-validating runs against system binaries.

## License

MIT. WebView2 SDK components under `third_party/webview2` follow the Microsoft WebView2 Runtime license (see `LICENSE.txt` / `NOTICE.txt` there).
