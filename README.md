# CodeBreak

A native binary analysis suite for Windows. CodeBreak loads compiled files — EXE, DLL, APK, JAR, DEX, ELF, Mach-O, Java classes, GZIP/TAR archives, PDF documents, ZIP — and shows what is actually inside them: machine-code structure, metadata, hashes, entropy, strings, and raw bytes. On top of that it runs a transparent **heuristic risk-scoring engine** that turns the parsed facts into a 0–100 threat score. Nothing is guessed or faked; every field is parsed from the file itself.

The GUI is a native Win32 application hosting Microsoft Edge WebView2. The parsing engine is dependency-free C++17 and also builds as a standalone CLI on Linux and Windows.

## The GUI

Run `CodeBreak.exe`, drop a file anywhere on the window (or press `Ctrl+O`) and the analysis appears in milliseconds: a full parse of `/bin/ls` takes ~4 ms, and a 2.2 MB `libc.so.6` — 17,299 extracted strings included — analyzes in ~45 ms. Files up to 4 GB load through a memory-mapped pipeline.

- **Overview** — file identity, format detection with confidence, SHA-256/SHA-1/MD5/CRC32, overall and per-16-KB entropy graph, a live security-indicator list, and a one-glance risk score.
- **Risk** — the heuristic threat score rendered as a gauge (0–100, clean → critical), the weighted signal groups that produced it, and the highest-confidence findings.
- **PE / APK / ZIP / ELF / Mach-O / Java class / GZIP / TAR / PDF tabs** — appear only when the format is present: imports and exports, rich header history, debug PDB paths, version info, TLS, Authenticode state; Android manifest (decoded from binary AXML), permissions, activities, services, DEX class map, signing schemes, native libraries; full archive trees, APK v2/v3 signature blocks; ELF sections/segments/interpreter/dynamic imports; Mach-O load commands; constant pool, fields and methods for `.class` files; gzip member metadata, POSIX tar member tables, PDF version/objects/streams/encryption/JavaScript presence.
- **Report** — a **Report** button in the toolbar exports a fully self-contained HTML report (no internet needed) capturing the summary, risk assessment, findings, hashes and the entire analysis tree.
- **Strings** — virtualized list over up to 2 million extracted strings, ASCII + UTF-16 wide detection, live filter box, minimum-length control, jump-to-offset.
- **Hex** — responsive hex viewer with offset jumping synced from the strings tab.

## Risk & threat model

Every analysis ends with a `risk` node computed by `src/risk.cpp`. The engine is intentionally *transparent*: a set of weighted signal groups, each reporting its category, weight and hit count, sum to a score capped at 100.

| Band | Score | Meaning |
|---|---|---|
| clean | 0–24 | no notable characteristics |
| low | 25–44 | benign quirks (e.g. high entropy alone) |
| medium | 45–64 | several weak signals or one strong one |
| high | 65–84 | strong evidence of packing / injection / unsigned code |
| critical | 85–100 | multiple corroborating indicators |

Signal groups include: **findings** (the parser-generated indicators, weighted by severity), **obfuscation / packing** (global and entry-region entropy, UPX/Themida/VMProtect & other protector markers), **execution** (VirtualAllocEx/WriteProcessMemory/CreateRemoteThread/process-hollowing primitives), **network** (download/HTTP-client APIs), **shell & persistence** (PowerShell `-enc`, cmd, mshta, certutil, reg add, schtasks), **encoding** (Base64 / crypto primitives), and **authenticity** (unsigned PE with no Authenticode). High-entropy content and protector strings are only scored as packing when they co-occur or sit at the code entry; the weights are tuned so benign, legitimately-compiled programs stay at clean/low.

The CLI mirrors this for automation: `--risk` prints the assessment alone, `--report` writes an HTML report, and `--batch` scans whole directory trees into JSON/CSV/HTML with per-file risk.

## CLI usage

```sh
codebreak-cli <file>                       # everything as one JSON document
codebreak-cli <file> --risk                # only the risk assessment
codebreak-cli <file> --report out.html     # self-contained HTML report
codebreak-cli <file> --strings --filter kernel32 --min-length 6
codebreak-cli <file> --strings --kind wide
codebreak-cli <file> --hex --offset 0x400 --length 512
codebreak-cli --batch DIR                  # scan a tree -> JSON on stdout
codebreak-cli --batch DIR --json scan.json --csv scan.csv --html report.html
codebreak-cli --batch DIR --limit 5000 --max-mb 64
```

Exit code 0 on success, 1 on error (message on stderr). All output is UTF-8 JSON, suitable for piping into `jq`. `--report` and the batch `--html` flag write self-contained HTML reports.

## What is parsed

| Format | Detection | Details extracted |
|---|---|---|
| PE (EXE/DLL/SYS) | `MZ` + `PE\0\0` | machine, timestamp, sections, entry point, imports per DLL, exports, rich header, debug directory + PDB GUID/age, resources, version info, TLS callbacks, Authenticode presence, .NET detection |
| APK / AAB / JAR | ZIP with expected layout | package, version, min/target SDK, permissions, activities/services/receivers with export flags, binary AXML manifest decode, DEX header + classes, native libs per ABI, v1/v2/v3 signing, zip alignment |
| ZIP | `PK` structures | entry tree, compression per entry, encrypted entries, zip64 |
| GZIP | `1F 8B` | method, flags, mtime, OS, optional filename/comment, offset, stored CRC32 + uncompressed size |
| TAR | `ustar` at 257 | member table (name/type/size/mode/mtime), totals, truncation flag |
| ELF | `\x7fELF` | class, endianness, machine, type, sections, program segments, interpreter, dynamic symbols, soname |
| Mach-O | magic `FEEDFACF`/`FEEDFACE`/`CAFEBABE` (big-endian variants) | load commands, segments and sections, entry point, linked dylibs |
| Java class | `CAFEBABE` | version, constant pool, fields, methods with descriptors |
| PDF | `%PDF` | version, object/stream/page counts, encryption (`/Encrypt`), embedded JavaScript, object-stream compression |
| DEX | `dex\n` | header, checksum + SHA-1 validation, string/type/proto/field/class/method counts |
| Anything else | — | hashes, entropy profile, strings, hex |

Entropy is computed over 16 KB blocks with Shannon's formula; the overall figure is the weighted mean. Strings extraction recognizes ASCII (CP437-safe printable run) and UTF-16LE/BE.

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

## Architecture

```
src/
  analyze.cpp      format detection + orchestration, one JSON document out
  pe.cpp elf.cpp zipfmt.cpp dex.cpp axml.cpp otherfmts.cpp miscfmt.cpp
                   format parsers (PE/COFF, ELF, ZIP/APK/JAR, DEX, binary AXML,
                   Mach-O, Java class, GZIP, TAR, PDF)
  risk.cpp         heuristic threat-scoring engine (0-100 + weighted signals)
  report.cpp       self-contained HTML report and batch-report generators
  hashes.cpp       SHA-256, SHA-1, MD5, CRC32, entropy
  util.cpp         file IO, string building, wide-string decode, formatting,
                   recursive directory walk (batch scans)
  jsonw.h jsonr.h  minimal JSON writer (engine) and parser (host)
  cli/main_cli.cpp command line front end (single-file, risk, report, batch)
  host/main.cpp    Win32 + WebView2 application host
  host/app.html    the entire UI (single file, no external assets)
tests/
  run_tests.py     67-assertion suite; checks real parser output
third_party/webview2  official WebView2 SDK headers + loader (1.0.2651.64)
tools/make_fixtures.py  builds PE, APK, DEX, ELF, Mach-O, class, ZIP, GZIP,
                        TAR and PDF fixtures from scratch
tools/make_icon.py       regenerates the application icon
```

The host and the UI talk over `window.chrome.webview.postMessage` with request/response envelopes (`{id, cmd, ...}` in, `{id, ok, data|error}` out). Heavy work (file reads, parsing, string indexing, HTML report export) runs on worker threads so the window never blocks; the UI thread only renders and dispatches.

To regenerate the application icon after editing `tools/make_icon.py`, run `python tools/make_icon.py` and rebuild.

## Testing

```sh
python3 tools/make_fixtures.py     # builds every fixture from scratch
CB_CLI=build-cli/codebreak-cli python3 tests/run_tests.py
```

The suite builds a real PE image (sections, imports, exports, rich header, debug directory, TLS, version info, certificate table), a real signed APK (ZIP + binary AXML manifest + DEX with valid SHA-1/Adler-32 + v1/v2 signature blocks), an ELF shared object, a Mach-O image, a Java class, plus GZIP, TAR and PDF fixtures — then asserts dozens of parsed fields against known ground truth (including that the new parsers and the risk engine are present in the output) and checksum-validating runs against system binaries.

## License

MIT. WebView2 SDK components under `third_party/webview2` follow the Microsoft WebView2 Runtime license (see `LICENSE.txt` / `NOTICE.txt` there).
