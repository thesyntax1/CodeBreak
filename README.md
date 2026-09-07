# CodeBreak

A native binary analysis suite for Windows. CodeBreak loads compiled files — EXE, DLL, APK, JAR, DEX, ELF, Mach-O, Java classes, GZIP/TAR archives, PDF documents, ZIP — and shows what is actually inside them: machine-code structure, metadata, hashes, entropy, strings, and raw bytes. On top of that it runs a transparent **heuristic risk-scoring engine** that turns the parsed facts into a 0–100 threat score. Nothing is guessed or faked; every field is parsed from the file itself.

The GUI is a self-contained native Win32 application (common controls only, no browser component and no runtime dependency). The parsing engine is dependency-free C++17 and also builds as a standalone CLI on Linux and Windows.

## The GUI

Run `CodeBreak.exe`, drop a file anywhere on the window (or press **Open File...**) and the analysis appears in milliseconds. The whole UI is drawn with the native Windows common controls — no embedded browser, no WebView2 runtime to install, nothing extra to ship next to the exe.

- **Summary bar** — the file name and size, the detected format, the risk band and score (0–100), the number of security indicators and the SHA-256 prefix.
- **Find box** — type any field name (`sha256`, `risk`, `imports`, `subject`, `version`...) and the tree filters live to matching fields.
- **Field tree** — the full parsed analysis as a browsable tree: every format section (PE sections/imports/security, ELF, APK manifest/DEX, ZIP entries, OLE2 streams, PKCS #7 signers, ...), hashes, entropy and risk signals.
- **Detail pane** — select any node to inspect its value (a scalar, or a readable summary of an object/array).

Heavy work (file reads, parsing, hashing) runs on a worker thread so the window never blocks; the UI thread only renders and dispatches. Analysis is also accepted on the command line: `CodeBreak.exe somefile.exe`.

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

The CLI mirrors this for automation: `--risk` prints the assessment alone, `--report` writes an HTML report, `--compare` diffs two files' analyses, and `--batch` scans whole directory trees into JSON/CSV/HTML with per-file risk.

## CLI usage

```sh
codebreak-cli <file>                       # everything as one JSON document
codebreak-cli <file> --risk                # only the risk assessment
codebreak-cli <file> --report out.html     # self-contained HTML report
codebreak-cli <file> --strings --filter kernel32 --min-length 6
codebreak-cli <file> --strings --kind wide
codebreak-cli <file> --hex --offset 0x400 --length 512
codebreak-cli --hash <file>                # full analysis JSON for one file
codebreak-cli --compare A B                # side-by-side structural + hash comparison
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
| OLE2 (.doc/.xls/.ppt/.msi) | CFB magic `D0 CF 11 E0` | compound-file kind, FAT/DIFAT layout, directory-entry tree (storages/streams with paths, sizes, red/black-tree order), macro/VBA project presence |
| PKCS #7 / CMS | SignedData OID | signer certificates (subject, issuer, serial, validity, signature algorithm, SHA-1 thumbprint), signer count, content type |
| Anything else | — | hashes, entropy profile, strings, hex |

Entropy is computed over 16 KB blocks with Shannon's formula; the overall figure is the weighted mean. Strings extraction recognizes ASCII (CP437-safe printable run) and UTF-16LE/BE.

## Building

### Windows GUI (Visual Studio 2022)

Requirements: Visual Studio 2022 with the *Desktop development with C++* workload (CMake ships with it). From the repository root:

```bat
build.bat
```

Output: `build\Release\CodeBreak.exe` and `build\Release\codebreak-cli.exe`. Both are self-contained; the GUI uses only the standard Windows common controls and needs no extra DLLs or runtime to be installed.

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
  olefmt.cpp x509.cpp
                   format parsers (PE/COFF, ELF, ZIP/APK/JAR, DEX, binary AXML,
                   Mach-O, Java class, GZIP, TAR, PDF, OLE2 compound files,
                   X.509/PKCS #7 signatures)
  risk.cpp         heuristic threat-scoring engine (0-100 + weighted signals)
  report.cpp       self-contained HTML report and batch-report generators
  hashes.cpp       SHA-256, SHA-1, MD5, CRC32, entropy
  util.cpp         file IO, string building, wide-string decode, formatting,
                   recursive directory walk (batch scans)
  jsonw.h jsonr.h  minimal JSON writer (engine) and parser (host)
  cli/main_cli.cpp command line front end (single-file, risk, report, batch)
  host/main.cpp    native Win32 GUI (tree + find + detail, no browser)
  host/app.rc      application icon, version info and manifest
tests/
  run_tests.py     assertion suite; checks real parser output
tools/make_fixtures.py  builds PE, APK, DEX, ELF, Mach-O, class, ZIP, GZIP,
                        TAR, PDF, OLE2 (.doc) and PKCS #7 fixtures from scratch
tools/cfbwriter.py      minimal OLE2 compound-file writer used by make_fixtures.py
tools/make_icon.py       regenerates the application icon
```

Heavy work (file reads, parsing, hashing) runs on a worker thread that posts its result back to the UI thread; the UI thread only renders and dispatches.

To regenerate the application icon after editing `tools/make_icon.py`, run `python tools/make_icon.py` and rebuild.

## Continuous integration

`.github/workflows/build.yml` runs on every push, pull request and on demand (Actions -> `build` -> Run workflow). It has two jobs:

- **Windows x64 (MSVC)** — configures `-A x64` and builds the full release, then uploads a self-contained `codebreak-windows-x64` artifact containing `CodeBreak.exe` and `codebreak-cli.exe`.
- **Linux CLI + tests** — builds `codebreak-cli` with the GUI disabled, regenerates every fixture and runs the full `tests/run_tests.py` suite, then uploads the `codebreak-linux-cli` artifact.

Grab the built exe from the workflow's **Artifacts** panel on the Actions tab (a workflow run must finish first; push a tag `v*` or click *Run workflow* to trigger a build).

## Testing

```sh
python3 tools/make_fixtures.py     # builds every fixture from scratch
CB_CLI=build-cli/codebreak-cli python3 tests/run_tests.py
```

The suite builds a real PE image (sections, imports, exports, rich header, debug directory, TLS, version info, certificate table), a real signed APK (ZIP + binary AXML manifest + DEX with valid SHA-1/Adler-32 + v1/v2 signature blocks), an ELF shared object, a Mach-O image, a Java class, a macro-bearing OLE2 `.doc` and an OpenSSL PKCS #7 signature, plus GZIP, TAR and PDF fixtures — then asserts dozens of parsed fields against known ground truth (including that the new parsers and the risk engine are present in the output) and checksum-validating runs against system binaries.

## License

MIT.
