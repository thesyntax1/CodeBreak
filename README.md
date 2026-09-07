# CodeBreak

A native binary analysis suite that runs entirely in the terminal. CodeBreak loads compiled files — EXE, DLL, APK, JAR, DEX, ELF, Mach-O, Java classes, GZIP/TAR archives, PDF documents, ZIP — and shows what is actually inside them: machine-code structure, metadata, hashes, entropy, strings, and raw bytes. On top of that it runs a transparent **heuristic risk-scoring engine** that turns the parsed facts into a 0–100 threat score. Nothing is guessed or faked; every field is parsed from the file itself.

The parsing engine is a single dependency-free C++17 codebase (`cb_core`) with one front end: `codebreak-cli`, a terminal-only command line tool that builds on Linux and Windows.

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

## CLI usage

`codebreak-cli` adapts its output to where stdout goes:

- **terminal** → a color-coded human summary (RISK badge, hashes, entropy, indicators);
- **piped / redirected** → clean raw JSON, ready for `jq`.

```sh
codebreak-cli <file>                        # human summary on a tty, raw JSON when piped
codebreak-cli <file> --view                 # force the human summary
codebreak-cli <file> --json                 # force raw JSON
codebreak-cli <file> --pretty               # force indented JSON
codebreak-cli <file> --risk                 # only the risk assessment (JSON)
codebreak-cli <file> --behavior             # static host-behavior trace (see below)
codebreak-cli <file> --asm                  # x86-64 disassembly of the code section
                        [--offset N] [--base N] [--length N]
codebreak-cli <file> --strings [PATTERN]    # extract strings; optional filter substring
                        [--min-len N]      # minimum string length (default 4)
                        [--kind all|ascii|wide] [--count N]
codebreak-cli <file> --hex OFFSET           # hex dump from a byte offset
                        [--hex-len N]       # how many bytes to show (default 256)
codebreak-cli <file> --report OUT.html      # write a self-contained HTML report
codebreak-cli --hash <file>                 # full analysis JSON for one file
codebreak-cli --compare A B [--view]        # side-by-side structural + hash comparison
codebreak-cli --batch DIR                   # scan a tree -> table on a tty, JSON when piped
codebreak-cli --batch DIR --json F --csv F --html F   # export the batch three ways
codebreak-cli --batch DIR --limit N --max-mb N        # bound the scan
codebreak-cli --version | -h
```

Exit code 0 on success, 1 on error (message on stderr). `--report` and the batch `--html` flag write self-contained HTML reports.

### Interactive shell

Run `codebreak-cli` with **no arguments** to enter an interactive `codebreak>` shell where you type commands the same way you would on the command line — bare file paths, `risk <file>`, `behavior <file>`, `asm <file>` (alias `code`/`disasm`), `strings <file>`, `hex <file> 0x400`, `batch <dir>`, `compare <a> <b>`, `hash <file>`, `report <file> out.html`, plus `history`, `help`, `version`, `clear` and `exit`. This is handy when you double-click the exe on Windows instead of running it from a terminal. Your typed commands are saved to a history file (`~/.codebreak_history` on Linux, `%APPDATA%\CodeBreak.history` on Windows).

### Code extraction (disassembly)

`codebreak-cli <file> --asm` decodes the main executable section of a native PE or ELF x86-64 binary into an objdump-style listing: address, raw bytes, mnemonic and operands. It resolves relative branches/jumps/calls to their target addresses and follows RIP-relative addressing and ModRM/SIB forms. Step into any byte window with `--offset N --base N --length N` (e.g. to walk a single function). Output is a colorized terminal table, or `{"code":{"lines":[...]}}` JSON when piped.

### Host behavior trace (static)

`--behavior` answers *"where does this sample reach out, and what does it touch?"* **without ever executing the file.** It cross-references the strings and the imported APIs and reports four groups:

- **network** — URLs / hostnames / IPs / e-mails found in the binary plus network-capable imports (`InternetOpen`/`HttpOpenRequest`, `WinHttp`, `WSAStartup`/`socket`/`connect`, `URLDownloadToFile`, ...);
- **fileSystem** — path strings the sample references (`C:\...`, `%APPDATA%`, `%TEMP%`, `\Users\...`) and file APIs (`CreateFileW`, `WriteFile`, `NtCreateFile`, `MoveFile`, `CopyFile`, ...);
- **process** — command/launch strings (`powershell`, `cmd /c`, `certutil`, `rundll32`, `schtasks`, ...) and process/code-injection APIs (`CreateProcessW`, `WriteProcessMemory`, `CreateRemoteThread`, ...);
- **persistence** — Run-key / `\Startup\` candidates and registry/service APIs.

Treat the output as *candidates*, not a runtime guarantee: it is derived statically and may include benign lookalikes (e.g. a version string such as `1.2.3.4` can read like an IP).

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

### Linux

```sh
./build.sh          # plain g++/CMake, no dependencies
```

Output: `build-cli/codebreak-cli`.

### Windows (Visual Studio 2022)

Requirements: Visual Studio 2022 with the *Desktop development with C++* workload (CMake ships with it). From the repository root:

```bat
build.bat
```

Output: `build\Release\codebreak-cli.exe`. It is a plain console program — run it from a terminal, or double-click it to open the interactive shell.

Equivalent manual commands:

```bat
cmake -S . -B build -A x64
cmake --build build --config Release
```

MinGW-w64 (UCRT x64) also works: `cmake -S . -B build-mingw -G "MinGW Makefiles" -DCMAKE_BUILD_TYPE=Release` then `cmake --build build-mingw -j`.

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
  behavior.cpp     static host-behavior extraction (network/file/process/persistence)
  disasm.cpp       x86-64 disassembler (ModRM/SIB/REX/RIP-relative, branches/calls)
  report.cpp       self-contained HTML report and batch-report generators
  hashes.cpp       SHA-256, SHA-1, MD5, CRC32, entropy
  util.cpp         file IO, string building, wide-string decode, formatting,
                   recursive directory walk (batch scans)
  jsonw.h jsonr.h  minimal JSON writer (engine) and parser (host)
  cli/main_cli.cpp terminal front end (human/JSON views, risk, report, batch,
                   interactive shell)
tests/
  run_tests.py     assertion suite; checks real parser output
tools/make_fixtures.py  builds PE, APK, DEX, ELF, Mach-O, class, ZIP, GZIP,
                        TAR, PDF, OLE2 (.doc) and PKCS #7 fixtures from scratch
tools/cfbwriter.py      minimal OLE2 compound-file writer used by make_fixtures.py
```

## Continuous integration

`.github/workflows/build.yml` runs on every push, pull request and on demand (Actions -> `build` -> Run workflow). It has two jobs:

- **Windows x64 (MSVC)** — configures `-A x64` and builds the release, then uploads `codebreak-cli.exe` as the `codebreak-windows-x64` artifact.
- **Linux CLI + tests** — builds `codebreak-cli`, regenerates every fixture and runs the full `tests/run_tests.py` suite, then uploads the `codebreak-linux-cli` artifact.

Grab the built exe from the workflow's **Artifacts** panel on the Actions tab (a workflow run must finish first; push a tag `v*` or click *Run workflow* to trigger a build).

## Testing

```sh
python3 tools/make_fixtures.py     # builds every fixture from scratch
CB_CLI=build-cli/codebreak-cli python3 tests/run_tests.py
```

The suite builds a real PE image (sections, imports, exports, rich header, debug directory, TLS, version info, certificate table), a real signed APK (ZIP + binary AXML manifest + DEX with valid SHA-1/Adler-32 + v1/v2 signature blocks), an ELF shared object, a Mach-O image, a Java class, a macro-bearing OLE2 `.doc` and an OpenSSL PKCS #7 signature, plus GZIP, TAR and PDF fixtures — then asserts dozens of parsed fields against known ground truth (including that the new parsers and the risk engine are present in the output) and checksum-validating runs against system binaries.

## License

MIT.
