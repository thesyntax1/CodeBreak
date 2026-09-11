#!/usr/bin/env python3
"""Corrupt-input smoke test.

Feeds the CLI pristine, truncated, bit-flipped and synthetic-magic inputs and
fails on any crash or sanitizer diagnostic. It is deterministic (fixed seed) and
works both with a plain release build (catches segfaults / aborts) and with an
ASan+UBSan build (catches out-of-bounds reads and undefined behaviour).

    CB_CLI=build/codebreak-cli python3 tests/sanitize_smoke.py

Regression coverage for:
  * ZIP EOCD backwards scan reading one byte before the buffer (size_t wrap)
  * PE export ordinal table read through a negative RVA offset (size_t wrap)
  * PE RVA map handing out offsets past EOF (version info / manifest / relocs)
  * OLE2 sector size computed with an out-of-range shift exponent (UB)
  * md5/sha1/sha256 calling memcpy(dst, nullptr, 0) on an empty file (UB)
"""
import os
import random
import subprocess
import sys
import tempfile

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.abspath(os.path.join(HERE, ".."))
CLI = os.environ.get("CB_CLI", os.path.join(ROOT, "build-cli", "codebreak-cli"))
FIX = os.path.join(HERE, "fixtures")

FLAGSETS = [
    [],
    ["--json"],
    ["--risk"],
    ["--deep"],
    ["--behavior"],
    ["--strings", "--kind", "all", "--min-len", "3"],
    ["--asm", "--length", "2048"],
    ["--calls"],
    ["--hash"],
    ["--view"],
    ["--lang", "tr"],
]

MAGICS = [
    b"MZ\x90\x00", b"\x7fELF", b"PK\x03\x04", b"PK\x05\x06", b"PK\x07\x08",
    b"dex\n035\x00", b"\xca\xfe\xba\xbe", b"\xcf\xfa\xed\xfe", b"\xfe\xed\xfa\xcf",
    b"\xd0\xcf\x11\xe0\xa1\xb1\x1a\xe1", b"%PDF-1.4", b"\x1f\x8b\x08", b"Rar!\x1a\x07",
    b"7z\xbc\xaf\x27\x1c", b"BZh9", b"\xfd7zXZ\x00", b"MSCF\x00\x00", b"\x00asm\x01\x00",
    b"\x89PNG\r\n", b"SQLite format 3\x00", b"!<arch>\n", b"RIFF\x00\x00",
]

def hostile_blobs():
    """Hand-crafted headers with values that used to defeat a bounds check.

    Every entry is a regression for a specific integer-overflow bug:
      * MZ + e_lfanew near 0xFFFFFFFF  -> "off + 24 > n" wrapped in uint32_t
      * ELF + e_shoff/e_phoff near 2^64 -> "o + k > n" wrapped in the reader
      * OLE + sectorShift >= 32        -> "1u << shift" was undefined behaviour
      * ZIP + EOCD comment/count extremes
    """
    import struct

    out = []

    def mz(e_lfanew, size=0x400):
        b = bytearray(size)
        b[0:2] = b"MZ"
        struct.pack_into("<I", b, 0x3C, e_lfanew & 0xFFFFFFFF)
        return bytes(b)

    for v in (0xFFFFFFFF, 0xFFFFFFE8, 0xFFFFFFF0, 0xFFFFFFFC, 0x40, 0x41, 0x1000000, 0x7FFFFFFF):
        out.append(("mz_lfanew_%08x" % v, mz(v)))

    def elf(shoff, phoff, is64=True, shnum=8, shentsize=64):
        b = bytearray(0x800)
        b[0:4] = b"\x7fELF"
        b[4] = 2 if is64 else 1
        b[5] = 1
        b[6] = 1
        if is64:
            struct.pack_into("<Q", b, 32, phoff & 0xFFFFFFFFFFFFFFFF)
            struct.pack_into("<Q", b, 40, shoff & 0xFFFFFFFFFFFFFFFF)
            struct.pack_into("<H", b, 58, shentsize)
            struct.pack_into("<H", b, 60, shnum)
            struct.pack_into("<H", b, 62, 1)
        else:
            struct.pack_into("<I", b, 28, phoff & 0xFFFFFFFF)
            struct.pack_into("<I", b, 32, shoff & 0xFFFFFFFF)
            struct.pack_into("<H", b, 46, shentsize)
            struct.pack_into("<H", b, 48, shnum)
        return bytes(b)

    for v in (0xFFFFFFFFFFFFFFDC, 0xFFFFFFFFFFFFFFF8, 0xFFFFFFFFFFFFFFFF, 0x8000000000000000, 0xFFFFFFFC):
        out.append(("elf64_shoff_%016x" % v, elf(v, v)))
        out.append(("elf32_shoff_%08x" % (v & 0xFFFFFFFF), elf(v, v, is64=False, shentsize=40)))
    out.append(("elf64_shoff0_shnum0", elf(0, 0, shnum=0)))
    out.append(("elf64_huge_entsize", elf(64, 64, shentsize=0xFFFF)))

    def ole(shift, major=4, size=8192):
        b = bytearray(size)
        b[0:8] = b"\xd0\xcf\x11\xe0\xa1\xb1\x1a\xe1"
        struct.pack_into("<H", b, 26, major)
        struct.pack_into("<H", b, 30, shift & 0xFFFF)
        struct.pack_into("<I", b, 44, 1)      # FAT sector count
        struct.pack_into("<I", b, 48, 1)      # first directory sector
        struct.pack_into("<I", b, 56, 4096)   # mini stream cutoff
        struct.pack_into("<I", b, 60, 0xFFFFFFFE)  # first mini FAT sector
        struct.pack_into("<I", b, 68, 0xFFFFFFFE)  # first DIFAT sector
        return bytes(b)

    for v in (6307, 0xFFFF, 31, 32, 33, 63, 64, 0, 3):
        out.append(("ole_shift_%d" % v, ole(v)))
        out.append(("ole3_shift_%d" % v, ole(v, major=3)))

    def zipeocd(comment_len, entries=0xFFFF, cd_off=0xFFFFFFFF, cd_size=0xFFFFFFFF):
        head = b"PK\x03\x04" + b"\x11" * 60
        eocd = struct.pack("<IHHHHIIH", 0x06054B50, 0, 0, entries, entries,
                           cd_size, cd_off, comment_len)
        return head + eocd + b"C" * min(comment_len, 64)

    for cl in (0xFFFF, 0x1000, 4, 0):
        out.append(("zip_eocd_comment_%d" % cl, zipeocd(cl)))
    out.append(("zip_eocd_only", struct.pack("<IHHHHIIH", 0x06054B50, 0, 0, 0xFFFF, 0xFFFF,
                                             0xFFFFFFFF, 0xFFFFFFFF, 0)))
    out.append(("zip64_locator", b"PK\x06\x07" + b"\xff" * 60))

    def dex(hdr_field, value, size=4096):
        b = bytearray(size)
        b[0:8] = b"dex\n035\x00"
        struct.pack_into("<I", b, hdr_field, value & 0xFFFFFFFF)
        return bytes(b)

    for field in (32, 36, 40, 56, 60, 64, 68, 72, 76, 80, 84, 88, 92, 96, 100, 104):
        out.append(("dex_f%d_max" % field, dex(field, 0xFFFFFFFF)))
        out.append(("dex_f%d_neg1" % field, dex(field, 0x7FFFFFFF)))

    def macho(cmd, cmdsize, size=4096):
        b = bytearray(size)
        struct.pack_into("<I", b, 0, 0xFEEDFACF)
        struct.pack_into("<I", b, 4, 0x01000007)
        struct.pack_into("<I", b, 16, cmd)
        struct.pack_into("<I", b, 20, cmdsize)
        if cmdsize >= 16:
            struct.pack_into("<I", b, 16, cmd)
            struct.pack_into("<I", b, 20, cmdsize)
        return bytes(b)

    out.append(("macho_huge_ncmds", macho(0xFFFFFFFF, 0)))
    out.append(("macho_huge_size", macho(1, 0xFFFFFFFF)))
    return out


BAD_MARKERS = (
    "runtime error",
    "AddressSanitizer",
    "LeakSanitizer",
    "MemorySanitizer",
    "UndefinedBehaviorSanitizer",
    "Segmentation fault",
    "stack-buffer-overflow",
    "heap-buffer-overflow",
)

TIMEOUT = int(os.environ.get("CB_SMOKE_TIMEOUT", "120"))


def run(path, flags):
    """Return (ok, detail). Acceptable exit codes are 0/1/2 (usage & parse errors)."""
    env = dict(os.environ)
    env["ASAN_OPTIONS"] = "detect_leaks=1"
    env["UBSAN_OPTIONS"] = "print_stacktrace=1"
    try:
        r = subprocess.run([CLI] + ([path] if path is not None else []) + flags,
                           capture_output=True, timeout=TIMEOUT, env=env)
    except subprocess.TimeoutExpired:
        return False, "timeout after %ds" % TIMEOUT
    err = r.stderr.decode("utf-8", "replace")
    for marker in BAD_MARKERS:
        if marker in err:
            line = next((l.strip() for l in err.splitlines() if marker in l), marker)
            return False, "sanitizer: " + line[:300]
    if r.returncode not in (0, 1, 2):
        return False, "exit code %d\n%s" % (r.returncode, err.strip()[:300])
    return True, ""


def variants(data, rnd):
    """Deterministic corrupt variants of one fixture."""
    out = {}
    for pct in (0, 1, 5, 25, 50, 75, 90, 99, 100):
        out["trunc%d" % pct] = data[: max(0, int(len(data) * pct / 100))]
    for k in range(3):
        b = bytearray(data)
        for _ in range(40):
            if b:
                b[rnd.randrange(len(b))] ^= 1 << rnd.randrange(8)
        out["flip%d" % k] = bytes(b)
    if data:
        b = bytearray(data)
        off = rnd.randrange(len(b))
        ln = min(64, len(b) - off)
        b[off:off + ln] = b"\xff" * ln
        out["window"] = bytes(b)
        b = bytearray(data)
        for i in range(min(len(b), 128)):
            b[i] = 0
        out["zerohead"] = bytes(b)
        out["doubled"] = data + data
    return out


def main():
    if not os.path.isfile(CLI):
        print("smoke: CLI not found at %s (set CB_CLI)" % CLI)
        return 2
    if not os.path.isdir(FIX):
        print("smoke: fixtures missing - run: python3 tools/make_fixtures.py")
        return 2

    rnd = random.Random(0xC0DEB7EA)
    tmp = tempfile.mkdtemp(prefix="cb-smoke-")
    cases = []  # (label, path-or-None, flags)

    names = sorted(n for n in os.listdir(FIX) if os.path.isfile(os.path.join(FIX, n)))
    for name in names:
        path = os.path.join(FIX, name)
        data = open(path, "rb").read()
        # pristine input, every flag set
        for flags in FLAGSETS:
            cases.append((name + " pristine", path, flags))
        # corrupt variants, a subset of flag sets
        for vname, blob in variants(data, rnd).items():
            vp = os.path.join(tmp, "%s.%s" % (name, vname))
            with open(vp, "wb") as f:
                f.write(blob)
            for flags in ([], ["--json"], ["--risk"], ["--strings"], ["--asm"]):
                cases.append(("%s/%s" % (name, vname), vp, flags))

    # synthetic files that only look like a known container
    for i, magic in enumerate(MAGICS):
        for size in (0, 8, 64, 1024, 65536):
            body = bytes(rnd.randrange(256) for _ in range(size))
            blob = magic + body
            vp = os.path.join(tmp, "magic%02d_%d.bin" % (i, size))
            with open(vp, "wb") as f:
                f.write(blob)
            for flags in ([], ["--json"], ["--deep"]):
                cases.append(("magic%02d_%d" % (i, size), vp, flags))

    # hand-crafted hostile headers (regressions for integer-overflow bugs)
    for label, blob in hostile_blobs():
        vp = os.path.join(tmp, label + ".bin")
        with open(vp, "wb") as f:
            f.write(blob)
        for flags in FLAGSETS:
            cases.append((label, vp, flags))

    # a genuinely empty file must not upset the hash routines
    empty = os.path.join(tmp, "empty.bin")
    open(empty, "wb").close()
    for flags in FLAGSETS:
        cases.append(("empty", empty, flags))

    # HTML report: written into the scratch dir so it works on every platform
    if names:
        cases.append(("report", os.path.join(FIX, names[0]),
                      ["--report", os.path.join(tmp, "report.html")]))

    # batch mode over a directory that holds all of the above
    for flags in ([], ["--json"], ["--csv", os.path.join(tmp, "b.csv")],
                  ["--html", os.path.join(tmp, "b.html")], ["--limit", "5"]):
        cases.append(("batch", None, ["--batch", tmp] + flags))

    failed = 0
    for label, path, flags in cases:
        argv = flags if path is None else [path] + flags
        ok, detail = run(path, flags)
        if not ok:
            failed += 1
            print("FAIL: %s %s -> %s" % (label, " ".join(argv), detail))
            if failed >= 25:
                print("(stopping after 25 failures)")
                break

    print("smoke: %d cases, %d failed" % (len(cases), failed))
    return 1 if failed else 0


if __name__ == "__main__":
    sys.exit(main())
