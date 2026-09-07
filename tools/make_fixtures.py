#!/usr/bin/env python3
import struct, hashlib, os, sys, random, zlib

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

def raw_deflate(data):
    co = zlib.compressobj(9, zlib.DEFLATED, -15)
    return co.compress(data) + co.flush()

HERE = os.path.dirname(os.path.abspath(__file__))
OUT = os.path.join(HERE, "..", "tests", "fixtures")
os.makedirs(OUT, exist_ok=True)

def u16(v): return struct.pack('<H', v & 0xFFFF)
def u32(v): return struct.pack('<I', v & 0xFFFFFFFF)
def u64(v): return struct.pack('<Q', v & 0xFFFFFFFFFFFFFFFF)
def be16(v): return struct.pack('>H', v)
def be32(v): return struct.pack('>I', v & 0xFFFFFFFF)
def be64(v): return struct.pack('>Q', v & 0xFFFFFFFFFFFFFFFF)

def pad4(b):
    while len(b) % 4:
        b += b'\x00'
    return b

def pad(b, n, fill=b'\x00'):
    while len(b) < n:
        b += fill
    return b

def wstr(s, z=True):
    return s.encode('utf-16-le') + (b'\x00\x00' if z else b'')

# ---------------------------------------------------------------- PE fixture

def build_pe():
    IMAGE_BASE = 0x140000000
    PE_OFF = 0x100
    TEXT_VA, TEXT_RAW, TEXT_SZ = 0x1000, 0x400, 0x200
    RDATA_VA, RDATA_RAW, RDATA_SZ = 0x2000, 0x600, 0x1000
    DATA_VA, DATA_RAW, DATA_SZ = 0x3000, 0x1600, 0x200

    text = bytearray()
    text += bytes([0x48, 0x89, 0x5C, 0x24, 0x08, 0x57, 0x48, 0x83, 0xEC, 0x20])
    text += b'\x90' * 32
    text += bytes([0xB8, 0x2A, 0x00, 0x00, 0x00, 0xC3])
    text += b'\xCC' * 64
    text += b'\x48\x8B\xC4\x48\x89\x58\x08\xC3'  # callback body at 0x1080+ area
    text = bytearray(pad(bytes(text), TEXT_SZ, b'\xCC'))

    rdata = bytearray(RDATA_SZ)
    rcur = 0
    def rall(data, align=2):
        nonlocal rcur
        while rcur % align:
            rcur += 1
        off = rcur
        rdata[off:off+len(data)] = data
        rcur = off + len(data)
        return off

    # exports
    name_dll = rall(b'TestLib.dll\x00')
    fnames = []
    for nm in [b'TestFunction\x00', b'AnotherFunc\x00']:
        fnames.append(rall(nm))
    ord_table = rall(u16(0) + u16(2))
    addr_names = rall(u32(RDATA_VA + fnames[0]) + u32(RDATA_VA + fnames[1]))
    addr_funcs = rall(u32(0x1010) + u32(0x1020) + u32(0x1030))
    exp = bytearray()
    exp += u32(0) + u32(0x6432F0D1) + u16(0) + u16(0)
    exp += u32(RDATA_VA + name_dll)
    exp += u32(1) + u32(3) + u32(2)
    exp += u32(RDATA_VA + addr_funcs) + u32(RDATA_VA + addr_names) + u32(RDATA_VA + ord_table)
    export_off = rall(bytes(pad4(bytes(exp))))

    # imports
    ibn = []
    for nm, hint in [(b'CreateFileW\x00', 0x0231), (b'ReadFile\x00', 0x00BE)]:
        ibn.append(rall(u16(hint) + nm))
    ubn = rall(u16(0x0245) + b'MessageBoxA\x00')
    kname = rall(b'KERNEL32.DLL\x00')
    uname = rall(b'USER32.dll\x00')
    ilt_k = rall(u64(RDATA_VA + ibn[0]) + u64(RDATA_VA + ibn[1]) + u64(0x8000000000000011) + u64(0))
    ilt_u = rall(u64(RDATA_VA + ubn) + u64(0))
    iat_k = rall(u64(RDATA_VA + ibn[0]) + u64(RDATA_VA + ibn[1]) + u64(0x8000000000000011) + u64(0))
    iat_u = rall(u64(RDATA_VA + ubn) + u64(0))
    imp = bytearray()
    imp += u32(RDATA_VA + ilt_k) + u32(0) + u32(0) + u32(RDATA_VA + kname) + u32(RDATA_VA + iat_k)
    imp += u32(RDATA_VA + ilt_u) + u32(0) + u32(0) + u32(RDATA_VA + uname) + u32(RDATA_VA + iat_u)
    imp += u32(0) * 5
    import_off = rall(bytes(pad4(bytes(imp))))

    # version info resource
    def vi_string(key, value):
        node = u16(len(value) + 1) + u16(1) + wstr(key)
        node = pad4(node)
        node += pad4(wstr(value))
        return bytearray(node)

    def vi_stringtable(lang):
        node = u16(0) + u16(1) + wstr(lang)
        node = pad4(node)
        children = bytearray()
        strings = [
            ("CompanyName", "CodeBreak Test Labs"),
            ("FileDescription", "PE Fixture Binary"),
            ("FileVersion", "1.2.3.4"),
            ("InternalName", "fixture"),
            ("OriginalFilename", "fixture.exe"),
            ("ProductName", "CodeBreak Fixtures"),
            ("ProductVersion", "1.2.3.4"),
            ("LegalCopyright", "(c) CodeBreak Test Labs"),
        ]
        for k, v in strings:
            children += vi_string(k, v)
        node = bytearray(u16(0) + u16(1) + wstr(lang))
        node = pad4(bytes(node))
        return bytearray(node) + children

    def vi_with_children(valuelen, wtype, key, value, children):
        node = u16(valuelen) + u16(wtype) + wstr(key)
        node = pad4(node)
        if value:
            node += pad4(value)
        node += pad4(children)
        return bytearray(node)

    def vi_var(key, value):
        node = u16(len(value)) + u16(0) + wstr(key)
        node = pad4(node)
        node += pad4(value)
        return bytearray(node)

    fixed = bytearray()
    fixed += u32(0xFEEF04BD) + u32(0x00010000)
    fixed += u32(0x00010002) + u32(0x00030004)
    fixed += u32(0x00010002) + u32(0x00030004)
    fixed += u32(0x0000003F) + u32(0) + u32(0x00000004) + u32(1)
    fixed += u32(0) + u32(0) + u32(0)
    assert len(fixed) == 52
    vi = vi_with_children(52, 0, "VS_VERSION_INFO", bytes(fixed),
                          vi_with_children(0, 1, "StringFileInfo", b"", vi_stringtable("040904b0")) +
                          vi_with_children(0, 1, "VarFileInfo", b"", vi_var("Translation", u16(0x0409) + u16(0x04B0))))
    vi_off = rall(bytes(vi), 4)

    manifest = b'<?xml version="1.0" encoding="UTF-8" standalone="yes"?><assembly xmlns="urn:schemas-microsoft-com:asm.v1" manifestVersion="1.0"><assemblyIdentity name="CodeBreak.fixture" version="1.2.3.4"/><description>CodeBreak test manifest</description></assembly>'
    manifest_off = rall(manifest, 4)
    rcdata = b'THIS_IS_RCDATA_PAYLOAD_1234567890'
    rcdata_off = rall(rcdata, 4)

    def res_dir(named, ids):
        out = u32(0) + u32(0) + u16(0) + u16(0) + u16(named) + u16(ids)
        return out

    def res_entry(name, off, is_dir=False):
        return u32(name | (0x80000000 if isinstance(name, str) else 0)) if False else u32(name) + u32(off | (0x80000000 if is_dir else 0))

    def leaf(rva, size, cp=0x409):
        return u32(rva) + u32(size) + u32(cp) + u32(0)

    # build the resource tree in one buffer
    res = bytearray()
    def rbuild_rva(off):
        return RDATA_VA + off
    # offsets computed by hand: assemble sequentially
    # total layout:
    #  0x00: root dir (16 + 3*8 = 40) -> entries: type16, type24, type10(named)
    #  0x28: dir for type16 lang level etc.
    # We assemble with placeholder pass
    res = bytearray()
    root_off = 0
    res += res_dir(0, 3)
    # entries filled later; reserve
    e16 = len(res); res += res_entry(16, 0, True)
    e24 = len(res); res += res_entry(24, 0, True)
    e10 = len(res); res += res_entry(0, 0, True)
    d16 = len(res); res += res_dir(0, 1); res += res_entry(1, 0, True)
    d16l2 = len(res); res += res_dir(0, 1); res += res_entry(0x409, 0, False)
    l16 = len(res); res += leaf(rbuild_rva(vi_off), len(vi))
    d24 = len(res); res += res_dir(0, 1); res += res_entry(1, 0, True)
    d24l2 = len(res); res += res_dir(0, 1); res += res_entry(0x409, 0, False)
    l24 = len(res); res += leaf(rbuild_rva(manifest_off), len(manifest))
    d10 = len(res); res += res_dir(0, 1); res += res_entry(1, 0, True)
    d10l2 = len(res); res += res_dir(0, 1); res += res_entry(0, 0, False)
    l10 = len(res); res += leaf(rbuild_rva(rcdata_off), len(rcdata))
    res = bytearray(res)
    # fix offsets
    def put32(buf, off, v):
        buf[off:off+4] = u32(v)
    put32(res, e16 + 4, d16 | 0x80000000)
    put32(res, e24 + 4, d24 | 0x80000000)
    put32(res, e10 + 4, d10 | 0x80000000)
    put32(res, d16 + 16 + 4, d16l2 | 0x80000000)
    put32(res, d16l2 + 16 + 4, l16)
    put32(res, d24 + 16 + 4, d24l2 | 0x80000000)
    put32(res, d24l2 + 16 + 4, l24)
    put32(res, d10 + 16 + 4, d10l2 | 0x80000000)
    put32(res, d10l2 + 16 + 4, l10)
    # named entry for type10: name field must have high bit set
    while rcur % 4:
        rcur += 1
    name_field_pos = e10
    res_off = rall(bytes(res), 4)
    name_config = rall(u16(7) + wstr("CONFIG"))
    rdata[res_off + name_field_pos:res_off + name_field_pos + 4] = u32((name_config - res_off) | 0x80000000)

    # debug
    guid = bytes([0x4D, 0x3C, 0x2B, 0x1A, 0x34, 0x12, 0x78, 0x56, 0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0x01, 0x02, 0x03])
    cv = b'RSDS' + guid + u32(7) + b'C:\\projects\\fixture\\build\\fixture.pdb\x00'
    cv_off = rall(cv, 4)
    dbg = u32(0) + u32(0x6432F0D2) + u16(0) + u16(0) + u32(2) + u32(len(cv)) + u32(0) + u32(RDATA_RAW + cv_off)
    debug_off = rall(pad4(dbg), 4)

    # TLS
    tls_callbacks_data_off = 0x20
    tls = u64(IMAGE_BASE + DATA_VA + 0x10) + u64(IMAGE_BASE + DATA_VA + 0x18) + \
          u64(IMAGE_BASE + DATA_VA + 0x00) + u64(IMAGE_BASE + DATA_VA + tls_callbacks_data_off) + \
          u32(0) + u32(0)
    tls_off = rall(pad4(tls), 4)

    rdata = bytearray(pad(bytes(rdata), RDATA_SZ))

    data = bytearray(DATA_SZ)
    data[tls_callbacks_data_off:tls_callbacks_data_off+8] = u64(IMAGE_BASE + 0x1180)
    data[tls_callbacks_data_off+8:tls_callbacks_data_off+16] = u64(0)
    data = bytearray(pad(bytes(data), DATA_SZ))

    # rich header
    rich_key = 0x9ABCDEF1
    pairs = [(125, 0x1690, 42), (101, 0x0A0A, 3), (129, 0x2710, 11)]
    plain = b'DanS' + b'\x11\x22\x33\x44' + b'\x55\x66\x77\x88' + b'\x99\xAA\xBB\xCC' + u32(rich_key)
    for prod, build, cnt in pairs:
        plain += u32((build << 16) | prod) + u32(cnt)
    enc = bytes(b ^ ((rich_key >> (8 * (i % 4))) & 0xFF) for i, b in enumerate(plain))
    rich = enc + b'Rich' + u32(rich_key)

    dos = bytearray(0x40)
    dos[0:2] = b'MZ'
    dos[0x3C:0x40] = u32(PE_OFF)
    stub = b'This program cannot be run in DOS mode.\r\r\n$'
    stub_area = bytearray(pad(b'\x20' + stub + b'\x20', 0x3C, b'\x00'))
    stub_area[0x00:0x0C] = b'\x0E\x1F\xBA\x0E\x00\xB4\x09\xCD\x21\xB8\x01\x4C'
    stub_area[0x0C:0x0E] = b'\xCD\x21'
    while len(stub_area) % 4:
        stub_area += b'\x00'
    rich_zone = stub_area + rich
    assert len(rich_zone) <= PE_OFF - 0x40
    rich_zone = pad(bytes(rich_zone), PE_OFF - 0x40)
    dos_image = dos + rich_zone

    # optional header PE32+
    timestamp = 1718900000
    dirs = [None] * 16
    dirs[0] = (RDATA_VA + export_off, 40)
    dirs[1] = (RDATA_VA + import_off, 40)
    dirs[2] = (RDATA_VA + res_off, len(res))
    dirs[3] = (0, 0)
    dirs[4] = None  # security set later
    dirs[5] = (0, 0)
    dirs[6] = (RDATA_VA + debug_off, 28)
    dirs[9] = (RDATA_VA + tls_off, 40)
    dirs[12] = (RDATA_VA + iat_k, 0x18)

    opt = bytearray()
    opt += u16(0x20B) + bytes([14, 29])
    opt += u32(TEXT_SZ) + u32(RDATA_SZ) + u32(0)
    opt += u32(0x1000) + u32(TEXT_VA)
    opt += u64(IMAGE_BASE)
    opt += u32(0x1000) + u32(0x200)
    opt += u16(6) + u16(1) + u16(0) + u16(0) + u16(6) + u16(1)
    opt += u32(0) + u32(0x4000) + u32(0x200)
    opt += u32(0)  # checksum placeholder
    opt += u16(3) + u16(0xC160)
    opt += u64(0x100000) + u64(0x1000) + u64(0x100000) + u64(0x1000)
    opt += u32(0) + u32(16)
    for i in range(16):
        r, s = dirs[i] if dirs[i] else (0, 0)
        opt += u32(r) + u32(s)
    assert len(opt) == 240

    coff = u16(0x8664) + u16(3) + u32(timestamp) + u32(0) + u32(0) + u16(240) + u16(0x0022)

    def sechdr(name, vsz, va, rsz, roff, chars):
        n = name.encode()[:8]
        n = n + b'\x00' * (8 - len(n))
        return n + u32(vsz) + u32(va) + u32(rsz) + u32(roff) + u32(0) + u32(0) + u16(0) + u16(0) + u32(chars)

    sec = sechdr('.text', TEXT_SZ, TEXT_VA, TEXT_SZ, TEXT_RAW, 0x60000020)
    sec += sechdr('.rdata', RDATA_SZ, RDATA_VA, RDATA_SZ, RDATA_RAW, 0x40000040)
    sec += sechdr('.data', DATA_SZ, DATA_VA, DATA_SZ, DATA_RAW, 0xC0000040)

    headers = dos_image + b'PE\x00\x00' + coff + bytes(opt) + sec
    headers = pad(headers, TEXT_RAW)

    # certificate table (standard WIN_CERTIFICATE layout)
    cert_body = bytes((i * 7 + 13) & 0xFF for i in range(96))
    cert = u32(8 + len(cert_body)) + u16(0x0200) + u16(0x0002) + cert_body
    cert_off = DATA_RAW + DATA_SZ

    img = bytearray()
    img += headers
    img += pad(bytes(text), TEXT_SZ)
    img += pad(bytes(rdata), RDATA_SZ)
    img += pad(bytes(data), DATA_SZ)
    assert len(img) == cert_off
    img += cert
    dirs[4] = (cert_off, len(cert))
    # re-splice security dir into optional header (index 4 => byte 112+4*8)
    secp = PE_OFF + 4 + 20 + 112 + 4 * 8
    img[secp:secp+8] = u32(cert_off) + u32(len(cert))

    # checksum
    ck_off = PE_OFF + 4 + 20 + 64
    saved = img[ck_off:ck_off+4]
    img[ck_off:ck_off+4] = b'\x00\x00\x00\x00'
    s = 0
    i = 0
    while i + 1 < len(img):
        s += img[i] | (img[i+1] << 8)
        s = (s & 0xFFFF) + (s >> 16)
        i += 2
    if len(img) & 1:
        s += img[-1]
        s = (s & 0xFFFF) + (s >> 16)
    s = (s & 0xFFFF) + (s >> 16)
    s = (s & 0xFFFF) + (s >> 16)
    ck = (s + len(img)) & 0xFFFFFFFF
    img[ck_off:ck_off+4] = u32(ck)

    path = os.path.join(OUT, "fixture_pe.exe")
    open(path, "wb").write(img)
    print("wrote", path, len(img), "bytes")
    return {
        "path": path,
        "md5": hashlib.md5(img).hexdigest(),
        "sha256": hashlib.sha256(img).hexdigest(),
        "size": len(img),
        "checksum": ck,
        "certOff": cert_off,
        "certLen": len(cert),
    }

# ---------------------------------------------------------------- helpers shared by zip builders

def make_zip_store(entries):
    """entries: list of (name, bytes). Returns raw zip with STORE method, and cd offset."""
    out = bytearray()
    central = bytearray()
    for name, data in entries:
        crc = zlib.crc32(data) & 0xFFFFFFFF
        off = len(out)
        out += b'PK\x03\x04' + u16(20) + u16(0) + u16(0) + u16(0) + u16(0) + u16(0)
        out += u32(crc) + u32(len(data)) + u32(len(data)) + u16(len(name)) + u16(0) + name + data
        central += b'PK\x01\x02' + u16(20) + u16(20) + u16(0) + u16(0) + u16(0) + u16(0)
        central += u32(crc) + u32(len(data)) + u32(len(data)) + u16(len(name)) + u16(0) + u16(0)
        central += u16(0) + u16(0) + u32(0) + u32(off) + name
    cd_off = len(out)
    out += central
    out += b'PK\x05\x06' + u16(0) + u16(0) + u16(len(entries)) + u16(len(entries))
    out += u32(len(central)) + u32(cd_off) + u16(0)
    return bytes(out), cd_off

def apk_signing_block(pair_ids):
    pairs = b''
    for pid in pair_ids:
        val = (b'VAL' + pid.to_bytes(4, 'little')) * 4
        pair = u64(8 + len(val)) + u64(pid) + val
        pairs += pair
    size = len(pairs) + 24
    blk = u64(size) + pairs + u64(size) + b'APK Sig Block 42'
    assert len(blk) == size + 8
    return blk


# ---------------------------------------------------------------- AXML builder

def build_axml():
    strings = [
        "",
        "http://schemas.android.com/apk/res/android",
        "manifest",
        "package",
        "android",
        "versionCode",
        "versionName",
        "platformBuildVersionCode",
        "uses-sdk",
        "minSdkVersion",
        "targetSdkVersion",
        "uses-permission",
        "name",
        "android.permission.INTERNET",
        "android.permission.CAMERA",
        "application",
        "label",
        "@string/app_name",
        "debuggable",
        "activity",
        "exported",
        "intent-filter",
        "action",
        "android.intent.action.MAIN",
        "category",
        "android.intent.category.LAUNCHER",
        "service",
        "com.example.fixture.MainActivity",
        "com.example.fixture.DataService",
        "com.example.fixture",
        "1.0.3",
        "usesCleartextTraffic",
    ]
    NS = 1
    def spool():
        data = b''
        offs = []
        for st in strings:
            offs.append(len(data))
            b = st.encode('utf-8')
            data += bytes([len(st) & 0x7F, len(b) & 0x7F]) + b + b'\x00'
        data = pad4(data)
        hdr = u16(0x0001) + u16(28) + u32(28 + 4 * len(strings) + len(data))
        hdr += u32(len(strings)) + u32(0) + u32(0x100) + u32(28 + 4 * len(strings)) + u32(0)
        return hdr + b''.join(u32(o) for o in offs) + data

    def el_start(tag_idx, ns_idx, attrs):
        sz = 36 + 20 * len(attrs)
        c = u16(0x0102) + u16(16) + u32(sz)
        c += u32(1) + u32(0xFFFFFFFF)
        c += u32(ns_idx) + u32(tag_idx)
        c += u16(20) + u16(20) + u16(len(attrs)) + u16(0) + u16(0) + u16(0)
        for (ans, aname, raw, dtype, data) in attrs:
            c += u32(ans) + u32(aname) + u32(raw) + u16(8) + b'\x00' + bytes([dtype]) + u32(data)
        return c

    def el_end(tag_idx, ns_idx):
        return u16(0x0103) + u16(16) + u32(24) + u32(1) + u32(0xFFFFFFFF) + u32(ns_idx) + u32(tag_idx)

    def ns_start():
        return u16(0x0100) + u16(16) + u32(24) + u32(1) + u32(0xFFFFFFFF) + u32(NS) + u32(4)

    def ns_end():
        return u16(0x0101) + u16(16) + u32(24) + u32(1) + u32(0xFFFFFFFF) + u32(NS) + u32(4)

    T_STR, T_INT, T_BOOL = 0x03, 0x10, 0x12
    idx = {s: i for i, s in enumerate(strings)}

    body = spool()
    body += ns_start()
    body += el_start(idx["manifest"], 0xFFFFFFFF, [
        (0xFFFFFFFF, idx["package"], idx["com.example.fixture"], T_STR, idx["com.example.fixture"]),
        (NS, idx["versionCode"], 0xFFFFFFFF, T_INT, 5),
        (NS, idx["versionName"], idx["1.0.3"], T_STR, idx["1.0.3"]),
        (NS, idx["platformBuildVersionCode"], 0xFFFFFFFF, T_INT, 33),
    ])
    body += el_start(idx["uses-sdk"], 0xFFFFFFFF, [
        (NS, idx["minSdkVersion"], 0xFFFFFFFF, T_INT, 21),
        (NS, idx["targetSdkVersion"], 0xFFFFFFFF, T_INT, 33),
    ])
    body += el_end(idx["uses-sdk"], 0xFFFFFFFF)
    for perm in ["android.permission.INTERNET", "android.permission.CAMERA"]:
        body += el_start(idx["uses-permission"], 0xFFFFFFFF, [
            (NS, idx["name"], idx[perm], T_STR, idx[perm]),
        ])
        body += el_end(idx["uses-permission"], 0xFFFFFFFF)
    body += el_start(idx["application"], 0xFFFFFFFF, [
        (NS, idx["label"], idx["@string/app_name"], T_STR, idx["@string/app_name"]),
        (NS, idx["debuggable"], 0xFFFFFFFF, T_BOOL, 1),
        (NS, idx["usesCleartextTraffic"], 0xFFFFFFFF, T_BOOL, 1),
    ])
    body += el_start(idx["activity"], 0xFFFFFFFF, [
        (NS, idx["name"], idx["com.example.fixture.MainActivity"], T_STR, idx["com.example.fixture.MainActivity"]),
        (NS, idx["exported"], 0xFFFFFFFF, T_BOOL, 1),
    ])
    body += el_start(idx["intent-filter"], 0xFFFFFFFF, [])
    body += el_start(idx["action"], 0xFFFFFFFF, [
        (NS, idx["name"], idx["android.intent.action.MAIN"], T_STR, idx["android.intent.action.MAIN"]),
    ])
    body += el_end(idx["action"], 0xFFFFFFFF)
    body += el_start(idx["category"], 0xFFFFFFFF, [
        (NS, idx["name"], idx["android.intent.category.LAUNCHER"], T_STR, idx["android.intent.category.LAUNCHER"]),
    ])
    body += el_end(idx["category"], 0xFFFFFFFF)
    body += el_end(idx["intent-filter"], 0xFFFFFFFF)
    body += el_end(idx["activity"], 0xFFFFFFFF)
    body += el_start(idx["service"], 0xFFFFFFFF, [
        (NS, idx["name"], idx["com.example.fixture.DataService"], T_STR, idx["com.example.fixture.DataService"]),
        (NS, idx["exported"], 0xFFFFFFFF, T_BOOL, 0),
    ])
    body += el_end(idx["service"], 0xFFFFFFFF)
    body += el_end(idx["application"], 0xFFFFFFFF)
    body += el_end(idx["manifest"], 0xFFFFFFFF)
    body += ns_end()

    return u16(0x0003) + u16(8) + u32(8 + len(body)) + body


# ---------------------------------------------------------------- DEX builder

def build_dex():
    strs = [
        "Lcom/example/fixture/MainActivity;",
        "Landroid/app/Activity;",
        "Ljava/lang/Object;",
        "Lcom/example/fixture/DataService;",
        "Lcom/example/fixture/BuildConfig;",
        "Ljava/lang/String;",
        "V",
        "I",
        "L",
        "LI;",
        "<init>",
        "onCreate",
        "helper",
        "MainActivity.java",
        "DataService.java",
        "BuildConfig.java",
    ]
    strmap = {s: i for i, s in enumerate(strs)}

    string_data = b''
    str_offs = []
    for st in strs:
        str_offs.append(len(string_data))
        b = st.encode('utf-8')
        string_data += bytes([len(st) & 0x7F]) + b + b'\x00'
    string_data = pad4(string_data)

    types = [strmap[s] for s in [
        "Lcom/example/fixture/MainActivity;", "Landroid/app/Activity;", "Ljava/lang/Object;",
        "Lcom/example/fixture/DataService;", "Lcom/example/fixture/BuildConfig;",
        "Ljava/lang/String;", "V", "I", "L", "LI;",
    ]]
    typemap = {t: i for i, t in enumerate(types)}

    protos = [
        (strmap["V"], typemap[6], 0),
        (strmap["L"], typemap[6], 0),
        (strmap["LI;"], typemap[7], 0),
    ]

    fields = [
        (typemap[0], typemap[5], strmap["helper"]),
    ]

    methods = [
        (typemap[0], 0, strmap["<init>"]),
        (typemap[0], 1, strmap["onCreate"]),
        (typemap[2], 0, strmap["<init>"]),
        (typemap[3], 0, strmap["<init>"]),
        (typemap[4], 0, strmap["<init>"]),
    ]

    class_defs = [
        (typemap[0], 0x0001, typemap[1], strmap["MainActivity.java"]),
        (typemap[3], 0x0001, typemap[2], strmap["DataService.java"]),
        (typemap[4], 0x0011, typemap[2], strmap["BuildConfig.java"]),
    ]

    header_size = 0x70
    string_ids_off = header_size
    type_ids_off = string_ids_off + 4 * len(strs)
    proto_off = type_ids_off + 4 * len(types)
    field_off = proto_off + 12 * len(protos)
    method_off = field_off + 8 * len(fields)
    class_off = method_off + 8 * len(methods)
    data_off = class_off + 32 * len(class_defs)
    total = data_off + len(string_data)

    hdr = bytearray(0x70)
    hdr[0:8] = b'dex\n035\x00'
    struct.pack_into('<I', hdr, 32, total)
    struct.pack_into('<I', hdr, 36, 0x70)
    struct.pack_into('<I', hdr, 40, 0x12345678)
    struct.pack_into('<II', hdr, 56, len(strs), string_ids_off)
    struct.pack_into('<II', hdr, 64, len(types), type_ids_off)
    struct.pack_into('<II', hdr, 72, len(protos), proto_off)
    struct.pack_into('<II', hdr, 80, len(fields), field_off)
    struct.pack_into('<II', hdr, 88, len(methods), method_off)
    struct.pack_into('<II', hdr, 96, len(class_defs), class_off)
    struct.pack_into('<II', hdr, 104, total - data_off, data_off)

    out = bytearray()
    out += hdr
    for o in str_offs:
        out += u32(data_off + o)
    for t in types:
        out += u32(t)
    for shorty, rt, po in protos:
        out += u32(shorty) + u32(rt) + u32(po)
    for cls, ty, nm in fields:
        out += u16(cls) + u16(ty) + u32(nm)
    for cls, pr, nm in methods:
        out += u16(cls) + u16(pr) + u32(nm)
    for cls, acc, sup, src in class_defs:
        out += u32(cls) + u32(acc) + u32(sup) + u32(0) + u32(src) + u32(0) + u32(0) + u32(0)
    out += string_data
    assert len(out) == total, (len(out), total)

    sig = hashlib.sha1(bytes(out[32:])).digest()
    out[12:32] = sig
    ck = zlib.adler32(bytes(out[12:])) & 0xFFFFFFFF
    struct.pack_into('<I', out, 8, ck)
    return bytes(out)


# ---------------------------------------------------------------- APK + ZIP + class fixtures

def make_zip_mixed(entries):
    out = bytearray()
    central = bytearray()
    for name, data, method in entries:
        crc = zlib.crc32(data) & 0xFFFFFFFF
        off = len(out)
        cdata = raw_deflate(data) if method == 8 else data
        out += b'PK\x03\x04' + u16(20) + u16(0x800) + u16(method) + u16(0) + u16(0x482B)
        out += u32(crc) + u32(len(cdata)) + u32(len(data)) + u16(len(name)) + u16(0) + name + cdata
        central += b'PK\x01\x02' + u16(20) + u16(20) + u16(0x800) + u16(method) + u16(0) + u16(0x482B)
        central += u32(crc) + u32(len(cdata)) + u32(len(data)) + u16(len(name)) + u16(0) + u16(0)
        central += u16(0) + u16(0) + u32(0) + u32(off) + name
    cd_off = len(out)
    out += central
    out += b'PK\x05\x06' + u16(0) + u16(0) + u16(len(entries)) + u16(len(entries))
    out += u32(len(central)) + u32(cd_off) + u16(0)
    return bytes(out), cd_off


def build_apk2():
    manifest = build_axml()
    dex = build_dex()
    so_bytes = bytes((i * 13 + 7) & 0xFF for i in range(2048))
    entries = [
        (b"AndroidManifest.xml", manifest, 8),
        (b"classes.dex", dex, 0),
        (b"resources.arsc", bytes(range(256)) * 4, 0),
        (b"META-INF/MANIFEST.MF", b"Manifest-Version: 1.0\r\nBuilt-By: codebreak-fixture\r\n\r\n", 8),
        (b"META-INF/CERT.SF", b"Signature-File: fixture\r\n\r\n", 8),
        (b"META-INF/CERT.RSA", bytes((i * 31 + 11) & 0xFF for i in range(512)), 0),
        (b"lib/arm64-v8a/libfixture.so", so_bytes, 0),
        (b"lib/x86_64/libfixture.so", so_bytes, 0),
        (b"assets/data/config.json", b'{"debug": true, "level": 42, "url": "http://example.com/api"}', 8),
    ]
    local = bytearray()
    central = bytearray()
    offsets = []
    for name, data, method in entries:
        crc = zlib.crc32(data) & 0xFFFFFFFF
        cdata = raw_deflate(data) if method == 8 else data
        offsets.append(len(local))
        local += b'PK\x03\x04' + u16(20) + u16(0x800) + u16(method) + u16(0) + u16(0x482B)
        local += u32(crc) + u32(len(cdata)) + u32(len(data)) + u16(len(name)) + u16(0) + name + cdata
    for (name, data, method), off in zip(entries, offsets):
        crc = zlib.crc32(data) & 0xFFFFFFFF
        cdata = raw_deflate(data) if method == 8 else data
        central += b'PK\x01\x02' + u16(20) + u16(20) + u16(0x800) + u16(method) + u16(0) + u16(0x482B)
        central += u32(crc) + u32(len(cdata)) + u32(len(data)) + u16(len(name)) + u16(0) + u16(0)
        central += u16(0) + u16(0) + u32(0) + u32(off) + name
    sig = apk_signing_block([0x7109871a, 0x42726577])
    cd_off = len(local) + len(sig)
    apk = bytes(local) + sig + bytes(central)
    apk += b'PK\x05\x06' + u16(0) + u16(0) + u16(len(entries)) + u16(len(entries))
    apk += u32(len(central)) + u32(cd_off) + u16(0)
    path = os.path.join(OUT, "fixture_app.apk")
    open(path, "wb").write(apk)
    print("wrote", path, len(apk), "bytes")


def build_plain_zip():
    entries = [
        (b"readme.txt", b"CodeBreak plain zip fixture\n" + b"line of text\n" * 40, 8),
        (b"bin/blob.bin", bytes((i * 7) & 0xFF for i in range(4096)), 0),
        (b"src/", b"", 0),
        (b"src/main.c", b"int main(void) { return 42; }\n", 8),
    ]
    data, _ = make_zip_mixed(entries)
    path = os.path.join(OUT, "fixture_plain.zip")
    open(path, "wb").write(data)
    print("wrote", path, len(data), "bytes")


def build_java_class():
    def utf8(s):
        b = s.encode()
        return bytes([1]) + be16(len(b)) + b
    def klass(n):
        return bytes([7]) + be16(n)
    cp = b''
    cp += utf8("com/fixture/FixtureClass")          # 1
    cp += klass(1)                                    # 2  this
    cp += utf8("java/lang/Object")                    # 3
    cp += klass(3)                                    # 4  super
    cp += utf8("fixtureValue")                        # 5
    cp += utf8("I")                                   # 6
    cp += bytes([9]) + be16(2) + be16(6)              # 7  fieldref
    cp += utf8("<init>")                              # 8
    cp += utf8("()V")                                 # 9
    cp += bytes([10]) + be16(2) + be16(9)             # 10 methodref
    cp += utf8("CodeBreak was here")                  # 11
    cp_count = 12
    out = b'\xCA\xFE\xBA\xBE' + be16(0) + be16(52) + be16(cp_count) + cp
    out += be16(0x0021)
    out += be16(2) + be16(4)
    out += be16(0)
    out += be16(1)
    out += be16(0x0002) + be16(5) + be16(6) + be16(0)
    out += be16(1)
    out += be16(0x0001) + be16(8) + be16(9) + be16(0)
    out += be16(0)
    path = os.path.join(OUT, "FixtureClass.class")
    open(path, "wb").write(out)
    print("wrote", path, len(out), "bytes")


def build_elf():
    src = b'#include <stdio.h>\nstatic const char* msg = "codebreak elf fixture";\nint helper(int x) { return x * 2 + 1; }\nint main(void) { printf("%s %d\\n", msg, helper(21)); return 0; }\n'
    import subprocess, tempfile
    with tempfile.TemporaryDirectory() as td:
        c = os.path.join(td, "f.c")
        o = os.path.join(td, "f")
        open(c, "wb").write(src)
        subprocess.run(["gcc", "-o", o, c], check=True)
        data = open(o, "rb").read()
    path = os.path.join(OUT, "fixture_elf64")
    open(path, "wb").write(data)
    print("wrote", path, len(data), "bytes")


def build_gzip():
    import struct, zlib
    payload = b"codebreak gzip fixture payload with a filename and comment.\n" * 4
    co = zlib.compressobj(9, zlib.DEFLATED, -15)
    body = co.compress(payload) + co.flush()
    fname = b"fixture_payload.bin"
    hdr = b"\x1f\x8b\x08\x08" + struct.pack("<I", 1650000000) + b"\x00\xff" + fname + b"\x00"
    tail = struct.pack("<II", zlib.crc32(payload) & 0xFFFFFFFF, len(payload))
    data = hdr + body + tail
    path = os.path.join(OUT, "fixture_data.gz")
    open(path, "wb").write(data)
    print("wrote", path, len(data), "bytes")


def build_tar():
    import tarfile, io
    data = b"tar member text payload for codebreak.\n"
    buf = io.BytesIO()
    with tarfile.open(fileobj=buf, mode="w") as t:
        ti = tarfile.TarInfo("src/lib.c")
        ti.size = len(data)
        t.addfile(ti, io.BytesIO(data))
        ti2 = tarfile.TarInfo("scripts/run.sh")
        sh = b"#!/bin/sh\necho codebreak\n"
        ti2.size = len(sh)
        t.addfile(ti2, io.BytesIO(sh))
    path = os.path.join(OUT, "fixture_bundle.tar")
    open(path, "wb").write(buf.getvalue())
    print("wrote", path, buf.tell(), "bytes")


def build_pdf():
    header = b"%PDF-1.7\n%\xe2\xe3\xcf\xd3\n"
    objs = [
        b"1 0 obj\n<< /Type /Catalog /Pages 2 0 R >>\nendobj\n",
        b"2 0 obj\n<< /Type /Pages /Kids [3 0 R] /Count 1 >>\nendobj\n",
        b"3 0 obj\n<< /Type /Page /Parent 2 0 R >>\nendobj\n",
        b"4 0 obj\n<< /Length 33 >>\nstream\nBT /F1 12 Tf (codebreak pdf) Tj ET\nendstream\nendobj\n",
    ]
    trailer = b"trailer\n<< /Size 5 /Root 1 0 R >>\n%%EOF\n"
    data = header + b"".join(objs) + trailer
    path = os.path.join(OUT, "fixture_doc.pdf")
    open(path, "wb").write(data)
    print("wrote", path, len(data), "bytes")


def build_ole():
    from cfbwriter import stream, storage, serialize
    word = stream("WordDocument", b"\x00" * 256 + b"codebreak-legacy-word-document" * 20)
    compobj = stream("\x01CompObj", b"\xfe\xff\x00\x00" + b"\x0a\x00" + b"MSWordDoc" + b"\x00" * 48)
    docsumm = stream("\x05DocumentSummaryInformation", b"\x00" * 4096)
    summ = stream("\x05SummaryInformation", b"\x00" * 4096)
    vba = storage("VBA", [
        stream("ThisDocument", b"\x43\x43" * 60),
        stream("_VBA_PROJECT", b"ID={00000000-0000-0000-0000-000000000000}\nDocument=ThisDocument\n"),
        stream("dir", b"base64-encoded-vba-source-here\n"),
        stream("__SRP_0", b"project-storage"),
        stream("__SRP_3", b"project-storage"),
        stream("PROJECT", b"Project=ThisDocument\nClass=ThisDocument\n"),
    ])
    macros = storage("Macros", [vba])
    path = os.path.join(OUT, "fixture_macro.doc")
    serialize([word, compobj, docsumm, summ, macros], path)
    print("wrote", path, os.path.getsize(path), "bytes")


def build_pkcs7():
    import subprocess, tempfile
    with tempfile.TemporaryDirectory() as td:
        cfg = os.path.join(td, "cfg.cnf")
        open(cfg, "w").write(
            "[req]\ndistinguished_name=dn\nprompt=no\n"
            "[dn]\nC=TR\nO=CodeBreak Test Labs\nOU=Signing\nCN=CodeBreak Fixture Signer\n"
            "emailAddress=dev@codebreak.local\n")
        key = os.path.join(td, "k.pem")
        cert = os.path.join(td, "cert.pem")
        payload = os.path.join(td, "payload.bin")
        open(payload, "wb").write(b"codebreak signed payload\n" * 2)
        subprocess.run(["openssl", "req", "-x509", "-newkey", "rsa:2048", "-nodes",
                        "-days", "30", "-keyout", key, "-out", cert,
                        "-config", cfg], check=True, capture_output=True)
        out = os.path.join(OUT, "fixture_signature.p7")
        subprocess.run(["openssl", "cms", "-sign", "-in", payload, "-signer", cert,
                        "-inkey", key, "-outform", "DER", "-out", out], check=True, capture_output=True)
        print("wrote", out, os.path.getsize(out), "bytes")


def build_signed_pe():
    pe_path = os.path.join(OUT, "fixture_pe.exe")
    p7_path = os.path.join(OUT, "fixture_signature.p7")
    img = bytearray(open(pe_path, "rb").read())
    p7 = open(p7_path, "rb").read()
    while len(img) % 8:
        img += b"\x00"
    cert_off = len(img)
    dwlen = 8 + len(p7)
    dwlen = (dwlen + 7) & ~7
    cert = bytearray(u32(dwlen) + u16(0x0200) + u16(0x0002))
    cert += p7
    while len(cert) < dwlen:
        cert += b"\x00"
    assert len(cert) == dwlen
    img += cert
    PE_OFF = 0x100
    secp = PE_OFF + 4 + 20 + 112 + 4 * 8
    img[secp:secp + 8] = u32(cert_off) + u32(len(cert))
    ck_off = PE_OFF + 4 + 20 + 64
    img[ck_off:ck_off + 4] = b"\x00\x00\x00\x00"
    s = 0
    i = 0
    while i + 1 < len(img):
        s += img[i] | (img[i + 1] << 8)
        s = (s & 0xFFFF) + (s >> 16)
        i += 2
    if len(img) & 1:
        s += img[-1]
        s = (s & 0xFFFF) + (s >> 16)
    s = (s & 0xFFFF) + (s >> 16)
    s = (s & 0xFFFF) + (s >> 16)
    img[ck_off:ck_off + 4] = u32((s + len(img)) & 0xFFFFFFFF)
    path = os.path.join(OUT, "fixture_signed.exe")
    open(path, "wb").write(img)
    print("wrote", path, len(img), "bytes")
    return path


if __name__ == "__main__":
    import sys
    which = sys.argv[1] if len(sys.argv) > 1 else "all"
    if which in ("all", "pe"):
        build_pe()
    if which in ("all", "apk"):
        build_apk2()
    if which in ("all", "zip"):
        build_plain_zip()
    if which in ("all", "class"):
        build_java_class()
    if which in ("all", "elf"):
        build_elf()
    if which in ("all", "gzip"):
        build_gzip()
    if which in ("all", "tar"):
        build_tar()
    if which in ("all", "pdf"):
        build_pdf()
    if which in ("all", "ole"):
        build_ole()
    if which in ("all", "pkcs7"):
        build_pkcs7()
    if which in ("all", "signedpe"):
        build_signed_pe()
