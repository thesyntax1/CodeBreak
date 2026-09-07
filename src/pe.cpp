#include "pe.h"
#include "jsonw.h"
#include "util.h"
#include "x509.h"
#include <cstring>
#include <cmath>

namespace cb {

bool looksLikePe(const uint8_t* d, size_t n) {
    if (n < 0x40) return false;
    Rd r(d, n);
    if (r.u16() != 0x5A4D) return false;
    r.seek(0x3C);
    uint32_t off = r.u32();
    if (!r.ok() || off < 0x40 || off + 24 > n) return false;
    return d[off] == 'P' && d[off + 1] == 'E' && d[off + 2] == 0 && d[off + 3] == 0;
}

static const char* machineName(uint16_t m) {
    switch (m) {
    case 0x014C: return "x86";
    case 0x8664: return "x86-64";
    case 0x01C0: return "ARM";
    case 0x01C2: return "ARM Thumb-2";
    case 0x01C4: return "ARMv7 Thumb-2";
    case 0xAA64: return "ARM64";
    case 0x0200: return "Itanium 64";
    case 0x0EBC: return "EFI Byte Code";
    case 0x5064: return "RISC-V 64";
    case 0x0290: return "PowerPC";
    case 0x0266: return "MIPS 16";
    case 0x0166: return "R4000 MIPS";
    default: return nullptr;
    }
}

static const char* subsystemName(uint16_t s) {
    switch (s) {
    case 1: return "Native";
    case 2: return "Windows GUI";
    case 3: return "Windows Console";
    case 5: return "OS/2 Console";
    case 7: return "POSIX Console";
    case 8: return "Native Windows 9x driver";
    case 9: return "Windows CE GUI";
    case 10: return "EFI Application";
    case 11: return "EFI Boot Service Driver";
    case 12: return "EFI Runtime Driver";
    case 13: return "EFI ROM";
    case 14: return "Xbox";
    case 16: return "Windows Boot Application";
    default: return nullptr;
    }
}

static void flagNames(std::vector<std::string>& out, uint32_t v, const uint32_t* bits, const char** names, size_t count) {
    for (size_t i = 0; i < count; i++) if (v & bits[i]) out.push_back(names[i]);
}

static const uint32_t coffBits[] = { 0x0001,0x0002,0x0004,0x0008,0x0010,0x0020,0x0080,0x0100,0x0200,0x0400,0x0800,0x1000,0x2000,0x4000,0x8000 };
static const char* coffNames[] = { "RELOCS_STRIPPED","EXECUTABLE_IMAGE","LINE_NUMS_STRIPPED","LOCAL_SYMS_STRIPPED","AGGRESSIVE_WS_TRIM","LARGE_ADDRESS_AWARE","BYTES_REVERSED_LO","32BIT_MACHINE","DEBUG_STRIPPED","REMOVABLE_RUN_FROM_SWAP","NET_RUN_FROM_SWAP","SYSTEM","DLL","UP_SYSTEM_ONLY","BYTES_REVERSED_HI" };

static const uint32_t dllCharBits[] = { 0x0020,0x0040,0x0080,0x0100,0x0200,0x0400,0x0800,0x1000,0x2000,0x4000,0x8000 };
static const char* dllCharNames[] = { "HIGH_ENTROPY_VA","DYNAMIC_BASE (ASLR)","FORCE_INTEGRITY","NX_COMPAT (DEP)","NO_ISOLATION","NO_SEH","NO_BIND","APPCONTAINER","WDM_DRIVER","GUARD_CF (CFG)","TERMINAL_SERVER_AWARE" };

static const uint32_t secCharBits[] = { 0x00000020,0x00000040,0x00000080,0x00000100,0x00000200,0x00000800,0x00001000,0x00008000,0x00010000,0x01000000,0x02000000,0x04000000,0x08000000,0x10000000,0x20000000,0x40000000,0x80000000 };
static const char* secCharNames[] = { "CNT_CODE","CNT_INITIALIZED_DATA","CNT_UNINITIALIZED_DATA","LNK_OTHER","LNK_INFO","LNK_REMOVE","LNK_COMDAT","GPREL","MEM_16BIT","LNK_NRELOC_OVFL","MEM_DISCARDABLE","MEM_NOT_CACHED","MEM_NOT_PAGED","MEM_SHARED","MEM_EXECUTE","MEM_READ","MEM_WRITE" };

static const char* dirNames[16] = { "Export","Import","Resource","Exception","Security","BaseReloc","Debug","Architecture","GlobalPtr","TLS","LoadConfig","BoundImport","IAT","DelayImport","CLR Runtime Header","Reserved" };

static const char* resTypeNames[25] = { "", "Cursor","Bitmap","Icon","Menu","Dialog","StringTable","FontDir","Font","Accelerator","RCData","MessageTable","GroupCursor","","GroupIcon","","Version","","HTML","Manifest" };
static const char* resTypeName(uint32_t id) {
    if (id == 0) return nullptr;
    if (id == 23) return "HTML";
    if (id == 24) return "Manifest";
    if (id < 25) return resTypeNames[id];
    return nullptr;
}

static const char* debugTypeName(uint32_t t) {
    switch (t) {
    case 1: return "COFF symbols";
    case 2: return "CodeView (PDB)";
    case 3: return "FPO";
    case 4: return "Misc";
    case 5: return "Exception";
    case 6: return "Fixup";
    case 7: return "OMAP to source";
    case 8: return "OMAP from source";
    case 9: return "Borland";
    case 11: return "CLSID";
    case 12: return "VC Feature";
    case 13: return "POGO";
    case 14: return "ILTCG";
    case 15: return "MPX";
    case 16: return "REPRO";
    default: return nullptr;
    }
}

static const char* richToolEra(uint32_t prodId) {
    if (prodId == 101) return "MASM";
    if (prodId >= 80 && prodId <= 99) return "MSVC 6.x-7.x era";
    if (prodId >= 100 && prodId <= 109) return "MSVC 8.0-9.0 era (VS2005/2008)";
    if (prodId >= 110 && prodId <= 111) return "MSVC 10.0 (VS2010)";
    if (prodId >= 112 && prodId <= 117) return "MSVC 11.0-12.0 (VS2012/2013)";
    if (prodId >= 118 && prodId <= 123) return "MSVC 14.0 (VS2015)";
    if (prodId >= 124 && prodId <= 127) return "MSVC 14.1x (VS2017)";
    if (prodId >= 128 && prodId <= 131) return "MSVC 14.2x (VS2019)";
    if (prodId >= 132 && prodId <= 139) return "MSVC 14.3x (VS2022)";
    return nullptr;
}

struct Sec {
    std::string name;
    uint32_t vsize = 0, va = 0, rsize = 0, roff = 0, chars = 0;
    double entropy = 0.0;
};

struct PeCtx {
    const uint8_t* d;
    size_t n;
    PeSummary sum;
    std::vector<Sec> secs;
    std::vector<std::string> notes;
    uint64_t imageBase = 0;
    bool plus = false;
    uint32_t sizeOfHeaders = 0;
    uint32_t dirs[16][2] = {{0}};

    int64_t offOf(uint32_t rva) const { return sum.rvaMap.toOff(rva); }

    std::string strAt(uint32_t rva, size_t cap = 4096) {
        int64_t o = offOf(rva);
        if (o < 0) return std::string();
        return readCStrAt(d, n, (size_t)o, cap);
    }

    std::string strOff(int64_t o, size_t cap = 4096) {
        if (o < 0) return std::string();
        return readCStrAt(d, n, (size_t)o, cap);
    }

    void note(const std::string& s) { if (notes.size() < 64) notes.push_back(s); }
};

static void writeStrFlags(Builder& b, const char* key, uint32_t v, const uint32_t* bits, const char** names, size_t count) {
    std::vector<std::string> f;
    flagNames(f, v, bits, names, count);
    b.arr(key);
    for (auto& s : f) b.valStr(s);
    b.endArr();
    b.kvHex("flagsRaw", v, 8);
}

struct ViParser {
    const uint8_t* d;
    size_t n;
    std::vector<std::pair<std::string, std::string>> strings;
    std::vector<std::pair<std::string, uint32_t>> vars;
    bool hasFixed = false;
    uint32_t fileVerMS = 0, fileVerLS = 0, prodVerMS = 0, prodVerLS = 0, fileType = 0, fileOS = 0, fileFlags = 0;
    std::string err;

    ViParser(const uint8_t* dd, size_t nn) : d(dd), n(nn) {}

    size_t align4(size_t v) { return (v + 3) & ~(size_t)3; }

    bool readNode(size_t off, size_t end, std::string& keyOut, uint16_t& typeOut, size_t& valueOff, size_t& valueLen, size_t& valueEnd) {
        if (off + 6 > end || off + 6 > n) { err = "bounds"; return false; }
        Rd r(d, n, off);
        uint16_t valueLenWords = r.u16();
        typeOut = r.u16();
        std::vector<uint16_t> w;
        while (r.o + 2 <= n) {
            uint16_t ch = r.u16();
            if (ch == 0) break;
            if (w.size() > 512) { err = "key too long"; return false; }
            w.push_back(ch);
        }
        if (r.err) { err = "bounds"; return false; }
        keyOut = wideToUtf8(w.data(), w.size());
        size_t vstart = align4(r.o);
        size_t bytes = typeOut == 1 ? (size_t)valueLenWords * 2 : (size_t)valueLenWords;
        valueOff = vstart;
        valueLen = bytes;
        valueEnd = vstart + bytes;
        return true;
    }

    void parse(size_t off, size_t end, int depth, const std::string& expectKey) {
        if (depth > 5) return;
        std::string key;
        uint16_t type;
        size_t vOff, vLen, vEnd;
        if (!readNode(off, end, key, type, vOff, vLen, vEnd)) return;
        size_t childrenStart = align4(vEnd);
        if (depth == 0) {
            if (vLen >= 52 && vOff + 52 <= n) {
                Rd f(d, n, vOff);
                uint32_t sig = f.u32();
                f.u32();
                fileVerMS = f.u32(); fileVerLS = f.u32(); prodVerMS = f.u32(); prodVerLS = f.u32();
                f.u32();
                fileFlags = f.u32(); fileOS = f.u32(); fileType = f.u32();
                hasFixed = sig == 0xFEEF04BDu;
            }
        } else if (expectKey == "StringFileInfo") {
            return;
        }
        if (key == "StringFileInfo" || key == "VarFileInfo" || key == "VS_VERSION_INFO" || (depth == 2 && !key.empty() && key.size() == 8 && key.find_first_not_of("0123456789abcdefABCDEF") == std::string::npos)) {
            size_t cur = childrenStart;
            while (cur + 8 <= end && cur < n) {
                size_t childEnd = end;
                size_t nxt = parseChild(cur, childEnd, depth + 1);
                if (nxt <= cur) break;
                cur = align4(nxt);
            }
        }
    }

    size_t parseChild(size_t off, size_t end, int depth) {
        std::string key;
        uint16_t type;
        size_t vOff, vLen, vEnd;
        if (!readNode(off, end, key, type, vOff, vLen, vEnd)) return 0;
        if (key == "StringFileInfo" || key == "VarFileInfo") {
            size_t cur = align4(vEnd);
            while (cur + 8 <= end && cur < n) {
                size_t nxt = parseChild(cur, end, depth + 1);
                if (nxt <= cur) break;
                cur = align4(nxt);
            }
            return cur > off ? cur : align4(vEnd);
        }
        if (depth == 2 && key.size() == 8 && key.find_first_not_of("0123456789abcdefABCDEF") == std::string::npos) {
            size_t cur = align4(vEnd);
            while (cur + 8 <= end && cur < n) {
                size_t nxt = parseChild(cur, end, depth + 1);
                if (nxt <= cur) break;
                cur = align4(nxt);
            }
            return cur > off ? cur : align4(vEnd);
        }
        if (type == 1 && vLen % 2 == 0 && vOff + vLen <= n) {
            std::string val = wideToUtf8((const uint16_t*)(d + vOff), vLen / 2);
            if (!key.empty()) strings.push_back({ key, val });
        } else if (key == "Translation" && vLen == 4 && vOff + 4 <= n) {
            vars.push_back({ "Translation", (uint32_t)d[vOff] | ((uint32_t)d[vOff + 1] << 8) | ((uint32_t)d[vOff + 2] << 16) | ((uint32_t)d[vOff + 3] << 24) });
        }
        return align4(vEnd);
    }
};

struct ResWalker {
    PeCtx& c;
    Builder& b;
    uint32_t base = 0;
    uint32_t versionRva = 0, versionSize = 0;
    uint32_t manifestRva = 0, manifestSize = 0;
    int nodeBudget = 40000;
    ResWalker(PeCtx& cc, Builder& bb) : c(cc), b(bb) {}
    bool fail = false;

    std::string resNameString(uint32_t nameField, uint32_t& idOut) {
        if (nameField & 0x80000000u) {
            int64_t o = c.offOf(base + (nameField & 0x7FFFFFFFu));
            if (o >= 0 && o + 2 <= (int64_t)c.n) {
                Rd r(c.d, c.n, (size_t)o);
                uint16_t len = r.u16();
                if (len <= 512 && r.o + (size_t)len * 2 <= c.n) {
                    const uint8_t* p = r.take((size_t)len * 2);
                    if (p) return wideToUtf8((const uint16_t*)p, len);
                }
            }
            idOut = nameField & 0x7FFFFFFFu;
            return hexU(nameField, 8);
        }
        idOut = nameField;
        return std::string();
    }

    void walkDir(uint32_t rva, int level, uint32_t typeId) {
        if (--nodeBudget < 0) { fail = true; return; }
        int64_t o = c.offOf(rva);
        if (o < 0 || (size_t)o + 16 > c.n) { c.note("resource directory at " + hexU(rva) + " out of bounds"); return; }
        Rd r(c.d, c.n, (size_t)o);
        r.u32(); r.u32(); r.u16(); r.u16();
        uint16_t named = r.u16(), ids = r.u16();
        if (r.err || (size_t)named + ids > 4096) { c.note("resource entry count invalid"); return; }
        size_t after = r.o + (size_t)(named + ids) * 8;
        std::vector<std::pair<uint32_t, uint32_t>> entries;
        Rd r2(c.d, c.n, r.o);
        for (uint32_t i = 0; i < (uint32_t)named + ids && r2.ok(); i++) {
            uint32_t nameF = r2.u32();
            uint32_t offF = r2.u32();
            if (nameF || offF) entries.push_back({ nameF, offF });
        }
        if (r2.err) { c.note("resource entries truncated"); return; }
        for (auto& e : entries) {
            if (fail) return;
            uint32_t id = 0;
            std::string nameStr = resNameString(e.first, id);
            if (e.second & 0x80000000u) {
                if (level == 0) {
                    b.beginObj();
                    const char* tn = resTypeName(id);
                    b.kv("id", (uint64_t)id);
                    b.kv("name", tn ? tn : (nameStr.empty() ? hexU(id, 8) : nameStr));
                    b.arr("names");
                    walkDir(base + (e.second & 0x7FFFFFFFu), 1, id);
                    b.endArr();
                    b.endObj();
                } else if (level == 1) {
                    b.beginObj();
                    b.kv("id", (uint64_t)id);
                    b.kv("name", nameStr.empty() ? hexU(id, 8) : nameStr);
                    b.arr("languages");
                    walkDir(base + (e.second & 0x7FFFFFFFu), 2, typeId);
                    b.endArr();
                    b.endObj();
                }
            } else {
                if (level != 2) continue;
                int64_t lo = c.offOf(base + e.second);
                if (lo < 0 || (size_t)lo + 16 > c.n) { c.note("resource data entry out of bounds"); continue; }
                Rd lr(c.d, c.n, (size_t)lo);
                uint32_t dataRva = lr.u32(), size = lr.u32(), codePage = lr.u32();
                lr.u32();
                int64_t doff = c.offOf(dataRva);
                b.beginObj();
                b.kv("lang", (uint64_t)id);
                b.kv("codePage", (uint64_t)codePage);
                b.kv("rva", (uint64_t)dataRva);
                b.kv("offset", doff >= 0 ? (uint64_t)doff : (uint64_t)0);
                b.kv("size", (uint64_t)size);
                b.endObj();
                if (typeId == 16 && versionRva == 0 && doff >= 0) { versionRva = dataRva; versionSize = size; }
                if (typeId == 24 && manifestRva == 0 && doff >= 0) { manifestRva = dataRva; manifestSize = size; }
            }
        }
        (void)after;
    }
};

static uint32_t computePeChecksum(const uint8_t* d, size_t n, size_t ckOff) {
    uint64_t sum = 0;
    size_t i = 0;
    while (i + 1 < n) {
        if (i != ckOff && i != ckOff + 2) {
            sum += (uint64_t)((uint32_t)d[i] | ((uint32_t)d[i + 1] << 8));
            sum = (sum & 0xFFFF) + (sum >> 16);
        }
        i += 2;
    }
    if (n & 1 && n - 1 != ckOff && n - 1 != ckOff + 2) {
        sum += d[n - 1];
        sum = (sum & 0xFFFF) + (sum >> 16);
    }
    sum = (sum & 0xFFFF) + (sum >> 16);
    sum = (sum & 0xFFFF) + (sum >> 16);
    return (uint32_t)(sum + n);
}

PeSummary peParse(const uint8_t* d, size_t n, Builder& b) {
    PeCtx c;
    c.d = d;
    c.n = n;
    c.sum.isPe = true;

    Rd dos(d, n);
    dos.skip(0x3C);
    uint32_t peOff = dos.u32();
    dos.seek(0x40);
    std::string dosStub;
    if (peOff > 0x40 && peOff <= n) {
        size_t lim = std::min((size_t)peOff, n);
        std::string raw = utf8Sanitize(d + 0x40, lim - 0x40);
        size_t cut = raw.size() > 200 ? 200 : raw.size();
        dosStub = raw.substr(0, cut);
    }

    Rd nt(d, n, peOff);
    nt.u32();
    uint16_t machine = nt.u16();
    uint16_t nsec = nt.u16();
    uint32_t ts = nt.u32();
    nt.u32(); nt.u32();
    uint16_t sizeOpt = nt.u16();
    uint16_t coffChars = nt.u16();

    c.sum.is64 = true;
    uint16_t magic = 0;
    if (sizeOpt >= 2) magic = nt.u16();
    if (magic != 0x20B) { c.sum.is64 = false; }
    c.plus = magic == 0x20B;
    if (magic != 0x10B && magic != 0x20B) {
        c.note("unknown optional header magic " + hexU(magic, 4) + ", assuming PE32");
    }
    uint8_t linkerMajor = nt.u8();
    uint8_t linkerMinor = nt.u8();
    uint32_t sizeOfCode = nt.u32();
    nt.u32(); nt.u32();
    uint32_t entryRva = nt.u32();
    nt.u32();
    if (!c.plus) nt.u32();
    c.imageBase = c.plus ? nt.u64() : nt.u32();
    uint32_t sectionAlign = nt.u32();
    uint32_t fileAlign = nt.u32();
    uint16_t osMaj = nt.u16(), osMin = nt.u16();
    uint16_t imgMaj = nt.u16(), imgMin = nt.u16();
    uint16_t subMaj = nt.u16(), subMin = nt.u16();
    nt.u32();
    uint32_t sizeOfImage = nt.u32();
    c.sizeOfHeaders = nt.u32();
    size_t cksumFieldOff = nt.o;
    uint32_t checksum = nt.u32();
    uint16_t subsystem = nt.u16();
    uint16_t dllChars = nt.u16();
    if (c.plus) { nt.u64(); nt.u64(); nt.u64(); nt.u64(); }
    else { nt.u32(); nt.u32(); nt.u32(); nt.u32(); }
    nt.u32();
    uint32_t numRva = nt.u32();
    if (!nt.ok()) { c.note("optional header truncated"); }
    if (numRva > 16) numRva = 16;
    for (uint32_t i = 0; i < numRva; i++) { c.dirs[i][0] = nt.u32(); c.dirs[i][1] = nt.u32(); }
    uint32_t computedChecksum = computePeChecksum(d, n, cksumFieldOff);

    size_t secTableOff = (size_t)peOff + 4 + 20 + sizeOpt;
    if (nsec > 96) { c.note("section count " + decU(nsec) + " exceeds sane range, truncated"); nsec = 96; }
    Rd sr(d, n, secTableOff);
    uint64_t maxRawEnd = 0;
    for (uint16_t i = 0; i < nsec && sr.ok(); i++) {
        Sec s;
        const uint8_t* nm = sr.take(8);
        if (!nm) break;
        char buf[9];
        memcpy(buf, nm, 8);
        buf[8] = 0;
        s.name = std::string(buf);
        if (!s.name.empty() && s.name.find_first_not_of(' ') == std::string::npos) s.name.clear();
        s.vsize = sr.u32();
        s.va = sr.u32();
        s.rsize = sr.u32();
        s.roff = sr.u32();
        sr.u32(); sr.u32(); sr.u16(); sr.u16();
        s.chars = sr.u32();
        if (!sr.ok()) { c.note("section table truncated"); break; }
        size_t ent = std::min((size_t)s.rsize, n > (size_t)s.roff ? n - s.roff : 0);
        if (ent) s.entropy = shannon(d + s.roff, ent);
        c.secs.push_back(s);
        if (s.rsize && (uint64_t)s.roff + s.rsize > maxRawEnd) maxRawEnd = (uint64_t)s.roff + s.rsize;
    }

    c.sum.rvaMap.ranges.push_back({ 0, std::max(c.sizeOfHeaders, (uint32_t)1), 0, c.sizeOfHeaders, "headers" });
    for (auto& s : c.secs) {
        uint32_t vsz = s.vsize ? s.vsize : s.rsize;
        c.sum.rvaMap.ranges.push_back({ s.va, vsz, s.roff, s.rsize, s.name });
    }
    c.sum.entryRva = entryRva;
    for (auto& s : c.secs) {
        if (entryRva >= s.va && entryRva < s.va + (s.vsize ? s.vsize : s.rsize ? s.rsize : 1)) { c.sum.entrySection = s.name; break; }
    }

    b.beginObj();

    const char* mach = machineName(machine);
    b.kv("machine", mach ? mach : "unknown");
    b.kvHex("machineRaw", machine, 4);
    b.kv("bitness", c.plus ? 64 : 32);
    b.kv("timestampRaw", (uint64_t)ts);
    b.kv("timestamp", fmtTimeUtc(ts));
    char linker[32];
    snprintf(linker, sizeof(linker), "%u.%u", linkerMajor, linkerMinor);
    b.kv("linkerVersion", linker);
    b.kv("entryPointRva", (uint64_t)entryRva);
    if (!c.sum.entrySection.empty()) b.kv("entryPointSection", c.sum.entrySection);
    b.kvHex("imageBase", c.imageBase);
    b.kv("sizeOfImage", (uint64_t)sizeOfImage);
    b.kv("sizeOfHeaders", (uint64_t)c.sizeOfHeaders);
    b.kv("sizeOfCode", (uint64_t)sizeOfCode);
    b.kv("sectionAlignment", (uint64_t)sectionAlign);
    b.kv("fileAlignment", (uint64_t)fileAlign);
    {
        char vbuf[64];
        snprintf(vbuf, sizeof(vbuf), "%u.%u", osMaj, osMin);
        b.kv("osVersion", vbuf);
        snprintf(vbuf, sizeof(vbuf), "%u.%u", subMaj, subMin);
        b.kv("subsystemVersion", vbuf);
        snprintf(vbuf, sizeof(vbuf), "%u.%u", imgMaj, imgMin);
        b.kv("imageVersion", vbuf);
    }
    const char* sub = subsystemName(subsystem);
    b.kv("subsystem", sub ? sub : "unknown");
    b.kv("subsystemId", (uint64_t)subsystem);
    b.kvHex("checksumStored", checksum, 8);
    b.kvHex("checksumComputed", computedChecksum, 8);
    b.kv("checksumValid", checksum != 0 && checksum == computedChecksum);
    writeStrFlags(b, "characteristics", coffChars, coffBits, coffNames, 15);
    writeStrFlags(b, "dllCharacteristics", dllChars, dllCharBits, dllCharNames, 11);
    if (dosStub.size() > 3) b.kv("dosStub", dosStub);

    b.arr("rich");
    if (peOff > 0x40) {
        for (size_t p = 0x40; p + 8 <= (size_t)peOff - 1 && p + 8 <= n; p++) {
            if (d[p] == 'R' && d[p + 1] == 'i' && d[p + 2] == 'c' && d[p + 3] == 'h') {
                uint32_t key = (uint32_t)d[p + 4] | ((uint32_t)d[p + 5] << 8) | ((uint32_t)d[p + 6] << 16) | ((uint32_t)d[p + 7] << 24);
                for (size_t q = 0x40; q + 4 <= p; q += 4) {
                    uint32_t w = (uint32_t)d[q] | ((uint32_t)d[q + 1] << 8) | ((uint32_t)d[q + 2] << 16) | ((uint32_t)d[q + 3] << 24);
                    if ((w ^ key) == 0x536E6144u) {
                        size_t e = q + 16;
                        bool keyOk = e + 4 <= n;
                        if (keyOk) {
                            uint32_t w2 = (uint32_t)d[e] | ((uint32_t)d[e + 1] << 8) | ((uint32_t)d[e + 2] << 16) | ((uint32_t)d[e + 3] << 24);
                            keyOk = (w2 ^ key) == key;
                        }
                        if (keyOk) {
                            size_t cur = e + 4;
                            while (cur + 8 <= p) {
                                uint32_t cid = ((uint32_t)d[cur] | ((uint32_t)d[cur + 1] << 8) | ((uint32_t)d[cur + 2] << 16) | ((uint32_t)d[cur + 3] << 24)) ^ key;
                                uint32_t cnt = ((uint32_t)d[cur + 4] | ((uint32_t)d[cur + 5] << 8) | ((uint32_t)d[cur + 6] << 16) | ((uint32_t)d[cur + 7] << 24)) ^ key;
                                uint32_t prodId = cid & 0xFFFF;
                                uint32_t build = cid >> 16;
                                const char* era = richToolEra(prodId);
                                b.beginObj();
                                b.kv("productId", (uint64_t)prodId);
                                b.kv("build", (uint64_t)build);
                                b.kv("count", (uint64_t)cnt);
                                if (era) b.kv("tool", era);
                                b.endObj();
                                cur += 8;
                            }
                        }
                        break;
                    }
                }
                break;
            }
        }
    }
    b.endArr();

    b.arr("sections");
    for (auto& s : c.secs) {
        b.beginObj();
        b.kv("name", s.name.empty() ? "(unnamed)" : s.name);
        b.kv("virtualSize", (uint64_t)s.vsize);
        b.kv("virtualAddress", (uint64_t)s.va);
        b.kv("rawSize", (uint64_t)s.rsize);
        b.kv("rawOffset", (uint64_t)s.roff);
        b.kv("entropy", s.entropy);
        bool exec = (s.chars & 0x20000000u) != 0;
        bool suspicious = (exec && s.entropy >= 7.0) || (s.rsize == 0 && s.vsize > 0x1000 && exec);
        b.kv("executable", exec);
        b.kv("writable", (s.chars & 0x80000000u) != 0);
        b.kv("suspicious", suspicious);
        writeStrFlags(b, "flags", s.chars, secCharBits, secCharNames, 17);
        b.endObj();
    }
    b.endArr();

    b.arr("directories");
    for (uint32_t i = 0; i < 16; i++) {
        b.beginObj();
        b.kv("index", (uint64_t)i);
        b.kv("name", dirNames[i]);
        b.kv("rva", (uint64_t)c.dirs[i][0]);
        b.kv("size", (uint64_t)c.dirs[i][1]);
        b.endObj();
    }
    b.endArr();

    uint64_t impTotal = 0;
    b.arr("imports");
    {
        int64_t io = c.offOf(c.dirs[1][0]);
        if (c.dirs[1][1] && io >= 0) {
            Rd ir(d, n, (size_t)io);
            for (uint32_t di = 0; di < 4096 && ir.ok(); di++) {
                uint32_t origThunk = ir.u32();
                ir.u32(); ir.u32();
                uint32_t nameRva = ir.u32();
                uint32_t thunkRva = ir.u32();
                if (!origThunk && !nameRva && !thunkRva) break;
                if (ir.err) { c.note("import table truncated"); break; }
                std::string dll = c.strAt(nameRva, 512);
                if (dll.empty()) dll = hexU(nameRva, 8);
                int64_t to = c.offOf(origThunk ? origThunk : thunkRva);
                b.beginObj();
                b.kv("dll", dll);
                b.arr("functions");
                uint32_t fcount = 0;
                if (to >= 0) {
                    Rd tr(d, n, (size_t)to);
                    for (uint32_t fi = 0; fi < 65536 && tr.ok(); fi++) {
                        uint64_t entry = c.plus ? tr.u64() : tr.u32();
                        if (tr.err) { c.note("thunk table truncated for " + dll); break; }
                        if (!entry) break;
                        b.beginObj();
                        if (entry & (c.plus ? 0x8000000000000000ull : 0x80000000ull)) {
                            uint64_t ord = entry & (c.plus ? 0xFFFFull : 0xFFFFull);
                            char ob[32];
                            snprintf(ob, sizeof(ob), "#%llu", (unsigned long long)ord);
                            b.kv("ordinal", ord);
                            b.kv("name", ob);
                        } else {
                            int64_t no = c.offOf((uint32_t)entry);
                            std::string fname;
                            uint16_t hint = 0;
                            if (no >= 0 && (size_t)no + 2 <= n) {
                                Rd nr(d, n, (size_t)no);
                                hint = nr.u16();
                                fname = readCStrAt(d, n, nr.o, 512);
                            }
                            b.kv("hint", (uint64_t)hint);
                            b.kv("name", fname.empty() ? hexU((uint32_t)entry, 8) : fname);
                        }
                        b.endObj();
                        fcount++;
                        impTotal++;
                        if (impTotal > 200000) { c.note("import list capped"); break; }
                    }
                }
                b.endArr();
                b.kv("count", (uint64_t)fcount);
                b.endObj();
            }
        }
    }
    b.endArr();
    b.kv("importFunctionTotal", impTotal);

    b.obj("exports");
    bool hasExports = false;
    {
        int64_t eo = c.offOf(c.dirs[0][0]);
        if (c.dirs[0][1] && eo >= 0) {
            Rd er(d, n, (size_t)eo);
            er.u32(); er.u32(); er.u16(); er.u16();
            uint32_t nameRva = er.u32();
            uint32_t ordBase = er.u32();
            uint32_t nFuncs = er.u32();
            uint32_t nNames = er.u32();
            uint32_t addrFuncs = er.u32();
            uint32_t addrNames = er.u32();
            uint32_t addrOrds = er.u32();
            if (nFuncs > 1000000) { c.note("export count implausible"); nFuncs = 0; }
            if (er.ok()) {
                hasExports = true;
                b.kv("name", c.strAt(nameRva, 512));
                b.kv("ordinalBase", (uint64_t)ordBase);
                b.kv("functionCount", (uint64_t)nFuncs);
                b.kv("namedCount", (uint64_t)nNames);
                b.arr("symbols");
                std::vector<uint32_t> nameRvas;
                int64_t no = c.offOf(addrNames);
                if (no >= 0 && nNames <= 1000000) {
                    Rd nr(d, n, (size_t)no);
                    for (uint32_t i = 0; i < nNames && nr.ok(); i++) nameRvas.push_back(nr.u32());
                }
                std::vector<uint16_t> ords;
                int64_t oo = c.offOf(addrOrds);
                if (no >= 0 && nNames <= 1000000) {
                    Rd orr(d, n, (size_t)oo);
                    for (uint32_t i = 0; i < nNames && orr.ok(); i++) ords.push_back(orr.u16());
                }
                std::vector<uint32_t> funcRvas;
                int64_t fo = c.offOf(addrFuncs);
                if (fo >= 0) {
                    Rd fr(d, n, (size_t)fo);
                    for (uint32_t i = 0; i < nFuncs && fr.ok(); i++) funcRvas.push_back(fr.u32());
                }
                for (uint32_t i = 0; i < nameRvas.size() && i < 65536; i++) {
                    uint32_t ordIdx = (i < ords.size()) ? ords[i] : i;
                    uint32_t ord = ordBase + ordIdx;
                    uint32_t frva = (ordIdx < funcRvas.size()) ? funcRvas[ordIdx] : 0;
                    b.beginObj();
                    b.kv("name", c.strAt(nameRvas[i], 1024));
                    b.kv("ordinal", (uint64_t)ord);
                    b.kv("rva", (uint64_t)frva);
                    int64_t foff = c.offOf(frva);
                    b.kv("fileOffset", foff >= 0 ? (uint64_t)foff : (uint64_t)0);
                    if (frva >= c.dirs[0][0] && frva < c.dirs[0][0] + c.dirs[0][1]) b.kv("forwarder", c.strAt(frva, 512));
                    b.endObj();
                }
                if (nNames == 0) {
                    for (uint32_t i = 0; i < funcRvas.size() && i < 4096; i++) {
                        b.beginObj();
                        b.kv("ordinal", (uint64_t)(ordBase + i));
                        b.kv("rva", (uint64_t)funcRvas[i]);
                        int64_t foff = c.offOf(funcRvas[i]);
                        b.kv("fileOffset", foff >= 0 ? (uint64_t)foff : (uint64_t)0);
                        b.endObj();
                    }
                }
                b.endArr();
            }
        }
        if (!hasExports) b.kv("present", false);
    }
    b.endObj();

    b.obj("resources");
    {
        ResWalker w(c, b);
        w.base = c.dirs[2][0];
        b.kv("present", c.dirs[2][1] != 0);
        b.arr("types");
        if (c.dirs[2][1]) w.walkDir(c.dirs[2][0], 0, 0);
        b.endArr();
        if (w.versionRva) {
            int64_t vo = c.offOf(w.versionRva);
            if (vo >= 0) {
                size_t vlen = std::min((size_t)w.versionSize, n - (size_t)vo);
                ViParser vi(d + (size_t)vo, vlen);
                vi.parse(0, vlen, 0, "");
                b.obj("versionInfo");
                if (vi.hasFixed) {
                    char vb[96];
                    snprintf(vb, sizeof(vb), "%u.%u.%u.%u",
                        vi.fileVerMS >> 16, vi.fileVerMS & 0xFFFF, vi.fileVerLS >> 16, vi.fileVerLS & 0xFFFF);
                    b.kv("fileVersion", vb);
                    snprintf(vb, sizeof(vb), "%u.%u.%u.%u",
                        vi.prodVerMS >> 16, vi.prodVerMS & 0xFFFF, vi.prodVerLS >> 16, vi.prodVerLS & 0xFFFF);
                    b.kv("productVersion", vb);
                }
                b.arr("strings");
                for (auto& p : vi.strings) {
                    b.beginObj();
                    b.kv("key", p.first);
                    b.kv("value", p.second);
                    b.endObj();
                }
                b.endArr();
                b.endObj();
            }
        }
        if (w.manifestRva) {
            int64_t mo = c.offOf(w.manifestRva);
            if (mo >= 0) {
                size_t mlen = std::min((size_t)w.manifestSize, n - (size_t)mo);
                if (mlen >= 2 && d[mo] == 0xFF && d[mo + 1] == 0xFE) {
                    std::vector<uint16_t> wv((const uint16_t*)(d + mo + 2), (const uint16_t*)(d + mo + 2) + (mlen - 2) / 2);
                    b.kv("manifest", wideToUtf8(wv.data(), wv.size()));
                } else {
                    b.kv("manifest", utf8Sanitize(d + mo, mlen));
                }
            }
        }
    }
    b.endObj();

    b.obj("tls");
    {
        int64_t to = c.offOf(c.dirs[9][0]);
        b.kv("present", c.dirs[9][1] != 0);
        if (c.dirs[9][1] && to >= 0) {
            Rd tr(d, n, (size_t)to);
            uint64_t startVa, endVa, idxVa, cbVa;
            if (c.plus) { startVa = tr.u64(); endVa = tr.u64(); idxVa = tr.u64(); cbVa = tr.u64(); }
            else { startVa = tr.u32(); endVa = tr.u32(); idxVa = tr.u32(); cbVa = tr.u32(); }
            uint32_t zeroFill = tr.u32();
            tr.u32();
            b.kvHex("startVa", startVa);
            b.kvHex("endVa", endVa);
            b.kvHex("indexVa", idxVa);
            b.kvHex("callbacksVa", cbVa);
            b.kv("zeroFill", (uint64_t)zeroFill);
            b.arr("callbacks");
            if (cbVa) {
                uint32_t cbRva = (uint32_t)(cbVa - c.imageBase);
                int64_t cbo = c.offOf(cbRva);
                if (cbo >= 0) {
                    Rd cr(d, n, (size_t)cbo);
                    for (int i = 0; i < 64; i++) {
                        uint64_t fn = c.plus ? cr.u64() : cr.u32();
                        if (!fn || cr.err) break;
                        b.valStr(hexU(fn));
                    }
                }
            }
            b.endArr();
            if (cbVa && c.offOf((uint32_t)(cbVa - c.imageBase)) >= 0) {
                Rd cr(d, n, (size_t)c.offOf((uint32_t)(cbVa - c.imageBase)));
                int cnt = 0;
                for (int i = 0; i < 64; i++) {
                    uint64_t fn = c.plus ? cr.u64() : cr.u32();
                    if (!fn || cr.err) break;
                    cnt++;
                }
                b.kv("callbackCount", (uint64_t)cnt);
                if (cnt) c.sum.inds.push_back({ 1, "TLS callbacks present", std::to_string(cnt) + " callback(s) execute before the entry point" });
            }
        }
    }
    b.endObj();

    b.obj("debug");
    {
        int64_t dgo = c.offOf(c.dirs[6][0]);
        b.kv("present", c.dirs[6][1] != 0);
        std::string pdb;
        if (c.dirs[6][1] && dgo >= 0) {
            uint32_t dbgCount = c.dirs[6][1] / 28;
            if (dbgCount > 128) dbgCount = 128;
            b.arr("entries");
            Rd dr(d, n, (size_t)dgo);
            for (uint32_t i = 0; i < dbgCount && dr.ok(); i++) {
                dr.u32(); dr.u32(); dr.u16(); dr.u16();
                uint32_t type = dr.u32();
                uint32_t sizeOfData = dr.u32();
                uint32_t addrRaw = dr.u32();
                uint32_t ptrRaw = dr.u32();
                if (dr.err) break;
                if (!type && !sizeOfData && !ptrRaw) break;
                const char* tn = debugTypeName(type);
                b.beginObj();
                b.kv("type", (uint64_t)type);
                b.kv("typeName", tn ? tn : "unknown");
                b.kv("size", (uint64_t)sizeOfData);
                b.kv("rawOffset", (uint64_t)ptrRaw);
                if (type == 2 && ptrRaw + 24 < n && d[ptrRaw] == 'R' && d[ptrRaw + 1] == 'S' && d[ptrRaw + 2] == 'D' && d[ptrRaw + 3] == 'S') {
                    const uint8_t* g = d + ptrRaw + 4;
                    char guid[48];
                    snprintf(guid, sizeof(guid), "%02x%02x%02x%02x-%02x%02x-%02x%02x-%02x%02x-%02x%02x%02x%02x%02x%02x",
                        g[3], g[2], g[1], g[0], g[5], g[4], g[7], g[6], g[8], g[9], g[10], g[11], g[12], g[13], g[14], g[15]);
                    uint32_t age = (uint32_t)g[16] | ((uint32_t)g[17] << 8) | ((uint32_t)g[18] << 16) | ((uint32_t)g[19] << 24);
                    b.kv("pdb", readCStrAt(d, n, ptrRaw + 24, 1024));
                    b.kv("pdbGuid", guid);
                    b.kv("pdbAge", (uint64_t)age);
                    if (pdb.empty()) pdb = readCStrAt(d, n, ptrRaw + 24, 1024);
                }
                b.endObj();
                (void)addrRaw;
            }
            b.endArr();
        }
        if (!pdb.empty()) c.sum.inds.push_back({ 0, "PDB path disclosed", pdb });
    }
    b.endObj();

    b.obj("security");
    {
        uint32_t certOff = c.dirs[4][0];
        uint32_t certSize = c.dirs[4][1];
        b.kv("signed", certSize > 0);
        if (certSize && certOff < n) {
            if ((uint64_t)certOff + certSize > n) c.note("certificate table extends past end of file");
            size_t secEnd = std::min((uint64_t)certOff + certSize, (uint64_t)n);
            size_t pos = certOff;
            uint32_t firstBlobOff = 0, firstBlobLen = 0;
            uint32_t winCertCount = 0;
            b.arr("certificates");
            while (pos + 8 <= secEnd && winCertCount < 64) {
                Rd cr(d, n, pos);
                uint32_t dwLen = cr.u32();
                uint16_t revision = cr.u16();
                uint16_t certType = cr.u16();
                uint64_t blobOff = pos + 8;
                uint64_t blobLen = dwLen >= 8 ? (uint64_t)dwLen - 8 : 0;
                if (dwLen < 8 || blobOff + blobLen > (uint64_t)n) { c.note("malformed WIN_CERTIFICATE at offset " + hexU(pos, 8)); break; }
                b.beginObj();
                b.kv("length", (uint64_t)dwLen);
                b.kvHex("revision", revision, 4);
                const char* ctype = certType == 2 ? "PKCS #7 Signed Data" : certType == 3 ? "Reserved" : certType == 4 ? "TS Stack Signed" : "unknown";
                b.kv("type", ctype);
                b.kv("typeRaw", (uint64_t)certType);
                b.endObj();
                c.sum.signed_ = true;
                if (certType == 2 && !firstBlobLen && blobLen >= 64) {
                    firstBlobOff = (uint32_t)blobOff;
                    firstBlobLen = (uint32_t)blobLen;
                }
                winCertCount++;
                uint64_t aligned = (pos + (uint64_t)dwLen + 7u) & ~(uint64_t)7u;
                if (aligned <= pos) break;
                pos = (size_t)std::min(aligned, secEnd);
            }
            b.endArr();
            if (firstBlobLen) {
                Pkcs7Result sign;
                if (parsePkcs7(d + firstBlobOff, firstBlobLen, sign) && !sign.signers.empty()) {
                    b.obj("signer");
                    const X509Signer& s = sign.signers[0];
                    b.kv("subject", s.subject);
                    b.kv("issuer", s.issuer);
                    b.kv("serial", s.serial);
                    if (!s.notBefore.empty()) b.kv("notBefore", s.notBefore);
                    if (!s.notAfter.empty()) b.kv("notAfter", s.notAfter);
                    b.kv("signatureAlg", s.signatureAlg);
                    b.kv("certCount", (uint64_t)sign.certCount);
                    b.kv("thumbprintSha1", s.thumbprintSha1);
                    b.endObj();
                    c.sum.inds.push_back({ 0, "Authenticode signer", s.subject });
                }
            }
        }
    }
    b.endObj();
    c.sum.signed_ = c.dirs[4][1] != 0;

    b.obj("clr");
    {
        uint32_t clrRva = c.dirs[14][0], clrSize = c.dirs[14][1];
        b.kv("present", clrSize != 0);
        c.sum.dotnet = clrSize != 0;
        if (clrSize) {
            int64_t co = c.offOf(clrRva);
            if (co >= 0 && (size_t)co + 24 <= n) {
                Rd cr(d, n, (size_t)co);
                cr.u32();
                uint16_t rmaj = cr.u16(), rmin = cr.u16();
                uint32_t mdRva = cr.u32(), mdSize = cr.u32();
                uint32_t flags = cr.u32();
                uint32_t epToken = cr.u32();
                char rv[32];
                snprintf(rv, sizeof(rv), "%u.%u", rmaj, rmin);
                b.kv("runtimeVersion", rv);
                b.kv("metadataSize", (uint64_t)mdSize);
                b.kvHex("entryPointToken", epToken, 8);
                std::vector<std::string> fl;
                if (flags & 0x1) fl.push_back("ILONLY");
                if (flags & 0x2) fl.push_back("32BITREQUIRED");
                if (flags & 0x4) fl.push_back("IL_LIBRARY");
                if (flags & 0x8) fl.push_back("STRONGNAMESIGNED");
                if (flags & 0x10) fl.push_back("NATIVE_ENTRYPOINT");
                if (flags & 0x10000) fl.push_back("TRACKDEBUGDATA");
                if (flags & 0x20000) fl.push_back("32BITPREFERRED");
                b.arr("flags");
                for (auto& f : fl) b.valStr(f);
                b.endArr();
                int64_t mo = c.offOf(mdRva);
                if (mo >= 0 && (size_t)mo + 16 <= n) {
                    Rd mr(d, n, (size_t)mo);
                    uint32_t sig = mr.u32();
                    mr.u16(); mr.u16();
                    mr.u32();
                    uint32_t vlen = mr.u32();
                    if (sig == 0x424A5342u) {
                        const uint8_t* vs = mr.take(vlen);
                        mr.u16();
                        uint16_t streams = mr.u16();
                        b.kv("dotnetVersion", std::string(vs ? (const char*)vs : "", vs ? strnlen((const char*)vs, vlen) : 0));
                        b.arr("metadataStreams");
                        for (uint16_t i = 0; i < streams && mr.ok() && i < 32; i++) {
                            uint32_t sOff = mr.u32(), sSize = mr.u32();
                            std::string nm;
                            while (mr.ok()) {
                                uint8_t ch = mr.u8();
                                if (!ch) break;
                                nm += (char)ch;
                                if (nm.size() > 32) break;
                            }
                            if (mr.o & 3) mr.skip(4 - (mr.o & 3));
                            b.beginObj();
                            b.kv("name", nm);
                            b.kv("offset", (uint64_t)sOff);
                            b.kv("size", (uint64_t)sSize);
                            b.endObj();
                        }
                        b.endArr();
                    }
                }
            }
        }
    }
    b.endObj();

    b.kv("dotnet", c.sum.dotnet);

    b.obj("relocations");
    {
        int64_t ro = c.offOf(c.dirs[5][0]);
        b.kv("present", c.dirs[5][1] != 0);
        if (c.dirs[5][1] && ro >= 0) {
            uint64_t count = 0, blocks = 0;
            Rd rr(d, n, (size_t)ro);
            size_t end = (size_t)ro + std::min((size_t)c.dirs[5][1], n - (size_t)ro);
            while (rr.o + 8 <= end && rr.ok() && blocks < 100000) {
                rr.u32();
                uint32_t blockSize = rr.u32();
                if (blockSize < 8 || rr.o + blockSize - 8 > end) break;
                uint32_t entries = (blockSize - 8) / 2;
                for (uint32_t i = 0; i < entries; i++) {
                    uint16_t e = rr.u16();
                    if ((e >> 12) != 0) count++;
                }
                blocks++;
            }
            b.kv("blocks", blocks);
            b.kv("entries", count);
        }
    }
    b.endObj();

    b.obj("loadConfig");
    {
        int64_t lo = c.offOf(c.dirs[10][0]);
        b.kv("present", c.dirs[10][1] != 0);
        if (c.dirs[10][1] && lo >= 0 && (size_t)lo + 4 <= n) {
            Rd lr(d, n, (size_t)lo);
            uint32_t sz = lr.u32();
            b.kv("size", (uint64_t)sz);
            b.kv("controlFlowGuard", (dllChars & 0x4000) != 0);
        }
    }
    b.endObj();

    b.obj("overlay");
    {
        uint64_t endOfLast = maxRawEnd;
        if (c.dirs[4][1]) {
            uint64_t certEnd = (uint64_t)c.dirs[4][0] + c.dirs[4][1];
            if (certEnd > endOfLast) endOfLast = certEnd;
        }
        if (endOfLast < n) {
            b.kv("present", true);
            b.kv("offset", endOfLast);
            b.kv("size", (uint64_t)n - endOfLast);
        } else b.kv("present", false);
    }
    b.endObj();

    if (!c.notes.empty()) {
        b.arr("notes");
        for (auto& s : c.notes) b.valStr(s);
        b.endArr();
    }

    b.endObj();

    {
        auto& I = c.sum.inds;
        bool execHigh = false, execVeryHigh = false;
        std::string highSec;
        for (auto& s : c.secs) {
            bool exec = (s.chars & 0x20000000u) != 0;
            if (exec && s.entropy >= 7.0) {
                execHigh = true;
                if (s.entropy >= 7.5) execVeryHigh = true;
                if (highSec.empty()) highSec = s.name + " (H=" + ([](double v) { char b[32]; snprintf(b, sizeof(b), "%.2f", v); return std::string(b); })(s.entropy) + ")";
            }
            static const char* packers[] = { "upx0","upx1","upx2","upx!",".aspack","aspack",".adata",".nsp0",".nsp1",".nsp2","themida",".themida",".boom",".taz",".petite",".mpress1",".mpress2",".pebundle",".svkp",".rlpack",".vmp0",".vmp1",".vmp2",".enigma1",".enigma2",".seau",".gentee",".sforce",".pklstb",".pebundle",".charmve",".dyamar",".kkrnch" };
            std::string ln = toLower(s.name);
            for (auto pk : packers) if (ln == pk) I.push_back({ 2, "Known packer section name", s.name + " indicates a packed executable" });
            if (s.rsize == 0 && s.vsize > 0x1000 && exec) I.push_back({ 1, "Executable section has no raw data", s.name + " occupies " + fmtSize(s.vsize) + " of virtual memory with zero raw bytes (unpacked at runtime by the loader or packer)" });
            if (exec && (s.chars & 0x80000000u)) I.push_back({ 1, "Writable and executable section", s.name + " has both MEM_WRITE and MEM_EXECUTE (self-modifying code risk)" });
        }
        if (execVeryHigh) I.push_back({ 2, "Very high entropy in executable code", highSec + " suggests encrypted or packed content" });
        else if (execHigh) I.push_back({ 1, "High entropy in executable code", highSec + " suggests packed or embedded compressed data" });
        if (!c.sum.entrySection.empty() && c.secs.size() >= 2) {
            const std::string& last = c.secs.back().name;
            std::string ln = toLower(last);
            if (c.sum.entrySection == last && (ln.find("upx") != std::string::npos || ln.find("text") == std::string::npos))
                I.push_back({ 1, "Entry point located in the last section", "OEP RVA " + hexU(entryRva) + " is in " + last + " (common for packed binaries)" });
        }
        if (!c.sum.dotnet && c.dirs[1][1] == 0 && c.secs.size())
            I.push_back({ 2, "No import directory", "The file declares no imports despite being a native executable (typical of heavily packed malware)" });
        if (impTotal > 0 && impTotal < 6 && !c.sum.dotnet)
            I.push_back({ 1, "Unusually small import table", "Only " + decU(impTotal) + " imported function(s); many packers reduce imports to LoadLibrary/GetProcAddress" });
        if (!c.sum.signed_) I.push_back({ 0, "Not digitally signed", "No Authenticode certificate table present" });
        else I.push_back({ 0, "Digitally signed", "Certificate table present (" + fmtSize(c.dirs[4][1]) + ")" });
        if (ts == 0) I.push_back({ 0, "Zero compile timestamp", "Header timestamp was zeroed (reproducible builds or anti-forensics)" });
        else if ((uint64_t)ts > 4102444800ull) I.push_back({ 1, "Implausible compile timestamp", fmtTimeUtc(ts) + " is in the future" });
        if (checksum != 0 && checksum != computedChecksum) I.push_back({ 0, "PE checksum mismatch", "Stored " + hexU(checksum, 8) + " != computed " + hexU(computedChecksum, 8) + " (modified after link or intentional)" });
        if (nsec == 0) I.push_back({ 1, "File has no sections", "Section table is empty" });
    }

    return c.sum;
}

}
