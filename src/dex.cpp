#include "dex.h"
#include "pe.h"
#include "jsonw.h"
#include "util.h"
#include "hashes.h"
#include <unordered_map>

namespace cb {

static std::string mutf8At(const uint8_t* d, size_t n, size_t off) {
    Rd r(d, n, off);
    r.uleb();
    size_t start = r.o;
    size_t end = start;
    while (end < n && d[end] != 0) end++;
    return mutf8ToUtf8(d + start, end - start);
}

static void accessFlagNames(std::vector<std::string>& out, uint32_t f) {
    struct { uint32_t bit; const char* name; } T[] = {
        {0x1,"public"},{0x2,"private"},{0x4,"protected"},{0x8,"static"},{0x10,"final"},{0x20,"synchronized"},
        {0x40,"volatile"},{0x80,"transient"},{0x100,"native"},{0x200,"interface"},{0x400,"abstract"},
        {0x800,"strict"},{0x1000,"synthetic"},{0x2000,"annotation"},{0x4000,"enum"},{0x10000,"constructor"},
        {0x20000,"declared-synchronized"}
    };
    for (auto& t : T) if (f & t.bit) out.push_back(t.name);
}

void dexParse(const uint8_t* d, size_t n, const char* entryName, Builder& b, IndCollector& inds, uint64_t dexSize) {
    b.beginObj();
    b.kv("name", entryName);
    if (n < 112) { b.kv("error", "truncated dex"); b.endObj(); return; }
    char ver[9] = { 0 };
    memcpy(ver, d + 4, 4);
    b.kv("version", ver);
    uint32_t storedCk = 0;
    memcpy(&storedCk, d + 8, 4);
    uint32_t calcCk = adler32Compute(d + 12, n - 12);
    b.kv("checksumOk", calcCk == storedCk);
    uint8_t storedSig[21] = { 0 };
    memcpy(storedSig, d + 12, 20);
    std::string calcSig = sha1Hex(d + 32, n - 32);
    std::string storedSigHex = hexBytes(storedSig, 20);
    b.kv("signatureOk", calcSig == storedSigHex);
    Rd h(d, n, 32);
    uint32_t fileSize = h.u32();
    uint32_t headerSize = h.u32();
    h.u32();
    h.u32(); h.u32();
    h.u32();
    uint32_t strCount = h.u32(), strOff = h.u32();
    uint32_t typCount = h.u32(), typOff = h.u32();
    uint32_t proCount = h.u32(); h.u32();
    uint32_t fldCount = h.u32(); h.u32();
    uint32_t mthCount = h.u32(); h.u32();
    uint32_t clsCount = h.u32(), clsOff = h.u32();
    h.u32(); h.u32();
    b.kv("fileSize", (uint64_t)fileSize);
    b.kv("headerSize", (uint64_t)headerSize);
    b.kv("fileSizeMatches", (uint64_t)fileSize == dexSize);
    b.kv("stringCount", (uint64_t)strCount);
    b.kv("typeCount", (uint64_t)typCount);
    b.kv("protoCount", (uint64_t)proCount);
    b.kv("fieldCount", (uint64_t)fldCount);
    b.kv("methodCount", (uint64_t)mthCount);
    b.kv("classCount", (uint64_t)clsCount);

    if (strCount > 1000000 || clsCount > 500000) { b.kv("error", "implausible counts"); b.endObj(); return; }

    std::vector<uint32_t> strOffs;
    strOffs.reserve(std::min(strCount, (uint32_t)400000u));
    {
        Rd r(d, n, strOff);
        for (uint32_t i = 0; i < strCount && r.ok(); i++) strOffs.push_back(r.u32());
    }
    auto getStr = [&](uint32_t idx) -> std::string {
        if (idx >= strOffs.size()) return std::string();
        return mutf8At(d, n, strOffs[idx]);
    };
    std::vector<uint32_t> typeIdx;
    typeIdx.reserve(std::min(typCount, (uint32_t)500000u));
    {
        Rd r(d, n, typOff);
        for (uint32_t i = 0; i < typCount && r.ok(); i++) typeIdx.push_back(r.u32());
    }
    auto getType = [&](uint32_t idx) -> std::string {
        if (idx >= typeIdx.size()) return std::string();
        return getStr(typeIdx[idx]);
    };

    b.arr("strings");
    uint32_t strCap = strCount < 1500 ? strCount : 1500;
    for (uint32_t i = 0; i < strCap; i++) b.valStr(getStr(i));
    b.endArr();

    b.arr("classes");
    uint32_t clsCap = clsCount < 5000 ? clsCount : 5000;
    bool clsTrunc = clsCap < clsCount;
    for (uint32_t i = 0; i < clsCount; i++) {
        Rd r(d, n, clsOff + (size_t)i * 32);
        uint32_t classIdx = r.u32();
        uint32_t access = r.u32();
        uint32_t superIdx = r.u32();
        r.u32();
        uint32_t sourceIdx = r.u32();
        r.u32(); r.u32(); r.u32();
        if (r.err) break;
        if (i < clsCap) {
            std::vector<std::string> flags;
            accessFlagNames(flags, access);
            b.beginObj();
            b.kv("name", getType(classIdx));
            b.kv("super", getType(superIdx));
            b.kvHex("access", access, 8);
            b.arr("flags");
            for (auto& f : flags) b.valStr(f);
            b.endArr();
            if (sourceIdx != 0xFFFFFFFFu) {
                std::string src = getStr(sourceIdx);
                if (!src.empty()) b.kv("source", src);
            }
            b.endObj();
        }
    }
    b.endArr();
    b.kv("classesTruncated", clsTrunc);
    b.endObj();

    if (strcmp(ver, "009") == 0 || strcmp(ver, "013") == 0) inds.add(0, "Legacy DEX version", std::string(entryName) + " uses dex version " + ver + " (pre-ICS format)");
}

}
