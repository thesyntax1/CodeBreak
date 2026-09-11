#include "formats.h"
#include "jsonw.h"
#include "util.h"
#include <cstring>
#include <vector>
#include <map>

namespace cb {

namespace {

constexpr uint32_t kFreeSector = 0xFFFFFFFFu;
constexpr uint32_t kEndOfChain = 0xFFFFFFFEu;
constexpr uint32_t kNoStream = 0xFFFFFFFFu;

struct OleHeader {
    uint16_t major = 0;
    uint32_t sectorShift = 0;
    uint32_t fatSectorCount = 0;
    uint32_t firstDirSector = 0;
    uint32_t miniCutoff = 0;
    uint32_t firstDifat = 0;
    uint32_t difatCount = 0;
    uint32_t firstMiniFat = 0;
};

bool parseHeader(const uint8_t* d, size_t n, OleHeader& h) {
    if (n < 512) return false;
    if (memcmp(d, "\xd0\xcf\x11\xe0\xa1\xb1\x1a\xe1", 8) != 0) return false;
    Rd r(d, n, 24);
    r.u16();
    h.major = r.u16();
    r.u16();
    h.sectorShift = r.u16();
    r.u16();
    r.skip(6);
    r.u32();
    h.fatSectorCount = r.u32();
    h.firstDirSector = r.u32();
    r.u32();
    h.miniCutoff = r.u32();
    h.firstMiniFat = r.u32();
    r.u32();
    h.firstDifat = r.u32();
    h.difatCount = r.u32();
    return r.ok();
}

struct DirEntry {
    std::string name;
    uint8_t type = 0;
    uint32_t left = 0;
    uint32_t right = 0;
    uint32_t child = 0;
    uint64_t size = 0;
};

std::string officeKindLabel(bool hasWord, bool hasXls, bool hasPpt, bool hasVba,
                            bool hasMacro, bool protectedOle, bool encrypted) {
    if (hasWord) return "Microsoft Word (legacy .doc binary format)";
    if (hasXls) return "Microsoft Excel (legacy .xls binary format)";
    if (hasPpt) return "Microsoft PowerPoint (legacy .ppt binary format)";
    if (hasVba) return "Office binary hosting a VBA macro project";
    if (protectedOle) return "OLE-protected / DRM container";
    if (encrypted) return "Encrypted compound file (EncryptedPackage)";
    if (hasMacro) return "Office binary with macro content";
    return "Generic Compound File (OLE2)";
}

} // namespace

void oleParse(const uint8_t* d, size_t n, Builder& b, IndCollector& inds) {
    OleHeader h;
    b.beginObj();
    if (!parseHeader(d, n, h)) {
        b.kv("error", "invalid OLE2 (Compound File) header");
        b.endObj();
        return;
    }
    // sectorShift is attacker-controlled: shifting a 32-bit value by 32 or
    // more is undefined behaviour, so fold it into the geometry check below.
    uint32_t sectorSize = h.sectorShift >= 32 ? 0u : (1u << h.sectorShift);
    bool big = h.major == 4;
    uint64_t headerSize = big ? sectorSize : 512u;
    uint64_t miniSize = 64;
    b.kv("majorVersion", (uint64_t)h.major);
    b.kv("sectorSize", (uint64_t)sectorSize);
    b.kv("miniSectorSize", miniSize);
    b.kv("miniStreamCutoff", (uint64_t)h.miniCutoff);
    b.kv("fatSectorCount", (uint64_t)h.fatSectorCount);
    b.kv("difatSectorCount", (uint64_t)h.difatCount);

    if (sectorSize < 512 || sectorSize > 65536 || n < headerSize) {
        b.kv("error", "implausible sector geometry");
        b.endObj();
        return;
    }

    uint64_t dataBytes = n - headerSize;
    uint64_t totalSectors = dataBytes / sectorSize;
    if (totalSectors < 1) { b.kv("error", "file too small"); b.endObj(); return; }

    auto sectOffset = [&](uint32_t num) -> uint64_t {
        return headerSize + (uint64_t)num * sectorSize;
    };
    auto readSector = [&](uint32_t num, std::vector<uint8_t>& out) -> bool {
        if (num >= totalSectors) return false;
        uint64_t off = sectOffset(num);
        if (off + sectorSize > n) return false;
        out.assign(d + off, d + off + sectorSize);
        return true;
    };

    std::vector<uint32_t> fatPhysical;
    {
        uint32_t fromHeader = h.fatSectorCount < 109 ? h.fatSectorCount : 109;
        for (uint32_t i = 0; i < fromHeader; i++) {
            uint32_t v = (uint32_t)d[76 + i * 4] | ((uint32_t)d[77 + i * 4] << 8) |
                         ((uint32_t)d[78 + i * 4] << 16) | ((uint32_t)d[79 + i * 4] << 24);
            if (v < totalSectors && v != kEndOfChain && v != kFreeSector) fatPhysical.push_back(v);
        }
        uint32_t cur = h.firstDifat;
        size_t guard = 0;
        while (cur < totalSectors && cur != kEndOfChain && guard++ < 2048) {
            std::vector<uint8_t> buf;
            if (!readSector(cur, buf)) break;
            uint32_t next = kEndOfChain;
            size_t per = buf.size() - 4;
            for (size_t i = 0; i + 4 <= per; i += 4) {
                uint32_t v = buf[i] | ((uint32_t)buf[i + 1] << 8) |
                             ((uint32_t)buf[i + 2] << 16) | ((uint32_t)buf[i + 3] << 24);
                if (v == kEndOfChain) break;
                if (v < totalSectors && v != kFreeSector) fatPhysical.push_back(v);
            }
            uint32_t last = buf[buf.size() - 4] | ((uint32_t)buf[buf.size() - 3] << 8) |
                            ((uint32_t)buf[buf.size() - 2] << 16) | ((uint32_t)buf[buf.size() - 1] << 24);
            next = last;
            cur = next;
        }
        if (fatPhysical.size() > h.fatSectorCount) fatPhysical.resize(h.fatSectorCount);
    }

    size_t perFat = sectorSize / 4;
    std::vector<uint32_t> fatArr((size_t)totalSectors, kFreeSector);
    for (size_t ordinal = 0; ordinal < fatPhysical.size(); ordinal++) {
        std::vector<uint8_t> buf;
        if (!readSector(fatPhysical[ordinal], buf)) continue;
        size_t base = ordinal * perFat;
        size_t avail = fatArr.size() - (base < fatArr.size() ? base : fatArr.size());
        size_t nent = perFat < avail ? perFat : avail;
        for (size_t j = 0; j < nent; j++) {
            fatArr[base + j] = buf[j * 4] | ((uint32_t)buf[j * 4 + 1] << 8) |
                               ((uint32_t)buf[j * 4 + 2] << 16) | ((uint32_t)buf[j * 4 + 3] << 24);
        }
    }

    auto chain = [&](uint32_t start, std::vector<uint32_t>& out) {
        uint32_t cur = start;
        size_t guard = 0;
        while (cur < fatArr.size() && cur != kEndOfChain && cur != kFreeSector && guard++ < 400000) {
            out.push_back(cur);
            cur = fatArr[cur];
        }
    };

    std::vector<uint8_t> dirData;
    {
        std::vector<uint32_t> secs;
        chain(h.firstDirSector, secs);
        for (uint32_t s : secs) {
            uint64_t off = sectOffset(s);
            if (off + sectorSize > n) break;
            dirData.insert(dirData.end(), d + off, d + off + sectorSize);
        }
    }

    std::vector<DirEntry> ents;
    size_t maxEnts = dirData.size() / 128;
    if (maxEnts > 65536) maxEnts = 65536;
    for (size_t i = 0; i < maxEnts; i++) {
        const uint8_t* e = dirData.data() + i * 128;
        DirEntry de;
        uint16_t nameLen = (uint16_t)e[64] | ((uint16_t)e[65] << 8);
        if (nameLen >= 2 && nameLen <= 64) {
            std::vector<uint16_t> w(nameLen / 2);
            for (size_t k = 0; k < w.size(); k++)
                w[k] = (uint16_t)e[k * 2] | ((uint16_t)e[k * 2 + 1] << 8);
            if (!w.empty()) de.name = wideToUtf8(w.data(), w.size());
        }
        de.type = e[66];
        if (de.type == 0) break;
        de.left = (uint32_t)e[68] | ((uint32_t)e[69] << 8) | ((uint32_t)e[70] << 16) | ((uint32_t)e[71] << 24);
        de.right = (uint32_t)e[72] | ((uint32_t)e[73] << 8) | ((uint32_t)e[74] << 16) | ((uint32_t)e[75] << 24);
        de.child = (uint32_t)e[76] | ((uint32_t)e[77] << 8) | ((uint32_t)e[78] << 16) | ((uint32_t)e[79] << 24);
        uint32_t start = (uint32_t)e[116] | ((uint32_t)e[117] << 8) |
                         ((uint32_t)e[118] << 16) | ((uint32_t)e[119] << 24);
        uint64_t lo = (uint64_t)e[120] | ((uint64_t)e[121] << 8) | ((uint64_t)e[122] << 16) | ((uint64_t)e[123] << 24);
        uint64_t hi = (uint64_t)e[124] | ((uint64_t)e[125] << 8) | ((uint64_t)e[126] << 16) | ((uint64_t)e[127] << 24);
        de.size = lo | (hi << 32);
        (void)start;
        ents.push_back(std::move(de));
    }

    uint64_t storageCount = 0, streamCount = 0, rootChild = kNoStream;
    for (size_t i = 0; i < ents.size(); i++) {
        if (ents[i].type == 1) storageCount++;
        else if (ents[i].type == 2) streamCount++;
        else if (ents[i].type == 5) rootChild = ents[i].child;
    }
    b.kv("directoryEntryCount", (uint64_t)ents.size());
    b.kv("storageCount", storageCount);
    b.kv("streamCount", streamCount);

    uint64_t listed = 0;
    bool truncated = false;
    b.arr("entries");
    std::vector<std::pair<uint32_t, int>> stack;
    stack.push_back({ rootChild, 0 });
    std::map<uint32_t, bool> visited;
    while (!stack.empty() && listed < 4000) {
        uint32_t idx = stack.back().first;
        int depth = stack.back().second;
        stack.pop_back();
        if (idx >= ents.size() || ents[idx].type == 0 || visited.count(idx)) continue;
        visited[idx] = true;
        const DirEntry& de = ents[idx];
        b.beginObj();
        b.kv("name", de.name);
        const char* ty = "unknown";
        if (de.type == 1) ty = "storage";
        else if (de.type == 2) ty = "stream";
        else if (de.type == 5) ty = "root";
        b.kv("type", ty);
        if (de.type == 2) {
            b.kv("size", de.size);
            b.kv("sizeHuman", fmtSize(de.size));
        }
        b.kv("depth", (int64_t)depth);
        b.endObj();
        listed++;
        if (de.right < ents.size() && ents[de.right].type != 0) stack.push_back({ de.right, depth });
        if (de.left < ents.size() && ents[de.left].type != 0) stack.push_back({ de.left, depth });
        if (de.child < ents.size() && ents[de.child].type != 0) stack.push_back({ de.child, depth + 1 });
    }
    b.endArr();
    if (ents.size() > 4000) truncated = true;
    b.kv("truncated", truncated);

    bool hasVba = false, hasMacro = false, encrypted = false, protectedOle = false;
    bool hasPpt = false, hasXls = false, hasWord = false;
    for (const DirEntry& de : ents) {
        std::string up = toUpper(de.name);
        if (up == "VBA" || up == "_VBA_PROJECT") hasVba = true;
        else if (up == "MACROS") hasMacro = true;
        if (up == "ENCRYPTEDPACKAGE" || up == "ENCRYPTIONINFO") encrypted = true;
        if (up == "DATASPACES") protectedOle = true;
        if (up == "POWERPOINT DOCUMENT" || up == "CURRENT USER") hasPpt = true;
        if (up == "WORKBOOK" || up == "BOOK") hasXls = true;
        if (up == "WORDDOCUMENT") hasWord = true;
    }
    std::string kind = officeKindLabel(hasWord, hasXls, hasPpt, hasVba, hasMacro, protectedOle, encrypted);
    b.kv("kind", kind);

    if (hasVba)
        inds.add(2, "VBA macro project embedded",
                 "Compound file hosts an Office VBA macro project; macro code may auto-run on open");
    if (encrypted)
        inds.add(1, "Encrypted OLE content",
                 "EncryptedPackage/EncryptionInfo streams present; content requires credentials");
    if (protectedOle)
        inds.add(0, "OLE Protected (DRM)", "Data Spaces stream present; content is rights-managed");
    if (!hasVba && !hasMacro && !hasWord && !hasXls && !hasPpt && !protectedOle && !encrypted)
        inds.add(0, "Compound File container", "Generic OLE2 structured storage");
    b.endObj();
}

}
