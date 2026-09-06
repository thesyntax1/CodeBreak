#include "pe.h"
#include "jsonw.h"
#include "util.h"
#include <cstring>

namespace cb {

static const char* machoCpuName(uint32_t t) {
    uint32_t base = t & 0xFF;
    switch (base) {
    case 1: return "VAX";
    case 6: return "MC680x0";
    case 7: return (t & 0x01000000) ? "x86-64" : "x86";
    case 10: return "MC98000";
    case 11: return "SPARC";
    case 12: return (t & 0x01000000) ? "ARM64" : "ARM";
    case 13: return "ARM64_32";
    case 14: return (t & 0x01000000) ? "PowerPC64" : "PowerPC";
    default: return nullptr;
    }
}

static const char* machoFileTypeName(uint32_t t) {
    switch (t) {
    case 1: return "Object";
    case 2: return "Executable";
    case 3: return "Fixed VM library";
    case 4: return "Core";
    case 5: return "Preloaded executable";
    case 6: return "Dylib";
    case 7: return "Dylinker";
    case 8: return "Bundle";
    case 9: return "Stub";
    case 10: return "DSYM";
    case 11: return "Kernel extension";
    default: return nullptr;
    }
}

static const char* machoCmdName(uint32_t c) {
    switch (c) {
    case 0x1: return "LC_SEGMENT";
    case 0x2: return "LC_SYMTAB";
    case 0x5: return "LC_UNIXTHREAD";
    case 0x8: return "LC_DYLD_INFO_ONLY";
    case 0xb: return "LC_DYSYMTAB";
    case 0xc: return "LC_LOAD_DYLIB";
    case 0xd: return "LC_ID_DYLIB";
    case 0xe: return "LC_LOAD_DYLINKER";
    case 0x11: return "LC_ROUTINES";
    case 0x1c: return "LC_RPATH";
    case 0x1d: return "LC_CODE_SIGNATURE";
    case 0x19: return "LC_SEGMENT_64";
    case 0x21: return "LC_ENCRYPTION_INFO";
    case 0x22: return "LC_DYLD_INFO";
    case 0x24: return "LC_VERSION_MIN_MACOSX";
    case 0x25: return "LC_VERSION_MIN_IPHONEOS";
    case 0x26: return "LC_FUNCTION_STARTS";
    case 0x29: return "LC_DATA_IN_CODE";
    case 0x2A: return "LC_SOURCE_VERSION";
    case 0x2B: return "LC_DYLIB_CODE_SIGN_DRS";
    case 0x2D: return "LC_BUILD_VERSION";
    case 0x80000028: return "LC_MAIN";
    case 0x8000001c: return "LC_RPATH";
    case 0x80000022: return "LC_UNIXTHREAD (old)";
    default: return nullptr;
    }
}

void machoParse(const uint8_t* d, size_t n, uint64_t magic, Builder& b, IndCollector& inds) {
    b.beginObj();
    bool rev = magic == 0xCEFAEDFEull || magic == 0xCFFAEDFEull;
    bool is64 = (magic == 0xFEEDFACFull || magic == 0xCFFAEDFEull);
    Rd r(d, n, 0);
    auto u32 = [&]() { return rev ? r.u32be() : r.u32(); };
    r.u32();
    uint32_t cputype = u32();
    uint32_t cpusub = u32();
    uint32_t filetype = u32();
    uint32_t ncmds = u32();
    uint32_t sizeofcmds = u32();
    uint32_t flags = u32();
    if (is64) r.u32();
    const char* cput = machoCpuName(cputype);
    const char* ftname = machoFileTypeName(filetype);
    b.kv("magic", is64 ? "MH_MAGIC_64" : "MH_MAGIC");
    b.kv("byteSwapped", rev);
    b.kv("cputype", cput ? cput : "unknown");
    b.kvHex("cputypeRaw", cputype, 8);
    b.kvHex("cpusubtypeRaw", cpusub, 8);
    b.kv("filetype", ftname ? ftname : "unknown");
    b.kv("filetypeRaw", (uint64_t)filetype);
    b.kv("commandCount", (uint64_t)ncmds);
    b.kv("commandsSize", (uint64_t)sizeofcmds);
    b.kvHex("flags", flags, 8);
    if (ncmds > 2048) ncmds = 2048;
    b.arr("loadCommands");
    uint64_t end = 0;
    for (uint32_t i = 0; i < ncmds && r.ok(); i++) {
        size_t chunkStart = r.o;
        uint32_t cmd = u32();
        uint32_t cmdsize = u32();
        if (cmdsize < 8 || chunkStart + cmdsize > n) break;
        const char* cn = machoCmdName(cmd);
        b.beginObj();
        b.kv("index", (uint64_t)i);
        b.kvHex("cmd", cmd, 8);
        b.kv("name", cn ? cn : "unknown");
        b.kv("size", (uint64_t)cmdsize);
        if ((cmd == 0x1 && !is64) || (cmd == 0x19 && is64)) {
            char segname[17] = { 0 };
            const uint8_t* snp = r.take(16);
            if (snp) memcpy(segname, snp, 16);
            uint64_t vmaddr, vmsize, fileoff, filesize;
            uint32_t maxprot, initprot, nsects;
            if (is64) {
                vmaddr = r.u64(); vmsize = r.u64(); fileoff = r.u64(); filesize = r.u64();
                maxprot = u32(); initprot = u32(); nsects = u32(); r.u32();
            } else {
                vmaddr = u32(); vmsize = u32(); fileoff = u32(); filesize = u32();
                maxprot = u32(); initprot = u32(); nsects = u32(); r.u32();
            }
            std::string prot;
            if (maxprot & 1 || initprot & 1) prot += "R";
            if (maxprot & 2 || initprot & 2) prot += "W";
            if (maxprot & 4 || initprot & 4) prot += "X";
            b.kv("segment", segname);
            b.kvHex("vmaddr", vmaddr);
            b.kv("vmsize", vmsize);
            b.kv("fileOffset", fileoff);
            b.kv("fileSize", filesize);
            b.kv("protection", prot);
            b.kv("sectionCount", (uint64_t)nsects);
            if (filesize > 4096 && (initprot & 4) && prot.find('W') != std::string::npos && fileoff < n) {
                inds.add(1, "Writable+executable segment", std::string(segname) + " is mapped W+X");
            }
        } else if (cmd == 0xe && cmdsize > 12) {
            b.kv("dylinker", readCStrAt(d, n, chunkStart + 12, 256));
        }
        r.seek(chunkStart + cmdsize);
        end = r.o;
        b.endObj();
    }
    b.endArr();
    (void)end;
    b.endObj();
}

void machoFatParse(const uint8_t* d, size_t n, Builder& b, IndCollector& inds) {
    b.beginObj();
    b.kv("kind", "Universal binary (FAT)");
    Rd r(d, n);
    r.u32();
    uint32_t nfat = r.u32be();
    if (nfat > 16) nfat = 16;
    b.kv("archCount", (uint64_t)nfat);
    b.arr("architectures");
    for (uint32_t i = 0; i < nfat && r.ok(); i++) {
        uint32_t cput = r.u32be(), sub = r.u32be();
        uint32_t off = r.u32be(), sz = r.u32be();
        uint32_t align = r.u32be();
        const char* cn = machoCpuName(cput);
        b.beginObj();
        b.kv("cputype", cn ? cn : "unknown");
        b.kvHex("cputypeRaw", cput, 8);
        b.kv("offset", (uint64_t)off);
        b.kv("size", (uint64_t)sz);
        b.kv("alignment", (uint64_t)align);
        (void)sub;
        b.endObj();
    }
    b.endArr();
    b.endObj();
}

void javaClassParse(const uint8_t* d, size_t n, Builder& b, IndCollector& inds) {
    b.beginObj();
    Rd r(d, n);
    r.u32();
    uint16_t minor = r.u16be();
    uint16_t major = r.u16be();
    auto majorName = [](uint16_t m) -> const char* {
        if (m <= 45) return "Java 1.1 or older";
        switch (m) {
        case 46: return "Java 1.2";
        case 47: return "Java 1.3";
        case 48: return "Java 1.4";
        case 49: return "Java 5";
        case 50: return "Java 6";
        case 51: return "Java 7";
        case 52: return "Java 8";
        case 53: return "Java 9";
        case 54: return "Java 10";
        case 55: return "Java 11";
        case 56: return "Java 12";
        case 57: return "Java 13";
        case 58: return "Java 14";
        case 59: return "Java 15";
        case 60: return "Java 16";
        case 61: return "Java 17";
        case 62: return "Java 18";
        case 63: return "Java 19";
        case 64: return "Java 20";
        case 65: return "Java 21";
        case 66: return "Java 22";
        default: return nullptr;
        }
    };
    const char* jname = majorName(major);
    b.kv("classVersion", std::to_string(major) + "." + std::to_string(minor));
    b.kv("javaVersion", jname ? jname : "unknown (newer)");
    uint16_t cpCount = r.u16be();
    b.kv("constantPoolCount", (uint64_t)(cpCount > 0 ? cpCount - 1 : 0));
    std::vector<std::string> cp(cpCount);
    std::vector<uint16_t> classRefName(cpCount, 0);
    uint64_t utf8Count = 0;
    uint16_t idx = 1;
    bool cpOk = true;
    while (idx < cpCount && r.ok()) {
        uint8_t tag = r.u8();
        switch (tag) {
        case 1: {
            uint16_t len = r.u16be();
            const uint8_t* p = r.take(len);
            if (p) { cp[idx] = utf8Sanitize(p, len); utf8Count++; }
            break;
        }
        case 3: case 4: r.skip(4); break;
        case 5: case 6: r.skip(8); idx++; break;
        case 7: classRefName[idx] = r.u16be(); break;
        case 8: case 16: case 19: case 20: r.skip(2); break;
        case 15: r.skip(3); break;
        case 9: case 10: case 11: case 12: case 17: case 18: r.skip(4); break;
        default: cpOk = false; break;
        }
        if (!cpOk) break;
        idx++;
    }
    b.kv("utf8ConstantCount", utf8Count);
    if (!cpOk) { b.kv("error", "invalid constant pool tag"); b.endObj(); return; }
    auto cpStr = [&](uint16_t i) -> std::string {
        if (i == 0 || i >= cpCount) return std::string();
        if (classRefName[i]) {
            uint16_t ni = classRefName[i];
            if (ni < cpCount) return cp[ni];
            return std::string();
        }
        return cp[i];
    };
    uint16_t access = r.u16be();
    uint16_t thisClass = r.u16be();
    uint16_t superClass = r.u16be();
    b.kv("className", cpStr(thisClass));
    uint16_t superNameIdx = 0;
    if (superClass) {
        Rd rr(d, n);
        (void)rr;
    }
    std::string superClassStr;
    if (superClass) superClassStr = cpStr(superClass);
    b.kv("superClass", superClassStr.empty() ? "java/lang/Object" : superClassStr);
    (void)superNameIdx;
    std::vector<std::string> af;
    if (access & 0x0001) af.push_back("public");
    if (access & 0x0010) af.push_back("final");
    if (access & 0x0020) af.push_back("super");
    if (access & 0x0200) af.push_back("interface");
    if (access & 0x0400) af.push_back("abstract");
    if (access & 0x1000) af.push_back("synthetic");
    if (access & 0x2000) af.push_back("annotation");
    if (access & 0x4000) af.push_back("enum");
    if (access & 0x8000) af.push_back("module");
    b.arr("accessFlags");
    for (auto& f : af) b.valStr(f);
    b.endArr();
    b.kvHex("accessRaw", access, 4);
    uint16_t ifCount = r.u16be();
    b.kv("interfaceCount", (uint64_t)ifCount);
    r.skip((size_t)ifCount * 2);
    uint16_t fCount = r.u16be();
    b.kv("fieldCount", (uint64_t)fCount);
    uint16_t mCount = 0;
    if (r.ok()) {
        for (uint16_t i = 0; i < fCount && r.ok(); i++) {
            r.u16be(); r.u16be(); r.u16be();
            uint16_t ac = r.u16be();
            r.skip(ac);
        }
        mCount = r.u16be();
        b.kv("methodCount", (uint64_t)mCount);
        b.arr("methods");
        for (uint16_t i = 0; i < mCount && mCount <= 8192 && r.ok(); i++) {
            uint16_t macc = r.u16be();
            uint16_t nameIdx = r.u16be();
            uint16_t descIdx = r.u16be();
            uint16_t attrCount = r.u16be();
            b.beginObj();
            b.kv("name", cpStr(nameIdx));
            b.kv("descriptor", cpStr(descIdx));
            std::string mf;
            if (macc & 0x0001) mf += "public ";
            if (macc & 0x0002) mf += "private ";
            if (macc & 0x0004) mf += "protected ";
            if (macc & 0x0008) mf += "static ";
            if (macc & 0x0010) mf += "final ";
            if (macc & 0x0020) mf += "synchronized ";
            if (macc & 0x0100) mf += "native ";
            if (macc & 0x0400) mf += "abstract ";
            b.kv("flags", mf);
            b.kv("attributeCount", (uint64_t)attrCount);
            b.endObj();
            for (uint16_t a = 0; a < attrCount && r.ok(); a++) {
                r.u16be();
                uint32_t alen = r.u32be();
                r.skip(alen);
            }
        }
        b.endArr();
    }
    b.endObj();
    (void)inds;
}

}
