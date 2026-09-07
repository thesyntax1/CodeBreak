#include "pe.h"
#include "jsonw.h"
#include "util.h"
#include <cstring>

namespace cb {

static const char* elfOsabi(uint8_t v) {
    switch (v) {
    case 0: return "UNIX System V";
    case 1: return "HP-UX";
    case 2: return "NetBSD";
    case 3: return "GNU/Linux";
    case 6: return "SunOS/Solaris";
    case 7: return "AIX";
    case 8: return "IRIX";
    case 9: return "FreeBSD";
    case 10: return "Tru64";
    case 11: return "Novell Modesto";
    case 12: return "OpenBSD";
    case 13: return "OpenVMS";
    case 14: return "NonStop Kernel";
    case 15: return "AROS";
    case 16: return "FenixOS";
    case 17: return "Nuxi CloudABI";
    case 64: return "ARM EABI";
    case 97: return "ARM";
    case 255: return "Standalone";
    default: return nullptr;
    }
}

static const char* elfTypeName(uint16_t t) {
    switch (t) {
    case 0: return "None";
    case 1: return "Relocatable";
    case 2: return "Executable";
    case 3: return "Shared object";
    case 4: return "Core dump";
    default: return nullptr;
    }
}

static const char* elfMachine(uint16_t m) {
    switch (m) {
    case 0x02: return "SPARC";
    case 0x03: return "x86";
    case 0x08: return "MIPS";
    case 0x14: return "PowerPC";
    case 0x28: return "ARM";
    case 0x32: return "IA-64";
    case 0x3E: return "x86-64";
    case 0xB7: return "AArch64";
    case 0xF3: return "RISC-V";
    case 0x18: return "S390";
    case 0x16: return "S390";
    case 0x15: return "PowerPC64";
    case 0x51: return "Xtensa? (0x51)";
    default: return nullptr;
    }
}

static const char* phdrTypeName(uint32_t t) {
    switch (t) {
    case 0: return "NULL";
    case 1: return "LOAD";
    case 2: return "DYNAMIC";
    case 3: return "INTERP";
    case 4: return "NOTE";
    case 5: return "SHLIB";
    case 6: return "PHDR";
    case 7: return "TLS";
    case 0x6474e550: return "GNU_EH_FRAME";
    case 0x6474e551: return "GNU_STACK";
    case 0x6474e552: return "GNU_RELRO";
    case 0x6474e553: return "GNU_PROPERTY";
    case 0x6474e554: return "GNU_SFRAME";
    default: return nullptr;
    }
}

static const char* shdrTypeName(uint32_t t) {
    switch (t) {
    case 0: return "NULL";
    case 1: return "PROGBITS";
    case 2: return "SYMTAB";
    case 3: return "STRTAB";
    case 4: return "RELA";
    case 5: return "HASH";
    case 6: return "DYNAMIC";
    case 7: return "NOTE";
    case 8: return "NOBITS";
    case 9: return "REL";
    case 10: return "SHLIB";
    case 11: return "DYNSYM";
    case 14: return "INIT_ARRAY";
    case 15: return "FINI_ARRAY";
    case 16: return "PREINIT_ARRAY";
    case 17: return "GROUP";
    case 18: return "SYMTAB_SHNDX";
    case 0x6ffffff5: return "GNU_ATTRIBUTES";
    case 0x6ffffff6: return "GNU_HASH";
    case 0x6ffffffd: return "GNU_verdef";
    case 0x6ffffffe: return "GNU_verneed";
    case 0x6fffffff: return "GNU_versym";
    default: return nullptr;
    }
}

void elfParse(const uint8_t* d, size_t n, Builder& b, IndCollector& inds) {
    b.beginObj();
    Rd ident(d, n);
    ident.skip(4);
    uint8_t eiClass = ident.u8();
    uint8_t eiData = ident.u8();
    ident.u8();
    uint8_t eiOsabi = ident.u8();
    ident.u8();
    bool is64 = eiClass == 2;
    bool be = eiData == 2;
    if (eiClass != 1 && eiClass != 2) { b.kv("error", "bad EI_CLASS"); b.endObj(); return; }
    if (eiData != 1 && eiData != 2) { b.kv("error", "bad EI_DATA"); b.endObj(); return; }
    const char* osabi = elfOsabi(eiOsabi);
    b.kv("class", is64 ? "ELF64" : "ELF32");
    b.kv("endianness", be ? "Big" : "Little");
    b.kv("osabi", osabi ? osabi : "unknown");
    b.kv("osabiRaw", (uint64_t)eiOsabi);
    b.kv("abiVersion", (uint64_t)ident.u8());

    struct R2 {
        const uint8_t* d;
        size_t n;
        bool be;
        uint16_t u16(size_t o) { if (o + 2 > n) return 0; uint16_t v; memcpy(&v, d + o, 2); return be ? ((v & 0xFF) << 8) | (v >> 8) : v; }
        uint32_t u32(size_t o) { if (o + 4 > n) return 0; uint32_t v; memcpy(&v, d + o, 4); if (be) v = ((v & 0xFF) << 24) | ((v & 0xFF00) << 8) | ((v >> 8) & 0xFF00) | (v >> 24); return v; }
        uint64_t u64(size_t o) { if (o + 8 > n) return 0; uint64_t v; memcpy(&v, d + o, 8); if (be) { uint64_t r = 0; for (int i = 0; i < 8; i++) r = (r << 8) | ((v >> (8 * i)) & 0xFF); return r; } return v; }
    } r{ d, n, be };

    uint16_t eType = r.u16(16);
    uint16_t eMachine = r.u16(18);
    uint32_t eVersion = r.u32(20);
    uint64_t entry = is64 ? r.u64(24) : r.u32(24);
    uint64_t phoff = is64 ? r.u64(32) : r.u32(28);
    uint64_t shoff = is64 ? r.u64(40) : r.u32(32);
    uint32_t eFlags = r.u32(is64 ? 48 : 36);
    uint16_t ehdz = is64 ? 64 : 52;
    uint16_t phentsize = r.u16(is64 ? 54 : 42);
    uint16_t phnum = r.u16(is64 ? 56 : 44);
    uint16_t shentsize = r.u16(is64 ? 58 : 46);
    uint16_t shnum = r.u16(is64 ? 60 : 48);
    uint16_t shstrndx = r.u16(is64 ? 62 : 50);
    (void)eVersion;
    (void)ehdz;

    const char* tname = elfTypeName(eType);
    b.kv("type", tname ? tname : "unknown");
    b.kv("typeRaw", (uint64_t)eType);
    const char* mname = elfMachine(eMachine);
    b.kv("machine", mname ? mname : "unknown");
    b.kvHex("machineRaw", eMachine, 4);
    b.kvHex("entry", entry);
    b.kvHex("flags", eFlags, 8);

    if (shnum == 0 && shoff) {
        uint64_t sz = is64 ? r.u64(shoff + 32) : r.u32(shoff + 20);
        shnum = (uint16_t)sz;
    }
    if (shstrndx == 0xFFFF && shoff) {
        shstrndx = (uint16_t)(is64 ? r.u32(shoff + 40) : r.u32(shoff + 24));
    }
    if (shnum > 4096) shnum = 4096;
    if (phnum > 512) phnum = 512;

    auto shName = [&](uint32_t off) -> std::string {
        if (!shoff || shstrndx >= shnum) return std::string();
        uint64_t strtabOff = is64 ? r.u64(shoff + (uint64_t)shstrndx * shentsize + 24) : r.u32(shoff + (uint64_t)shstrndx * shentsize + 16);
        if (strtabOff + off >= n) return std::string();
        return readCStrAt(d, n, (size_t)(strtabOff + off), 256);
    };
    auto shField = [&](uint16_t idx, int which) -> uint64_t {
        uint64_t base = shoff + (uint64_t)idx * shentsize;
        if (base + shentsize > n || !shentsize) return 0;
        if (is64) {
            switch (which) {
            case 0: return r.u32(base);       // name
            case 1: return r.u32(base + 4);   // type
            case 2: return r.u64(base + 8);   // flags
            case 3: return r.u64(base + 16);  // addr
            case 4: return r.u64(base + 24);  // offset
            case 5: return r.u64(base + 32);  // size
            case 6: return r.u32(base + 40);  // link
            case 7: return r.u32(base + 44);  // info
            }
        } else {
            switch (which) {
            case 0: return r.u32(base);
            case 1: return r.u32(base + 4);
            case 2: return r.u32(base + 8);
            case 3: return r.u32(base + 12);
            case 4: return r.u32(base + 16);
            case 5: return r.u32(base + 20);
            case 6: return r.u32(base + 24);
            case 7: return r.u32(base + 28);
            }
        }
        return 0;
    };

    b.arr("programHeaders");
    for (uint16_t i = 0; i < phnum; i++) {
        uint64_t base = phoff + (uint64_t)i * phentsize;
        if (!phentsize || base + phentsize > n) break;
        uint32_t pType = r.u32(base);
        uint32_t pFlags = is64 ? r.u32(base + 4) : 0;
        uint64_t pOff, pVa, pFs, pMs;
        uint32_t flags32 = pFlags;
        if (is64) {
            pFlags = r.u32(base + 4);
            pOff = r.u64(base + 8);
            pVa = r.u64(base + 16);
            pFs = r.u64(base + 32);
            pMs = r.u64(base + 40);
        } else {
            pOff = r.u32(base + 4);
            pVa = r.u32(base + 8);
            pFs = r.u32(base + 16);
            pMs = r.u32(base + 20);
            flags32 = r.u32(base + 24);
        }
        const char* tn = phdrTypeName(pType);
        b.beginObj();
        b.kv("index", (uint64_t)i);
        b.kv("type", tn ? tn : "unknown");
        b.kvHex("typeRaw", pType, 8);
        std::string fl;
        if (flags32 & 4) fl += "R";
        if (flags32 & 2) fl += "W";
        if (flags32 & 1) fl += "X";
        b.kv("flags", fl);
        b.kvHex("offset", pOff);
        b.kvHex("vaddr", pVa);
        b.kv("fileSize", pFs);
        b.kv("memSize", pMs);
        if (pType == 3 && pOff < n) {
            b.kv("interpreter", readCStrAt(d, n, (size_t)pOff, 256));
        }
        if (pType == 1 && (flags32 & 2) && (flags32 & 1)) {
            inds.add(1, "Writable+executable LOAD segment", "Segment " + std::to_string(i) + " has RWX permissions");
        }
        b.endObj();
    }
    b.endArr();

    b.arr("sections");
    for (uint16_t i = 0; i < shnum; i++) {
        if (shoff + (uint64_t)(i + 1) * shentsize > n) break;
        uint32_t nameOff = (uint32_t)shField(i, 0);
        uint32_t sType = (uint32_t)shField(i, 1);
        uint64_t sFlags = shField(i, 2);
        uint64_t sAddr = shField(i, 3);
        uint64_t sOff = shField(i, 4);
        uint64_t sSize = shField(i, 5);
        uint64_t sLink = shField(i, 6);
        uint64_t sInfo = shField(i, 7);
        const char* tn = shdrTypeName(sType);
        std::string nm = shName(nameOff);
        b.beginObj();
        b.kv("index", (uint64_t)i);
        b.kv("name", nm);
        b.kv("type", tn ? tn : "unknown");
        b.kvHex("typeRaw", sType, 8);
        std::string fl;
        if (sFlags & 0x1) fl += "W";
        if (sFlags & 0x2) fl += "A";
        if (sFlags & 0x4) fl += "X";
        if (sFlags & 0x10) fl += "M";
        if (sFlags & 0x20) fl += "S";
        if (sFlags & 0x40) fl += "I";
        if (sFlags & 0x200) fl += "o";
        b.kv("flags", fl);
        b.kvHex("flagsRaw", sFlags, 16);
        b.kvHex("addr", sAddr);
        b.kv("offset", sOff);
        b.kv("size", sSize);
        if (sType != 8 && sOff < n && sSize) {
            size_t ent = std::min((size_t)sSize, n - (size_t)sOff);
            size_t ent2 = std::min(ent, (size_t)16 << 20);
            b.kv("entropy", shannon(d + sOff, ent2));
        }
        b.kv("link", sLink);
        b.kv("info", sInfo);
        b.endObj();
        if (!nm.empty() && nm.size() >= 8 && nm.substr(0, 4) == ".text" && (sFlags & 0x4)) {
            size_t ent = std::min((size_t)sSize, n > (size_t)sOff ? n - (size_t)sOff : 0);
            if (ent > 4096) {
                double e = shannon(d + sOff, ent);
                if (e >= 7.0) inds.add(1, "High entropy in executable section", nm + " entropy " + ([](double v) { char bb[32]; snprintf(bb, sizeof(bb), "%.2f", v); return std::string(bb); })(e));
            }
        }
    }
    b.endArr();

    if (eType == 4) inds.add(0, "Core dump", "This ELF is a process core dump");
    b.endObj();
}

}
