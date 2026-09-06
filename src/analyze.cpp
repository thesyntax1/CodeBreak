#include "formats.h"
#include "jsonw.h"
#include "util.h"
#include "hashes.h"
#include "pe.h"
#include "zipfmt.h"
#include "dex.h"
#include <cstring>

namespace cb {

FormatId detectFormat(const uint8_t* d, size_t n, const std::string& lowerName) {
    if (looksLikePe(d, n)) return FMT_PE;
    if (n >= 8 && looksLikeZip(d, n)) return FMT_ZIP;
    if (n >= 8 && memcmp(d, "dex\n", 4) == 0) return FMT_DEX;
    if (n >= 20 && memcmp(d, "\x7f" "ELF", 4) == 0) return FMT_ELF;
    if (n >= 16) {
        uint32_t m32 = (uint32_t)d[0] | ((uint32_t)d[1] << 8) | ((uint32_t)d[2] << 16) | ((uint32_t)d[3] << 24);
        uint32_t be = ((uint32_t)d[0] << 24) | ((uint32_t)d[1] << 16) | ((uint32_t)d[2] << 8) | d[3];
        if (m32 == 0xFEEDFACEu || m32 == 0xFEEDFACFu) return FMT_MACHO;
        if (be == 0xCAFEBABEu) {
            uint32_t maj = ((uint32_t)d[6] << 8) | d[7];
            uint32_t nfat = ((uint32_t)d[4] << 24) | ((uint32_t)d[5] << 16) | ((uint32_t)d[6] << 8) | d[7];
            if (maj >= 45 && maj <= 90) return FMT_JAVACLASS;
            if (nfat && nfat < 32) return FMT_MACHO_FAT;
            return FMT_JAVACLASS;
        }
        if (be == 0xFEEDFACEu || be == 0xFEEDFACFu) return FMT_MACHO;
    }
    if (n >= 8 && memcmp(d, "\xd0\xcf\x11\xe0\xa1\xb1\x1a\xe1", 8) == 0) return FMT_OLE;
    if (n >= 8 && memcmp(d, "\x00" "asm", 4) == 0) return FMT_WASM;
    if (n >= 5 && memcmp(d, "%PDF", 4) == 0) return FMT_PDF;
    if (n >= 2 && d[0] == '#' && d[1] == '!') return FMT_SCRIPT;
    if (n >= 8 && memcmp(d, "\x89PNG\r\n\x1a\n", 8) == 0) return FMT_IMAGE;
    if (n >= 3 && d[0] == 0xFF && d[1] == 0xD8 && d[2] == 0xFF) return FMT_IMAGE;
    if (n >= 6 && (memcmp(d, "GIF87a", 6) == 0 || memcmp(d, "GIF89a", 6) == 0)) return FMT_IMAGE;
    return FMT_UNKNOWN;
}

const char* formatLabel(FormatId f) {
    switch (f) {
    case FMT_PE: return "PE executable";
    case FMT_ZIP: return "ZIP archive";
    case FMT_APK: return "Android package";
    case FMT_DEX: return "Dalvik executable";
    case FMT_ELF: return "ELF executable";
    case FMT_MACHO: return "Mach-O binary";
    case FMT_MACHO_FAT: return "Mach-O universal binary";
    case FMT_JAVACLASS: return "Java class";
    case FMT_OLE: return "Compound File (OLE2)";
    case FMT_SCRIPT: return "Script";
    case FMT_WASM: return "WebAssembly";
    case FMT_PDF: return "PDF document";
    case FMT_IMAGE: return "Image file";
    default: return "Unknown / raw binary";
    }
}

static void writeEntropy(Builder& b, const uint8_t* d, size_t n) {
    double overall = shannon(d, n);
    b.kv("overall", overall);
    size_t targetBlocks = 2048;
    size_t block = (n + targetBlocks - 1) / targetBlocks;
    if (block < 4096) block = 4096;
    b.kv("blockSize", (uint64_t)block);
    b.arr("blocks");
    for (size_t off = 0; off < n; off += block) {
        size_t len = std::min(block, n - off);
        if (len < 64 && off) break;
        b.beginObj();
        b.kv("off", (uint64_t)off);
        b.kv("e", shannon(d + off, len));
        b.endObj();
    }
    b.endArr();
}

AnalysisOutput analyzeFile(const uint8_t* d, size_t n, const std::string& pathUtf8, const FileInfo& fi) {
    AnalysisOutput out;
    out.ok = false;
    out.fmt = FMT_UNKNOWN;
    std::string j;
    Builder b(j);
    b.beginObj();

    size_t slash = pathUtf8.find_last_of("/\\");
    std::string fname = slash == std::string::npos ? pathUtf8 : pathUtf8.substr(slash + 1);
    std::string lowerName = toLower(fname);

    FormatId fmt = detectFormat(d, n, lowerName);

    b.obj("file");
    b.kv("path", pathUtf8);
    b.kv("name", fname);
    b.kv("size", (uint64_t)n);
    b.kv("sizeHuman", fmtSize(n));
    if (fi.exists) {
        b.kv("modified", fmtTimeUtc(fi.modified));
        b.kv("created", fmtTimeUtc(fi.created));
        b.kv("accessed", fmtTimeUtc(fi.accessed));
    }
    b.endObj();

    b.obj("hashes");
    b.kv("crc32", hexU(crc32Compute(d, n), 8));
    b.kv("md5", md5Hex(d, n));
    b.kv("sha1", sha1Hex(d, n));
    b.kv("sha256", sha256Hex(d, n));
    b.endObj();

    b.kv("magic", hexBytes(d, n < 16 ? n : 16));

    b.obj("entropy");
    writeEntropy(b, d, n);
    b.endObj();

    IndCollector inds;

    double overall = shannon(d, n);
    if (iendsWith(lowerName, ".exe") && fmt != FMT_PE && fmt != FMT_UNKNOWN)
        inds.add(1, "Extension mismatch", "File has .exe extension but content is " + std::string(formatLabel(fmt)));
    if ((iendsWith(lowerName, ".apk") || iendsWith(lowerName, ".jar")) && fmt != FMT_ZIP)
        inds.add(1, "Extension mismatch", "File has a package extension but content is " + std::string(formatLabel(fmt)));

    StringsIndex si;
    si.build(d, n, 4, 2000000);

    std::string label = formatLabel(fmt);

    switch (fmt) {
    case FMT_PE: {
        b.key("pe");
        PeSummary ps = peParse(d, n, b);
        for (auto& i : ps.inds) inds.add(i.severity, i.title, i.detail);
        label = ps.dotnet ? "PE executable (.NET)" : (ps.is64 ? "PE32+ executable (64-bit)" : "PE32 executable (32-bit)");
        break;
    }
    case FMT_ZIP: {
        b.key("zip");
        ZipData zd = zipParse(d, n, b, inds);
        if (zd.isApk) {
            b.key("apk");
            apkParse(zd, b, inds);
            label = "Android package (APK)";
            out.fmt = FMT_APK;
        } else if (zd.isJar) label = "Java archive (JAR)";
        else if (zd.isEpub) label = "EPUB e-book";
        else if (zd.isIpa) label = "iOS app package (IPA)";
        else label = "ZIP archive";
        break;
    }
    case FMT_DEX: {
        b.key("dex");
        IndCollector di;
        dexParse(d, n, "classes.dex", b, di, n);
        for (auto& i : di.items) inds.add(i.severity, i.title, i.detail);
        label = "Dalvik executable (DEX)";
        break;
    }
    case FMT_ELF: {
        b.key("elf");
        elfParse(d, n, b, inds);
        label = "ELF executable/library";
        break;
    }
    case FMT_MACHO: {
        b.key("macho");
        uint32_t m32 = (uint32_t)d[0] | ((uint32_t)d[1] << 8) | ((uint32_t)d[2] << 16) | ((uint32_t)d[3] << 24);
        machoParse(d, n, m32, b, inds);
        label = "Mach-O binary";
        break;
    }
    case FMT_MACHO_FAT: {
        b.key("macho");
        machoFatParse(d, n, b, inds);
        label = "Mach-O universal binary";
        break;
    }
    case FMT_JAVACLASS: {
        b.key("javaclass");
        javaClassParse(d, n, b, inds);
        label = "Java class file";
        break;
    }
    case FMT_OLE:
        b.obj("ole");
        b.kv("sectorShift", (uint64_t)((uint32_t)d[0x1E] | ((uint32_t)d[0x1F] << 8)));
        b.kv("miniSectorShift", (uint64_t)((uint32_t)d[0x20] | ((uint32_t)d[0x21] << 8)));
        inds.add(0, "Compound File container", "Used by MSI installers and legacy Office documents");
        b.endObj();
        break;
    case FMT_SCRIPT: {
        b.obj("script");
        size_t e = 0;
        while (e < n && d[e] != '\n' && e < 512) e++;
        std::string line = utf8Sanitize(d + 2, e > 2 ? e - 2 : 0);
        b.kv("interpreter", line);
        b.endObj();
        break;
    }
    default:
        if (overall >= 7.5) inds.add(1, "Very high entropy content", "File is almost certainly encrypted, packed or compressed media");
        break;
    }

    b.obj("format");
    b.kv("id", (int)out.fmt == (int)FMT_UNKNOWN ? (int)fmt : (int)out.fmt);
    b.kv("label", label);
    b.endObj();

    b.obj("stringsInfo");
    b.kv("total", (uint64_t)si.size());
    b.kv("truncated", si.truncated());
    b.endObj();

    b.arr("indicators");
    for (auto& i : inds.items) {
        b.beginObj();
        const char* sev = i.severity == 3 ? "critical" : i.severity == 2 ? "high" : i.severity == 1 ? "medium" : "info";
        b.kv("severity", sev);
        b.kv("severityNum", (int64_t)i.severity);
        b.kv("title", i.title);
        b.kv("detail", i.detail);
        b.endObj();
    }
    b.endArr();

    b.endObj();
    out.json = std::move(j);
    out.fmt = fmt;
    out.ok = true;
    return out;
}

}
