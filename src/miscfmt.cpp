#include "formats.h"
#include "jsonw.h"
#include "util.h"
#include <cstring>
#include <string>

namespace cb {

void gzipParse(const uint8_t* d, size_t n, Builder& b, IndCollector& inds) {
    b.beginObj();
    Rd r(d, n);
    r.u8();
    r.u8();
    uint8_t cm = r.u8();
    uint8_t flg = r.u8();
    uint32_t mtime = r.u32();
    uint8_t xfl = r.u8();
    uint8_t os = r.u8();
    const char* method = cm == 8 ? "deflate" : (cm == 0 ? "stored" : "unknown");
    b.kv("method", method);
    b.kvHex("flags", flg, 2);
    b.arr("flagBits");
    if (flg & 0x01) b.valStr("FTEXT");
    if (flg & 0x02) b.valStr("FHCRC");
    if (flg & 0x04) b.valStr("FEXTRA");
    if (flg & 0x08) b.valStr("FNAME");
    if (flg & 0x10) b.valStr("FCOMMENT");
    b.endArr();
    b.kv("mtime", fmtTimeUtc(mtime));
    b.kvHex("xfl", xfl, 2);
    const char* osName = nullptr;
    switch (os) {
    case 0: osName = "FAT filesystem"; break;
    case 3: osName = "Unix"; break;
    case 7: osName = "Macintosh"; break;
    case 11: osName = "NTFS"; break;
    case 255: osName = "unknown"; break;
    default: break;
    }
    b.kv("os", osName ? osName : "unknown");
    if (flg & 0x04) {
        uint16_t xlen = r.u16();
        if (r.ok()) {
            if (flg & 0x01) {
                std::string text;
                for (size_t k = 0; k < xlen && k < 512 && r.ok(); k++) {
                    uint8_t c = r.u8();
                    if (c >= 32 && c < 127) text += (char)c;
                }
                if (!text.empty()) b.kv("extra", text);
            } else {
                r.skip(xlen);
            }
        }
    }
    if (flg & 0x08) {
        std::string name;
        while (r.ok() && name.size() < 4096) {
            uint8_t c = r.u8();
            if (!c) break;
            name += (char)c;
        }
        if (!name.empty()) b.kv("filename", name);
    }
    if (flg & 0x10) {
        std::string comment;
        while (r.ok() && comment.size() < 4096) {
            uint8_t c = r.u8();
            if (!c) break;
            comment += (char)c;
        }
        if (!comment.empty()) b.kv("comment", comment);
    }
    uint64_t dataOff = r.o;
    b.kv("dataOffset", dataOff);
    if (n >= dataOff + 8) {
        uint32_t crc = (uint32_t)d[n - 8] | ((uint32_t)d[n - 7] << 8) |
                       ((uint32_t)d[n - 6] << 16) | ((uint32_t)d[n - 5] << 24);
        uint32_t isize = (uint32_t)d[n - 4] | ((uint32_t)d[n - 3] << 8) |
                         ((uint32_t)d[n - 2] << 16) | ((uint32_t)d[n - 1] << 24);
        b.kv("crc32", hexU(crc, 8));
        b.kv("uncompressedSize", (uint64_t)isize);
        b.kv("uncompressedSizeHuman", fmtSize(isize));
    }
    inds.add(0, "Compressed stream (GZIP)", "Single-member gzip container; inspect the extracted payload");
    b.endObj();
}

static uint64_t tarOctal(const uint8_t* hdr, size_t at, size_t len) {
    uint64_t v = 0;
    for (size_t i = 0; i < len; i++) {
        char c = (char)hdr[at + i];
        if (c >= '0' && c <= '7') v = v * 8 + (uint64_t)(c - '0');
        else if (c != 0 && c != ' ') break;
    }
    return v;
}

void tarParse(const uint8_t* d, size_t n, Builder& b, IndCollector& inds) {
    b.beginObj();
    uint64_t count = 0;
    size_t off = 0;
    uint64_t totalData = 0;
    bool truncated = false;
    b.arr("entries");
    while (off + 512 <= n && count < 20000) {
        const uint8_t* hdr = d + off;
        bool allZero = true;
        for (size_t i = 0; i < 512; i++) if (hdr[i]) { allZero = false; break; }
        if (allZero) break;
        if (memcmp(hdr + 257, "ustar", 5) != 0) { truncated = true; break; }
        size_t nameLen = 0;
        while (nameLen < 100 && hdr[nameLen]) nameLen++;
        std::string name((const char*)hdr, nameLen);
        if (name.empty()) { off += 512; continue; }
        char typeflag = (char)hdr[156];
        size_t prefixLen = 0;
        while (prefixLen < 155 && hdr[345 + prefixLen]) prefixLen++;
        if (prefixLen) name = std::string((const char*)(hdr + 345), prefixLen) + "/" + name;
        uint64_t size = tarOctal(hdr, 124, 12);
        uint64_t mode = tarOctal(hdr, 100, 8);
        uint64_t mtime = tarOctal(hdr, 136, 12);
        const char* tyname = "file";
        switch (typeflag) {
        case '\0': case '0': tyname = "file"; break;
        case '1': tyname = "hard link"; break;
        case '2': tyname = "symbolic link"; break;
        case '3': tyname = "character device"; break;
        case '4': tyname = "block device"; break;
        case '5': tyname = "directory"; break;
        case '6': tyname = "FIFO"; break;
        case '7': tyname = "contiguous file"; break;
        case 'g': tyname = "global extended header"; break;
        case 'x': tyname = "per-file extended header"; break;
        case 'L': tyname = "GNU long name"; break;
        case 'K': tyname = "GNU long link"; break;
        default: tyname = "unknown"; break;
        }
        if (count < 3000) {
            b.beginObj();
            b.kv("name", name);
            b.kv("type", tyname);
            b.kv("size", size);
            b.kv("mode", mode);
            b.kv("mtime", fmtTimeUtc(mtime));
            b.endObj();
        } else {
            truncated = true;
        }
        bool skipSize = (typeflag != '5' && typeflag != 'x' && typeflag != 'g' && typeflag != 'L');
        if (skipSize) totalData += size;
        count++;
        off += 512;
        uint64_t blocks = (size + 511) / 512;
        if (blocks > (n - off) / 512) { truncated = true; break; }
        off += blocks * 512;
        if (count >= 20000) { truncated = true; break; }
    }
    b.endArr();
    b.kv("entryCount", count);
    b.kv("totalDataSize", totalData);
    b.kv("totalDataSizeHuman", fmtSize(totalData));
    b.kv("truncated", truncated);
    inds.add(0, "POSIX tar archive", "Bundle of files; scan members individually for threats");
    b.endObj();
}

void pdfParse(const uint8_t* d, size_t n, Builder& b, IndCollector& inds) {
    b.beginObj();
    size_t hdrLen = n < 32 ? n : 32;
    std::string hdr((const char*)d, hdrLen);
    size_t ver = hdr.find("PDF-");
    std::string version = "unknown";
    if (ver != std::string::npos) {
        char buf[8];
        size_t k = 0;
        for (size_t i = ver + 4; i < hdrLen && k < 6 && d[i] != '\r' && d[i] != '\n'; i++)
            buf[k++] = (char)d[i];
        buf[k] = 0;
        version = buf;
    }
    b.kv("version", version);
    size_t cap = n < (64ull * 1024 * 1024) ? n : (64ull * 1024 * 1024);
    uint64_t objects = 0, streams = 0, pages = 0;
    bool encrypted = false, hasJs = false, xrefStream = false, objStream = false;
    size_t i = 0;
    for (; i + 4 < cap && objects < 200000; i++) {
        if (d[i] == '/') {
            if (cap - i >= 8 && memcmp(d + i, "/Encrypt", 8) == 0) { encrypted = true; i += 7; }
            else if (cap - i >= 11 && memcmp(d + i, "/JavaScript", 11) == 0) { hasJs = true; i += 10; }
            else if (cap - i >= 6 && memcmp(d + i, "/XRef", 5) == 0) { xrefStream = true; i += 4; }
            else if (cap - i >= 7 && memcmp(d + i, "/ObjStm", 7) == 0) { objStream = true; i += 6; }
            else if (cap - i >= 12 && memcmp(d + i, "/Type /Page", 11) == 0 &&
                     d[i + 11] != 's' && d[i + 11] != 'S') { pages++; i += 10; }
            continue;
        }
        if (d[i] == 's' && cap - i >= 7 && memcmp(d + i, "stream", 6) == 0) {
            char a = (char)d[i + 6];
            if (a == 0 || a == '\r' || a == '\n') streams++;
            i += 6;
        }
        if (d[i] == ' ' && cap - i >= 5 && memcmp(d + i + 1, "obj", 3) == 0) {
            if (i > 1 && d[i - 1] >= '0' && d[i - 1] <= '9') objects++;
            i += 3;
        }
    }
    b.kv("objectCount", objects);
    b.kv("streamCount", streams);
    b.kv("pageObjects", pages);
    b.kv("encrypted", encrypted);
    b.kv("hasJavaScript", hasJs);
    b.kv("xrefStream", xrefStream);
    b.kv("objectStream", objStream);
    b.arr("features");
    if (encrypted) b.valStr("Encrypted");
    if (hasJs) b.valStr("JavaScript present");
    if (objStream) b.valStr("Compressed object streams");
    b.endArr();
    if (encrypted) {
        inds.add(2, "Encrypted PDF", "Document declares /Encrypt; content requires credentials to read");
    }
    if (hasJs) {
        inds.add(1, "PDF JavaScript", "Action triggers may execute code when the document opens");
    }
    b.endObj();
}

}
