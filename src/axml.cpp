#include "axml.h"
#include "jsonw.h"
#include "util.h"
#include <cstring>

namespace cb {

struct AxmlCtx {
    const uint8_t* d;
    size_t n;
    std::vector<std::string> strings;
    std::string err;
    int stringCap = 400000;

    bool loadStrings(const uint8_t* pool, size_t poolN) {
        Rd r(pool, poolN);
        r.u16();
        r.u16();
        uint32_t size = r.u32();
        (void)size;
        uint32_t count = r.u32();
        r.u32();
        uint32_t flags = r.u32();
        uint32_t stringsStart = r.u32();
        r.u32();
        if (r.err || count > 1000000) { err = "bad string pool"; return false; }
        bool utf8 = (flags & 0x100) != 0;
        std::vector<uint32_t> offs;
        offs.reserve(count);
        for (uint32_t i = 0; i < count && r.ok(); i++) offs.push_back(r.u32());
        if (r.err) { err = "string offsets truncated"; return false; }
        strings.resize(count);
        size_t decoded = 0;
        for (uint32_t i = 0; i < count; i++) {
            if (decoded >= (size_t)stringCap) break;
            size_t so = (size_t)stringsStart + offs[i];
            if (so >= poolN) continue;
            Rd s(pool, poolN, so);
            if (utf8) {
                uint8_t l1 = s.u8();
                size_t clen = l1 & 0x80 ? ((l1 & 0x7F) << 8) | s.u8() : l1;
                uint8_t l2 = s.u8();
                size_t blen = l2 & 0x80 ? ((l2 & 0x7F) << 8) | s.u8() : l2;
                (void)clen;
                const uint8_t* p = s.take(blen < 8192 ? blen : 8192);
                if (p) { strings[i] = mutf8ToUtf8(p, blen < 8192 ? blen : 8192); decoded++; }
            } else {
                uint16_t l1 = s.u16();
                size_t clen = l1 & 0x8000 ? ((size_t)(l1 & 0x7FFF) << 16) | s.u16() : l1;
                if (clen > 16384) clen = 16384;
                const uint8_t* p = s.take(clen * 2);
                if (p) { strings[i] = wideToUtf8((const uint16_t*)p, clen); decoded++; }
            }
        }
        return true;
    }

    std::string str(uint32_t idx) const {
        if (idx == 0xFFFFFFFFu || idx >= strings.size()) return std::string();
        return strings[idx];
    }
};

static std::string formatComplex(uint32_t data, bool fraction) {
    static const char* units[] = { "px","dip","sp","pt","in","mm" };
    static const char* funits[] = { "%","%" };
    int radix = (data >> 4) & 3;
    static const int shifts[] = { 23, 16, 8, 0 };
    int64_t mantissa = (int64_t)(data & 0xFFFFFF00u) >> 8;
    double v = (double)mantissa * (double)(1 << shifts[radix]);
    int unit = data & 0xF;
    char buf[64];
    if (unit <= 5) snprintf(buf, sizeof(buf), "%.4g%s", v, units[unit]);
    else if (fraction && unit <= 1) snprintf(buf, sizeof(buf), "%.4g%s", v * 100.0 / (1 << shifts[radix]) * (1 << shifts[radix]) / (double)(1 << shifts[radix]), funits[unit]);
    else snprintf(buf, sizeof(buf), "%.4g@0x%x", v, unit);
    return std::string(buf);
}

static AxmlAttr formatAttr(AxmlCtx& c, uint32_t ns, uint32_t name, uint32_t rawValue, uint8_t dataType, uint32_t data) {
    AxmlAttr a;
    a.name = c.str(name);
    if (ns != 0xFFFFFFFFu) {
        std::string nss = c.str(ns);
        if (nss.find("schemas.android.com") != std::string::npos) a.name = "android:" + a.name;
        else if (!nss.empty()) a.name = nss + ":" + a.name;
    }
    if (rawValue != 0xFFFFFFFFu) a.raw = c.str(rawValue);
    char buf[48];
    switch (dataType) {
    case 0x00: a.value = a.raw.empty() ? "<null>" : a.raw; a.type = "null"; break;
    case 0x01: snprintf(buf, sizeof(buf), "@ref/0x%08x", data); a.value = buf; a.type = "reference"; break;
    case 0x02: snprintf(buf, sizeof(buf), "?attr/0x%08x", data); a.value = buf; a.type = "attribute"; break;
    case 0x03: a.value = a.raw.empty() ? c.str(data) : a.raw; a.type = "string"; break;
    case 0x04: { float f; memcpy(&f, &data, 4); snprintf(buf, sizeof(buf), "%g", f); a.value = buf; a.type = "float"; break; }
    case 0x05: a.value = formatComplex(data, false); a.type = "dimension"; break;
    case 0x06: a.value = formatComplex(data, true); a.type = "fraction"; break;
    case 0x10: snprintf(buf, sizeof(buf), "%d", (int32_t)data); a.value = buf; a.type = "int"; break;
    case 0x11: snprintf(buf, sizeof(buf), "0x%x", data); a.value = buf; a.type = "hex"; break;
    case 0x12: a.value = data ? "true" : "false"; a.type = "boolean"; break;
    case 0x1c: case 0x1d: case 0x1e: case 0x1f:
        snprintf(buf, sizeof(buf), "#%06x", data & 0xFFFFFF); a.value = buf; a.type = "color"; break;
    default: snprintf(buf, sizeof(buf), "0x%08x (type 0x%02x)", data, dataType); a.value = buf; a.type = "unknown"; break;
    }
    return a;
}

bool axmlParse(const uint8_t* d, size_t n, AxmlNode& root, std::string& errOut) {
    AxmlCtx c;
    c.d = d;
    c.n = n;
    Rd top(d, n);
    uint16_t topType = top.u16();
    top.u16();
    top.u32();
    if (top.err || topType != 0x0003) { errOut = "not a binary XML document"; return false; }

    std::vector<AxmlNode*> stack;
    std::vector<std::pair<std::string, std::string>> nsMap;
    root = AxmlNode();

    Rd r(d, n, 8);
    while (r.ok() && r.o + 8 <= n && c.err.empty()) {
        uint16_t type = r.u16();
        r.u16();
        uint32_t size = r.u32();
        if (size < 8 || r.o - 8 + size > n) { errOut = "chunk overruns buffer"; return false; }
        size_t next = r.o - 8 + size;
        if (type == 0x0001) {
            if (!c.loadStrings(d + r.o - 8, size)) { errOut = c.err; return false; }
        } else if (type == 0x0100) {
            Rd x(d, n, r.o);
            x.u32(); x.u32();
            uint32_t nsIdx = x.u32(), nameIdx = x.u32();
            nsMap.push_back({ c.str(nameIdx), c.str(nsIdx) });
            (void)nsIdx;
        } else if (type == 0x0101) {
            if (!nsMap.empty()) nsMap.pop_back();
        } else if (type == 0x0102) {
            Rd x(d, n, r.o);
            x.u32(); x.u32();
            uint32_t nsIdx = x.u32(), nameIdx = x.u32();
            x.u16();
            x.u16();
            uint16_t attrCount = x.u16();
            x.u16(); x.u16(); x.u16();
            AxmlNode node;
            node.tag = c.str(nameIdx);
            if (attrCount > 256) attrCount = 256;
            for (uint16_t i = 0; i < attrCount && x.ok(); i++) {
                uint32_t aNs = x.u32(), aName = x.u32(), aRaw = x.u32();
                x.u16();
                x.u8();
                uint8_t dt = x.u8();
                uint32_t aData = x.u32();
                if (x.err) break;
                node.attrs.push_back(formatAttr(c, aNs, aName, aRaw, dt, aData));
            }
            if (stack.empty()) {
                root = std::move(node);
                stack.push_back(&root);
            } else {
                AxmlNode* parent = stack.back();
                parent->children.push_back(std::move(node));
                stack.push_back(&parent->children.back());
            }
        } else if (type == 0x0103) {
            if (!stack.empty()) stack.pop_back();
        } else if (type == 0x0104) {
        }
        r.seek(next);
    }
    if (c.err.size()) { errOut = c.err; return false; }
    if (root.tag.empty()) { errOut = "no root element"; return false; }
    return true;
}

void axmlWriteTree(const AxmlNode& node, Builder& b, int depth, int& budget) {
    if (budget <= 0 || depth > 12) return;
    budget--;
    b.beginObj();
    b.kv("tag", node.tag);
    b.arr("attrs");
    for (auto& a : node.attrs) {
        b.beginObj();
        b.kv("name", a.name);
        b.kv("value", a.value);
        b.endObj();
    }
    b.endArr();
    b.arr("children");
    for (auto& ch : node.children) axmlWriteTree(ch, b, depth + 1, budget);
    b.endArr();
    b.endObj();
}

}
