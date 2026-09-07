#include "../formats.h"
#include "../jsonw.h"
#include "../jsonr.h"
#include "../util.h"
#include "../hashes.h"
#include "../pe.h"
#include "../risk.h"
#include "../report.h"
#include <cstdio>
#include <cstring>
#include <cstdlib>
#include <string>
#include <vector>
#include <chrono>

#ifdef _WIN32
#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#include <io.h>
#define isatty _isatty
#define fileno _fileno
#else
#include <unistd.h>
#endif

using namespace cb;

#define CB_VERSION "2.0.0"

static void printUsage();

static bool g_color = false;

static std::string esc(int c) { return std::string("\x1b[") + std::to_string(c) + "m"; }
static std::string R() { return g_color ? esc(0) : ""; }
static std::string B() { return g_color ? esc(1) : ""; }
static std::string DIM() { return g_color ? esc(2) : ""; }
static std::string RED() { return g_color ? esc(31) : ""; }
static std::string GRN() { return g_color ? esc(32) : ""; }
static std::string YEL() { return g_color ? esc(33) : ""; }
static std::string BLU() { return g_color ? esc(34) : ""; }
static std::string MAG() { return g_color ? esc(35) : ""; }
static std::string CYN() { return g_color ? esc(36) : ""; }
static std::string WHT() { return g_color ? esc(37) : ""; }
static std::string REDB() { return g_color ? esc(41) : ""; }

static bool stdoutIsTty() { return isatty(fileno(stdout)) != 0; }

static void initColor() {
    g_color = stdoutIsTty();
#ifdef _WIN32
    if (g_color) {
        HANDLE h = GetStdHandle(STD_OUTPUT_HANDLE);
        DWORD m = 0;
        if (GetConsoleMode(h, &m)) SetConsoleMode(h, m | ENABLE_VIRTUAL_TERMINAL_PROCESSING);
    }
#endif
}

static std::string riskColor(const std::string& level) {
    std::string l = level;
    for (auto& c : l) if (c >= 'A' && c <= 'Z') c = (char)(c + 32);
    if (l == "critical") return REDB();
    if (l == "high") return RED();
    if (l == "medium") return YEL();
    return GRN();
}

static std::string sevColor(int sev) {
    if (sev >= 2) return RED();
    if (sev == 1) return YEL();
    return DIM();
}

static void rule(const std::string& title) {
    fprintf(stdout, "%s%s %s %s\n", CYN().c_str(), std::string(8, '=').c_str(), title.c_str(), std::string(8, '=').c_str());
}

static std::vector<std::string> splitArgs(const std::string& line) {
    std::vector<std::string> out;
    std::string cur;
    bool inq = false;
    for (char ch : line) {
        if (ch == '"') { inq = !inq; continue; }
        if (ch == ' ' || ch == '\t' || ch == '\r' || ch == '\n') {
            if (!inq && !cur.empty()) { out.push_back(cur); cur.clear(); }
            else if (inq) cur += ch;
        } else cur += ch;
    }
    if (!cur.empty()) out.push_back(cur);
    return out;
}

static std::string fileBase(const std::string& p) {
    size_t s = p.find_last_of("/\\");
    return s == std::string::npos ? p : p.substr(s + 1);
}

static void emitValue(Builder& b, const JVal& v) {
    switch (v.type) {
    case JVal::NUL: b.valNull(); break;
    case JVal::BOOL: b.valB(v.b); break;
    case JVal::NUM:
        if (v.num == (double)(long long)v.num && v.num >= -9.007199254740992e15 && v.num <= 9.007199254740992e15)
            b.valI((long long)v.num);
        else b.valD(v.num);
        break;
    case JVal::STR: b.valStr(v.str); break;
    case JVal::ARR:
        b.beginArr();
        for (const JVal& e : v.arr) emitValue(b, e);
        b.endArr();
        break;
    case JVal::OBJ: {
        b.beginObj();
        for (const auto& p : v.props) { b.key(p.first.c_str()); emitValue(b, p.second); }
        b.endObj();
        break;
    }
    }
}

static void emitTop(const JVal& v, const char* key, std::string& out) {
    Builder b(out);
    b.beginObj();
    b.key(key);
    emitValue(b, v);
    b.endObj();
}

static std::string scalarText(const JVal& v) {
    switch (v.type) {
    case JVal::NUL: return "null";
    case JVal::BOOL: return v.b ? "true" : "false";
    case JVal::NUM: {
        double d = v.num;
        if (d == (double)(long long)d && d > -9.2e15 && d < 9.2e15) return std::to_string((long long)d);
        return std::to_string(d);
    }
    case JVal::STR: return v.str;
    default: return "";
    }
}

static std::string prettyJson(const std::string& j) {
    int depth = 0;
    std::string o;
    o.reserve(j.size() * 2);
    bool instr = false, escq = false;
    for (char ch : j) {
        if (instr) {
            o += ch;
            if (escq) escq = false;
            else if (ch == '\\') escq = true;
            else if (ch == '"') instr = false;
            continue;
        }
        if (ch == '"') { instr = true; o += ch; continue; }
        if (ch == '{' || ch == '[') { o += ch; depth++; o += '\n'; o.append((size_t)depth * 2, ' '); }
        else if (ch == '}' || ch == ']') { depth--; o += '\n'; o.append((size_t)depth * 2, ' '); o += ch; }
        else if (ch == ',') { o += ",\n"; o.append((size_t)depth * 2, ' '); }
        else if (ch == ':') o += ": ";
        else o += ch;
    }
    return o;
}

static bool writeFileUtf8(const std::string& path, const std::string& content, std::string& err) {
    FILE* f = nullptr;
#ifdef _WIN32
    std::wstring w = utf8ToWide(path);
    f = _wfopen(w.c_str(), L"wb");
#else
    f = fopen(path.c_str(), "wb");
#endif
    if (!f) { err = "cannot write file: " + path; return false; }
    fwrite(content.data(), 1, content.size(), f);
    fclose(f);
    return true;
}

struct Analysis {
    std::string raw;
    JVal doc;
    double ms = 0;
    bool ok = false;
    std::string error;
};

static Analysis analyzePath(const std::string& path) {
    Analysis a;
    std::vector<uint8_t> d;
    if (!readFileBytes(path, d, a.error)) { a.error = "cannot open: " + a.error; return a; }
    FileInfo fi = queryFileInfo(path);
    auto t0 = std::chrono::steady_clock::now();
    AnalysisOutput ao = analyzeFile(d.data(), d.size(), path, fi);
    auto t1 = std::chrono::steady_clock::now();
    a.ms = std::chrono::duration<double, std::milli>(t1 - t0).count();
    if (!ao.ok) { a.error = "analysis failed"; return a; }
    a.raw = ao.json;
    a.ok = jsonParse(ao.json, a.doc) && a.doc.type == JVal::OBJ;
    if (!a.ok) { a.error = "could not parse analysis"; return a; }
    return a;
}

static void withAnalysisMs(std::string& json, double ms) {
    if (json.empty() || json.back() != '}') return;
    char mb[40];
    snprintf(mb, sizeof(mb), "%.1f", ms);
    json.insert(json.size() - 1, ", \"analysisMs\": " + std::string(mb));
}

static void o(const std::string& s) { fputs(s.c_str(), stdout); }

static std::string padTo(const std::string& s, size_t n) {
    std::string r = s;
    if (r.size() < n) r.append(n - r.size(), ' ');
    return r;
}

static void renderHuman(const JVal& doc, const std::string& path, double ms) {
    const JVal* file = doc.get("file");
    const JVal* fmt = doc.get("format");
    const JVal* risk = doc.get("risk");
    const JVal* hashes = doc.get("hashes");
    const JVal* ent = doc.get("entropy");
    const JVal* inds = doc.get("indicators");

    std::string name = fileBase(path);
    std::string s;
    s += "\n";
    s += CYN() + "========== " + B() + name + R() + CYN() + " ==========" + R() + "\n";
    s += "\n";
    s += padTo("  Path", 12) + WHT() + path + R() + "\n";
    if (file) {
        double sz = file->getNum("size");
        std::string szs = file->getStr("sizeHuman") + "  (" + std::to_string((long long)sz) + " bytes)";
        s += padTo("  Size", 12) + szs + "\n";
        if (!file->getStr("modified").empty()) s += padTo("  Modified", 12) + file->getStr("modified") + "\n";
        if (!file->getStr("created").empty()) s += padTo("  Created", 12) + file->getStr("created") + "\n";
    }
    if (fmt) s += padTo("  Format", 12) + WHT() + fmt->getStr("label") + R() + "\n";
    if (ent) {
        char eb[40];
        snprintf(eb, sizeof(eb), "%.2f / 8.00", ent->getNum("overall", 0));
        s += padTo("  Entropy", 12) + eb + "\n";
    }
    if (hashes) {
        s += "\n";
        s += CYN() + "========== " + "Hashes" + " ==========" + R() + "\n";
        s += "  SHA-256  " + WHT() + hashes->getStr("sha256") + R() + "\n";
        s += "  SHA-1    " + hashes->getStr("sha1") + "\n";
        s += "  MD5      " + hashes->getStr("md5") + "\n";
        s += "  CRC-32   " + hashes->getStr("crc32") + "\n";
    }
    if (risk) {
        std::string lvl = risk->getStr("level");
        long long score = (long long)risk->getNum("score", 0);
        s += "\n";
        s += CYN() + "========== " + "Risk" + " ==========" + R() + "\n";
        s += "  " + B() + riskColor(lvl) + "RISK " + lvl + " " + std::to_string(score) + "/100" + R() + "\n";
        std::string summary = risk->getStr("summary");
        if (!summary.empty()) s += "  " + DIM() + summary + R() + "\n";
        const JVal* tf = risk->get("topFindings");
        if (tf && tf->type == JVal::ARR && !tf->arr.empty()) {
            s += "\n";
            for (const JVal& f : tf->arr)
                s += "    " + YEL() + "*" + R() + " " + WHT() + scalarText(f) + R() + "\n";
        }
    }
    if (inds && inds->type == JVal::ARR && !inds->arr.empty()) {
        s += "\n";
        s += CYN() + "========== " + "Indicators" + " ==========" + R() + "\n";
        for (const JVal& i : inds->arr) {
            int sev = i.getInt("severityNum", i.getInt("severity", 0));
            s += "  " + B() + "[" + sevColor(sev) + i.getStr("severity") + R() + B() + "]" + R() + " " +
                 WHT() + i.getStr("title") + R() + "\n";
            std::string det = i.getStr("detail");
            if (!det.empty()) s += "      " + DIM() + det + R() + "\n";
        }
    }
    char buf[48];
    snprintf(buf, sizeof(buf), "%.2f ms", ms);
    s += "\n" + DIM() + "analysis time: " + buf + R() + "\n";
    o(s);
}

static void renderStringsHuman(const std::string& path, const std::string& pat,
                               uint32_t minLen, int kind, uint32_t count) {
    std::vector<uint8_t> d;
    std::string err;
    if (!readFileBytes(path, d, err)) { fprintf(stderr, "error: %s\n", err.c_str()); return; }
    StringsIndex si;
    si.build(d.data(), d.size(), minLen, 2000000);
    std::string j;
    Builder b(j);
    b.beginObj();
    b.key("items");
    uint64_t total = 0;
    si.query(b, 0, count, minLen, kind, pat, total);
    b.kv("total", total);
    b.endObj();
    JVal doc;
    if (!jsonParse(j, doc)) return;
    const JVal* items = doc.get("items");
    std::string s;
    s += "\n";
    s += CYN() + "========== " + "strings of " + fileBase(path) + " ==========" + R() + "\n";
    if (items) {
        for (const JVal& it : items->arr) {
            char o2[32];
            snprintf(o2, sizeof(o2), "0x%-8llx", (unsigned long long)(uint64_t)it.getNum("off"));
            s += "  " + DIM() + o2 + R() + " " + WHT() + it.getStr("text") + R() + "\n";
        }
    }
    if (total > count) s += DIM() + "  ... " + std::to_string((long long)(total - count)) + " more (use --count)" + R() + "\n";
    else if (total == 0) s += "  none found\n";
    o(s);
}

static void renderHexHuman(const std::string& path, uint64_t off, uint64_t len) {
    std::vector<uint8_t> d;
    std::string err;
    if (!readFileBytes(path, d, err)) { fprintf(stderr, "error: %s\n", err.c_str()); return; }
    uint64_t end = off + len < d.size() ? off + len : d.size();
    std::string s;
    s += "\n";
    s += CYN() + "========== " + "hex " + fileBase(path) + " @ " + hexU(off) + " ==========" + R() + "\n";
    for (uint64_t row = off; row < end; row += 16) {
        char r2[32];
        snprintf(r2, sizeof(r2), "0x%08llx", (unsigned long long)row);
        s += "  " + CYN() + r2 + R() + "  ";
        std::string asc;
        for (uint64_t i = row; i < row + 16; i++) {
            if (i < end) {
                unsigned char c = d[(size_t)i];
                char hb[4];
                snprintf(hb, sizeof(hb), "%02x ", c);
                s += hb;
                asc += (c >= 0x20 && c < 0x7F) ? (char)c : '.';
            } else s += "   ";
        }
        s += " " + DIM() + "|" + asc + "|" + R() + "\n";
    }
    o(s);
}

static int cmdRisk(const Analysis& a, bool indent) {
    const JVal* risk = a.doc.get("risk");
    if (!risk) { fprintf(stderr, "no risk section\n"); return 1; }
    std::string out;
    emitTop(*risk, "risk", out);
    printf("%s\n", indent ? prettyJson(out).c_str() : out.c_str());
    return 0;
}

static int cmdFull(const Analysis& a, bool indent) {
    std::string j = a.raw;
    withAnalysisMs(j, a.ms);
    printf("%s\n", indent ? prettyJson(j).c_str() : j.c_str());
    return 0;
}

static int cmdHash(const std::string& path) {
    Analysis a = analyzePath(path);
    if (!a.ok) { fprintf(stderr, "error: %s\n", a.error.c_str()); return 1; }
    return cmdFull(a, false);
}

static int runSingle(const std::vector<std::string>& args) {
    std::string path = args[0];
    std::string pat;
    std::string reportPath;
    bool view = false, json = false, pretty = false, risk = false, strings = false;
    bool hex = false, indent = false;
    uint32_t minLen = 4, count = 300;
    uint64_t hexOff = 0, hexLen = 256;
    int kind = 0;
    for (size_t i = 1; i < args.size(); i++) {
        std::string a = args[i];
        if (a == "--view") view = true;
        else if (a == "--json") json = true;
        else if (a == "--pretty") pretty = true;
        else if (a == "--indent") indent = true;
        else if (a == "--risk") risk = true;
        else if (a == "--strings") { strings = true; if (i + 1 < args.size() && args[i + 1][0] != '-') pat = args[++i]; }
        else if (a == "--min-len" && i + 1 < args.size()) minLen = (uint32_t)strtoul(args[++i].c_str(), nullptr, 0);
        else if (a == "--kind" && i + 1 < args.size()) { std::string k = args[++i]; kind = k == "ascii" ? 1 : k == "wide" ? 2 : 0; }
        else if (a == "--count" && i + 1 < args.size()) count = (uint32_t)strtoul(args[++i].c_str(), nullptr, 0);
        else if (a == "--hex" && i + 1 < args.size()) { hex = true; hexOff = strtoull(args[++i].c_str(), nullptr, 0); }
        else if (a == "--hex-len" && i + 1 < args.size()) hexLen = strtoull(args[++i].c_str(), nullptr, 0);
        else if (a == "--report" && i + 1 < args.size()) reportPath = args[++i];
        else { fprintf(stderr, "unknown option: %s\n", a.c_str()); return 2; }
    }

    if (strings) {
        std::vector<uint8_t> d;
        std::string err;
        if (!readFileBytes(path, d, err)) { fprintf(stderr, "error: %s\n", err.c_str()); return 1; }
        StringsIndex si;
        si.build(d.data(), d.size(), minLen, 2000000);
        std::string j;
        Builder b(j);
        b.beginObj();
        b.key("items");
        uint64_t total = 0;
        si.query(b, 0, count, minLen, kind, pat, total);
        b.kv("total", total);
        b.endObj();
        bool human = view || (!json && !indent && stdoutIsTty());
        if (human) renderStringsHuman(path, pat, minLen, kind, count);
        else printf("%s\n", indent ? prettyJson(j).c_str() : j.c_str());
        return 0;
    }
    if (hex) {
        std::vector<uint8_t> d;
        std::string err;
        if (!readFileBytes(path, d, err)) { fprintf(stderr, "error: %s\n", err.c_str()); return 1; }
        bool human = view || (!json && !indent && stdoutIsTty());
        if (human) { renderHexHuman(path, hexOff, hexLen); return 0; }
        std::string j;
        Builder b(j);
        b.beginObj();
        b.kv("offset", hexOff);
        b.kv("length", hexLen);
        b.arr("bytes");
        uint64_t lim = hexOff + hexLen < d.size() ? hexOff + hexLen : d.size();
        for (uint64_t i = hexOff; i < lim; i++) b.valU(d[(size_t)i]);
        b.endArr();
        b.endObj();
        printf("%s\n", j.c_str());
        return 0;
    }

    Analysis a = analyzePath(path);
    if (!a.ok) { fprintf(stderr, "error: %s\n", a.error.c_str()); return 1; }

    int rc = 0;
    bool human = (stdoutIsTty() && !json && !indent && !risk) || view;
    if (risk) rc = cmdRisk(a, indent || pretty);
    else if (human) renderHuman(a.doc, path, a.ms);
    else rc = cmdFull(a, indent || pretty);

    if (!reportPath.empty()) {
        std::string html = buildHtmlReport(a.raw, path);
        std::string err;
        if (!writeFileUtf8(reportPath, html, err)) { fprintf(stderr, "error: %s\n", err.c_str()); return 1; }
        fprintf(stderr, "report written: %s\n", reportPath.c_str());
    }
    return rc;
}

static int cmdBatch(const std::vector<std::string>& args) {
    if (args.empty()) { printUsage(); return 2; }
    std::string dir = args[0];
    std::string jsonPath, htmlPath, csvPath;
    size_t limit = (size_t)100000;
    uint64_t maxMb = 0;
    for (size_t i = 1; i < args.size(); i++) {
        std::string a = args[i];
        if ((a == "--json" || a == "--html" || a == "--csv") && i + 1 < args.size()) {
            std::string val = args[++i];
            if (a == "--json") jsonPath = val;
            else if (a == "--html") htmlPath = val;
            else csvPath = val;
        } else if (a == "--limit" && i + 1 < args.size()) limit = (size_t)strtoul(args[++i].c_str(), nullptr, 10);
        else if (a == "--max-mb" && i + 1 < args.size()) maxMb = (uint64_t)strtoull(args[++i].c_str(), nullptr, 10);
        else if (a == "--view") { }
        else { fprintf(stderr, "unknown option: %s\n", a.c_str()); return 2; }
    }

    std::vector<std::string> files;
    std::string err;
    if (!walkDirectory(dir, files, err)) { fprintf(stderr, "error: %s\n", err.c_str()); return 1; }
    std::vector<BatchItem> items;
    auto t0 = std::chrono::steady_clock::now();
    uint64_t totalBytes = 0;
    size_t processed = 0;
    std::string full;
    Builder b(full);
    b.beginObj();
    b.obj("meta");
    b.kv("scanRoot", dir);
    b.kv("fileCount", (uint64_t)files.size());
    b.endObj();
    b.arr("items");
    for (const std::string& path : files) {
        if (processed >= limit) break;
        BatchItem it;
        it.path = path;
        FileInfo fi = queryFileInfo(path);
        if (!fi.exists || (maxMb && fi.size > maxMb * 1024ull * 1024ull)) {
            it.ok = false;
            it.error = fi.exists ? "file too large" : "stat failed";
            items.push_back(it);
            b.beginObj(); b.kv("path", path); b.kv("ok", false); b.kv("error", it.error); b.endObj();
            continue;
        }
        std::vector<uint8_t> d;
        std::string rerr;
        if (!readFileBytes(path, d, rerr)) {
            it.ok = false; it.error = rerr; items.push_back(it);
            b.beginObj(); b.kv("path", path); b.kv("ok", false); b.kv("error", rerr); b.endObj();
            continue;
        }
        totalBytes += d.size();
        it.size = d.size();
        it.sha256 = sha256Hex(d.data(), d.size());
        AnalysisOutput ao = analyzeFile(d.data(), d.size(), path, fi);
        if (!ao.ok) {
            it.ok = false; it.error = "analysis failed"; items.push_back(it);
            b.beginObj(); b.kv("path", path); b.kv("ok", false); b.kv("error", "analysis failed"); b.endObj();
            continue;
        }
        JVal doc;
        if (jsonParse(ao.json, doc)) {
            const JVal* fmt = doc.get("format");
            const JVal* risk = doc.get("risk");
            const JVal* inds = doc.get("indicators");
            if (fmt) it.format = fmt->getStr("label");
            if (risk) { it.riskScore = risk->getInt("score"); it.riskLevel = risk->getStr("level"); }
            if (inds) it.indicators = (int)inds->arr.size();
        }
        it.ok = true;
        items.push_back(it);
        processed++;
        b.beginObj();
        b.kv("path", path);
        b.kv("format", it.format);
        b.kv("size", it.size);
        b.kv("sha256", it.sha256);
        b.kv("riskScore", (int64_t)it.riskScore);
        b.kv("riskLevel", it.riskLevel);
        b.kv("indicators", (int64_t)it.indicators);
        b.kv("ok", true);
        b.endObj();
    }
    b.endArr();
    b.endObj();
    auto t1 = std::chrono::steady_clock::now();
    double ms = std::chrono::duration<double, std::milli>(t1 - t0).count();
    std::string out = full;
    char mb[48];
    snprintf(mb, sizeof(mb), ", \"durationMs\": %.1f", ms);
    out.insert(out.size() - 1, mb);

    bool table = stdoutIsTty() && jsonPath.empty() && htmlPath.empty() && csvPath.empty();
    if (table) {
        fprintf(stdout, "\n");
        rule(" batch scan of " + dir);
        fprintf(stdout, "  %-46s %-6s %6s %-8s %-9s %s\n", "Path", "Format", "Size", "Risk", "Level", "SHA-256");
        for (auto& it : items) {
            std::string shortPath = it.path;
            if (shortPath.size() > 46) shortPath = "..." + shortPath.substr(shortPath.size() - 43);
            fprintf(stdout, "  %s%-46s%s %-6s %6s %s%3d%s %-9s %s\n",
                    WHT().c_str(), shortPath.c_str(), R().c_str(),
                    it.format.empty() ? "-" : it.format.c_str(),
                    std::to_string(it.size).c_str(),
                    riskColor(it.riskLevel).c_str(), it.riskScore, R().c_str(),
                    it.riskLevel.empty() ? "-" : it.riskLevel.c_str(),
                    it.sha256.substr(0, 12).c_str());
        }
        char d[48];
        snprintf(d, sizeof(d), "%zu files  |  %.2f ms", items.size(), ms);
        fprintf(stdout, "\n%s%s%s\n", DIM().c_str(), d, R().c_str());
        return 0;
    }
    if (jsonPath.empty()) {
        printf("%s\n", out.c_str());
    } else {
        if (!writeFileUtf8(jsonPath, out, err)) { fprintf(stderr, "error: %s\n", err.c_str()); return 1; }
        printf("wrote %s (%zu files)\n", jsonPath.c_str(), items.size());
    }
    if (!htmlPath.empty()) {
        std::string html = buildBatchHtml(items, totalBytes, ms);
        if (!writeFileUtf8(htmlPath, html, err)) { fprintf(stderr, "error: %s\n", err.c_str()); return 1; }
        printf("wrote %s\n", htmlPath.c_str());
    }
    if (!csvPath.empty()) {
        std::string csv = "path,format,size,sha256,risk_score,risk_level,indicators,ok,error\n";
        for (const auto& it : items) {
            std::string safe = it.path;
            for (auto& c : safe) if (c == ',') c = ';';
            csv += "\"" + safe + "\",\"" + it.format + "\"," + std::to_string(it.size) + "," +
                   it.sha256 + "," + std::to_string(it.riskScore) + ",\"" + it.riskLevel +
                   "\"," + std::to_string(it.indicators) + "," + (it.ok ? "1" : "0") + ",\"" + it.error + "\"\n";
        }
        if (!writeFileUtf8(csvPath, csv, err)) { fprintf(stderr, "error: %s\n", err.c_str()); return 1; }
        printf("wrote %s\n", csvPath.c_str());
    }
    return 0;
}

static int cmdCompare(const std::vector<std::string>& args) {
    if (args.size() < 2) { printUsage(); return 2; }
    bool indent = false, human = false;
    for (size_t i = 2; i < args.size(); i++) {
        if (args[i] == "--indent") indent = true;
        if (args[i] == "--view") human = true;
    }
    Analysis A = analyzePath(args[0]);
    Analysis Bb = analyzePath(args[1]);
    if (!A.ok || !Bb.ok) { fprintf(stderr, "analysis error\n"); return 1; }
    const JVal* ha = A.doc.get("hashes");
    const JVal* hb = Bb.doc.get("hashes");
    const JVal* fa = A.doc.get("format");
    const JVal* fb = Bb.doc.get("format");
    const JVal* ra = A.doc.get("risk");
    const JVal* rb = Bb.doc.get("risk");
    const JVal* fa2 = A.doc.get("file");
    const JVal* fb2 = Bb.doc.get("file");
    std::string sa = ha ? ha->getStr("sha256") : "";
    std::string sb = hb ? hb->getStr("sha256") : "";

    if (human) {
        std::string la = fa ? fa->getStr("label") : "-";
        std::string lb = fb ? fb->getStr("label") : "-";
        int rsa = ra ? ra->getInt("score") : 0;
        int rsb = rb ? rb->getInt("score") : 0;
        std::string rla = ra ? ra->getStr("level") : "-";
        std::string rlb = rb ? rb->getStr("level") : "-";
        std::string s;
        s += "\n";
        s += CYN() + "========== " + "compare" + " ==========" + R() + "\n\n";
        bool id = (sa == sb && sa.size() == 64);
        s += "  identical       " + (id ? GRN() + "YES" : RED() + "NO") + R() + "\n";
        s += "  sha256Equal     " + std::string(sa == sb ? "true" : "false") + "\n\n";
        s += "  " + padTo("File", 40) + " " + padTo("Format", 30) + " " + padTo("Risk", 9) + " SHA-256\n";
        s += "  " + padTo(fileBase(args[0]), 40) + " " + padTo(la, 30) + " " +
             B() + riskColor(rla) + padTo(rla + " " + std::to_string(rsa), 9) + R() + " " + sa.substr(0, 16) + "\n";
        s += "  " + padTo(fileBase(args[1]), 40) + " " + padTo(lb, 30) + " " +
             B() + riskColor(rlb) + padTo(rlb + " " + std::to_string(rsb), 9) + R() + " " + sb.substr(0, 16) + "\n";
        o(s);
        return 0;
    }
    std::string out;
    Builder bw(out);
    bw.beginObj();
    bw.kv("identical", sa == sb && sa.size() == 64);
    bw.kv("sha256Equal", sa == sb);
    auto putSide = [&](const char* key, const JVal& d2, const JVal* fmt, const JVal* risk, const JVal* f, const JVal* h) {
        bw.obj(key);
        bw.kv("path", f ? f->getStr("path") : std::string());
        bw.kv("size", f ? (uint64_t)f->getNum("size", 0) : (uint64_t)0);
        bw.kv("sizeHuman", f ? f->getStr("sizeHuman") : std::string());
        bw.kv("format", fmt ? fmt->getStr("label") : std::string());
        bw.kv("sha256", h ? h->getStr("sha256") : std::string());
        bw.kv("md5", h ? h->getStr("md5") : std::string());
        if (risk) { bw.kv("riskScore", (int64_t)risk->getInt("score")); bw.kv("riskLevel", risk->getStr("level")); }
        const JVal* inds = d2.get("indicators");
        bw.kv("indicatorCount", inds ? (int64_t)inds->arr.size() : (int64_t)0);
        bw.endObj();
    };
    putSide("a", A.doc, fa, ra, fa2, ha);
    putSide("b", Bb.doc, fb, rb, fb2, hb);
    bw.kv("analysisMsA", A.ms);
    bw.kv("analysisMsB", Bb.ms);
    bw.endObj();
    printf("%s\n", indent ? prettyJson(out).c_str() : out.c_str());
    return 0;
}

static void printUsage() {
    fprintf(stderr,
        "CodeBreak v" CB_VERSION "  -  native binary analysis for the terminal\n"
        "\n"
        "USAGE\n"
        "  codebreak-cli <file>                       analyze a file\n"
        "        prints a colored human summary on a terminal,\n"
        "        or raw JSON when piped/redirected\n"
        "\n"
        "  codebreak-cli <file> --view                force human summary\n"
        "  codebreak-cli <file> --json                force raw JSON\n"
        "  codebreak-cli <file> --pretty              indented JSON\n"
        "  codebreak-cli <file> --risk                risk assessment JSON\n"
        "  codebreak-cli <file> --strings [PATTERN] [--min-len N]\n"
        "                        [--kind all|ascii|wide] [--count N]\n"
        "  codebreak-cli <file> --hex OFFSET [--hex-len N]\n"
        "  codebreak-cli <file> --report OUT.html\n"
        "  codebreak-cli --batch DIR [--json F] [--csv F] [--html F] [--limit N] [--max-mb N]\n"
        "  codebreak-cli --compare <a> <b> [--view]\n"
        "  codebreak-cli --hash <file>\n"
        "  codebreak-cli --version    |    -h\n"
        "\n"
        "Run with no arguments to open the interactive shell.\n");
}

static void printHelp() {
    printUsage();
    fprintf(stdout,
        "\n"
        "INTERACTIVE SHELL\n"
        "  <file>               analyze (human summary)\n"
        "  json <file>          analyze (raw JSON)\n"
        "  risk <file>          risk assessment\n"
        "  strings <file> ...   extract strings\n"
        "  hex <file> OFFSET    hex dump\n"
        "  compare <a> <b>      compare two files\n"
        "  hash <file>          full JSON for one file\n"
        "  batch <dir>          scan a directory\n"
        "  report <file>        write an HTML report\n"
        "  version / help / clear / exit\n"
        "\n");
}

static std::vector<std::string> g_history;
static std::string g_histFile;

static void loadHistory() {
#ifdef _WIN32
    const char* app = getenv("APPDATA");
    if (!app) return;
    g_histFile = std::string(app) + "\\CodeBreak.history";
#else
    const char* home = getenv("HOME");
    if (!home) return;
    g_histFile = std::string(home) + "/.codebreak_history";
#endif
    FILE* f = fopen(g_histFile.c_str(), "r");
    if (!f) return;
    char line[4096];
    while (fgets(line, sizeof(line), f)) {
        size_t n = strlen(line);
        while (n && (line[n - 1] == '\n' || line[n - 1] == '\r')) line[--n] = 0;
        if (n) g_history.push_back(line);
    }
    fclose(f);
}

static void saveHistory() {
    if (g_histFile.empty()) return;
    FILE* f = fopen(g_histFile.c_str(), "w");
    if (!f) return;
    for (auto& h : g_history) fprintf(f, "%s\n", h.c_str());
    fclose(f);
}

static void addHistory(const std::string& line) {
    if (line.empty()) return;
    if (!g_history.empty() && g_history.back() == line) return;
    g_history.push_back(line);
    if (g_history.size() > 500) g_history.erase(g_history.begin());
}

static void runInteractive();

static int runTokens(const std::vector<std::string>& args) {
    if (args.empty()) { runInteractive(); return 0; }
    std::string first = args[0];

    if (first == "--compare" || first == "-c" || first == "compare")
        return cmdCompare(std::vector<std::string>(args.begin() + 1, args.end()));
    if (first == "--batch" || first == "-b" || first == "batch")
        return cmdBatch(std::vector<std::string>(args.begin() + 1, args.end()));
    if (first == "--hash" || first == "hash") {
        if (args.size() < 2) { printUsage(); return 2; }
        return cmdHash(args[1]);
    }
    if (first == "--version" || first == "version") { printf("CodeBreak v%s\n", CB_VERSION); return 0; }
    if (first == "-h" || first == "--help" || first == "help") { printUsage(); return 0; }
    if (first == "json") {
        if (args.size() < 2) { fprintf(stderr, "usage: json <file>\n"); return 2; }
        Analysis a = analyzePath(args[1]);
        if (!a.ok) { fprintf(stderr, "error: %s\n", a.error.c_str()); return 1; }
        return cmdFull(a, false);
    }
    if (first == "risk") {
        if (args.size() < 2) { fprintf(stderr, "usage: risk <file>\n"); return 2; }
        std::vector<std::string> sub = { args[1] };
        for (size_t i = 2; i < args.size(); i++) sub.push_back(args[i]);
        sub.push_back("--risk");
        return runSingle(sub);
    }
    if (first == "strings") {
        if (args.size() < 2) { fprintf(stderr, "usage: strings <file> [PATTERN] [--min-len N]\n"); return 2; }
        std::vector<std::string> sub = { args[1], "--strings" };
        for (size_t i = 2; i < args.size(); i++) sub.push_back(args[i]);
        sub.push_back("--view");
        return runSingle(sub);
    }
    if (first == "hex") {
        if (args.size() < 2) { fprintf(stderr, "usage: hex <file> [OFFSET]\n"); return 2; }
        std::vector<std::string> sub = { args[1], "--hex", args.size() > 2 ? args[2] : "0" };
        for (size_t i = 3; i < args.size(); i++) sub.push_back(args[i]);
        sub.push_back("--view");
        return runSingle(sub);
    }
    if (first == "analyze" || first == "open" || first == "view") {
        if (args.size() < 2) { fprintf(stderr, "usage: %s <file>\n", first.c_str()); return 2; }
        std::vector<std::string> sub(args.begin() + 1, args.end());
        sub.push_back("--view");
        return runSingle(sub);
    }
    if (first == "report") {
        if (args.size() < 2) { fprintf(stderr, "usage: report <file> [OUT.html]\n"); return 2; }
        std::string out = args.size() > 2 ? args[2] : (fileBase(args[1]) + ".html");
        std::vector<std::string> sub = { args[1], "--report", out, "--view" };
        return runSingle(sub);
    }
    if (first == "clear") { fprintf(stdout, "\x1b[2J\x1b[H"); return 0; }
    if (first == "exit" || first == "quit" || first == "q") return -100;

    return runSingle(args);
}

static void runInteractive() {
    loadHistory();
    printHelp();
    fprintf(stdout, "Type a command and press Enter. Files/paths with spaces must be quoted.\n\n");
    for (;;) {
        fprintf(stdout, "%scodebreak>%s ", GRN().c_str(), R().c_str());
        fflush(stdout);
        std::string line;
        int c;
        bool any = false;
        while ((c = getchar()) != EOF && c != '\n') { line += (char)c; any = true; }
        if (!any && c == EOF) { fprintf(stdout, "\n"); break; }
        std::vector<std::string> t = splitArgs(line);
        if (t.empty()) continue;
        std::string cmd = t[0];
        for (auto& ch : cmd) if (ch >= 'A' && ch <= 'Z') ch = (char)(ch + 32);
        if (cmd == "exit" || cmd == "quit" || cmd == "q") { addHistory(line); break; }
        if (cmd == "history") {
            for (size_t i = 0; i < g_history.size(); i++) fprintf(stdout, "  %3zu  %s\n", i + 1, g_history[i].c_str());
            continue;
        }
        addHistory(line);
        std::vector<std::string> tt = t;
        for (auto& ch : tt[0]) if (ch >= 'A' && ch <= 'Z') ch = (char)(ch + 32);
        int rc = runTokens(tt);
        if (rc == -100) break;
        fprintf(stdout, "\n");
    }
    saveHistory();
}

int main(int argc, char** argv) {
    initColor();
    if (argc < 2) {
        runInteractive();
        return 0;
    }
    std::vector<std::string> args(argv + 1, argv + argc);
    return runTokens(args);
}
