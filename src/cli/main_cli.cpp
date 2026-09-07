#include "../formats.h"
#include "../jsonw.h"
#include "../jsonr.h"
#include "../util.h"
#include "../hashes.h"
#include "../pe.h"
#include "../risk.h"
#include "../behavior.h"
#include "../disasm.h"
#include "../report.h"
#include <cstdio>
#include <cstring>
#include <cstdlib>
#include <string>
#include <vector>
#include <set>
#include <map>
#include <algorithm>
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

static void collectImports(const JVal& doc, std::vector<std::string>& out) {
    const JVal* pe = doc.get("pe");
    if (!pe) return;
    const JVal* imports = pe->get("imports");
    if (!imports || imports->type != JVal::ARR) return;
    for (const JVal& mod : imports->arr) {
        const JVal* funcs = mod.get("functions");
        if (!funcs || funcs->type != JVal::ARR) continue;
        for (const JVal& f : funcs->arr) {
            std::string nm = f.getStr("name");
            if (!nm.empty() && out.size() < 600) out.push_back(nm);
        }
    }
}

static std::string asciiLowerName(const std::string& p) {
    std::string r = p;
    for (auto& c : r) if (c >= 'A' && c <= 'Z') c = (char)(c + 32);
    return r;
}

static std::string behaviorHumanText(const BehaviorResult& br) {
    std::string s;
    s += "\n";
    s += CYN() + "========== Host behavior (static) ==========" + R() + "\n";
    if (br.endpoints.empty() && br.filePaths.empty() && br.commands.empty() &&
        br.persistence.empty() && br.networkApis.empty() && br.fileApis.empty() &&
        br.processApis.empty() && br.persistenceApis.empty()) {
        s += "  " + DIM() + "no suspicious network, file or process signals found" + R() + "\n";
        return s;
    }
    if (!br.endpoints.empty()) {
        s += "\n" + B() + WHT() + "NETWORK TARGETS" + R() + "\n";
        for (const auto& e : br.endpoints) {
            const char* tag = e.kind == "url" ? "url   " : e.kind == "ip" ? "ip    " : e.kind == "email" ? "email " : "domain";
            s += "  " + (e.kind == "ip" ? YEL() : GRN()) + "[" + std::string(tag) + "]" + R() + " " + WHT() + e.value + R() + "\n";
        }
    }
    if (!br.filePaths.empty()) {
        s += "\n" + B() + WHT() + "FILES / PATHS TOUCHED" + R() + "\n";
        for (const auto& p : br.filePaths) s += "  " + CYN() + p + R() + "\n";
    }
    if (!br.commands.empty()) {
        s += "\n" + B() + WHT() + "COMMANDS / LAUNCHES" + R() + "\n";
        for (const auto& c : br.commands) s += "  " + RED() + c + R() + "\n";
    }
    if (!br.persistence.empty()) {
        s += "\n" + B() + WHT() + "PERSISTENCE CANDIDATES" + R() + "\n";
        for (const auto& p : br.persistence) s += "  " + YEL() + p + R() + "\n";
    }
    auto apiBlock = [&](const char* title, const std::vector<std::string>& apis) {
        if (apis.empty()) return;
        s += "\n" + B() + WHT() + std::string(title) + " (imported APIs)" + R() + "\n";
        std::string line = "  ";
        for (size_t i = 0; i < apis.size(); i++) {
            line += DIM() + apis[i] + R();
            if (i + 1 < apis.size()) line += ", ";
            if (line.size() > 96) { s += line + "\n"; line = "  "; }
        }
        if (line != "  ") s += line + "\n";
    };
    apiBlock("NETWORK", br.networkApis);
    apiBlock("FILE SYSTEM", br.fileApis);
    apiBlock("PROCESS / CODE", br.processApis);
    apiBlock("PERSISTENCE", br.persistenceApis);
    return s;
}

static int cmdBehavior(const std::string& path, bool indent) {
    std::vector<uint8_t> d;
    std::string err;
    if (!readFileBytes(path, d, err)) { fprintf(stderr, "error: %s\n", err.c_str()); return 1; }
    Analysis a = analyzePath(path);
    std::vector<std::string> imports;
    if (a.ok) collectImports(a.doc, imports);
    BehaviorResult br = analyzeBehavior(d.data(), d.size(), imports, asciiLowerName(path));
    std::string j;
    Builder b(j);
    b.beginObj();
    writeBehaviorJson(b, br);
    b.endObj();
    bool human = !indent && stdoutIsTty();
    if (human) { o(behaviorHumanText(br)); return 0; }
    printf("%s\n", indent ? prettyJson(j).c_str() : j.c_str());
    return 0;
}

struct AsmLine {
    uint64_t addr;
    std::string bytes;
    std::string text;
    bool hasTarget;
    uint64_t target;
    bool isCall;
    bool isJump;
};

static uint64_t jnumOf(const JVal* v) {
    if (!v) return 0;
    if (v->type == JVal::NUM) return (uint64_t)v->num;
    if (v->type == JVal::STR) return strtoull(v->str.c_str(), nullptr, 0);
    return 0;
}

static const JVal* findCodeSection(const JVal& doc, std::string& nameOut) {
    const JVal* fmtRoot = doc.get("pe");
    const JVal* sections = nullptr;
    if (fmtRoot) {
        sections = fmtRoot->get("sections");
        std::string want = fmtRoot->getStr("entryPointSection");
        if (!want.empty() && sections && sections->type == JVal::ARR)
            for (const JVal& s : sections->arr)
                if (s.getStr("name") == want) { nameOut = want; return &s; }
    } else {
        fmtRoot = doc.get("elf");
        if (fmtRoot) {
            sections = fmtRoot->get("sections");
            if (sections && sections->type == JVal::ARR)
                for (const JVal& s : sections->arr)
                    if (s.getStr("name") == ".text") { nameOut = ".text"; return &s; }
        }
    }
    if (sections && sections->type == JVal::ARR) {
        for (const JVal& s : sections->arr) {
            if (s.getInt("executable", 0)) { nameOut = s.getStr("name"); return &s; }
        }
        if (!sections->arr.empty()) { nameOut = sections->arr[0].getStr("name"); return &sections->arr[0]; }
    }
    return nullptr;
}


static std::string asmHexByte(uint8_t c) {
    static const char* h = "0123456789abcdef";
    std::string s;
    s += h[c >> 4]; s += h[c & 15];
    return s;
}

static std::string hexId(uint64_t v) {
    std::string h = hexU(v, 0);
    return (h.size() > 2 && h[0] == '0' && (h[1] == 'x' || h[1] == 'X')) ? h.substr(2) : h;
}

static std::string asmHumanText(const std::vector<AsmLine>& lines, uint64_t base, uint64_t length,
                                const std::string& section, size_t limit) {
    std::vector<uint64_t> subs, locs;
    uint64_t hi = base + (length ? length : 0);
    for (const AsmLine& L : lines) {
        if (!L.hasTarget || L.target < base || (hi && L.target > hi)) continue;
        if (L.isCall) subs.push_back(L.target);
        else locs.push_back(L.target);
    }
    std::vector<std::pair<uint64_t, std::string>> lab;
    for (uint64_t a : subs) {
        bool d = false;
        for (auto& q : lab) if (q.first == a) { d = true; break; }
        if (!d) lab.push_back({ a, "sub_" + hexId(a) });
    }
    for (uint64_t a : locs) {
        bool d = false;
        for (auto& q : lab) if (q.first == a) { d = true; break; }
        if (!d) lab.push_back({ a, "loc_" + hexId(a) });
    }
    auto labFor = [&](uint64_t a) {
        for (auto& q : lab) if (q.first == a) return q.second;
        return std::string();
    };

    std::string s;
    s += "\n";
    std::string t = section.empty() ? std::string("code") : section;
    s += CYN() + "========== " + t + " (x86-64 disassembly) ==========" + R() + "\n";
    char sb[64];
    snprintf(sb, sizeof(sb), "%s @ 0x%llx  (%llu bytes)", section.empty() ? "code" : section.c_str(),
             (unsigned long long)base, (unsigned long long)length);
    s += DIM() + "  " + sb + R() + "\n\n";
    size_t n = 0;
    for (const AsmLine& L : lines) {
        if (limit && n >= limit) {
            s += DIM() + "  ... (use 'asm' for the full listing)" + R() + "\n";
            break;
        }
        std::string lb = labFor(L.addr);
        if (!lb.empty()) s += B() + WHT() + "        " + lb + ":" + R() + "\n";
        char ad[24];
        snprintf(ad, sizeof(ad), "0x%06llx", (unsigned long long)L.addr);
        std::string ln = "  " + CYN() + ad + R() + "  ";
        std::string bytes = L.bytes;
        if (bytes.size() < 23) bytes.append(23 - bytes.size(), ' ');
        ln += DIM() + bytes + R() + "  ";
        ln += WHT() + L.text + R();
        if (L.hasTarget) {
            std::string lf = labFor(L.target);
            if (!lf.empty()) ln += "  " + DIM() + "; " + lf + R();
        }
        s += ln + "\n";
        n++;
    }
    if (lines.empty()) s += DIM() + "  no decodable code bytes" + R() + "\n";
    return s;
}

static int cmdAsm(const std::string& path, uint64_t setOff, uint64_t setBase, uint64_t setLen) {
    std::vector<uint8_t> d;
    std::string err;
    if (!readFileBytes(path, d, err)) { fprintf(stderr, "error: %s\n", err.c_str()); return 1; }
    Analysis a = analyzePath(path);
    uint64_t fileOff = 0, base = 0, length = 0;
    std::string section;
    if (a.ok) {
        const JVal* sec = findCodeSection(a.doc, section);
        if (sec) {
            fileOff = jnumOf(sec->get("rawOffset"));
            if (!fileOff) fileOff = jnumOf(sec->get("offset"));
            uint64_t rawSize = jnumOf(sec->get("rawSize"));
            uint64_t sz = jnumOf(sec->get("size"));
            length = rawSize ? rawSize : sz;
            uint64_t vaddr = jnumOf(sec->get("virtualAddress"));
            uint64_t saddr = jnumOf(sec->get("addr"));
            base = vaddr ? vaddr : saddr;
            if (a.doc.get("pe")) {
                uint64_t imageBase = jnumOf(a.doc.get("pe") ? a.doc.get("pe")->get("imageBase") : nullptr);
                if (imageBase) base = imageBase + (vaddr ? vaddr : 0);
            }
        }
    }
    if (setLen != UINT64_MAX) length = setLen;
    if (setOff != UINT64_MAX) fileOff = setOff;
    if (setBase != UINT64_MAX) base = setBase;
    if (!length) length = d.size() > fileOff ? d.size() - fileOff : 0;
    if (fileOff >= d.size()) { fprintf(stderr, "error: offset %llu out of range\n", (unsigned long long)fileOff); return 1; }
    if (fileOff + length > d.size()) length = d.size() - fileOff;

    std::vector<AsmLine> lines;
    uint64_t pos = fileOff;
    uint64_t end = fileOff + length;
    while (pos < end && lines.size() < 4000) {
        AsmInsn in;
        size_t adv = disasmNext(d.data() + pos, (size_t)(end - pos), base + (pos - fileOff), in);
        if (!adv) adv = 1;
        AsmLine L;
        L.addr = base + (pos - fileOff);
        std::string hx;
        for (size_t i = 0; i < adv && pos + i < end; i++) {
            if (!hx.empty()) hx += " ";
            hx += asmHexByte(d[pos + i]);
        }
        L.bytes = hx;
        L.text = in.mnemonic + (in.operands.empty() ? std::string() : (" " + in.operands));
        L.hasTarget = in.hasTarget;
        L.target = in.target;
        L.isCall = in.isCall;
        L.isJump = in.isJump;
        lines.push_back(L);
        pos += adv;
    }

    std::string j;
    Builder b(j);
    b.beginObj();
    b.obj("code");
    b.kv("format", a.ok ? a.doc.get("format")->getStr("label") : "raw");
    b.kv("section", section);
    b.kv("fileOffset", fileOff);
    b.kv("base", hexU(base, 0));
    b.kv("bytes", length);
    b.arr("lines");
    for (const AsmLine& L : lines) {
        b.beginObj();
        b.kv("addr", hexU(L.addr, 0));
        b.kv("bytes", L.bytes);
        b.kv("text", L.text);
        if (L.hasTarget) b.kv("target", hexU(L.target, 0));
        if (L.isCall) b.kv("call", true);
        if (L.isJump) b.kv("jump", true);
        b.endObj();
    }
    b.endArr();
    b.endObj();
    b.endObj();

    if (!stdoutIsTty()) { printf("%s\n", j.c_str()); return 0; }
    o(asmHumanText(lines, base, length, section, 0));
    return 0;
}

static int cmdDeep(const std::string& path, bool indent) {
    std::vector<uint8_t> d;
    std::string err;
    if (!readFileBytes(path, d, err)) { fprintf(stderr, "error: %s\n", err.c_str()); return 1; }
    Analysis a = analyzePath(path);
    if (!a.ok) { fprintf(stderr, "error: %s\n", a.error.c_str()); return 1; }
    std::vector<std::string> imports;
    collectImports(a.doc, imports);
    BehaviorResult br = analyzeBehavior(d.data(), d.size(), imports, asciiLowerName(path));

    std::vector<AsmLine> clines;
    uint64_t cbase = 0, clen = 0;
    std::string csec;
    const JVal* sec = findCodeSection(a.doc, csec);
    uint64_t fileOff = 0;
    if (sec) {
        fileOff = jnumOf(sec->get("rawOffset"));
        if (!fileOff) fileOff = jnumOf(sec->get("offset"));
        uint64_t raw = jnumOf(sec->get("rawSize"));
        clen = raw ? raw : jnumOf(sec->get("size"));
        uint64_t vaddr = jnumOf(sec->get("virtualAddress"));
        cbase = vaddr ? vaddr : jnumOf(sec->get("addr"));
        if (a.doc.get("pe")) {
            uint64_t ib = jnumOf(a.doc.get("pe")->get("imageBase"));
            if (ib) cbase = ib + vaddr;
        }
    }
    if (!clen) clen = d.size() > fileOff ? d.size() - fileOff : 0;
    if (fileOff >= d.size()) fileOff = 0;
    if (fileOff + clen > d.size()) clen = d.size() - fileOff;
    {
        uint64_t pos = fileOff, end = fileOff + clen;
        while (pos < end && clines.size() < 200) {
            AsmInsn in;
            size_t adv = disasmNext(d.data() + pos, (size_t)(end - pos), cbase + (pos - fileOff), in);
            if (!adv) adv = 1;
            AsmLine L;
            L.addr = cbase + (pos - fileOff);
            std::string hx;
            for (size_t i = 0; i < adv && pos + i < end; i++) {
                if (!hx.empty()) hx += " ";
                hx += asmHexByte(d[pos + i]);
            }
            L.bytes = hx;
            L.text = in.mnemonic + (in.operands.empty() ? std::string() : (" " + in.operands));
            L.hasTarget = in.hasTarget;
            L.target = in.target;
            L.isCall = in.isCall;
            L.isJump = in.isJump;
            clines.push_back(L);
            pos += adv;
        }
    }

    if (!indent && stdoutIsTty()) {
        renderHuman(a.doc, path, a.ms);
        o(behaviorHumanText(br));
        o(asmHumanText(clines, cbase, clen, csec, 60));
        return 0;
    }
    JVal doc = a.doc;
    {
        std::string jb;
        Builder bb(jb);
        bb.beginObj();
        writeBehaviorJson(bb, br);
        bb.endObj();
        JVal bv;
        if (jsonParse(jb, bv)) doc.props.push_back({ "behavior", bv });
    }
    {
        std::string jc;
        Builder bc(jc);
        bc.beginObj();
        bc.kv("format", a.doc.get("format")->getStr("label"));
        bc.kv("section", csec);
        bc.kv("base", hexU(cbase, 0));
        bc.kv("bytes", clen);
        bc.arr("lines");
        for (const AsmLine& L : clines) {
            bc.beginObj();
            bc.kv("addr", hexU(L.addr, 0));
            bc.kv("bytes", L.bytes);
            bc.kv("text", L.text);
            if (L.hasTarget) bc.kv("target", hexU(L.target, 0));
            if (L.isCall) bc.kv("call", true);
            if (L.isJump) bc.kv("jump", true);
            bc.endObj();
        }
        bc.endArr();
        bc.endObj();
        JVal cv;
        if (jsonParse(jc, cv)) doc.props.push_back({ "code", cv });
    }
    std::string out;
    Builder bo(out);
    emitValue(bo, doc);
    printf("%s\n", indent ? prettyJson(out).c_str() : out.c_str());
    return 0;
}


static int cmdGraph(const std::string& path, bool wantDot, bool wantIndent) {
    std::vector<uint8_t> d;
    std::string err;
    if (!readFileBytes(path, d, err)) { fprintf(stderr, "error: %s\n", err.c_str()); return 1; }
    Analysis a = analyzePath(path);
    if (!a.ok) { fprintf(stderr, "error: %s\n", a.error.c_str()); return 1; }
    std::string section;
    uint64_t fileOff = 0, base = 0, length = 0, entryVA = 0;
    const JVal* sec = findCodeSection(a.doc, section);
    if (sec) {
        fileOff = jnumOf(sec->get("rawOffset"));
        if (!fileOff) fileOff = jnumOf(sec->get("offset"));
        uint64_t raw = jnumOf(sec->get("rawSize"));
        length = raw ? raw : jnumOf(sec->get("size"));
        uint64_t vaddr = jnumOf(sec->get("virtualAddress"));
        uint64_t saddr = jnumOf(sec->get("addr"));
        base = vaddr ? vaddr : saddr;
        if (a.doc.get("pe")) {
            uint64_t ib = jnumOf(a.doc.get("pe")->get("imageBase"));
            if (ib) base = ib + (vaddr ? vaddr : 0);
        }
    }
    if (!length) length = d.size() > fileOff ? d.size() - fileOff : 0;
    if (fileOff >= d.size()) { fprintf(stderr, "error: no code section\n"); return 1; }
    if (fileOff + length > d.size()) length = d.size() - fileOff;
    if (a.doc.get("pe")) {
        uint64_t ib = jnumOf(a.doc.get("pe")->get("imageBase"));
        uint64_t rva = jnumOf(a.doc.get("pe")->get("entryPointRva"));
        if (ib && rva) entryVA = ib + rva;
    } else if (a.doc.get("elf")) {
        entryVA = jnumOf(a.doc.get("elf")->get("entry"));
    }
    if (!entryVA) entryVA = base;

    struct ALine {
        uint64_t addr, target;
        bool call, jump, hasTarget, isRet;
        std::string mnemonic, text;
    };
    std::vector<ALine> ls;
    {
        uint64_t pos = fileOff, end = fileOff + length;
        while (pos < end && ls.size() < 6000) {
            AsmInsn in;
            size_t adv = disasmNext(d.data() + pos, (size_t)(end - pos), base + (pos - fileOff), in);
            if (!adv) adv = 1;
            ALine L;
            L.addr = base + (pos - fileOff); L.target = in.target;
            L.call = in.isCall; L.jump = in.isJump; L.hasTarget = in.hasTarget; L.isRet = in.isRet;
            L.mnemonic = in.mnemonic; L.text = in.operands;
            ls.push_back(L); pos += adv;
        }
    }
    if (ls.empty()) { fprintf(stderr, "error: no decodable code bytes\n"); return 1; }

    auto inRange = [&](uint64_t x) { return x >= base && x <= base + length; };
    auto isPadding = [&](const ALine& L) {
        return L.mnemonic == "nop" || L.mnemonic == "int3";
    };
    auto isTerm = [&](const ALine& L) {
        return L.isRet || L.mnemonic == "hlt" || L.mnemonic == "retf";
    };
    auto plausibleStart = [&](const ALine& L) {
        if (L.mnemonic == "endbr64") return true;
        if (L.mnemonic == "push") {
            for (const char* r : { "rbp", "rbx", "rdi", "rsi", "r12", "r13", "r14", "r15" })
                if (L.text == r) return true;
        }
        return false;
    };

    // function starts: entry + every direct-call target within range
    std::set<uint64_t> starts;
    starts.insert(entryVA);
    for (const ALine& L : ls)
        if (L.call && L.hasTarget && inRange(L.target)) starts.insert(L.target);
    // plus a plausible new function after each flow terminator (skip nop/int3 padding)
    bool ended = false;
    for (const ALine& L : ls) {
        if (ended) {
            if (isPadding(L)) continue;
            if (plausibleStart(L)) starts.insert(L.addr);
            ended = false;
        }
        if (isTerm(L)) ended = true;
    }
    std::vector<uint64_t> funcs(starts.begin(), starts.end());
    std::sort(funcs.begin(), funcs.end());

    auto ownerOf = [&](uint64_t addr) {
        uint64_t owner = 0;
        for (uint64_t f : funcs) if (f <= addr) owner = f; else break;
        return owner;
    };
    auto fname = [&](uint64_t f) {
        char b[40];
        if (f == entryVA) snprintf(b, sizeof(b), "start_%llx", (unsigned long long)f);
        else snprintf(b, sizeof(b), "sub_%llx", (unsigned long long)f);
        return std::string(b);
    };
    std::map<uint64_t, std::set<uint64_t>> outInt;
    std::map<uint64_t, std::set<std::string>> outExt;
    std::map<uint64_t, int> inCnt;
    std::map<uint64_t, std::vector<uint64_t>> callersOf; // target -> call-site addrs
    size_t directCalls = 0, indirectCalls = 0;
    for (const ALine& L : ls) {
        if (!L.call) continue;
        uint64_t own = ownerOf(L.addr);
        if (L.hasTarget) {
            directCalls++;
            if (own) {
                if (inRange(L.target)) {
                    outInt[own].insert(L.target);
                    inCnt[L.target]++;
                    callersOf[L.target].push_back(L.addr);
                } else {
                    char b[40]; snprintf(b, sizeof(b), "ext_%llx", (unsigned long long)L.target);
                    outExt[own].insert(std::string(b));
                }
            }
        } else {
            indirectCalls++;
        }
    }

    bool human = !wantDot && !wantIndent && stdoutIsTty();
    if (wantDot) {
        std::string s;
        s = "digraph callgraph {\n";
        s += "  rankdir=LR;\n  node [shape=box, fontname=\"monospace\"];\n";
        for (uint64_t f : funcs) s += "  \"" + fname(f) + "\" [label=\"" + fname(f) + "\\n@" + hexId(f) + "\"];\n";
        for (auto& kv : outInt)
            for (uint64_t t : kv.second) s += "  \"" + fname(kv.first) + "\" -> \"" + fname(t) + "\";\n";
        for (auto& kv : outExt)
            for (const std::string& t : kv.second) s += "  \"" + fname(kv.first) + "\" -> \"" + t + "\";\n";
        s += "}\n";
        printf("%s", s.c_str());
        return 0;
    }
    if (human) {
        std::string s;
        s += "\n" + CYN() + "========== Call graph (" + section + ") ==========" + R() + "\n";
        char st[96];
        snprintf(st, sizeof(st), "  %s @ 0x%llx  |  %zu functions  |  %zu direct calls  |  %zu indirect calls",
                 section.empty() ? "code" : section.c_str(), (unsigned long long)base,
                 funcs.size(), directCalls, indirectCalls);
        s += DIM() + st + R() + "\n";
        for (uint64_t f : funcs) {
            s += "\n" + B() + WHT() + "  " + fname(f) + R() + DIM() + "  @ 0x" + hexId(f) + R();
            if (f == entryVA) s += "  " + DIM() + "(entry)" + R();
            s += "\n";
            std::vector<std::string> callees;
            auto it = outInt.find(f);
            if (it != outInt.end()) for (uint64_t t : it->second) callees.push_back(fname(t));
            auto it2 = outExt.find(f);
            if (it2 != outExt.end()) for (const std::string& t : it2->second) callees.push_back(t);
            if (callees.empty()) {
                s += DIM() + "      calls: (none)" + R() + "\n";
            } else {
                std::string line = "      calls: ";
                for (size_t i = 0; i < callees.size(); i++) {
                    line += CYN() + callees[i] + R();
                    if (i + 1 < callees.size()) line += ", ";
                }
                s += line + "\n";
            }
            auto c = inCnt.find(f);
            int callers = c == inCnt.end() ? 0 : c->second;
            if (callers) {
                s += DIM() + "      called from: ";
                auto ci = callersOf.find(f);
                std::string sites;
                if (ci != callersOf.end())
                    for (size_t i = 0; i < ci->second.size(); i++) {
                        if (i) sites += ", ";
                        char bb[24]; snprintf(bb, sizeof(bb), "0x%llx", (unsigned long long)ci->second[i]);
                        sites += bb;
                    }
                s += sites + R() + "\n";
            } else if (f != entryVA) {
                s += DIM() + "      no internal direct callers" + R() + "\n";
            }
        }
        o(s);
        return 0;
    }
    std::string j;
    Builder b(j);
    b.beginObj();
    b.kv("format", a.doc.get("format")->getStr("label"));
    b.kv("section", section);
    b.kv("entry", hexU(entryVA, 0));
    b.kv("directCalls", (int64_t)directCalls);
    b.kv("indirectCalls", (int64_t)indirectCalls);
    b.arr("functions");
    for (uint64_t f : funcs) {
        b.beginObj();
        b.kv("addr", hexU(f, 0));
        b.kv("name", fname(f));
        b.kv("entry", f == entryVA);
        b.arr("calls");
        auto it = outInt.find(f);
        std::vector<uint64_t> allInt;
        if (it != outInt.end()) for (uint64_t t : it->second) allInt.push_back(t);
        std::sort(allInt.begin(), allInt.end());
        for (uint64_t t : allInt) b.valStr(fname(t));
        auto it2 = outExt.find(f);
        if (it2 != outExt.end()) for (const std::string& t : it2->second) b.valStr(t);
        b.endArr();
        auto ci = callersOf.find(f);
        b.arr("callers");
        if (ci != callersOf.end()) for (uint64_t t : ci->second) b.valStr(hexU(t, 0));
        b.endArr();
        auto c = inCnt.find(f);
        b.kv("callerCount", (int64_t)(c == inCnt.end() ? 0 : c->second));
        b.endObj();
    }
    b.endArr();
    b.endObj();
    printf("%s\n", wantIndent ? prettyJson(j).c_str() : j.c_str());
    return 0;
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
        "  codebreak-cli <file> --deep                combined deep analysis\n"
        "                                             (parse summary + behavior + code)\n"
        "  codebreak-cli <file> --behavior            static host-behavior trace (network,\n"
        "                                             file paths, processes, persistence)\n"
        "  codebreak-cli <file> --calls               static call graph of the code section\n"
        "                [--dot]                      (human/JSON, or Graphviz DOT)\n"
        "  codebreak-cli <file> --asm                 x86-64 disassembly of the code section\n"
        "                [--offset N] [--base N] [--length N]\n"
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
        "  behavior <file>      static host-behavior trace\n"
        "  deep <file>          combined deep analysis (summary+behavior+code)\n"
        "  calls <file> [--dot] static call graph of code\n"
        "  asm <file>           x86-64 disassembly of code (alias code/disasm)\n"
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
    if (first == "--behavior" || first == "-be" || first == "behavior") {
        if (args.size() < 2) { fprintf(stderr, "usage: behavior <file>\n"); return 2; }
        bool bIndent = false;
        for (size_t i = 2; i < args.size(); i++)
            if (args[i] == "--indent" || args[i] == "--pretty") bIndent = true;
        return cmdBehavior(args[1], bIndent);
    }
    if (first == "--deep" || first == "deep" || first == "--full") {
        if (args.size() < 2) { fprintf(stderr, "usage: deep <file>\n"); return 2; }
        bool dIndent = false;
        for (size_t i = 2; i < args.size(); i++)
            if (args[i] == "--indent" || args[i] == "--pretty") dIndent = true;
        return cmdDeep(args[1], dIndent);
    }
    if (first == "--calls" || first == "calls" || first == "--graph" || first == "graph") {
        if (args.size() < 2) { fprintf(stderr, "usage: calls <file> [--dot]\n"); return 2; }
        bool gDot = false, gIndent = false;
        for (size_t i = 2; i < args.size(); i++) {
            if (args[i] == "--dot") gDot = true;
            if (args[i] == "--indent" || args[i] == "--pretty") gIndent = true;
        }
        return cmdGraph(args[1], gDot, gIndent);
    }
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
    bool isAsmVerb = first == "asm" || first == "code" || first == "disasm" ||
                     first == "--asm" || first == "--code" || first == "--disasm";
    if (isAsmVerb) {
        if (args.size() < 2) { fprintf(stderr, "usage: %s <file> [--offset N] [--base N] [--length N]\n", first.c_str()); return 2; }
        uint64_t off = UINT64_MAX, ba = UINT64_MAX, len = UINT64_MAX;
        for (size_t i = 2; i < args.size(); i++) {
            if (args[i] == "--offset" && i + 1 < args.size()) off = strtoull(args[++i].c_str(), nullptr, 0);
            else if (args[i] == "--base" && i + 1 < args.size()) ba = strtoull(args[++i].c_str(), nullptr, 0);
            else if (args[i] == "--length" && i + 1 < args.size()) len = strtoull(args[++i].c_str(), nullptr, 0);
        }
        return cmdAsm(args[1], off, ba, len);
    }
    for (const auto& a : args) {
        if (a == "--behavior") {
            bool ind = false;
            for (const auto& b2 : args) if (b2 == "--indent" || b2 == "--pretty") ind = true;
            return cmdBehavior(args[0], ind);
        }
        if (a == "--deep" || a == "--full") {
            bool ind = false;
            for (const auto& b2 : args) if (b2 == "--indent" || b2 == "--pretty") ind = true;
            return cmdDeep(args[0], ind);
        }
        if (a == "--calls" || a == "--graph") {
            bool gd = false, gi = false;
            for (const auto& b2 : args) { if (b2 == "--dot") gd = true; if (b2 == "--indent" || b2 == "--pretty") gi = true; }
            return cmdGraph(args[0], gd, gi);
        }
        if (a == "--asm" || a == "--code" || a == "--disasm") {
            uint64_t off = UINT64_MAX, ba = UINT64_MAX, len = UINT64_MAX;
            for (size_t i = 1; i < args.size(); i++) {
                if (args[i] == "--offset" && i + 1 < args.size()) off = strtoull(args[++i].c_str(), nullptr, 0);
                else if (args[i] == "--base" && i + 1 < args.size()) ba = strtoull(args[++i].c_str(), nullptr, 0);
                else if (args[i] == "--length" && i + 1 < args.size()) len = strtoull(args[++i].c_str(), nullptr, 0);
            }
            return cmdAsm(args[0], off, ba, len);
        }
    }

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
