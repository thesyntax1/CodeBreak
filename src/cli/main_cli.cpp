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
#include <string>
#include <vector>
#include <chrono>
#ifdef _WIN32
#include <windows.h>
#endif

using namespace cb;

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

static void printUsage() {
    fprintf(stderr,
        "codebreak-cli <file> [--strings [pattern]] [--min-len N] [--kind all|ascii|wide] [--count N]\n"
        "                 [--hex OFFSET] [--hex-len N] [--indent] [--risk] [--report FILE.html]\n"
        "codebreak-cli --batch DIR [--json FILE.json] [--html FILE.html] [--csv FILE.csv]\n"
        "                              [--limit N] [--max-mb N]\n"
        "codebreak-cli --hash <file> | --compare <a> <b> | -h\n"
        "\n"
        "Run without arguments for an interactive shell where you can type these commands.\n");
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

static std::string prettyJson(const std::string& j) {
    int depth = 0;
    std::string o;
    o.reserve(j.size() * 2);
    bool instr = false, esc = false;
    for (char ch : j) {
        if (instr) {
            o += ch;
            if (esc) esc = false;
            else if (ch == '\\') esc = true;
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

static int analyzeOne(const std::string& path, bool indent, bool riskOnly) {
    std::vector<uint8_t> d;
    std::string err;
    if (!readFileBytes(path, d, err)) { fprintf(stderr, "error: %s\n", err.c_str()); return 1; }
    FileInfo fi = queryFileInfo(path);
    auto t0 = std::chrono::steady_clock::now();
    AnalysisOutput ao = analyzeFile(d.data(), d.size(), path, fi);
    auto t1 = std::chrono::steady_clock::now();
    double ms = std::chrono::duration<double, std::milli>(t1 - t0).count();
    if (!ao.ok) { fprintf(stderr, "analysis failed\n"); return 1; }
    if (riskOnly) {
        JVal doc;
        if (!jsonParse(ao.json, doc)) { fprintf(stderr, "internal parse error\n"); return 1; }
        const JVal* risk = doc.get("risk");
        if (!risk) { fprintf(stderr, "no risk section\n"); return 1; }
        std::string out;
        emitTop(*risk, "risk", out);
        printf("%s\n", indent ? prettyJson(out).c_str() : out.c_str());
        return 0;
    }
    std::string j = ao.json;
    if (!j.empty() && j.back() == '}') {
        char mb[40];
        snprintf(mb, sizeof(mb), "%.1f", ms);
        j.insert(j.size() - 1, ", \"analysisMs\": " + std::string(mb));
    }
    printf("%s\n", indent ? prettyJson(j).c_str() : j.c_str());
    return 0;
}

static int runBatch(const std::string& dir, const std::string& jsonPath,
                    const std::string& htmlPath, const std::string& csvPath,
                    size_t limit, uint64_t maxBytes) {
    std::vector<std::string> files;
    std::string err;
    if (!walkDirectory(dir, files, err)) { fprintf(stderr, "error: %s\n", err.c_str()); return 1; }
    auto t0 = std::chrono::steady_clock::now();
    std::vector<BatchItem> items;
    std::string full;
    Builder b(full);
    b.beginObj();
    b.obj("meta");
    b.kv("scanRoot", dir);
    b.kv("fileCount", (uint64_t)files.size());
    b.endObj();
    b.arr("items");
    uint64_t totalBytes = 0;
    size_t processed = 0;
    for (const std::string& path : files) {
        if (processed >= limit) break;
        BatchItem it;
        it.path = path;
        FileInfo fi = queryFileInfo(path);
        if (!fi.exists || (maxBytes && fi.size > maxBytes)) {
            it.ok = false;
            it.error = fi.exists ? "file too large" : "stat failed";
            items.push_back(it);
            b.beginObj();
            b.kv("path", path);
            b.kv("ok", false);
            b.kv("error", it.error);
            b.endObj();
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
            if (risk) {
                it.riskScore = risk->getInt("score");
                it.riskLevel = risk->getStr("level");
            }
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

static int runBatchCmd(const std::vector<std::string>& args, size_t offset) {
    if (args.size() < offset + 1) { printUsage(); return 2; }
    std::string dir = args[offset];
    std::string jsonPath, htmlPath, csvPath;
    size_t limit = (size_t)100000;
    uint64_t maxMb = 0;
    for (size_t i = offset + 1; i < args.size(); i++) {
        std::string a = args[i];
        if ((a == "--json" || a == "--html" || a == "--csv") && i + 1 < args.size()) {
            std::string val = args[++i];
            if (a == "--json") jsonPath = val;
            else if (a == "--html") htmlPath = val;
            else csvPath = val;
        } else if (a == "--limit" && i + 1 < args.size()) limit = (size_t)strtoul(args[++i].c_str(), nullptr, 10);
        else if (a == "--max-mb" && i + 1 < args.size()) maxMb = (uint64_t)strtoull(args[++i].c_str(), nullptr, 10);
        else { fprintf(stderr, "unknown arg: %s\n", a.c_str()); printUsage(); return 2; }
    }
    return runBatch(dir, jsonPath, htmlPath, csvPath, limit, maxMb ? maxMb * 1024ull * 1024ull : 0);
}

#ifdef _WIN32
static int launchGui(const std::string& file) {
    HINSTANCE r = ShellExecuteW(nullptr, L"open", L"CodeBreak.exe",
                                file.empty() ? nullptr : utf8ToWide(file).c_str(),
                                nullptr, SW_SHOWNORMAL);
    if ((INT_PTR)r <= 32) {
        fprintf(stderr, "gui: failed to launch CodeBreak.exe (%lld). Is it next to this CLI?\n", (long long)(INT_PTR)r);
        return 1;
    }
    return 0;
}
#endif

static int analyzeFileFull(const std::string& path, bool indent, bool riskOnly) {
    return analyzeOne(path, indent, riskOnly);
}

static void printInteractiveBanner();

static int runCommand(const std::vector<std::string>& args) {
    if (args.empty()) { printUsage(); return 2; }
    std::string first = args[0];

    if (first == "--compare" || first == "-c") {
        if (args.size() < 3) { printUsage(); return 2; }
        bool indent = false;
        for (size_t i = 3; i < args.size(); i++) if (args[i] == "--indent") indent = true;
        auto analyze1 = [&](const std::string& p, JVal& doc, double& ms) -> bool {
            std::vector<uint8_t> d; std::string e;
            if (!readFileBytes(p, d, e)) { fprintf(stderr, "error %s: %s\n", p.c_str(), e.c_str()); return false; }
            FileInfo fi = queryFileInfo(p);
            auto t0 = std::chrono::steady_clock::now();
            AnalysisOutput ao = analyzeFile(d.data(), d.size(), p, fi);
            auto t1 = std::chrono::steady_clock::now();
            ms = std::chrono::duration<double, std::milli>(t1 - t0).count();
            return jsonParse(ao.json, doc);
        };
        JVal da, db;
        double ma = 0, mb = 0;
        if (!analyze1(args[1], da, ma) || !analyze1(args[2], db, mb)) return 1;
        const JVal* ha = da.get("hashes");
        const JVal* hb = db.get("hashes");
        const JVal* fa = da.get("format");
        const JVal* fb = db.get("format");
        const JVal* ra = da.get("risk");
        const JVal* rb = db.get("risk");
        const JVal* fa2 = da.get("file");
        const JVal* fb2 = db.get("file");
        std::string sa = ha ? ha->getStr("sha256") : "";
        std::string sb = hb ? hb->getStr("sha256") : "";
        std::string out;
        Builder bw(out);
        bw.beginObj();
        bw.kv("identical", sa == sb && sa.size() == 64);
        bw.kv("sha256Equal", sa == sb);
        auto putSide = [&](const char* key, const JVal& d2, const JVal* fmt, const JVal* risk,
                           const JVal* f, const JVal* hashes) {
            bw.obj(key);
            bw.kv("path", f ? f->getStr("path") : std::string());
            bw.kv("size", f ? (uint64_t)f->getNum("size", 0) : (uint64_t)0);
            bw.kv("sizeHuman", f ? f->getStr("sizeHuman") : std::string());
            bw.kv("format", fmt ? fmt->getStr("label") : std::string());
            bw.kv("sha256", hashes ? hashes->getStr("sha256") : std::string());
            bw.kv("md5", hashes ? hashes->getStr("md5") : std::string());
            if (risk) {
                bw.kv("riskScore", (int64_t)risk->getInt("score"));
                bw.kv("riskLevel", risk->getStr("level"));
            }
            const JVal* inds = d2.get("indicators");
            bw.kv("indicatorCount", inds ? (int64_t)inds->arr.size() : (int64_t)0);
            bw.endObj();
        };
        putSide("a", da, fa, ra, fa2, ha);
        putSide("b", db, fb, rb, fb2, hb);
        bw.kv("analysisMsA", ma);
        bw.kv("analysisMsB", mb);
        bw.endObj();
        printf("%s\n", indent ? prettyJson(out).c_str() : out.c_str());
        return 0;
    }

    if (first == "--hash") {
        if (args.size() < 2) { printUsage(); return 2; }
        std::vector<uint8_t> d; std::string e;
        if (!readFileBytes(args[1], d, e)) { fprintf(stderr, "error: %s\n", e.c_str()); return 1; }
        FileInfo fi = queryFileInfo(args[1]);
        AnalysisOutput ao = analyzeFile(d.data(), d.size(), args[1], fi);
        printf("%s\n", ao.json.c_str());
        return 0;
    }

    if (first == "--batch" || first == "-b") return runBatchCmd(args, 1);
    if (first == "--gui") {
#ifdef _WIN32
        return launchGui(args.size() > 1 ? args[1] : "");
#else
        fprintf(stderr, "gui: only available on Windows\n"); return 1;
#endif
    }
    if (first == "-h" || first == "--help") { printUsage(); return 0; }

    std::string path = first;
    std::string stringsPattern;
    bool stringsMode = false;
    bool indent = false;
    bool riskOnly = false;
    std::string reportPath;
    uint32_t minLen = 4;
    int kind = 0;
    uint32_t count = 300;
    bool hexMode = false;
    uint64_t hexOff = 0;
    uint64_t hexLen = 256;

    for (size_t i = 1; i < args.size(); i++) {
        std::string a = args[i];
        if (a == "--strings") { stringsMode = true; if (i + 1 < args.size() && args[i + 1][0] != '-') stringsPattern = args[++i]; }
        else if (a == "--min-len" && i + 1 < args.size()) minLen = (uint32_t)strtoul(args[++i].c_str(), nullptr, 0);
        else if (a == "--kind" && i + 1 < args.size()) { std::string k = args[++i]; kind = k == "ascii" ? 1 : k == "wide" ? 2 : 0; }
        else if (a == "--count" && i + 1 < args.size()) count = (uint32_t)strtoul(args[++i].c_str(), nullptr, 0);
        else if (a == "--hex" && i + 1 < args.size()) { hexMode = true; hexOff = strtoull(args[++i].c_str(), nullptr, 0); }
        else if (a == "--hex-len" && i + 1 < args.size()) hexLen = strtoull(args[++i].c_str(), nullptr, 0);
        else if (a == "--indent") indent = true;
        else if (a == "--risk") riskOnly = true;
        else if (a == "--report" && i + 1 < args.size()) reportPath = args[++i];
        else { fprintf(stderr, "unknown arg: %s\n", a.c_str()); printUsage(); return 2; }
    }

    std::vector<uint8_t> d;
    std::string err;
    if (!readFileBytes(path, d, err)) { fprintf(stderr, "error: %s\n", err.c_str()); return 1; }
    FileInfo fi = queryFileInfo(path);

    if (hexMode) {
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

    if (stringsMode) {
        StringsIndex si;
        si.build(d.data(), d.size(), 4, 2000000);
        std::string j;
        Builder b(j);
        b.beginObj();
        b.key("items");
        uint64_t total = 0;
        si.query(b, 0, count, minLen, kind, stringsPattern, total);
        b.kv("total", total);
        b.endObj();
        printf("%s\n", j.c_str());
        return 0;
    }

    int rc = analyzeFileFull(path, indent, riskOnly);
    if (rc) return rc;
    if (!reportPath.empty()) {
        std::vector<uint8_t> rd;
        std::string rerr;
        if (!readFileBytes(path, rd, rerr)) { fprintf(stderr, "error: %s\n", rerr.c_str()); return 1; }
        AnalysisOutput ao = analyzeFile(rd.data(), rd.size(), path, fi);
        if (!ao.ok) { fprintf(stderr, "analysis failed\n"); return 1; }
        std::string html = buildHtmlReport(ao.json, path);
        if (!writeFileUtf8(reportPath, html, rerr)) { fprintf(stderr, "error: %s\n", rerr.c_str()); return 1; }
        fprintf(stderr, "report written: %s\n", reportPath.c_str());
    }
    return 0;
}

static void runInteractive() {
    printInteractiveBanner();
    fprintf(stdout, "Type a command, then press Enter. Try 'help' or just a file path.\n\n");
    for (;;) {
        fprintf(stdout, "codebreak> ");
        fflush(stdout);
        std::string line;
        int c;
        bool any = false;
        while ((c = getchar()) != EOF && c != '\n') { line += (char)c; any = true; }
        if (!any && c == EOF) { fprintf(stdout, "\n"); break; }
        std::vector<std::string> t = splitArgs(line);
        if (t.empty()) continue;
        std::string cmd = t[0];
        for (size_t i = 0; i < cmd.size(); i++)
            if (cmd[i] >= 'A' && cmd[i] <= 'Z') cmd[i] = (char)(cmd[i] + 32);
        if (cmd == "exit" || cmd == "quit" || cmd == "q") break;
        if (cmd == "help" || cmd == "h" || cmd == "?") { printInteractiveBanner(); continue; }

        std::vector<std::string> out;
        if (cmd == "analyze" || cmd == "open") {
            out.assign(t.begin() + 1, t.end());
        } else if (cmd == "risk") {
            if (t.size() < 2) { fprintf(stderr, "usage: risk <file>\n"); continue; }
            out.assign(t.begin() + 1, t.end());
            out.push_back("--risk");
        } else if (cmd == "batch") {
            out.push_back("--batch");
            out.insert(out.end(), t.begin() + 1, t.end());
        } else if (cmd == "compare") {
            out.push_back("--compare");
            out.insert(out.end(), t.begin() + 1, t.end());
        } else if (cmd == "hash") {
            out.push_back("--hash");
            out.insert(out.end(), t.begin() + 1, t.end());
        } else if (cmd == "gui") {
            out.push_back("--gui");
            out.insert(out.end(), t.begin() + 1, t.end());
        } else {
            out = t;
        }
        runCommand(out);
        fprintf(stdout, "\n");
    }
}

static void printInteractiveBanner() {
    fprintf(stdout,
        "  CodeBreak - interactive analysis shell\n"
        "  ---------------------------------------------\n"
        "  <file>               analyze a file (full JSON)\n"
        "  analyze <file>       same as above\n"
        "  risk <file>          risk assessment only\n"
        "  batch <dir>          scan a directory tree\n"
        "  compare <a> <b>      compare two files\n"
        "  hash <file>          analysis JSON for a file\n"
        "  gui <file>           open a file in the GUI (Windows)\n"
        "  help / exit          show this help / leave the shell\n"
        "\n");
}

int main(int argc, char** argv) {
    if (argc < 2) {
#ifdef _WIN32
        DWORD pids[2];
        DWORD cnt = GetConsoleProcessList(pids, 2);
        if (cnt <= 1) {
            runInteractive();
            return 0;
        }
#endif
        runInteractive();
        return 0;
    }
    std::vector<std::string> args(argv + 1, argv + argc);
    return runCommand(args);
}
