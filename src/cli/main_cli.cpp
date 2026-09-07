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
        "                              [--limit N] [--max-mb N]\n");
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

    if (jsonPath.empty()) {
        std::string out = full;
        char mb[48];
        snprintf(mb, sizeof(mb), ", \"durationMs\": %.1f", ms);
        out.insert(out.size() - 1, mb);
        printf("%s\n", out.c_str());
    } else {
        std::string out = full;
        char mb[48];
        snprintf(mb, sizeof(mb), ", \"durationMs\": %.1f", ms);
        out.insert(out.size() - 1, mb);
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

int main(int argc, char** argv) {
    if (argc < 2) { printUsage(); return 2; }
    std::string first = argv[1];
    if (first == "--batch" || first == "-b") {
        if (argc < 3) { printUsage(); return 2; }
        std::string dir = argv[2];
        std::string jsonPath, htmlPath, csvPath;
        size_t limit = (size_t)100000;
        uint64_t maxMb = 0;
        for (int i = 3; i < argc; i++) {
            std::string a = argv[i];
            if ((a == "--json" || a == "--html" || a == "--csv") && i + 1 < argc) {
                std::string val = argv[++i];
                if (a == "--json") jsonPath = val;
                else if (a == "--html") htmlPath = val;
                else csvPath = val;
            } else if (a == "--limit" && i + 1 < argc) limit = (size_t)strtoul(argv[++i], nullptr, 10);
            else if (a == "--max-mb" && i + 1 < argc) maxMb = (uint64_t)strtoull(argv[++i], nullptr, 10);
            else { fprintf(stderr, "unknown arg: %s\n", a.c_str()); printUsage(); return 2; }
        }
        return runBatch(dir, jsonPath, htmlPath, csvPath, limit, maxMb ? maxMb * 1024ull * 1024ull : 0);
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

    for (int i = 2; i < argc; i++) {
        std::string a = argv[i];
        if (a == "--strings") { stringsMode = true; if (i + 1 < argc && argv[i + 1][0] != '-') stringsPattern = argv[++i]; }
        else if (a == "--min-len" && i + 1 < argc) minLen = (uint32_t)strtoul(argv[++i], nullptr, 0);
        else if (a == "--kind" && i + 1 < argc) { std::string k = argv[++i]; kind = k == "ascii" ? 1 : k == "wide" ? 2 : 0; }
        else if (a == "--count" && i + 1 < argc) count = (uint32_t)strtoul(argv[++i], nullptr, 0);
        else if (a == "--hex" && i + 1 < argc) { hexMode = true; hexOff = strtoull(argv[++i], nullptr, 0); }
        else if (a == "--hex-len" && i + 1 < argc) hexLen = strtoull(argv[++i], nullptr, 0);
        else if (a == "--indent") indent = true;
        else if (a == "--risk") riskOnly = true;
        else if (a == "--report" && i + 1 < argc) reportPath = argv[++i];
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

    int rc = analyzeOne(path, indent, riskOnly);
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
