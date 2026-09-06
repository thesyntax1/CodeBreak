#include "../formats.h"
#include "../jsonw.h"
#include "../util.h"
#include "../hashes.h"
#include "../pe.h"
#include <cstdio>
#include <cstring>
#include <string>
#include <vector>
#include <chrono>

using namespace cb;

static void printUsage() {
    fprintf(stderr,
        "codebreak-cli <file> [--strings [pattern]] [--min-len N] [--kind all|ascii|wide] [--count N]\n"
        "                 [--hex OFFSET] [--hex-len N] [--indent]\n");
}

int main(int argc, char** argv) {
    if (argc < 2) { printUsage(); return 2; }
    std::string path = argv[1];
    std::string stringsPattern;
    bool stringsMode = false;
    bool indent = false;
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

    auto t0 = std::chrono::steady_clock::now();
    AnalysisOutput ao = analyzeFile(d.data(), d.size(), path, fi);
    auto t1 = std::chrono::steady_clock::now();
    double ms = std::chrono::duration<double, std::milli>(t1 - t0).count();
    if (!ao.ok) { fprintf(stderr, "analysis failed\n"); return 1; }
    std::string j = ao.json;
    if (j.size() > 2 && j[j.size() - 1] == '}') {
        j.insert(j.size() - 1, ", \"analysisMs\": " + ([](double v) { char b[40]; snprintf(b, sizeof(b), "%.1f", v); return std::string(b); })(ms));
    }
    if (indent) {
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
            if (ch == '{' || ch == '[') { o += ch; depth++; o += '\n'; o.append(depth * 2, ' '); }
            else if (ch == '}' || ch == ']') { depth--; o += '\n'; o.append(depth * 2, ' '); o += ch; }
            else if (ch == ',') { o += ",\n"; o.append(depth * 2, ' '); }
            else if (ch == ':') o += ": ";
            else o += ch;
        }
        printf("%s\n", o.c_str());
    } else {
        printf("%s\n", j.c_str());
    }
    return 0;
}
