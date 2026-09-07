#include "risk.h"
#include "util.h"
#include "jsonw.h"
#include <algorithm>
#include <cstring>
#include <map>
#include <vector>

namespace cb {

namespace {

struct ThreatRule {
    const char* token;
    int weight;
    const char* category;
    const char* label;
};

const ThreatRule kExecutionRules[] = {
    { "virtualallocex", 12, "execution", "Remote process allocation (VirtualAllocEx)" },
    { "writeprocessmemory", 12, "execution", "Cross-process memory write (WriteProcessMemory)" },
    { "readprocessmemory", 5, "execution", "Cross-process memory read (ReadProcessMemory)" },
    { "createremotethread", 14, "execution", "Remote thread creation (CreateRemoteThread)" },
    { "ntunmapviewofsection", 14, "execution", "Process hollowing primitive (NtUnmapViewOfSection)" },
    { "ntmapviewofsection", 12, "execution", "Section mapping for injection (NtMapViewOfSection)" },
    { "queueuserapc", 10, "execution", "APC injection primitive (QueueUserAPC)" },
    { "setwindowshookex", 6, "execution", "System-wide input hooking (SetWindowsHookEx)" },
    { "setthreadcontext", 9, "execution", "Thread context rewrite (SetThreadContext)" },
    { "getsyscallnumber", 7, "execution", "Direct syscall resolution (getSyscallNumber)" },
    { "hell's gate", 9, "execution", "Hell's Gate syscall evasion marker" },
    { "shellexecuteex", 8, "execution", "Elevated shell execution (ShellExecuteEx)" },
    { "shellexecute", 5, "execution", "Shell execution (ShellExecute)" },
    { "winexec", 5, "execution", "Process spawn (WinExec)" },
};

const ThreatRule kNetworkRules[] = {
    { "winhttp", 3, "network", "WinHTTP client library" },
    { "wininet", 3, "network", "WinINet legacy client library" },
    { "urlmon", 4, "network", "URL download library (URLMon)" },
    { "internetopenurl", 5, "network", "Direct URL retrieval (InternetOpenUrl)" },
    { "urldownloadtofile", 7, "network", "File download primitive (URLDownloadToFile)" },
    { "http://", 3, "network", "Plaintext HTTP endpoint" },
};

const ThreatRule kShellRules[] = {
    { "powershell", 7, "shell", "PowerShell engine reference" },
    { "-encodedcommand", 9, "shell", "Encoded PowerShell command" },
    { "-enc ", 8, "shell", "PowerShell -EncodedCommand switch" },
    { "cmd.exe", 3, "shell", "cmd shell invocation" },
    { "cmd /c", 7, "shell", "Inline shell command (cmd /c)" },
    { "mshta", 8, "shell", "HTA execution host (mshta)" },
    { "certutil", 8, "shell", "certutil abuse vector" },
    { "bitsadmin", 7, "shell", "BITS transfer abuse (bitsadmin)" },
    { "regsvr32", 4, "shell", "Squiblydoo vector (regsvr32)" },
    { "rundll32", 4, "shell", "DLL execution vector (rundll32)" },
    { "reg add", 6, "persist", "Registry modification (reg add)" },
    { "schtasks", 7, "persist", "Scheduled task creation (schtasks)" },
    { "runonce", 5, "persist", "RunOnce auto-start key" },
    { "hklm\\..\\run", 6, "persist", "HKLM Run auto-start key" },
    { "startup folder", 4, "persist", "Startup folder reference" },
};

const ThreatRule kDataRules[] = {
    { "base64", 2, "encoding", "Base64 decoding routine" },
    { "cryptdecode", 2, "encoding", "Cryptographic decode routine" },
    { "stringxor", 2, "encoding", "String XOR obfuscation" },
    { "xor loop", 2, "encoding", "XOR transform loop" },
    { "bytearray", 1, "encoding", "In-memory byte blob" },
};

const ThreatRule kPackerRules[] = {
    { "upx!", 20, "packing", "UPX compression marker" },
    { "asprotect", 16, "packing", "ASProtect protector" },
    { "aspack", 14, "packing", "ASPack packer" },
    { "mpr compress", 14, "packing", "MPRESS packer" },
    { "themida", 16, "packing", "Themida protector" },
    { "vmprotect", 16, "packing", "VMProtect protector" },
    { "enigma prot", 12, "packing", "Enigma protector" },
    { "petite", 12, "packing", "Petite packer" },
    { "nfpack", 12, "packing", "NSPack packer" },
    { "molebox", 12, "packing", "MoleBox packer" },
};

struct RuleHit {
    const ThreatRule* rule;
    int hits;
};

void scanToken(const uint8_t* d, size_t n, size_t window, const ThreatRule* rules,
               size_t ruleCount, std::vector<RuleHit>& out) {
    out.clear();
    size_t len = n < window ? n : window;
    std::string hay;
    hay.reserve(len);
    for (size_t i = 0; i < len; i++) {
        char c = (char)d[i];
        if (c >= 'A' && c <= 'Z') c = (char)(c - 'A' + 'a');
        hay += c;
    }
    for (size_t r = 0; r < ruleCount; r++) {
        const ThreatRule& rule = rules[r];
        const char* raw = rule.token;
        std::string token;
        token.reserve(1);
        bool anchored = false;
        for (const char* p = raw; *p; p++) {
            if (*p == '!') { anchored = true; break; }
            token += (char)(*p >= 'A' && *p <= 'Z' ? *p - 'A' + 'a' : *p);
        }
        if (token.empty()) continue;
        int count = 0;
        size_t pos = 0;
        while ((pos = hay.find(token, pos)) != std::string::npos) {
            count++;
            if (count >= 4) break;
            pos += token.size();
        }
        if (count == 0) continue;
        if (anchored && count > 0) count = 1;
        out.push_back({ &rule, count });
    }
}

struct Agg {
    int weight = 0;
    int hits = 0;
    std::string label;
};

void accumulate(std::map<std::string, Agg>& agg, const std::vector<RuleHit>& hits) {
    for (const RuleHit& h : hits) {
        Agg& a = agg[h.rule->category];
        a.weight += h.rule->weight;
        a.hits += h.hits;
        if (a.label.empty() || h.rule->weight >= 6) a.label = h.rule->label;
    }
}

} // namespace

const char* riskLevelLabel(int score) {
    if (score >= 85) return "critical";
    if (score >= 65) return "high";
    if (score >= 45) return "medium";
    if (score >= 25) return "low";
    return "clean";
}

RiskResult assessRisk(const uint8_t* d, size_t n, const std::string& lowerName,
                      FormatId fmt, const std::vector<Indicator>& inds) {
    RiskResult out;
    std::map<std::string, Agg> agg;
    auto addPlain = [&](const std::string& cat, const std::string& label, int weight, int hits) {
        Agg& a = agg[cat];
        a.weight += weight;
        a.hits += hits;
        if (a.label.empty()) a.label = label;
    };

    for (const Indicator& i : inds) {
        if (i.severity <= 0) continue;
        int w = i.severity == 3 ? 30 : i.severity == 2 ? 20 : 10;
        addPlain("findings", i.title, w, 1);
        if (i.severity >= 2 && out.topFindings.size() < 6) out.topFindings.push_back(i.title);
    }

    double globalEntropy = shannon(d, n);
    if (globalEntropy >= 7.9) {
        addPlain("obfuscation", "Uniformly high global entropy", 20, 1);
    } else if (globalEntropy >= 7.4) {
        addPlain("obfuscation", "Elevated global entropy", 12, 1);
    }

    size_t head = n < 4096 ? n : 4096;
    bool isCode = (fmt == FMT_PE || fmt == FMT_ELF || fmt == FMT_MACHO);
    if (isCode && head >= 256 && shannon(d, head) >= 7.4) {
        addPlain("packing", "High-entropy code entry region", 12, 1);
    }

    std::vector<RuleHit> hits;
    scanToken(d, n, 24ull * 1024 * 1024, kExecutionRules,
              sizeof(kExecutionRules) / sizeof(kExecutionRules[0]), hits);
    accumulate(agg, hits);
    scanToken(d, n, 24ull * 1024 * 1024, kNetworkRules,
              sizeof(kNetworkRules) / sizeof(kNetworkRules[0]), hits);
    accumulate(agg, hits);
    scanToken(d, n, 8ull * 1024 * 1024, kShellRules,
              sizeof(kShellRules) / sizeof(kShellRules[0]), hits);
    accumulate(agg, hits);
    scanToken(d, n, 24ull * 1024 * 1024, kDataRules,
              sizeof(kDataRules) / sizeof(kDataRules[0]), hits);
    accumulate(agg, hits);
    size_t scanWin = n < 6ull * 1024 * 1024 ? n : 6ull * 1024 * 1024;
    scanToken(d, n, scanWin, kPackerRules,
              sizeof(kPackerRules) / sizeof(kPackerRules[0]), hits);
    accumulate(agg, hits);

    bool packed = agg.count("packing") || globalEntropy >= 7.4;

    if (iendsWith(lowerName, ".exe") && !packed && fmt == FMT_PE) {
        bool signedAny = false;
        for (const Indicator& i : inds) {
            if (icontains(i.title, "signed") || icontains(i.title, "authenticode")) signedAny = true;
        }
        if (!signedAny) {
            addPlain("authenticity", "Unsigned portable executable", 10, 1);
            if (out.topFindings.size() < 8) out.topFindings.push_back("Unsigned portable executable");
        }
    }

    int score = 0;
    for (auto& kv : agg) score += kv.second.weight;
    if (score > 100) score = 100;
    out.score = score;
    out.level = riskLevelLabel(score);

    if (agg.empty()) {
        out.summary = "No suspicious characteristics were identified. Low trust risk.";
    } else {
        auto worst = std::max_element(agg.begin(), agg.end(), [](const auto& a, const auto& b) {
            return a.second.weight < b.second.weight;
        });
        out.summary = "Weighted over " + std::to_string(agg.size()) +
                      " signal groups; leading contributor: " + worst->first + ".";
    }

    for (auto& kv : agg) {
        RiskSignal s;
        s.category = kv.first;
        s.title = kv.second.label.empty() ? kv.first : kv.second.label;
        s.evidence = kv.second.label.empty() ? kv.first : kv.second.label;
        s.weight = kv.second.weight;
        s.hits = kv.second.hits;
        out.signals.push_back(std::move(s));
    }
    std::sort(out.signals.begin(), out.signals.end(),
              [](const RiskSignal& a, const RiskSignal& b) { return a.weight > b.weight; });

    if (out.topFindings.empty() && !out.signals.empty() && out.score >= 25)
        out.topFindings.push_back(out.signals[0].title);
    return out;
}

void writeRiskJson(Builder& b, const RiskResult& r) {
    b.kv("score", (int64_t)r.score);
    b.kv("level", r.level);
    b.kv("summary", r.summary);
    b.arr("signals");
    for (const RiskSignal& s : r.signals) {
        b.beginObj();
        b.kv("category", s.category);
        b.kv("title", s.title);
        b.kv("evidence", s.evidence);
        b.kv("weight", (int64_t)s.weight);
        b.kv("hits", (int64_t)s.hits);
        b.endObj();
    }
    b.endArr();
    b.arr("topFindings");
    for (const std::string& f : r.topFindings) b.valStr(f);
    b.endArr();
}

}
