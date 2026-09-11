#include "behavior.h"
#include "jsonw.h"
#include <algorithm>
#include <cstring>
#include <set>

namespace cb {

bool BehaviorResult::empty() const {
    return endpoints.empty() && filePaths.empty() && commands.empty() &&
           persistence.empty() && networkApis.empty() && fileApis.empty() &&
           processApis.empty() && persistenceApis.empty();
}

namespace {

std::string lower(const std::string& s) {
    std::string r = s;
    for (auto& c : r)
        if (c >= 'A' && c <= 'Z') c = (char)(c + 32);
    return r;
}

bool isAsciiPrintable(unsigned char c) {
    return (c >= 0x20 && c <= 0x7e) || c == '\t';
}

bool isAlpha(char c) {
    return (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z');
}

bool isDigit(char c) { return c >= '0' && c <= '9'; }
bool isAlnum(char c) { return isAlpha(c) || isDigit(c); }

void collectAscii(const uint8_t* d, size_t n, std::vector<std::string>& out) {
    size_t i = 0;
    while (i < n) {
        if (!isAsciiPrintable(d[i])) { i++; continue; }
        size_t j = i;
        while (j < n && isAsciiPrintable(d[j]) && j - i < 4096) j++;
        size_t len = j - i;
        while (len && d[i + len - 1] == '\t') len--;
        if (len >= 3) {
            out.emplace_back(reinterpret_cast<const char*>(d + i), len);
        }
        i = j;
    }
}

void collectWide(const uint8_t* d, size_t n, std::vector<std::string>& out) {
    size_t i = 0;
    while (i + 1 < n) {
        uint8_t c = d[i];
        if (c == 0 || !(c >= 0x20 && c <= 0x7e)) { i++; continue; }
        size_t j = i;
        size_t len = 0;
        while (j + 1 < n && len < 4096) {
            uint8_t c2 = d[j];
            if (c2 >= 0x20 && c2 <= 0x7e && d[j + 1] == 0) { len++; j += 2; }
            else break;
        }
        if (len >= 3) {
            std::string s;
            s.reserve(len);
            for (size_t k = 0; k < len; k++) s += (char)d[i + k * 2];
            out.push_back(std::move(s));
        }
        i = j + 1;
    }
}

const char* const kDomainSuffixes[] = {
    "com", "net", "org", "io", "info", "biz", "ru", "cn", "de", "uk", "co", "us", "jp",
    "fr", "br", "in", "it", "nl", "pl", "au", "ca", "tr", "xyz", "top", "site", "online",
    "club", "shop", "store", "app", "dev", "me", "tv", "cc", "ws", "pro", "name", "mobi",
    "click", "link", "pw", "icu", "tech", "space", "host", "zip", "mov", "monster", "email",
};

bool hasScheme(const std::string& s) {
    std::string l = lower(s);
    return l.rfind("http://", 0) == 0 || l.rfind("https://", 0) == 0 ||
           l.rfind("ftp://", 0) == 0 || l.rfind("ws://", 0) == 0 ||
           l.rfind("wss://", 0) == 0 || l.rfind("tcp://", 0) == 0 ||
           l.rfind("smb://", 0) == 0;
}

bool isIpv4(const std::string& s) {
    int parts = 0;
    size_t i = 0;
    while (i <= s.size()) {
        size_t j = i;
        while (j < s.size() && isDigit(s[j])) j++;
        if (j == i) return false;
        size_t len = j - i;
        if (len > 3) return false;
        std::string num = s.substr(i, len);
        if (num.size() > 1 && num[0] == '0') return false;
        if (atoi(num.c_str()) > 255) return false;
        parts++;
        if (parts > 4) return false;
        if (j == s.size()) break;
        if (s[j] != '.') return false;
        i = j + 1;
    }
    return parts == 4;
}

bool looksDomainish(const std::string& t) {
    size_t dots = 0;
    for (char c : t) if (c == '.') dots++;
    return dots >= 1;
}

std::string domainSuffixOf(const std::string& t) {
    std::string l = lower(t);
    for (auto* suf : kDomainSuffixes) {
        size_t sl = strlen(suf);
        if (l.size() >= sl + 2 && l.compare(l.size() - sl, sl, suf) == 0 && l[l.size() - sl - 1] == '.')
            return t.substr(t.size() - sl - 1);
    }
    return std::string();
}

bool hasAtHost(const std::string& s, size_t& atPos) {
    for (size_t i = 0; i < s.size(); i++)
        if (s[i] == '@' && i > 0 && i + 1 < s.size()) { atPos = i; return true; }
    return false;
}

std::string sanitizeEndpoint(const std::string& s) {
    size_t e = s.size();
    while (e > 0 && (s[e - 1] == '.' || s[e - 1] == '/' || s[e - 1] == ':' ||
                     s[e - 1] == ',' || s[e - 1] == ';' || s[e - 1] == ')' || s[e - 1] == ']' || s[e - 1] == '\''))
        e--;
    size_t b = 0;
    while (b < e && s[b] == '(') b++;
    if (b >= e) return std::string();
    return s.substr(b, e - b);
}

bool isExecOrCommonExt(const std::string& s) {
    std::string l = lower(s);
    static const char* exts[] = { ".exe", ".dll", ".sys", ".bat", ".cmd", ".ps1", ".vbs", ".js",
                                  ".scr", ".pif", ".com", ".lnk", ".tmp", ".dat", ".ini", ".log",
                                  ".txt", ".pdf", ".doc", ".docx", ".xls", ".zip", ".rar", ".7z",
                                  ".jpg", ".png", ".jpeg", ".gif", ".mp3", ".mp4", ".cab", ".msi" };
    for (auto* e : exts) {
        size_t el = strlen(e);
        if (l.size() >= el && l.compare(l.size() - el, el, e) == 0) return true;
    }
    return false;
}

bool isFileLike(const std::string& s) {
    if (s.size() < 4) return false;
    bool hasSep = s.find('\\') != std::string::npos;
    if (!hasSep) return false;
    std::string l = lower(s);
    if (l.rfind("c:\\", 0) == 0 || l.rfind("d:\\", 0) == 0 || l.rfind("e:\\", 0) == 0) return true;
    if (s.size() >= 2 && s[0] == '\\' && s[1] == '\\') return true;
    if (l.find(":\\windows\\") != std::string::npos ||
        l.find(":\\users\\") != std::string::npos ||
        l.find("\\appdata\\") != std::string::npos ||
        l.find("\\temp\\") != std::string::npos ||
        l.find("\\programdata\\") != std::string::npos ||
        l.find("\\startup\\") != std::string::npos)
        return true;
    if (l.find("%appdata%") != std::string::npos ||
        l.find("%temp%") != std::string::npos ||
        l.find("%tmp%") != std::string::npos ||
        l.find("%userprofile%") != std::string::npos)
        return true;
    return isExecOrCommonExt(s) && s.size() >= 6;
}

const char* const kApiClasses[][3] = {
    { "NETWORK", "INTERNET", "url download to local file" },
    { "NETWORK", "HTTP", "" },
    { "NETWORK", "WINHTTP", "" },
    { "NETWORK", "URLDOWNLOAD", "" },
    { "NETWORK", "SOCKET", "" },
    { "NETWORK", "WSASOCKET", "" },
    { "NETWORK", "WSASTARTUP", "" },
    { "NETWORK", "WSAGETLASTERROR", "" },
    { "NETWORK", "GETHOSTBYNAME", "" },
    { "NETWORK", "GETADDRINFO", "" },
    { "NETWORK", "DNSE", "" },
    { "NETWORK", "FTPOPEN", "" },
    { "NETWORK", "FTPGET", "" },
    { "NETWORK", "CONNECT", "" },
    { "FILE", "CREATEFILE", "" },
    { "FILE", "NTCREATEFILE", "" },
    { "FILE", "WRITEFILE", "" },
    { "FILE", "SETENDOFFILE", "" },
    { "FILE", "READFILE", "" },
    { "FILE", "MOVEFILE", "" },
    { "FILE", "COPYFILE", "" },
    { "FILE", "DELETEFILE", "" },
    { "FILE", "CREATEDIRECTORY", "" },
    { "FILE", "GETTEMPPATH", "" },
    { "FILE", "SETFILEATTRIBUTES", "" },
    { "FILE", "REPLACEFILE", "" },
    { "FILE", "GETFILEATTRIBUTES", "" },
    { "PROCESS", "CREATEPROCESS", "" },
    { "PROCESS", "SHELLEXECUTE", "" },
    { "PROCESS", "WINSHEXECUTE", "" },
    { "PROCESS", "LOADLIBRARY", "" },
    { "PROCESS", "VIRTUALALLOC", "" },
    { "PROCESS", "WRITEPROCESSMEMORY", "" },
    { "PROCESS", "READPROCESSMEMORY", "" },
    { "PROCESS", "CREATEREMOTETHREAD", "" },
    { "PROCESS", "CREATETHREAD", "" },
    { "PROCESS", "RESUMETHREAD", "" },
    { "PROCESS", "OPENPROCESS", "" },
    { "PROCESS", "QUEUEUSERAPC", "" },
    { "PROCESS", "NTUNMAPVIEWOFSECTION", "" },
    { "PROCESS", "ADJUSTTOKENPRIVILEGES", "" },
    { "PERSIST", "REGCREATEKEY", "" },
    { "PERSIST", "REGOPENKEY", "" },
    { "PERSIST", "REGSETVALUE", "" },
    { "PERSIST", "REGDELETEKEY", "" },
    { "PERSIST", "SHGETVALUE", "" },
    { "PERSIST", "CREATESERVICE", "" },
    { "PERSIST", "SCHTASKS", "" },
};

void classifyApi(const std::string& name, BehaviorResult& r, std::set<std::string>& seen) {
    if (seen.count(name)) return;
    std::string u = name;
    for (auto& c : u) if (c >= 'a' && c <= 'z') c = (char)(c - 32);
    for (auto& row : kApiClasses) {
        const std::string& cls = row[0];
        const std::string& frag = row[1];
        if (u.find(frag) != std::string::npos) {
            seen.insert(name);
            if (cls == "NETWORK") r.networkApis.push_back(name);
            else if (cls == "FILE") r.fileApis.push_back(name);
            else if (cls == "PROCESS") r.processApis.push_back(name);
            else r.persistenceApis.push_back(name);
            return;
        }
    }
}

bool containsIc(const std::string& s, const char* frag) {
    return lower(s).find(frag) != std::string::npos;
}

void addEndpoint(BehaviorResult& r, const std::string& kind, std::string value,
                 std::vector<std::pair<std::string, std::string>>& seenEnd) {
    value = sanitizeEndpoint(value);
    if (value.empty() || value.size() > 512) return;
    std::string key = kind + "|" + lower(value);
    for (auto& p : seenEnd)
        if (p.second == key) return;
    if (seenEnd.size() >= 200) return;
    seenEnd.push_back({ key, key });
    r.endpoints.push_back({ kind, value });
}

std::string trimDots(const std::string& s) {
    size_t b = 0, e = s.size();
    while (b < e && s[b] == '.') b++;
    while (e > b && (s[e - 1] == '.' || s[e - 1] == '/')) e--;
    return s.substr(b, e - b);
}

}

BehaviorResult analyzeBehavior(const uint8_t* d, size_t n,
                               const std::vector<std::string>& importNames,
                               const std::string& lowerName) {
    BehaviorResult r;
    (void)lowerName;
    std::set<std::string> seenApi;
    for (const auto& name : importNames) classifyApi(name, r, seenApi);

    std::vector<std::string> asciiStrings;
    std::vector<std::string> wideStrings;
    collectAscii(d, n, asciiStrings);
    collectWide(d, n, wideStrings);

    std::vector<std::pair<std::string, std::string>> seenEnd;
    std::set<std::string> seenFile;
    std::set<std::string> seenCmd;

    auto processString = [&](const std::string& s) {
        std::string t = s;
        while (!t.empty() && (t.back() == '\t' || t.back() == ' ')) t.pop_back();
        if (t.empty()) return;

        if (hasScheme(t)) {
            addEndpoint(r, "url", t, seenEnd);
            r.urlCount++;
            return;
        }

        if (isIpv4(trimDots(t))) {
            addEndpoint(r, "ip", trimDots(t), seenEnd);
            r.ipCount++;
            return;
        }

        size_t atPos = 0;
        if (hasAtHost(t, atPos)) {
            std::string host = t.substr(atPos + 1);
            if (isIpv4(trimDots(host)) || (looksDomainish(host) && !domainSuffixOf(host).empty())) {
                addEndpoint(r, "email", t, seenEnd);
                r.emailCount++;
            }
        }

        if (containsIc(t, "://") || hasScheme(t)) return;

        if (isFileLike(t)) {
            if (!seenFile.count(t)) {
                seenFile.insert(t);
                if (r.filePaths.size() < 120) r.filePaths.push_back(t);
            }
            return;
        }

        std::string lt = lower(t);
        bool cmd = false;
        static const char* cmdWords[] = { "powershell", "cmd.exe", "cmd /c", "/c ", "certutil",
                                          "mshta", "wscript", "cscript", "regsvr32", "rundll32",
                                          "bitsadmin", "schtasks", "curl.exe", "wget.exe" };
        for (auto* w : cmdWords) {
            if (lt.find(w) != std::string::npos) { cmd = true; break; }
        }
        if (cmd) {
            if (!seenCmd.count(t)) {
                seenCmd.insert(t);
                if (r.commands.size() < 80) r.commands.push_back(t);
            }
            return;
        }

        bool persist = false;
        static const char* persWords[] = { "hkcu\\software\\microsoft\\windows\\currentversion\\run",
                                           "hklm\\software\\microsoft\\windows\\currentversion\\run",
                                           "\\startup\\", "\\run\\", "hkey_local_machine", "hkey_current_user",
                                           "currentversion\\run" };
        for (auto* w : persWords) {
            if (lt.find(w) != std::string::npos) { persist = true; break; }
        }
        if (persist) {
            if (r.persistence.size() < 60) r.persistence.push_back(t);
            return;
        }

        if (looksDomainish(t) && domainSuffixOf(t).size() > 2) {
            std::string dom = trimDots(t);
            if (!dom.empty() && isAlnum(dom[0])) {
                addEndpoint(r, "domain", dom, seenEnd);
                r.domainCount++;
            }
        }
    };

    for (const auto& s : asciiStrings) processString(s);
    for (const auto& s : wideStrings) processString(s);
    return r;
}

void writeBehaviorJson(Builder& b, const BehaviorResult& r) {
    b.obj("network");
    b.arr("endpoints");
    for (const auto& e : r.endpoints) {
        b.beginObj();
        b.kv("kind", e.kind);
        b.kv("value", e.value);
        b.endObj();
    }
    b.endArr();
    b.kv("urlCount", (int64_t)r.urlCount);
    b.kv("domainCount", (int64_t)r.domainCount);
    b.kv("ipCount", (int64_t)r.ipCount);
    b.kv("emailCount", (int64_t)r.emailCount);
    b.arr("apis");
    for (const auto& a : r.networkApis) b.valStr(a);
    b.endArr();
    b.endObj();

    b.obj("fileSystem");
    b.arr("paths");
    for (const auto& p : r.filePaths) b.valStr(p);
    b.endArr();
    b.arr("apis");
    for (const auto& a : r.fileApis) b.valStr(a);
    b.endArr();
    b.endObj();

    b.obj("process");
    b.arr("commands");
    for (const auto& c : r.commands) b.valStr(c);
    b.endArr();
    b.arr("apis");
    for (const auto& a : r.processApis) b.valStr(a);
    b.endArr();
    b.endObj();

    b.obj("persistence");
    b.arr("candidates");
    for (const auto& p : r.persistence) b.valStr(p);
    b.endArr();
    b.arr("apis");
    for (const auto& a : r.persistenceApis) b.valStr(a);
    b.endArr();
    b.endObj();
}

}
