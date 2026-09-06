#include "util.h"
#include "jsonw.h"
#include <cstdio>
#include <cstring>
#include <cmath>
#include <ctime>
#include <cctype>
#include <algorithm>

#ifdef _WIN32
#include <windows.h>
#else
#include <sys/stat.h>
#endif

namespace cb {

std::string hexU(uint64_t v, int width) {
    static const char* d = "0123456789abcdef";
    std::string s = "0x";
    char buf[20];
    int i = 0;
    if (v == 0) buf[i++] = '0';
    while (v) { buf[i++] = d[v & 0xF]; v >>= 4; }
    while (i < width) buf[i++] = '0';
    for (int j = i - 1; j >= 0; j--) s += buf[j];
    return s;
}

std::string hexBytes(const uint8_t* d, size_t n) {
    static const char* h = "0123456789abcdef";
    std::string s;
    s.reserve(n * 2);
    for (size_t i = 0; i < n; i++) { s += h[d[i] >> 4]; s += h[d[i] & 0xF]; }
    return s;
}

std::string decU(uint64_t v) {
    char buf[24];
    snprintf(buf, sizeof(buf), "%llu", (unsigned long long)v);
    return std::string(buf);
}

std::string utf8Sanitize(const uint8_t* d, size_t n) {
    std::string s;
    s.reserve(n);
    size_t i = 0;
    while (i < n) {
        uint8_t c = d[i];
        if (c < 0x80) {
            if (c >= 0x20 && c != 0x7F) s += (char)c;
            else s += ' ';
            i++;
        } else {
            size_t len = c >= 0xF0 ? 4 : c >= 0xE0 ? 3 : c >= 0xC0 ? 2 : 0;
            bool ok = len > 0 && i + len <= n;
            if (ok) {
                uint32_t cp = (uint32_t)(c & (0xFF >> (len + 1))) << (6 * (len - 1));
                for (size_t k = 1; k < len; k++) {
                    if ((d[i + k] & 0xC0) != 0x80) { ok = false; break; }
                    cp |= (uint32_t)(d[i + k] & 0x3F) << (6 * (len - 1 - k));
                }
                if (ok && (cp > 0x10FFFF || (cp >= 0xD800 && cp <= 0xDFFF))) ok = false;
                if (ok && cp == 0) ok = false;
            }
            if (ok) { s.append((const char*)d + i, len); i += len; }
            else { s += (char)0xEF; s += (char)0xBF; s += (char)0xBD; i++; }
        }
    }
    return s;
}

static void appendUtf8(std::string& s, uint32_t cp) {
    if (cp > 0x10FFFF || (cp >= 0xD800 && cp <= 0xDFFF)) cp = 0xFFFD;
    if (cp < 0x80) s += (char)cp;
    else if (cp < 0x800) { s += (char)(0xC0 | (cp >> 6)); s += (char)(0x80 | (cp & 0x3F)); }
    else if (cp < 0x10000) { s += (char)(0xE0 | (cp >> 12)); s += (char)(0x80 | ((cp >> 6) & 0x3F)); s += (char)(0x80 | (cp & 0x3F)); }
    else { s += (char)(0xF0 | (cp >> 18)); s += (char)(0x80 | ((cp >> 12) & 0x3F)); s += (char)(0x80 | ((cp >> 6) & 0x3F)); s += (char)(0x80 | (cp & 0x3F)); }
}

std::string wideToUtf8(const uint16_t* w, size_t len) {
    std::string s;
    s.reserve(len);
    size_t i = 0;
    while (i < len) {
        uint32_t cp = w[i];
        if (cp >= 0xD800 && cp <= 0xDBFF && i + 1 < len && w[i + 1] >= 0xDC00 && w[i + 1] <= 0xDFFF) {
            cp = 0x10000 + ((cp - 0xD800) << 10) + (w[i + 1] - 0xDC00);
            i += 2;
        } else if (cp >= 0xD800 && cp <= 0xDFFF) {
            cp = 0xFFFD;
            i++;
        } else i++;
        if (cp == 0) break;
        appendUtf8(s, cp);
    }
    return s;
}

std::string mutf8ToUtf8(const uint8_t* d, size_t n) {
    std::string s;
    s.reserve(n);
    size_t i = 0;
    while (i < n) {
        uint8_t c = d[i];
        if (c < 0x80) { if (c == 0) break; s += (char)c; i++; continue; }
        int len = c >= 0xF0 ? 4 : c >= 0xE0 ? 3 : c >= 0xC0 ? 2 : 0;
        if (len == 0 || i + (size_t)len > n) { appendUtf8(s, 0xFFFD); i++; continue; }
        uint32_t cp = c & (0xFF >> (len + 1));
        bool ok = true;
        for (int k = 1; k < len; k++) {
            uint8_t cc = d[i + k];
            if ((cc & 0xC0) != 0x80) { ok = false; break; }
            cp = (cp << 6) | (cc & 0x3F);
        }
        if (!ok) { appendUtf8(s, 0xFFFD); i++; continue; }
        if (cp == 0) { s += (char)0xC0; s += (char)0x80; }
        else appendUtf8(s, cp);
        i += len;
    }
    return s;
}

std::string readCStrAt(const uint8_t* p, size_t n, size_t off, size_t cap) {
    if (!p || off >= n) return std::string();
    size_t end = off;
    size_t lim = std::min(n, off + cap);
    while (end < lim && p[end] != 0) end++;
    return std::string((const char*)p + off, end - off);
}

double shannon(const uint8_t* d, size_t n) {
    if (!n) return 0.0;
    uint64_t cnt[256] = { 0 };
    for (size_t i = 0; i < n; i++) cnt[d[i]]++;
    double e = 0.0;
    for (int i = 0; i < 256; i++) {
        if (!cnt[i]) continue;
        double p = (double)cnt[i] / (double)n;
        e -= p * std::log2(p);
    }
    return e;
}

std::string fmtTimeUtc(uint64_t unixSec) {
    if (unixSec == 0) return std::string();
    time_t t = (time_t)unixSec;
    struct tm tmv;
#ifdef _WIN32
    if (_gmtime64_s(&tmv, &t) != 0) return std::string();
#else
    if (!gmtime_r(&t, &tmv)) return std::string();
#endif
    char buf[40];
    snprintf(buf, sizeof(buf), "%04d-%02d-%02d %02d:%02d:%02d UTC",
        tmv.tm_year + 1900, tmv.tm_mon + 1, tmv.tm_mday, tmv.tm_hour, tmv.tm_min, tmv.tm_sec);
    return std::string(buf);
}

std::string fmtSize(uint64_t bytes) {
    char buf[48];
    double v = (double)bytes;
    if (bytes >= 1024ULL * 1024 * 1024) snprintf(buf, sizeof(buf), "%.2f GB", v / (1024.0 * 1024 * 1024));
    else if (bytes >= 1024 * 1024) snprintf(buf, sizeof(buf), "%.2f MB", v / (1024.0 * 1024));
    else if (bytes >= 1024) snprintf(buf, sizeof(buf), "%.2f KB", v / 1024.0);
    else snprintf(buf, sizeof(buf), "%llu B", (unsigned long long)bytes);
    return std::string(buf);
}

static char lc(char c) { return (char)((c >= 'A' && c <= 'Z') ? c + 32 : c); }
static char uc(char c) { return (char)((c >= 'a' && c <= 'z') ? c - 32 : c); }

std::string toLower(const std::string& s) { std::string r(s); std::transform(r.begin(), r.end(), r.begin(), lc); return r; }
std::string toUpper(const std::string& s) { std::string r(s); std::transform(r.begin(), r.end(), r.begin(), uc); return r; }

bool icontains(const std::string& hay, const std::string& needle) {
    if (needle.empty()) return true;
    if (needle.size() > hay.size()) return false;
    for (size_t i = 0; i + needle.size() <= hay.size(); i++) {
        size_t j = 0;
        for (; j < needle.size(); j++) if (lc(hay[i + j]) != lc(needle[j])) break;
        if (j == needle.size()) return true;
    }
    return false;
}

bool iendsWith(const std::string& s, const std::string& suffix) {
    if (suffix.size() > s.size()) return false;
    for (size_t i = 0; i < suffix.size(); i++)
        if (lc(s[s.size() - suffix.size() + i]) != lc(suffix[i])) return false;
    return true;
}

bool iequals(const std::string& a, const std::string& b) {
    if (a.size() != b.size()) return false;
    for (size_t i = 0; i < a.size(); i++) if (lc(a[i]) != lc(b[i])) return false;
    return true;
}

static bool prn(uint8_t c) { return c >= 0x20 && c < 0x7F; }

void StringsIndex::build(const uint8_t* d, size_t n, uint32_t minLen, size_t cap) {
    base_ = d; size_ = n; minLen_ = minLen; truncated_ = false;
    refs_.clear();
    refs_.reserve(std::min(cap, (size_t)(n / 8 + 16)));
    size_t i = 0;
    while (i < n) {
        if (refs_.size() >= cap) { truncated_ = true; break; }
        uint8_t c = d[i];
        if (prn(c)) {
            size_t a = i;
            while (a < n && prn(d[a])) a++;
            size_t aLen = a - i;
            size_t wPairs = 0;
            if (d[i] >= 0x20 && i + 1 < n && d[i + 1] == 0) {
                size_t q = i;
                while (q + 1 < n && prn(d[q]) && d[q + 1] == 0) { wPairs++; q += 2; }
            }
            size_t wBytes = wPairs * 2;
            if (aLen >= minLen && aLen + 1 >= wBytes) {
                refs_.push_back({ (uint64_t)i, (uint32_t)aLen, 0 });
                i = a;
            } else if (wBytes >= minLen) {
                refs_.push_back({ (uint64_t)i, (uint32_t)wBytes, 1 });
                i += wBytes;
            } else {
                i = a > i ? a : i + 1;
            }
        } else if (c >= 0x20 && i + 1 < n && d[i + 1] == 0) {
            size_t q = i;
            size_t wPairs = 0;
            while (q + 1 < n && d[q] >= 0x20 && d[q] < 0x7F && d[q + 1] == 0) { wPairs++; q += 2; }
            size_t wBytes = wPairs * 2;
            if (wBytes >= minLen) { refs_.push_back({ (uint64_t)i, (uint32_t)wBytes, 1 }); i += wBytes; }
            else i++;
        } else {
            i++;
        }
    }
}

std::string StringsIndex::text(const StrRef& r) const {
    if (!base_ || r.off >= size_) return std::string();
    size_t len = std::min((size_t)r.len, size_ - (size_t)r.off);
    if (r.wide) {
        std::vector<uint16_t> w;
        w.reserve(len / 2 + 1);
        for (size_t i = 0; i + 1 < len + 1 && i + 1 < size_ + 1; i += 2) {
            uint16_t u = base_[r.off + i] | ((uint16_t)base_[r.off + i + 1] << 8);
            w.push_back(u);
        }
        return wideToUtf8(w.data(), w.size());
    }
    return utf8Sanitize(base_ + r.off, len);
}

void StringsIndex::query(Builder& b, uint64_t startIdx, uint32_t count, uint32_t minLen, int kind, const std::string& filter, uint64_t& totalOut) const {
    totalOut = 0;
    std::string f = toLower(filter);
    b.beginArr();
    uint64_t emitted = 0;
    for (const StrRef& r : refs_) {
        if ((uint32_t)r.len < minLen) continue;
        if (kind == 1 && r.wide) continue;
        if (kind == 2 && !r.wide) continue;
        if (!f.empty()) {
            std::string t = toLower(text(r));
            if (t.find(f) == std::string::npos) continue;
        }
        if (totalOut >= startIdx && emitted < count) {
            b.beginObj();
            b.kv("off", r.off);
            b.kv("len", (uint64_t)r.len);
            b.kv("wide", r.wide != 0);
            b.kv("text", text(r));
            b.endObj();
            emitted++;
        }
        totalOut++;
    }
    b.endArr();
}

struct BitR {
    const uint8_t* d;
    size_t n;
    size_t pos;
    uint32_t bitbuf;
    int bitcnt;
    bool err;
    BitR(const uint8_t* dd, size_t nn) : d(dd), n(nn), pos(0), bitbuf(0), bitcnt(0), err(false) {}
    int bit() {
        if (bitcnt == 0) {
            if (pos >= n) { err = true; return 0; }
            bitbuf = d[pos++];
            bitcnt = 8;
        }
        int b = bitbuf & 1;
        bitbuf >>= 1;
        bitcnt--;
        return b;
    }
    uint32_t bits(int k) {
        uint32_t v = 0;
        for (int i = 0; i < k; i++) v |= (uint32_t)bit() << i;
        return v;
    }
    void alignByte() { bitbuf = 0; bitcnt = 0; }
};

struct Huff {
    uint16_t count[16];
    uint16_t symbol[288];
    bool err;
    Huff() : err(false) { for (int i = 0; i < 16; i++) count[i] = 0; }
};

static int huffDecode(BitR& br, const Huff& h) {
    int code = 0, first = 0, index = 0;
    for (int len = 1; len <= 15; len++) {
        code |= br.bit();
        if (br.err) return -1;
        int cnt = h.count[len];
        if (code - cnt < first) return h.symbol[index + (code - first)];
        index += cnt;
        first += cnt;
        first <<= 1;
        code <<= 1;
    }
    return -1;
}

static Huff huffBuild(const uint8_t* lengths, int n) {
    Huff h;
    for (int i = 0; i < n; i++) h.count[lengths[i]]++;
    if (h.count[0] == n) { h.err = true; return h; }
    int left = 1;
    for (int len = 1; len <= 15; len++) { left <<= 1; left -= h.count[len]; if (left < 0) { h.err = true; return h; } }
    uint16_t offs[16];
    offs[1] = 0;
    for (int len = 1; len < 15; len++) offs[len + 1] = offs[len] + h.count[len];
    for (int i = 0; i < n; i++) if (lengths[i]) h.symbol[offs[lengths[i]]++] = (uint16_t)i;
    return h;
}

static const uint16_t LBASE[29] = { 3,4,5,6,7,8,9,10,11,13,15,17,19,23,27,31,35,43,51,59,67,83,99,115,131,163,195,227,258 };
static const uint16_t LEXT[29] = { 0,0,0,0,0,0,0,0,1,1,1,1,2,2,2,2,3,3,3,3,4,4,4,4,5,5,5,5,0 };
static const uint16_t DBASE[30] = { 1,2,3,4,5,7,9,13,17,25,33,49,65,97,129,193,257,385,513,769,1025,1537,2049,3073,4097,6145,8193,12289,16385,24577 };
static const uint16_t DEXT[30] = { 0,0,0,0,1,1,2,2,3,3,4,4,5,5,6,6,7,7,8,8,9,9,10,10,11,11,12,12,13,13 };
static const uint8_t CORDER[19] = { 16,17,18,0,8,7,9,6,10,5,11,4,12,3,13,2,14,1,15 };

bool inflateZlibOrRaw(const uint8_t* in, size_t inN, std::vector<uint8_t>& out, bool zlibWrapped, size_t maxOut, std::string& errOut) {
    BitR br(in, inN);
    if (zlibWrapped) {
        if (inN < 6) { errOut = "zlib stream too short"; return false; }
        uint8_t cmf = in[0], flg = in[1];
        if ((cmf & 0x0F) != 8 || ((cmf * 256 + flg) % 31) != 0) { errOut = "bad zlib header"; return false; }
        br.pos = 2;
    }
    uint8_t lit[288], dst[30];
    int final = 0;
    while (!final) {
        final = br.bit();
        if (br.err) { errOut = "truncated block header"; return false; }
        int type = (int)br.bits(2);
        if (br.err) { errOut = "truncated block type"; return false; }
        if (type == 0) {
            br.alignByte();
            if (br.pos + 4 > inN) { errOut = "truncated stored block"; return false; }
            uint16_t len = (uint16_t)(in[br.pos] | (in[br.pos + 1] << 8));
            uint16_t nlen = (uint16_t)(in[br.pos + 2] | (in[br.pos + 3] << 8));
            br.pos += 4;
            if ((uint16_t)~nlen != len) { errOut = "stored length check failed"; return false; }
            if (br.pos + len > inN) { errOut = "stored block exceeds input"; return false; }
            if (out.size() + len > maxOut) { errOut = "output exceeds limit"; return false; }
            out.insert(out.end(), in + br.pos, in + br.pos + len);
            br.pos += len;
        } else if (type == 1 || type == 2) {
            Huff lh, dh;
            if (type == 1) {
                for (int i = 0; i < 144; i++) lit[i] = 8;
                for (int i = 144; i < 256; i++) lit[i] = 9;
                for (int i = 256; i < 280; i++) lit[i] = 7;
                for (int i = 280; i < 288; i++) lit[i] = 8;
                for (int i = 0; i < 30; i++) dst[i] = 5;
                lh = huffBuild(lit, 288);
                dh = huffBuild(dst, 30);
            } else {
                int hlit = (int)br.bits(5) + 257;
                int hdist = (int)br.bits(5) + 1;
                int hclen = (int)br.bits(4) + 4;
                if (hlit > 286 || hdist > 30) { errOut = "too many codes"; return false; }
                uint8_t cl[19] = { 0 };
                for (int i = 0; i < hclen; i++) cl[CORDER[i]] = (uint8_t)br.bits(3);
                Huff ch = huffBuild(cl, 19);
                if (ch.err) { errOut = "bad code length table"; return false; }
                uint8_t all[320] = { 0 };
                int idx = 0;
                while (idx < hlit + hdist) {
                    int sym = huffDecode(br, ch);
                    if (sym < 0) { errOut = "bad code length symbol"; return false; }
                    if (sym < 16) all[idx++] = (uint8_t)sym;
                    else {
                        int rep = 0;
                        uint8_t val = 0;
                        if (sym == 16) { if (idx == 0) { errOut = "bad repeat"; return false; } rep = 3 + (int)br.bits(2); val = all[idx - 1]; }
                        else if (sym == 17) { rep = 3 + (int)br.bits(3); }
                        else { rep = 11 + (int)br.bits(7); }
                        if (idx + rep > hlit + hdist) { errOut = "too many code lengths"; return false; }
                        while (rep--) all[idx++] = val;
                    }
                    if (br.err) { errOut = "truncated code lengths"; return false; }
                }
                lh = huffBuild(all, hlit);
                dh = huffBuild(all + hlit, hdist);
            }
            if (lh.err || dh.err) { errOut = "bad huffman table"; return false; }
            for (;;) {
                int sym = huffDecode(br, lh);
                if (br.err || sym < 0) { errOut = "bad literal/length code"; return false; }
                if (sym < 256) {
                    if (out.size() + 1 > maxOut) { errOut = "output exceeds limit"; return false; }
                    out.push_back((uint8_t)sym);
                } else if (sym == 256) break;
                else {
                    sym -= 257;
                    if (sym >= 29) { errOut = "invalid length symbol"; return false; }
                    int len = LBASE[sym] + (int)br.bits(LEXT[sym]);
                    int dsym = huffDecode(br, dh);
                    if (br.err || dsym < 0 || dsym >= 30) { errOut = "bad distance code"; return false; }
                    int dist = DBASE[dsym] + (int)br.bits(DEXT[dsym]);
                    if ((size_t)dist > out.size()) { errOut = "distance too far back"; return false; }
                    if (out.size() + (size_t)len > maxOut) { errOut = "output exceeds limit"; return false; }
                    size_t from = out.size() - (size_t)dist;
                    for (int k = 0; k < len; k++) out.push_back(out[from + (size_t)k]);
                }
            }
        } else { errOut = "invalid block type"; return false; }
    }
    if (zlibWrapped) {
        if (br.pos + 4 <= inN) {
            uint32_t want = (uint32_t)in[br.pos] | ((uint32_t)in[br.pos + 1] << 8) | ((uint32_t)in[br.pos + 2] << 16) | ((uint32_t)in[br.pos + 3] << 24);
            (void)want;
        }
    }
    return true;
}

uint64_t fileTimeNowUnix() {
    return (uint64_t)time(nullptr);
}

#ifdef _WIN32
static std::wstring utf8ToWide(const std::string& s) {
    if (s.empty()) return std::wstring();
    int n = MultiByteToWideChar(CP_UTF8, 0, s.data(), (int)s.size(), nullptr, 0);
    std::wstring w((size_t)n, 0);
    if (n) MultiByteToWideChar(CP_UTF8, 0, s.data(), (int)s.size(), &w[0], n);
    return w;
}
#endif

FileInfo queryFileInfo(const std::string& pathUtf8) {
    FileInfo fi;
#ifdef _WIN32
    struct _stat64 st;
    std::wstring w = utf8ToWide(pathUtf8);
    if (_wstat64(w.c_str(), &st) == 0 && (st.st_mode & _S_IFREG)) {
        fi.exists = true;
        fi.size = (uint64_t)st.st_size;
        fi.created = (uint64_t)st.st_ctime;
        fi.modified = (uint64_t)st.st_mtime;
        fi.accessed = (uint64_t)st.st_atime;
    }
#else
    struct stat st;
    if (stat(pathUtf8.c_str(), &st) == 0 && S_ISREG(st.st_mode)) {
        fi.exists = true;
        fi.size = (uint64_t)st.st_size;
        fi.created = (uint64_t)st.st_ctime;
        fi.modified = (uint64_t)st.st_mtime;
        fi.accessed = (uint64_t)st.st_atime;
    }
#endif
    return fi;
}

bool readFileBytes(const std::string& pathUtf8, std::vector<uint8_t>& out, std::string& errOut) {
    FILE* f = nullptr;
#ifdef _WIN32
    std::wstring w = utf8ToWide(pathUtf8);
    f = _wfopen(w.c_str(), L"rb");
#else
    f = fopen(pathUtf8.c_str(), "rb");
#endif
    if (!f) { errOut = "cannot open file"; return false; }
    out.clear();
    uint8_t buf[1 << 16];
    size_t r;
    while ((r = fread(buf, 1, sizeof(buf), f)) > 0) out.insert(out.end(), buf, buf + r);
    bool bad = ferror(f) != 0;
    fclose(f);
    if (bad) { errOut = "read error"; return false; }
    return true;
}

}
