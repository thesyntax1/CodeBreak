#pragma once
#include <cstdint>
#include <cstddef>
#include <string>
#include <vector>

#ifdef _WIN32
std::wstring utf8ToWide(const std::string& s);
#endif

namespace cb {

class Builder;

struct Rd {
    const uint8_t* p = nullptr;
    size_t n = 0;
    size_t o = 0;
    bool err = false;
    Rd() = default;
    Rd(const uint8_t* data, size_t size, size_t off = 0) : p(data), n(size), o(off) {}
    bool ok() const { return !err; }
    size_t left() const { return err || o > n ? 0 : n - o; }
    void fail() { err = true; }
    uint8_t u8() { if (o + 1 > n) { err = true; return 0; } return p[o++]; }
    uint16_t u16() { if (o + 2 > n) { err = true; return 0; } uint16_t v = (uint16_t)(p[o] | ((uint16_t)p[o + 1] << 8)); o += 2; return v; }
    uint32_t u32() { if (o + 4 > n) { err = true; return 0; } uint32_t v = (uint32_t)p[o] | ((uint32_t)p[o + 1] << 8) | ((uint32_t)p[o + 2] << 16) | ((uint32_t)p[o + 3] << 24); o += 4; return v; }
    uint64_t u64() { if (o + 8 > n) { err = true; return 0; } uint64_t v = 0; for (int i = 7; i >= 0; i--) v = (v << 8) | p[o + i]; o += 8; return v; }
    uint16_t u16be() { if (o + 2 > n) { err = true; return 0; } uint16_t v = ((uint16_t)p[o] << 8) | p[o + 1]; o += 2; return v; }
    uint32_t u32be() { if (o + 4 > n) { err = true; return 0; } uint32_t v = ((uint32_t)p[o] << 24) | ((uint32_t)p[o + 1] << 16) | ((uint32_t)p[o + 2] << 8) | p[o + 3]; o += 4; return v; }
    uint64_t u64be() { if (o + 8 > n) { err = true; return 0; } uint64_t v = 0; for (int i = 0; i < 8; i++) v = (v << 8) | p[o + i]; o += 8; return v; }
    uint64_t uleb() {
        uint64_t v = 0; int shift = 0;
        for (int i = 0; i < 10; i++) {
            if (o + 1 > n) { err = true; return v; }
            uint8_t b = p[o++];
            v |= (uint64_t)(b & 0x7F) << shift;
            if (!(b & 0x80)) break;
            shift += 7;
        }
        return v;
    }
    const uint8_t* take(size_t k) { if (k > n || o > n - k) { err = true; return nullptr; } const uint8_t* r = p + o; o += k; return r; }
    bool skip(size_t k) { if (k > n || o > n - k) { err = true; return false; } o += k; return true; }
    bool seek(size_t off) { if (off > n) { err = true; return false; } o = off; return true; }
};

std::string hexU(uint64_t v, int width = 0);
std::string hexBytes(const uint8_t* d, size_t n);
std::string decU(uint64_t v);
std::string utf8Sanitize(const uint8_t* d, size_t n);
std::string wideToUtf8(const uint16_t* w, size_t len);
std::string mutf8ToUtf8(const uint8_t* d, size_t n);
std::string readCStrAt(const uint8_t* p, size_t n, size_t off, size_t cap = 8192);
double shannon(const uint8_t* d, size_t n);
std::string fmtTimeUtc(uint64_t unixSec);
std::string fmtSize(uint64_t bytes);
std::string toLower(const std::string& s);
std::string toUpper(const std::string& s);
bool icontains(const std::string& hay, const std::string& needle);
bool iendsWith(const std::string& s, const std::string& suffix);
bool iequals(const std::string& a, const std::string& b);

struct StrRef {
    uint64_t off;
    uint32_t len;
    uint8_t wide;
};

class StringsIndex {
public:
    void build(const uint8_t* d, size_t n, uint32_t minLen, size_t cap);
    size_t size() const { return refs_.size(); }
    bool truncated() const { return truncated_; }
    uint32_t minLen() const { return minLen_; }
    std::string text(const StrRef& r) const;
    void query(Builder& b, uint64_t startIdx, uint32_t count, uint32_t minLen, int kind, const std::string& filter, uint64_t& totalOut) const;
private:
    const uint8_t* base_ = nullptr;
    size_t size_ = 0;
    uint32_t minLen_ = 4;
    std::vector<StrRef> refs_;
    bool truncated_ = false;
};

bool inflateZlibOrRaw(const uint8_t* in, size_t inN, std::vector<uint8_t>& out, bool zlibWrapped, size_t maxOut, std::string& errOut);

uint64_t fileTimeNowUnix();

struct FileInfo {
    bool exists = false;
    uint64_t size = 0;
    uint64_t created = 0;
    uint64_t modified = 0;
    uint64_t accessed = 0;
};
FileInfo queryFileInfo(const std::string& pathUtf8);

bool readFileBytes(const std::string& pathUtf8, std::vector<uint8_t>& out, std::string& errOut);

struct WalkOptions {
    bool includeHiddenDirs = false;
    size_t maxFiles = 200000;
};

bool walkDirectory(const std::string& dirUtf8, std::vector<std::string>& out,
                   std::string& errOut, const WalkOptions& opt = WalkOptions());

}

