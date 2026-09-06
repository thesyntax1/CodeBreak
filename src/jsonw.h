#pragma once
#include <string>
#include <cstdint>
#include <cstdio>
#include <cstring>
#include <vector>

namespace cb {

std::string hexU(uint64_t v, int width);


class Builder {
public:
    explicit Builder(std::string& out) : s_(out) { s_.clear(); }
    void beginObj() { pre(); s_ += '{'; st_.push_back(false); }
    void endObj() { s_ += '}'; if (!st_.empty()) st_.pop_back(); }
    void beginArr() { pre(); s_ += '['; st_.push_back(false); }
    void endArr() { s_ += ']'; if (!st_.empty()) st_.pop_back(); }
    void key(const char* k) { if (!st_.empty()) { if (st_.back()) s_ += ','; st_.back() = true; } s_ += '"'; escape(k, strlen(k)); s_ += "\": "; keyPending_ = true; }
    void valStr(const std::string& v) { pre(); s_ += '"'; escape(v.data(), v.size()); s_ += '"'; }
    void valCStr(const char* v) { pre(); if (v) { s_ += '"'; escape(v, strlen(v)); s_ += '"'; } else s_ += "null"; }
    void valI(int64_t v) { pre(); char b[24]; snprintf(b, sizeof(b), "%lld", (long long)v); s_ += b; }
    void valU(uint64_t v) { pre(); char b[24]; snprintf(b, sizeof(b), "%llu", (unsigned long long)v); s_ += b; }
    void valD(double v) {
        pre();
        if (v != v || v > 1.7976931348623157e308 || v < -1.7976931348623157e308) { s_ += "null"; return; }
        char b[40];
        snprintf(b, sizeof(b), "%.10g", v);
        s_ += b;
        if (!strchr(b, '.') && !strchr(b, 'e') && !strchr(b, 'E') && !strchr(b, 'n')) s_ += ".0";
    }
    void valB(bool v) { pre(); s_ += v ? "true" : "false"; }
    void valNull() { pre(); s_ += "null"; }
    void raw(const char* txt) { pre(); s_ += txt; }
    void kv(const char* k, const std::string& v) { key(k); valStr(v); }
    void kv(const char* k, const char* v) { key(k); valCStr(v); }
    void kv(const char* k, int64_t v) { key(k); valI(v); }
    void kv(const char* k, uint64_t v) { key(k); valU(v); }
    void kv(const char* k, int v) { key(k); valI(v); }
    void kv(const char* k, uint32_t v) { key(k); valU(v); }
    void kv(const char* k, bool v) { key(k); valB(v); }
    void kv(const char* k, double v) { key(k); valD(v); }
    void kvHex(const char* k, uint64_t v, int width = 0) { key(k); valStr(hexU(v, width)); }
    void obj(const char* k) { key(k); beginObj(); }
    void arr(const char* k) { key(k); beginArr(); }
    const std::string& str() const { return s_; }
private:
    void pre() {
        if (keyPending_) { keyPending_ = false; return; }
        if (!st_.empty()) { if (st_.back()) s_ += ','; st_.back() = true; }
    }
    void escape(const char* v, size_t n) {
        static const char* h = "0123456789abcdef";
        for (size_t i = 0; i < n; i++) {
            unsigned char c = (unsigned char)v[i];
            switch (c) {
            case '"': s_ += "\\\""; break;
            case '\\': s_ += "\\\\"; break;
            case '\b': s_ += "\\b"; break;
            case '\f': s_ += "\\f"; break;
            case '\n': s_ += "\\n"; break;
            case '\r': s_ += "\\r"; break;
            case '\t': s_ += "\\t"; break;
            default:
                if (c < 0x20) { s_ += "\\u00"; s_ += h[c >> 4]; s_ += h[c & 0xF]; }
                else s_ += (char)c;
            }
        }
    }
    std::string& s_;
    std::vector<bool> st_;
    bool keyPending_ = false;
};

}
