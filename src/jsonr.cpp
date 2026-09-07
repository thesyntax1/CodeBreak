#include "jsonr.h"

namespace cb {

namespace {

struct JParser {
    const char* s;
    size_t n;
    size_t o = 0;
    bool err = false;

    JParser(const char* ss, size_t nn) : s(ss), n(nn) {}

    void ws() { while (o < n && (s[o] == ' ' || s[o] == '\t' || s[o] == '\n' || s[o] == '\r')) o++; }

    bool parseValue(JVal& out) {
        ws();
        if (o >= n) { err = true; return false; }
        char c = s[o];
        if (c == '{') return parseObj(out);
        if (c == '[') return parseArr(out);
        if (c == '"') { out.type = JVal::STR; return parseStr(out.str); }
        if (c == 't') { return lit(out, JVal::BOOL, "true") && (out.b = true, true); }
        if (c == 'f') { return lit(out, JVal::BOOL, "false"); }
        if (c == 'n') { return lit(out, JVal::NUL, "null"); }
        return parseNum(out);
    }

    bool lit(JVal& out, JVal::Type t, const char* l) {
        size_t len = strlen(l);
        if (o + len > n || strncmp(s + o, l, len) != 0) { err = true; return false; }
        o += len;
        out.type = t;
        return true;
    }

    bool parseNum(JVal& out) {
        char* end = nullptr;
        double v = strtod(s + o, &end);
        if (end == s + o) { err = true; return false; }
        o = (size_t)(end - s);
        out.type = JVal::NUM;
        out.num = v;
        return true;
    }

    void utf8Append(std::string& out, unsigned cp) {
        if (cp < 0x80) out += (char)cp;
        else if (cp < 0x800) { out += (char)(0xC0 | (cp >> 6)); out += (char)(0x80 | (cp & 0x3F)); }
        else if (cp < 0x10000) { out += (char)(0xE0 | (cp >> 12)); out += (char)(0x80 | ((cp >> 6) & 0x3F)); out += (char)(0x80 | (cp & 0x3F)); }
        else { out += (char)(0xF0 | (cp >> 18)); out += (char)(0x80 | ((cp >> 12) & 0x3F)); out += (char)(0x80 | ((cp >> 6) & 0x3F)); out += (char)(0x80 | (cp & 0x3F)); }
    }

    bool parseHex4(unsigned& v) {
        v = 0;
        for (int i = 0; i < 4; i++) {
            if (o >= n) { err = true; return false; }
            char c = s[o++];
            v <<= 4;
            if (c >= '0' && c <= '9') v |= (unsigned)(c - '0');
            else if (c >= 'a' && c <= 'f') v |= (unsigned)(c - 'a' + 10);
            else if (c >= 'A' && c <= 'F') v |= (unsigned)(c - 'A' + 10);
            else { err = true; return false; }
        }
        return true;
    }

    bool parseStr(std::string& out) {
        out.clear();
        if (o >= n || s[o] != '"') { err = true; return false; }
        o++;
        while (o < n) {
            char c = s[o++];
            if (c == '"') return true;
            if (c == '\\') {
                if (o >= n) { err = true; return false; }
                char e = s[o++];
                switch (e) {
                case '"': out += '"'; break;
                case '\\': out += '\\'; break;
                case '/': out += '/'; break;
                case 'b': out += '\b'; break;
                case 'f': out += '\f'; break;
                case 'n': out += '\n'; break;
                case 'r': out += '\r'; break;
                case 't': out += '\t'; break;
                case 'u': {
                    unsigned cp;
                    if (!parseHex4(cp)) return false;
                    if (cp >= 0xD800 && cp <= 0xDBFF && o + 1 < n && s[o] == '\\' && s[o + 1] == 'u') {
                        size_t save = o;
                        o += 2;
                        unsigned lo;
                        if (!parseHex4(lo)) return false;
                        if (lo >= 0xDC00 && lo <= 0xDFFF) cp = 0x10000 + ((cp - 0xD800) << 10) + (lo - 0xDC00);
                        else o = save;
                    }
                    utf8Append(out, cp);
                    break;
                }
                default: err = true; return false;
                }
            } else {
                out += c;
            }
        }
        err = true;
        return false;
    }

    bool parseArr(JVal& out) {
        out.type = JVal::ARR;
        o++;
        ws();
        if (o < n && s[o] == ']') { o++; return true; }
        for (;;) {
            JVal v;
            if (!parseValue(v)) return false;
            out.arr.push_back(std::move(v));
            ws();
            if (o < n && s[o] == ',') { o++; continue; }
            if (o < n && s[o] == ']') { o++; return true; }
            err = true;
            return false;
        }
    }

    bool parseObj(JVal& out) {
        out.type = JVal::OBJ;
        o++;
        ws();
        if (o < n && s[o] == '}') { o++; return true; }
        for (;;) {
            ws();
            std::string key;
            if (!parseStr(key)) return false;
            ws();
            if (o >= n || s[o] != ':') { err = true; return false; }
            o++;
            JVal v;
            if (!parseValue(v)) return false;
            out.props.push_back({ std::move(key), std::move(v) });
            ws();
            if (o < n && s[o] == ',') { o++; continue; }
            if (o < n && s[o] == '}') { o++; return true; }
            err = true;
            return false;
        }
    }
};

}

bool jsonParse(const char* s, size_t n, JVal& out) {
    JParser p(s, n);
    if (!p.parseValue(out)) return false;
    p.ws();
    return !p.err && p.o == n;
}

bool jsonParse(const std::string& s, JVal& out) {
    return jsonParse(s.data(), s.size(), out);
}

}
