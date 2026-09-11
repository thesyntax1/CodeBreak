#pragma once
#include <string>
#include <vector>
#include <utility>
#include <cstdlib>
#include <cstring>

namespace cb {

struct JVal {
    enum Type { NUL, BOOL, NUM, STR, ARR, OBJ } type = NUL;
    bool b = false;
    double num = 0;
    std::string str;
    std::vector<JVal> arr;
    std::vector<std::pair<std::string, JVal>> props;

    const JVal* get(const char* k) const {
        for (auto& p : props) if (p.first == k) return &p.second;
        return nullptr;
    }
    std::string getStr(const char* k, const std::string& def = std::string()) const {
        const JVal* v = get(k);
        return v && v->type == STR ? v->str : def;
    }
    double getNum(const char* k, double def = 0) const {
        const JVal* v = get(k);
        return v && v->type == NUM ? v->num : def;
    }
    int getInt(const char* k, int def = 0) const {
        const JVal* v = get(k);
        return v && v->type == NUM ? (int)(long long)v->num : def;
    }
};

bool jsonParse(const char* s, size_t n, JVal& out);
bool jsonParse(const std::string& s, JVal& out);

}
