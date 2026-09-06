#pragma once
#include <cstdint>
#include <string>
#include <vector>

namespace cb {

class Builder;

struct AxmlAttr {
    std::string name;
    std::string value;
    std::string raw;
    std::string type;
};

struct AxmlNode {
    std::string tag;
    std::vector<AxmlAttr> attrs;
    std::vector<AxmlNode> children;
    const AxmlAttr* find(const char* name) const {
        for (auto& a : attrs) if (a.name == name) return &a;
        return nullptr;
    }
};

bool axmlParse(const uint8_t* d, size_t n, AxmlNode& root, std::string& errOut);
void axmlWriteTree(const AxmlNode& node, Builder& b, int depth, int& budget);

}
