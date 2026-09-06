#pragma once
#include <cstdint>
#include <string>
#include <vector>

namespace cb {

class Builder;

struct Indicator {
    int severity;
    std::string title;
    std::string detail;
};

class IndCollector {
public:
    std::vector<Indicator> items;
    void add(int severity, const std::string& title, const std::string& detail) {
        if (items.size() < 256) items.push_back({ severity, title, detail });
    }
};

struct RvaRange {
    uint32_t rvaStart;
    uint32_t rvaSize;
    uint32_t fileOff;
    uint32_t rawSize;
    std::string section;
};

struct RvaMap {
    std::vector<RvaRange> ranges;
    int64_t toOff(uint32_t rva) const {
        for (const auto& r : ranges) {
            if (rva >= r.rvaStart && rva < r.rvaStart + r.rvaSize) {
                uint32_t d = rva - r.rvaStart;
                if (d < r.rawSize) return (int64_t)(r.fileOff + d);
                return -1;
            }
        }
        return -1;
    }
};

struct PeSummary {
    std::vector<Indicator> inds;
    bool isPe = false;
    bool is64 = false;
    bool dotnet = false;
    bool signed_ = false;
    uint32_t entryRva = 0;
    std::string entrySection;
    RvaMap rvaMap;
};

PeSummary peParse(const uint8_t* d, size_t n, Builder& b);
bool looksLikePe(const uint8_t* d, size_t n);

}
