#pragma once
#include <cstdint>
#include <string>
#include <vector>

namespace cb {

class Builder;

struct DexStringsRef {
    uint32_t idx;
    std::string text;
};

void dexParse(const uint8_t* d, size_t n, const char* entryName, Builder& b, class IndCollector& inds, uint64_t dexSize);

}
