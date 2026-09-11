#pragma once
#include <cstdint>
#include <string>
#include <vector>
#include "pe.h"

namespace cb {

class Builder;

struct ZipEntryInfo {
    std::string name;
    uint16_t method;
    uint64_t compSize;
    uint64_t size;
    uint32_t crc32;
    uint32_t localOffset;
    bool isDir;
};

struct ZipData {
    std::vector<ZipEntryInfo> entries;
    bool truncated = false;
    uint64_t cdOffset = 0;
    uint64_t cdSize = 0;
    uint64_t eocdOffset = 0;
    std::string comment;
    bool zip64 = false;
    bool isApk = false;
    bool isJar = false;
    bool isEpub = false;
    bool isIpa = false;
    bool apkV1 = false;
    bool apkV2 = false;
    bool apkV3 = false;
    bool apkV31 = false;
    std::vector<std::pair<uint64_t, std::string>> signingBlocks;
    const uint8_t* data = nullptr;
    size_t size = 0;
    bool entryData(size_t index, std::vector<uint8_t>& out, std::string& errOut) const;
};

bool looksLikeZip(const uint8_t* d, size_t n);
ZipData zipParse(const uint8_t* d, size_t n, Builder& b, IndCollector& inds);
void apkParse(ZipData& z, Builder& b, IndCollector& inds);

}
