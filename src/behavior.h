#pragma once
#include <cstdint>
#include <string>
#include <vector>

namespace cb {

class Builder;

struct BehEndpoint {
    std::string kind;
    std::string value;
};

struct BehaviorResult {
    std::vector<std::string> networkApis;
    std::vector<std::string> fileApis;
    std::vector<std::string> processApis;
    std::vector<std::string> persistenceApis;
    std::vector<BehEndpoint> endpoints;
    std::vector<std::string> filePaths;
    std::vector<std::string> commands;
    std::vector<std::string> persistence;
    int urlCount = 0;
    int domainCount = 0;
    int ipCount = 0;
    int emailCount = 0;
    bool empty() const;
};

BehaviorResult analyzeBehavior(const uint8_t* d, size_t n,
                               const std::vector<std::string>& importNames,
                               const std::string& lowerName);
void writeBehaviorJson(Builder& b, const BehaviorResult& r);

}
