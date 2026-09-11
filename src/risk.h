#pragma once
#include <cstdint>
#include <string>
#include <vector>

#include "formats.h"

namespace cb {

class Builder;
struct Indicator;

struct RiskSignal {
    std::string category;
    std::string title;
    std::string evidence;
    int weight;
    int hits;
};

struct RiskResult {
    int score = 0;
    std::string level;
    std::string summary;
    std::vector<RiskSignal> signals;
    std::vector<std::string> topFindings;
};

RiskResult assessRisk(const uint8_t* d, size_t n, const std::string& lowerName,
                      FormatId fmt, const std::vector<Indicator>& inds);
void writeRiskJson(Builder& b, const RiskResult& r);

const char* riskLevelLabel(int score);

}
