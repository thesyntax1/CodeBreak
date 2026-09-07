#pragma once
#include <string>
#include <vector>

namespace cb {

std::string escapeHtml(const std::string& s);

std::string buildHtmlReport(const std::string& analysisJson, const std::string& sourcePath);

struct BatchItem {
    std::string path;
    std::string format;
    uint64_t size;
    std::string sha256;
    int riskScore;
    std::string riskLevel;
    int indicators;
    bool ok;
    std::string error;
};

std::string buildBatchHtml(const std::vector<BatchItem>& items,
                           uint64_t totalBytes, double elapsedMs);

}
