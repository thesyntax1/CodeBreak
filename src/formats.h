#pragma once
#include <cstdint>
#include <string>
#include "pe.h"
#include "util.h"

namespace cb {

class Builder;

enum FormatId {
    FMT_UNKNOWN = 0,
    FMT_PE,
    FMT_ZIP,
    FMT_APK,
    FMT_DEX,
    FMT_ELF,
    FMT_MACHO,
    FMT_MACHO_FAT,
    FMT_JAVACLASS,
    FMT_OLE,
    FMT_SCRIPT,
    FMT_WASM,
    FMT_PDF,
    FMT_IMAGE,
    FMT_GZIP,
    FMT_TAR,
};

FormatId detectFormat(const uint8_t* d, size_t n, const std::string& lowerName);
const char* formatLabel(FormatId f);

void elfParse(const uint8_t* d, size_t n, Builder& b, IndCollector& inds);
void machoParse(const uint8_t* d, size_t n, uint64_t magic, Builder& b, IndCollector& inds);
void machoFatParse(const uint8_t* d, size_t n, Builder& b, IndCollector& inds);
void javaClassParse(const uint8_t* d, size_t n, Builder& b, IndCollector& inds);
void gzipParse(const uint8_t* d, size_t n, Builder& b, IndCollector& inds);
void tarParse(const uint8_t* d, size_t n, Builder& b, IndCollector& inds);
void pdfParse(const uint8_t* d, size_t n, Builder& b, IndCollector& inds);

struct AnalysisOutput {
    std::string json;
    FormatId fmt;
    bool ok;
};

AnalysisOutput analyzeFile(const uint8_t* d, size_t n, const std::string& pathUtf8, const FileInfo& fi);

}
