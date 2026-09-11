#pragma once
#include <cstdint>
#include <cstddef>
#include <string>

namespace cb {

uint32_t crc32Compute(const uint8_t* d, size_t n);
uint32_t adler32Compute(const uint8_t* d, size_t n);
std::string md5Hex(const uint8_t* d, size_t n);
std::string sha1Hex(const uint8_t* d, size_t n);
std::string sha256Hex(const uint8_t* d, size_t n);

}
