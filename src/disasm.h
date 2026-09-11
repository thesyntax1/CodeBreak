#pragma once
#include <cstdint>
#include <string>
#include <vector>

namespace cb {

struct AsmInsn {
    uint64_t addr = 0;
    std::string hexBytes;
    std::string mnemonic;
    std::string operands;
    bool hasTarget = false;
    bool isCall = false;
    bool isJump = false;
    bool isRet = false;
    uint64_t target = 0;
};

size_t disasmNext(const uint8_t* d, size_t n, uint64_t addr, AsmInsn& out);

}
