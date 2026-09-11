#include "disasm.h"
#include <cstdio>

namespace cb {

namespace {

const char* const R16[16] = { "ax", "cx", "dx", "bx", "sp", "bp", "si", "di",
                              "r8w", "r9w", "r10w", "r11w", "r12w", "r13w", "r14w", "r15w" };
const char* const R32[16] = { "eax", "ecx", "edx", "ebx", "esp", "ebp", "esi", "edi",
                              "r8d", "r9d", "r10d", "r11d", "r12d", "r13d", "r14d", "r15d" };
const char* const R64[16] = { "rax", "rcx", "rdx", "rbx", "rsp", "rbp", "rsi", "rdi",
                              "r8", "r9", "r10", "r11", "r12", "r13", "r14", "r15" };

std::string name8(int idx, bool rex) {
    if (idx >= 8) {
        static const char* const e[8] = { "r8b", "r9b", "r10b", "r11b", "r12b", "r13b", "r14b", "r15b" };
        return e[idx - 8];
    }
    static const char* const a[8] = { "al", "cl", "dl", "bl", "ah", "ch", "dh", "bh" };
    static const char* const b[8] = { "al", "cl", "dl", "bl", "spl", "bpl", "sil", "dil" };
    return rex ? b[idx] : a[idx];
}

std::string nameReg(int w, int idx) {
    switch (w) {
    case 1: return name8(idx, false);
    case 2: return R16[idx & 15];
    case 4: return R32[idx & 15];
    default: return R64[idx & 15];
    }
}

struct Cur {
    const uint8_t* d;
    size_t n;
    size_t p = 0;
    bool eof() const { return p >= n; }
    uint8_t peek() const { return p < n ? d[p] : 0; }
    uint8_t next() { return p < n ? d[p++] : 0; }
    int8_t s8() { return (int8_t)next(); }
    int32_t s32() {
        uint32_t v = 0;
        for (int i = 0; i < 4; i++) v |= ((uint32_t)next()) << (8 * i);
        return (int32_t)v;
    }
    uint16_t u16() { return (uint16_t)(next() | (next() << 8)); }
};

struct Dec {
    bool rexW = false, rexR = false, rexX = false, rexB = false;
    bool op66 = false, opF3 = false;
    int width() const { return rexW ? 8 : (op66 ? 2 : 4); }
};

std::string immStr(int64_t v) {
    if (v >= -9 && v <= 9) return std::to_string(v);
    char b[48];
    if (v < 0) snprintf(b, sizeof(b), "-0x%llx", (unsigned long long)(uint64_t)(-v));
    else snprintf(b, sizeof(b), "0x%llx", (unsigned long long)v);
    return b;
}

std::string addrStr(uint64_t v) {
    char b[40];
    snprintf(b, sizeof(b), "0x%llx", (unsigned long long)v);
    return b;
}

struct ModRM {
    bool isReg = false;
    int regIdx = 0;
    std::string rm;
};

ModRM readModRM(Cur& c, const Dec& dec, int rWidth) {
    ModRM m;
    uint8_t b = c.next();
    int mod = b >> 6;
    int reg = (b >> 3) & 7;
    int rm = b & 7;
    m.regIdx = reg + (dec.rexR ? 8 : 0);
    if (mod == 3) {
        m.isReg = true;
        int idx = rm + (dec.rexB ? 8 : 0);
        m.rm = rWidth == 1 ? name8(idx, true) : nameReg(rWidth, idx);
        return m;
    }
    bool hasSib = (rm == 4);
    int scale = 1, index = -1, base = -1;
    bool baseIsRip = false;
    if (hasSib) {
        uint8_t sib = c.next();
        scale = 1 << ((sib >> 6) & 3);
        int iField = (sib >> 3) & 7;
        int bField = sib & 7;
        if (!(iField == 4 && !dec.rexX)) index = iField + (dec.rexX ? 8 : 0);
        if (!(mod == 0 && bField == 5)) base = bField + (dec.rexB ? 8 : 0);
    } else {
        if (mod == 0 && rm == 5) baseIsRip = true;
        else base = rm + (dec.rexB ? 8 : 0);
    }
    int64_t disp = 0;
    if (mod == 1) disp = c.s8();
    else if (mod == 2) disp = c.s32();
    else if (baseIsRip || (hasSib && base < 0)) disp = c.s32();

    std::string s = "[";
    if (baseIsRip) {
        s += "rip";
        if (disp) s += (disp < 0 ? "-" : "+") + immStr(disp < 0 ? -disp : disp);
        s += "]";
        m.rm = s;
        return m;
    }
    std::string body;
    if (hasSib) {
        if (base >= 0) body += R64[base & 15];
        std::string iv;
        if (index >= 0) {
            iv = R64[index & 15];
            if (scale > 1) iv += "*" + std::to_string(scale);
        }
        if (!body.empty() && !iv.empty()) body += "+" + iv;
        else if (body.empty()) body = iv;
    } else {
        body = R64[base & 15];
    }
    if (body.empty()) body = "0";
    s += body;
    if (disp) s += (disp < 0 ? "-" : "+") + immStr(disp < 0 ? -disp : disp);
    s += "]";
    m.rm = s;
    return m;
}

std::string memTagged(const std::string& mem, int w) {
    const char* t = w == 1 ? "byte ptr " : w == 2 ? "word ptr " : w == 8 ? "qword ptr " : "dword ptr ";
    return std::string(t) + mem;
}

std::string rmOp(const ModRM& m, int w) { return m.isReg ? m.rm : memTagged(m.rm, w); }

const char* const ALU[8] = { "add", "or", "adc", "sbb", "and", "sub", "xor", "cmp" };

}

size_t disasmNext(const uint8_t* d, size_t n, uint64_t addr, AsmInsn& out) {
    Cur c{ d, n, 0 };
    Dec dec;
    for (;;) {
        uint8_t p = c.peek();
        if (p == 0x66) { dec.op66 = true; c.next(); continue; }
        if (p == 0xF3) { dec.opF3 = true; c.next(); continue; }
        if (p == 0xF2) { c.next(); continue; }
        if (p == 0x26 || p == 0x2E || p == 0x36 || p == 0x3E || p == 0x64 || p == 0x65) { c.next(); continue; }
        if ((p & 0xF0) == 0x40) {
            dec.rexW = (p & 8) != 0; dec.rexR = (p & 4) != 0;
            dec.rexX = (p & 2) != 0; dec.rexB = (p & 1) != 0;
            c.next();
            continue;
        }
        break;
    }
    uint8_t op = c.next();
    int W = dec.width();
    auto mk = [&](AsmInsn& i, const char* mn, const std::string& ops,
                  bool tgt, uint64_t tv, bool call, bool jump, bool ret) {
        i.mnemonic = mn; i.operands = ops;
        i.hasTarget = tgt; i.target = tv;
        i.isCall = call; i.isJump = jump; i.isRet = ret;
    };
    auto rel32 = [&](const char* mn, bool call, bool jump) {
        int32_t r = c.s32();
        uint64_t t = addr + (uint64_t)c.p + (uint64_t)(int64_t)r;
        mk(out, mn, addrStr(t), true, t, call, jump, false);
        return c.p;
    };
    auto rel8 = [&](const char* mn, bool jump) {
        int8_t r = c.s8();
        uint64_t t = addr + (uint64_t)c.p + (uint64_t)(int64_t)r;
        mk(out, mn, addrStr(t), true, t, false, jump, false);
        return c.p;
    };
    auto byteOp = [&](const char* mn) {
        mk(out, mn, "", false, 0, false, false, false);
        return c.p;
    };

    switch (op) {
    case 0x90: return byteOp("nop");
    case 0xF4: return byteOp("hlt");
    case 0xCC: return byteOp("int3");
    case 0xC3: mk(out, "ret", "", false, 0, false, false, true); return c.p;
    case 0xCB: mk(out, "retf", "", false, 0, false, false, true); return c.p;
    case 0xC2: { int16_t i = (int16_t)c.u16(); mk(out, "ret", immStr(i), false, 0, false, false, true); return c.p; }
    case 0xCA: { int16_t i = (int16_t)c.u16(); mk(out, "retf", immStr(i), false, 0, false, false, true); return c.p; }
    case 0xE8: return rel32("call", true, false);
    case 0xE9: return rel32("jmp", false, true);
    case 0xEB: return rel8("jmp", true);
    case 0x68: mk(out, "push", immStr(c.s32()), false, 0, false, false, false); return c.p;
    case 0x6A: mk(out, "push", immStr(c.s8()), false, 0, false, false, false); return c.p;
    case 0x9C: return byteOp("pushfq");
    case 0x9D: return byteOp("popfq");
    default: break;
    }

    if (op >= 0x70 && op <= 0x7F) {
        static const char* const cc[16] = { "jo", "jno", "jb", "jae", "je", "jne", "jbe", "ja",
                                            "js", "jns", "jp", "jnp", "jl", "jge", "jle", "jg" };
        return rel8(cc[op - 0x70], true);
    }
    if (op >= 0x50 && op <= 0x57) {
        int idx = (op - 0x50) + (dec.rexB ? 8 : 0);
        mk(out, "push", R64[idx & 15], false, 0, false, false, false);
        return c.p;
    }
    if (op >= 0x58 && op <= 0x5F) {
        int idx = (op - 0x58) + (dec.rexB ? 8 : 0);
        mk(out, "pop", R64[idx & 15], false, 0, false, false, false);
        return c.p;
    }


    if (op < 0x40) {
        int g = op >> 3, s = op & 7;
        if (s <= 3) {
            int bw = (s == 0 || s == 2) ? 1 : W;
            bool regDest = (s == 2 || s == 3);
            ModRM m = readModRM(c, dec, bw);
            std::string regOp = nameReg(bw, m.regIdx);
            std::string rmOp = m.isReg ? m.rm : memTagged(m.rm, bw);
            std::string ops = regDest ? (regOp + ", " + rmOp) : (rmOp + ", " + regOp);
            mk(out, ALU[g], ops, false, 0, false, false, false);
            return c.p;
        }
        if (s == 4) {
            mk(out, ALU[g], "al, " + immStr(c.s8()), false, 0, false, false, false);
            return c.p;
        }
        if (s == 5) {
            if (dec.rexW) mk(out, ALU[g], "rax, " + immStr(c.s32()), false, 0, false, false, false);
            else if (dec.op66) { uint16_t v = c.u16(); mk(out, ALU[g], "ax, " + immStr(v), false, 0, false, false, false); }
            else mk(out, ALU[g], "eax, " + immStr((uint32_t)c.s32()), false, 0, false, false, false);
            return c.p;
        }
    }


    if (op >= 0x88 && op <= 0x8B) {
        int s = op & 7;
        if (s <= 3) {
            int bw = (s == 0 || s == 2) ? 1 : W;
            bool regDest = (s == 2 || s == 3);
            ModRM m = readModRM(c, dec, bw);
            std::string regOp = nameReg(bw, m.regIdx);
            std::string rmOp = m.isReg ? m.rm : memTagged(m.rm, bw);
            if (regDest) mk(out, "mov", regOp + ", " + rmOp, false, 0, false, false, false);
            else mk(out, "mov", rmOp + ", " + regOp, false, 0, false, false, false);
            return c.p;
        }
    }
    if (op == 0x8D) {
        ModRM m = readModRM(c, dec, W);
        mk(out, "lea", nameReg(W, m.regIdx) + ", " + m.rm, false, 0, false, false, false);
        return c.p;
    }
    if (op == 0x84 || op == 0x85) {
        int bw = op == 0x84 ? 1 : W;
        ModRM m = readModRM(c, dec, bw);
        std::string rmOp = m.isReg ? m.rm : memTagged(m.rm, bw);
        mk(out, "test", rmOp + ", " + nameReg(bw, m.regIdx), false, 0, false, false, false);
        return c.p;
    }
    if ((op & 0xF0) == 0xB0) {
        int idx = (op & 7) + (dec.rexB ? 8 : 0);
        if (op < 0xB8) {
            mk(out, "mov", std::string(name8(idx, true)) + ", " + immStr(c.s8()), false, 0, false, false, false);
            return c.p;
        }
        if (dec.rexW) {
            uint64_t v = 0;
            for (int i = 0; i < 8; i++) v |= ((uint64_t)c.next()) << (8 * i);
            mk(out, "mov", std::string(R64[idx & 15]) + ", " + immStr((int64_t)v), false, 0, false, false, false);
        } else if (dec.op66) {
            uint16_t v = c.u16();
            mk(out, "mov", std::string(R16[idx & 15]) + ", " + immStr(v), false, 0, false, false, false);
        } else {
            mk(out, "mov", std::string(R32[idx & 15]) + ", " + immStr((uint32_t)c.s32()), false, 0, false, false, false);
        }
        return c.p;
    }
    if (op == 0xC6 || op == 0xC7) {
        int bw = op == 0xC6 ? 1 : W;
        ModRM m = readModRM(c, dec, bw);
        std::string dst = rmOp(m, bw);
        int64_t imm = op == 0xC6 ? c.s8() : (bw == 8 ? (int64_t)c.s32() : (int64_t)(int32_t)((bw == 2) ? (uint16_t)c.u16() : c.s32()));
        mk(out, "mov", dst + ", " + immStr(imm), false, 0, false, false, false);
        return c.p;
    }
    if (op == 0x69 || op == 0x6B) {
        ModRM m = readModRM(c, dec, W);
        std::string rm = rmOp(m, W);
        int64_t imm = op == 0x6B ? c.s8() : c.s32();
        mk(out, "imul", nameReg(W, m.regIdx) + ", " + rm + ", " + immStr(imm), false, 0, false, false, false);
        return c.p;
    }
    if (op == 0x80 || op == 0x82 || op == 0x81 || op == 0x83) {
        int bw = (op == 0x80 || op == 0x82) ? 1 : W;
        ModRM m = readModRM(c, dec, bw);
        int grp = m.regIdx & 7;
        bool imm8 = (op == 0x83);
        bool byte = (op == 0x80 || op == 0x82);
        std::string rm = rmOp(m, bw);
        int64_t imm;
        if (imm8) imm = c.s8();
        else if (byte) imm = c.s8();
        else if (bw == 2) imm = (int16_t)c.u16();
        else if (bw == 8) imm = c.s32();
        else imm = c.s32();
        mk(out, ALU[grp], rm + ", " + immStr(imm), false, 0, false, false, false);
        return c.p;
    }
    if (op == 0xF6 || op == 0xF7) {
        int bw = op == 0xF6 ? 1 : W;
        ModRM m = readModRM(c, dec, bw);
        int grp = m.regIdx & 7;
        static const char* const g[8] = { "test", "?", "not", "neg", "mul", "imul", "div", "idiv" };
        std::string rm = rmOp(m, bw);
        if (grp == 0) {
            int64_t imm = op == 0xF6 ? c.s8() : (bw == 2 ? (int16_t)c.u16() : (bw == 8 ? (int64_t)c.s32() : (int64_t)c.s32()));
            mk(out, "test", rm + ", " + immStr(imm), false, 0, false, false, false);
        } else {
            mk(out, g[grp], rm, false, 0, false, false, false);
        }
        return c.p;
    }
    if (op == 0xFF) {
        ModRM m = readModRM(c, dec, 8);
        int grp = m.regIdx & 7;
        if (grp == 2) { mk(out, "call", m.rm, false, 0, true, false, false); return c.p; }
        if (grp == 4) { mk(out, "jmp", m.rm, false, 0, false, true, false); return c.p; }
        if (grp == 6) { mk(out, "push", m.isReg ? m.rm : memTagged(m.rm, 8), false, 0, false, false, false); return c.p; }
        if (grp == 0 || grp == 1) {
            std::string rm = m.isReg ? m.rm : memTagged(m.rm, W);
            mk(out, grp == 0 ? "inc" : "dec", rm, false, 0, false, false, false);
            return c.p;
        }
        return byteOp(".byte");
    }
    if (op == 0xC0 || op == 0xC1 || op == 0xD0 || op == 0xD1 || op == 0xD2 || op == 0xD3) {
        int bw = (op == 0xC0 || op == 0xD0 || op == 0xD2) ? 1 : W;
        ModRM m = readModRM(c, dec, bw);
        static const char* const g[8] = { "rol", "ror", "rcl", "rcr", "shl", "shr", "sal", "sar" };
        std::string rm = rmOp(m, bw);
        bool imm = (op == 0xC0 || op == 0xC1);
        bool cl = (op == 0xD2 || op == 0xD3);
        std::string arg = (imm ? immStr(c.s8()) : (cl ? std::string("cl") : std::string("1")));
        mk(out, g[m.regIdx & 7], rm + ", " + arg, false, 0, false, false, false);
        return c.p;
    }

    if (op == 0x0F) {
        uint8_t o2 = c.next();
        switch (o2) {
        case 0x05: return byteOp("syscall");
        case 0x31: return byteOp("rdtsc");
        case 0xA2: return byteOp("cpuid");
        case 0x0B: return byteOp("ud2");
        case 0x1F: { ModRM m = readModRM(c, dec, W); mk(out, "nop", m.isReg ? "" : m.rm, false, 0, false, false, false); return c.p; }
        case 0x1E: { readModRM(c, dec, W); return byteOp(dec.opF3 ? "endbr64" : "nop"); }
        default: break;
        }
        if (o2 >= 0x40 && o2 <= 0x4F) {
            static const char* const cc[16] = { "o", "no", "b", "ae", "e", "ne", "be", "a",
                                                "s", "ns", "p", "np", "l", "ge", "le", "g" };
            ModRM m = readModRM(c, dec, W);
            std::string src = rmOp(m, W);
            mk(out, (std::string("cmov") + cc[o2 - 0x40]).c_str(), nameReg(W, m.regIdx) + ", " + src, false, 0, false, false, false);
            return c.p;
        }
        if (o2 >= 0x80 && o2 <= 0x8F) {
            static const char* const cc[16] = { "jo", "jno", "jb", "jae", "je", "jne", "jbe", "ja",
                                                "js", "jns", "jp", "jnp", "jl", "jge", "jle", "jg" };
            int32_t r = c.s32();
            uint64_t t = addr + (uint64_t)c.p + (uint64_t)(int64_t)r;
            mk(out, cc[o2 - 0x80], addrStr(t), true, t, false, true, false);
            return c.p;
        }
        if (o2 == 0xAF) {
            ModRM m = readModRM(c, dec, W);
            std::string src = rmOp(m, W);
            mk(out, "imul", nameReg(W, m.regIdx) + ", " + src, false, 0, false, false, false);
            return c.p;
        }
        if (o2 == 0xB6 || o2 == 0xBE) {
            ModRM m = readModRM(c, dec, 1);
            std::string src = rmOp(m, 1);
            mk(out, o2 == 0xB6 ? "movzx" : "movsx", nameReg(W, m.regIdx) + ", " + src, false, 0, false, false, false);
            return c.p;
        }
        if (o2 == 0xB7 || o2 == 0xBF) {
            ModRM m = readModRM(c, dec, 2);
            std::string src = rmOp(m, 2);
            mk(out, o2 == 0xB7 ? "movzx" : "movsx", nameReg(W, m.regIdx) + ", " + src, false, 0, false, false, false);
            return c.p;
        }
        if (o2 == 0xB9) return byteOp(".byte");
        return byteOp(".byte");
    }
    mk(out, ".byte", immStr(op), false, 0, false, false, false);
    return c.p;
}

}
