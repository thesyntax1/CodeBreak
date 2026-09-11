#include "hashes.h"
#include "util.h"
#include <cmath>
#include <cstring>

namespace cb {

uint32_t crc32Compute(const uint8_t* d, size_t n) {
    static uint32_t table[256];
    static bool init = false;
    if (!init) {
        for (uint32_t i = 0; i < 256; i++) {
            uint32_t c = i;
            for (int k = 0; k < 8; k++) c = (c & 1) ? (0xEDB88320u ^ (c >> 1)) : (c >> 1);
            table[i] = c;
        }
        init = true;
    }
    uint32_t c = 0xFFFFFFFFu;
    for (size_t i = 0; i < n; i++) c = table[(c ^ d[i]) & 0xFF] ^ (c >> 8);
    return c ^ 0xFFFFFFFFu;
}

uint32_t adler32Compute(const uint8_t* d, size_t n) {
    uint32_t a = 1, b = 0;
    size_t i = 0;
    while (i < n) {
        size_t chunk = n - i < 5552 ? n - i : 5552;
        for (size_t k = 0; k < chunk; k++) { a += d[i + k]; b += a; }
        a %= 65521u;
        b %= 65521u;
        i += chunk;
    }
    return (b << 16) | a;
}

static void md5Transform(uint32_t* st, const uint8_t* block) {
    static uint32_t K[64];
    static bool init = false;
    if (!init) {
        for (int i = 0; i < 64; i++) K[i] = (uint32_t)(std::floor(std::fabs(std::sin((double)(i + 1))) * 4294967296.0));
        init = true;
    }
    static const int S[64] = {
        7,12,17,22, 7,12,17,22, 7,12,17,22, 7,12,17,22,
        5, 9,14,20, 5, 9,14,20, 5, 9,14,20, 5, 9,14,20,
        4,11,16,23, 4,11,16,23, 4,11,16,23, 4,11,16,23,
        6,10,15,21, 6,10,15,21, 6,10,15,21, 6,10,15,21
    };
    uint32_t M[16];
    for (int i = 0; i < 16; i++)
        M[i] = (uint32_t)block[i * 4] | ((uint32_t)block[i * 4 + 1] << 8) | ((uint32_t)block[i * 4 + 2] << 16) | ((uint32_t)block[i * 4 + 3] << 24);
    uint32_t a = st[0], bb = st[1], c = st[2], dd = st[3];
    for (int i = 0; i < 64; i++) {
        uint32_t f; int g;
        if (i < 16) { f = (bb & c) | (~bb & dd); g = i; }
        else if (i < 32) { f = (dd & bb) | (~dd & c); g = (5 * i + 1) & 15; }
        else if (i < 48) { f = bb ^ c ^ dd; g = (3 * i + 5) & 15; }
        else { f = c ^ (bb | ~dd); g = (7 * i) & 15; }
        uint32_t tmp = dd;
        dd = c;
        c = bb;
        uint32_t x = a + f + K[i] + M[g];
        bb = bb + ((x << S[i]) | (x >> (32 - S[i])));
        a = tmp;
    }
    st[0] += a; st[1] += bb; st[2] += c; st[3] += dd;
}

std::string md5Hex(const uint8_t* d, size_t n) {
    uint32_t st[4] = { 0x67452301u, 0xEFCDAB89u, 0x98BADCFEu, 0x10325476u };
    size_t full = n / 64;
    for (size_t i = 0; i < full; i++) md5Transform(st, d + i * 64);
    uint8_t tail[128];
    size_t rem = n - full * 64;
    memcpy(tail, d + full * 64, rem);
    tail[rem] = 0x80;
    size_t padded = (rem + 1 <= 56) ? 64 : 128;
    memset(tail + rem + 1, 0, padded - rem - 1);
    uint64_t bits = (uint64_t)n * 8;
    for (int i = 0; i < 8; i++) tail[padded - 8 + i] = (uint8_t)(bits >> (8 * i));
    md5Transform(st, tail);
    if (padded == 128) md5Transform(st, tail + 64);
    uint8_t out[16];
    for (int i = 0; i < 4; i++) {
        out[i * 4] = (uint8_t)st[i];
        out[i * 4 + 1] = (uint8_t)(st[i] >> 8);
        out[i * 4 + 2] = (uint8_t)(st[i] >> 16);
        out[i * 4 + 3] = (uint8_t)(st[i] >> 24);
    }
    return hexBytes(out, 16);
}

static void sha1Transform(uint32_t* h, const uint8_t* block) {
    uint32_t w[80];
    for (int i = 0; i < 16; i++)
        w[i] = ((uint32_t)block[i * 4] << 24) | ((uint32_t)block[i * 4 + 1] << 16) | ((uint32_t)block[i * 4 + 2] << 8) | block[i * 4 + 3];
    for (int i = 16; i < 80; i++) {
        uint32_t v = w[i - 3] ^ w[i - 8] ^ w[i - 14] ^ w[i - 16];
        w[i] = (v << 1) | (v >> 31);
    }
    uint32_t a = h[0], b = h[1], c = h[2], dd = h[3], e = h[4];
    for (int i = 0; i < 80; i++) {
        uint32_t f, k;
        if (i < 20) { f = (b & c) | (~b & dd); k = 0x5A827999u; }
        else if (i < 40) { f = b ^ c ^ dd; k = 0x6ED9EBA1u; }
        else if (i < 60) { f = (b & c) | (b & dd) | (c & dd); k = 0x8F1BBCDCu; }
        else { f = b ^ c ^ dd; k = 0xCA62C1D6u; }
        uint32_t t = ((a << 5) | (a >> 27)) + f + e + k + w[i];
        e = dd; dd = c; c = (b << 30) | (b >> 2); b = a; a = t;
    }
    h[0] += a; h[1] += b; h[2] += c; h[3] += dd; h[4] += e;
}

std::string sha1Hex(const uint8_t* d, size_t n) {
    uint32_t h[5] = { 0x67452301u, 0xEFCDAB89u, 0x98BADCFEu, 0x10325476u, 0xC3D2E1F0u };
    size_t full = n / 64;
    for (size_t i = 0; i < full; i++) sha1Transform(h, d + i * 64);
    uint8_t tail[128];
    size_t rem = n - full * 64;
    memcpy(tail, d + full * 64, rem);
    tail[rem] = 0x80;
    size_t padded = (rem + 1 <= 56) ? 64 : 128;
    memset(tail + rem + 1, 0, padded - rem - 1);
    uint64_t bits = (uint64_t)n * 8;
    for (int i = 0; i < 8; i++) tail[padded - 1 - i] = (uint8_t)(bits >> (8 * i));
    sha1Transform(h, tail);
    if (padded == 128) sha1Transform(h, tail + 64);
    uint8_t out[20];
    for (int i = 0; i < 5; i++) {
        out[i * 4] = (uint8_t)(h[i] >> 24);
        out[i * 4 + 1] = (uint8_t)(h[i] >> 16);
        out[i * 4 + 2] = (uint8_t)(h[i] >> 8);
        out[i * 4 + 3] = (uint8_t)h[i];
    }
    return hexBytes(out, 20);
}

static void sha256Transform(uint32_t* h, const uint8_t* block) {
    static uint32_t K[64];
    static bool init = false;
    if (!init) {
        int primes[64] = {
            2,3,5,7,11,13,17,19,23,29,31,37,41,43,47,53,59,61,67,71,73,79,83,89,97,101,103,107,109,113,127,131,
            137,139,149,151,157,163,167,173,179,181,191,193,197,199,211,223,227,229,233,239,241,251,257,263,269,271,277,281,283,293,307,311
        };
        for (int i = 0; i < 64; i++) {
            double x = std::cbrt((double)primes[i]);
            K[i] = (uint32_t)((x - std::floor(x)) * 4294967296.0);
        }
        init = true;
    }
    uint32_t w[64];
    for (int i = 0; i < 16; i++)
        w[i] = ((uint32_t)block[i * 4] << 24) | ((uint32_t)block[i * 4 + 1] << 16) | ((uint32_t)block[i * 4 + 2] << 8) | block[i * 4 + 3];
    for (int i = 16; i < 64; i++) {
        uint32_t s0 = ((w[i - 15] >> 7) | (w[i - 15] << 25)) ^ ((w[i - 15] >> 18) | (w[i - 15] << 14)) ^ (w[i - 15] >> 3);
        uint32_t s1 = ((w[i - 2] >> 17) | (w[i - 2] << 15)) ^ ((w[i - 2] >> 19) | (w[i - 2] << 13)) ^ (w[i - 2] >> 10);
        w[i] = w[i - 16] + s0 + w[i - 7] + s1;
    }
    uint32_t a = h[0], b = h[1], c = h[2], d = h[3], e = h[4], f = h[5], g = h[6], hh = h[7];
    for (int i = 0; i < 64; i++) {
        uint32_t S1 = ((e >> 6) | (e << 26)) ^ ((e >> 11) | (e << 21)) ^ ((e >> 25) | (e << 7));
        uint32_t ch = (e & f) ^ (~e & g);
        uint32_t t1 = hh + S1 + ch + K[i] + w[i];
        uint32_t S0 = ((a >> 2) | (a << 30)) ^ ((a >> 13) | (a << 19)) ^ ((a >> 22) | (a << 10));
        uint32_t maj = (a & b) ^ (a & c) ^ (b & c);
        uint32_t t2 = S0 + maj;
        hh = g; g = f; f = e; e = d + t1; d = c; c = b; b = a; a = t1 + t2;
    }
    h[0] += a; h[1] += b; h[2] += c; h[3] += d; h[4] += e; h[5] += f; h[6] += g; h[7] += hh;
}

std::string sha256Hex(const uint8_t* d, size_t n) {
    uint32_t h[8];
    int initPrimes[8] = { 2,3,5,7,11,13,17,19 };
    for (int i = 0; i < 8; i++) {
        double x = std::sqrt((double)initPrimes[i]);
        h[i] = (uint32_t)((x - std::floor(x)) * 4294967296.0);
    }
    size_t full = n / 64;
    for (size_t i = 0; i < full; i++) sha256Transform(h, d + i * 64);
    uint8_t tail[128];
    size_t rem = n - full * 64;
    memcpy(tail, d + full * 64, rem);
    tail[rem] = 0x80;
    size_t padded = (rem + 1 <= 56) ? 64 : 128;
    memset(tail + rem + 1, 0, padded - rem - 1);
    uint64_t bits = (uint64_t)n * 8;
    for (int i = 0; i < 8; i++) tail[padded - 1 - i] = (uint8_t)(bits >> (8 * i));
    sha256Transform(h, tail);
    if (padded == 128) sha256Transform(h, tail + 64);
    uint8_t out[32];
    for (int i = 0; i < 8; i++) {
        out[i * 4] = (uint8_t)(h[i] >> 24);
        out[i * 4 + 1] = (uint8_t)(h[i] >> 16);
        out[i * 4 + 2] = (uint8_t)(h[i] >> 8);
        out[i * 4 + 3] = (uint8_t)h[i];
    }
    return hexBytes(out, 32);
}

}
