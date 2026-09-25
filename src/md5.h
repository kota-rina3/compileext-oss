// md5.h — 紧凑的 RFC 1321 MD5 实现（无第三方依赖）
// K 表用公式 K[i] = floor(|sin(i+1)| * 2^32) 现场计算，避免手抄表出错。
#pragma once

#include <cstdint>
#include <cstring>
#include <cmath>
#include <string>

namespace jscx {

namespace detail {

inline uint32_t rotl32(uint32_t x, int c) { return (x << c) | (x >> (32 - c)); }

struct MD5 {
    uint32_t a0 = 0x67452301, b0 = 0xefcdab89, c0 = 0x98badcfe, d0 = 0x10325476;
    uint64_t total = 0;
    uint8_t buf[64] = {0};
    size_t buflen = 0;

    static const uint32_t* ktable() {
        static uint32_t K[64];
        static bool init = false;
        if (!init) {
            for (int i = 0; i < 64; i++)
                K[i] = (uint32_t)std::floor(std::fabs(std::sin(i + 1)) * 4294967296.0);
            init = true;
        }
        return K;
    }

    void block(const uint8_t* p) {
        static const int S[64] = {7,12,17,22, 7,12,17,22, 7,12,17,22, 7,12,17,22,
                                  5, 9,14,20, 5, 9,14,20, 5, 9,14,20, 5, 9,14,20,
                                  4,11,16,23, 4,11,16,23, 4,11,16,23, 4,11,16,23,
                                  6,10,15,21, 6,10,15,21, 6,10,15,21, 6,10,15,21};
        const uint32_t* K = ktable();
        uint32_t M[16];
        for (int i = 0; i < 16; i++)
            M[i] = (uint32_t)p[i*4] | ((uint32_t)p[i*4+1] << 8) |
                   ((uint32_t)p[i*4+2] << 16) | ((uint32_t)p[i*4+3] << 24);
        uint32_t A = a0, B = b0, C = c0, D = d0;
        for (int i = 0; i < 64; i++) {
            uint32_t F; int g;
            if (i < 16)      { F = (B & C) | (~B & D);      g = i; }
            else if (i < 32) { F = (D & B) | (~D & C);      g = (5*i + 1) % 16; }
            else if (i < 48) { F = B ^ C ^ D;               g = (3*i + 5) % 16; }
            else             { F = C ^ (B | ~D);            g = (7*i) % 16; }
            uint32_t tmp = D;
            D = C;
            C = B;
            B = B + rotl32(A + F + K[i] + M[g], S[i]);
            A = tmp;
        }
        a0 += A; b0 += B; c0 += C; d0 += D;
    }

    void update(const uint8_t* data, size_t len) {
        total += len;
        while (len > 0) {
            size_t n = 64 - buflen;
            if (n > len) n = len;
            std::memcpy(buf + buflen, data, n);
            buflen += n; data += n; len -= n;
            if (buflen == 64) { block(buf); buflen = 0; }
        }
    }

    void final(uint8_t out[16]) {
        uint64_t bits = total * 8;
        uint8_t pad = 0x80;
        update(&pad, 1);
        uint8_t z = 0;
        while (buflen != 56) update(&z, 1);
        uint8_t lenb[8];
        for (int i = 0; i < 8; i++) lenb[i] = (uint8_t)(bits >> (8 * i));
        update(lenb, 8);
        uint32_t regs[4] = {a0, b0, c0, d0};
        for (int i = 0; i < 4; i++)
            for (int j = 0; j < 4; j++) out[i*4+j] = (uint8_t)(regs[i] >> (8 * j));
    }
};

} // namespace detail

inline std::string md5_hex(const void* data, size_t len) {
    detail::MD5 h;
    h.update((const uint8_t*)data, len);
    uint8_t out[16];
    h.final(out);
    static const char* hexd = "0123456789abcdef";
    std::string s;
    s.reserve(32);
    for (int i = 0; i < 16; i++) {
        s.push_back(hexd[out[i] >> 4]);
        s.push_back(hexd[out[i] & 0xf]);
    }
    return s;
}

inline std::string md5_hex(const std::string& s) { return md5_hex(s.data(), s.size()); }

} // namespace jscx
