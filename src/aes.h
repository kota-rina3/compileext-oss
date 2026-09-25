// aes.h — 紧凑的 AES-128（ECB 模式 + PKCS7 填充），无第三方依赖
// S 盒用 GF(2^8) 逆元 + 仿射变换现场生成，避免手抄 256 字节表出错。
// 已知答案测试见 compileext.cpp 的 SelfTest()。
#pragma once

#include <cstdint>
#include <cstring>
#include <string>
#include <vector>

namespace jscx {

namespace detail {

inline uint8_t xt(uint8_t a) { return (uint8_t)((a << 1) ^ ((a >> 7) * 0x1b)); }
inline uint8_t gmul(uint8_t a, uint8_t b) {
    uint8_t p = 0;
    while (b) {
        if (b & 1) p ^= a;
        a = xt(a);
        b >>= 1;
    }
    return p;
}

struct Tables {
    uint8_t sbox[256], inv[256];
    Tables() {
        for (int i = 0; i < 256; i++) {
            // GF(2^8) 逆元（暴力找）
            uint8_t inverse = 0;
            if (i != 0) {
                for (int y = 1; y < 256; y++) {
                    if (gmul((uint8_t)i, (uint8_t)y) == 1) { inverse = (uint8_t)y; break; }
                }
            }
            // 仿射变换: b_i = s_i ^ s_{i+4} ^ s_{i+5} ^ s_{i+6} ^ s_{i+7} ^ 0x63_i
            uint8_t s = inverse, r = 0x63;
            for (int b = 0; b < 8; b++) {
                uint8_t bit = ((s >> b) ^ (s >> ((b + 4) % 8)) ^ (s >> ((b + 5) % 8)) ^
                               (s >> ((b + 6) % 8)) ^ (s >> ((b + 7) % 8))) & 1;
                r ^= (uint8_t)(bit << b);
            }
            sbox[i] = r;
        }
        for (int i = 0; i < 256; i++) inv[sbox[i]] = (uint8_t)i;
    }
};

inline const Tables& tables() {
    static Tables t;
    return t;
}

inline void expand_key128(const uint8_t key[16], uint8_t rk[176]) {
    std::memcpy(rk, key, 16);
    static const uint8_t rcon[10] = {0x01,0x02,0x04,0x08,0x10,0x20,0x40,0x80,0x1b,0x36};
    const uint8_t* sb = tables().sbox;
    for (int r = 1; r <= 10; r++) {
        uint8_t* prev = rk + 16 * (r - 1);
        uint8_t* cur  = rk + 16 * r;
        uint8_t t[4] = {sb[prev[13]], sb[prev[14]], sb[prev[15]], sb[prev[12]]};
        t[0] ^= rcon[r - 1];
        for (int i = 0; i < 4; i++) cur[i]      = prev[i]     ^ t[i];
        for (int i = 0; i < 4; i++) cur[4 + i]  = prev[4 + i] ^ cur[i];
        for (int i = 0; i < 4; i++) cur[8 + i]  = prev[8 + i] ^ cur[4 + i];
        for (int i = 0; i < 4; i++) cur[12 + i] = prev[12 + i] ^ cur[8 + i];
    }
}

// state 布局: state[4*c + r] = AES 状态第 c 列第 r 行（与输入字节序一致）
inline uint8_t& st(uint8_t* s, int r, int c) { return s[4 * c + r]; }

inline void encrypt_block(const uint8_t rk[176], const uint8_t in[16], uint8_t out[16]) {
    const uint8_t* sb = tables().sbox;
    uint8_t s[16];
    for (int i = 0; i < 16; i++) s[i] = in[i] ^ rk[i];
    for (int round = 1; round <= 10; round++) {
        uint8_t t[16];
        // SubBytes
        for (int i = 0; i < 16; i++) t[i] = sb[s[i]];
        // ShiftRows
        for (int r = 0; r < 4; r++)
            for (int c = 0; c < 4; c++) st(s, r, c) = t[4 * ((c + r) % 4) + r];
        // MixColumns（最后一轮跳过）
        if (round < 10) {
            for (int c = 0; c < 4; c++) {
                uint8_t a0 = st(s,0,c), a1 = st(s,1,c), a2 = st(s,2,c), a3 = st(s,3,c);
                st(s,0,c) = (uint8_t)(gmul(a0,2) ^ gmul(a1,3) ^ a2 ^ a3);
                st(s,1,c) = (uint8_t)(a0 ^ gmul(a1,2) ^ gmul(a2,3) ^ a3);
                st(s,2,c) = (uint8_t)(a0 ^ a1 ^ gmul(a2,2) ^ gmul(a3,3));
                st(s,3,c) = (uint8_t)(gmul(a0,3) ^ a1 ^ a2 ^ gmul(a3,2));
            }
        }
        // AddRoundKey
        for (int i = 0; i < 16; i++) s[i] ^= rk[16 * round + i];
    }
    std::memcpy(out, s, 16);
}

inline void decrypt_block(const uint8_t rk[176], const uint8_t in[16], uint8_t out[16]) {
    const uint8_t* iv = tables().inv;
    uint8_t s[16];
    for (int i = 0; i < 16; i++) s[i] = in[i] ^ rk[160 + i];
    for (int round = 9; round >= 0; round--) {
        uint8_t t[16];
        // InvShiftRows（行右移：s'[r][c] = s[r][(c - r) mod 4]）
        for (int r = 0; r < 4; r++)
            for (int c = 0; c < 4; c++) t[4 * c + r] = st(s, r, (c + 4 - (r % 4)) % 4);
        // InvSubBytes
        for (int i = 0; i < 16; i++) s[i] = iv[t[i]];
        // AddRoundKey
        for (int i = 0; i < 16; i++) s[i] ^= rk[16 * round + i];
        // InvMixColumns（第 0 轮前不做——注意：标准是除最后一轮外都做）
        if (round > 0) {
            for (int c = 0; c < 4; c++) {
                uint8_t a0 = st(s,0,c), a1 = st(s,1,c), a2 = st(s,2,c), a3 = st(s,3,c);
                st(s,0,c) = (uint8_t)(gmul(a0,14) ^ gmul(a1,11) ^ gmul(a2,13) ^ gmul(a3,9));
                st(s,1,c) = (uint8_t)(gmul(a0,9) ^ gmul(a1,14) ^ gmul(a2,11) ^ gmul(a3,13));
                st(s,2,c) = (uint8_t)(gmul(a0,13) ^ gmul(a1,9) ^ gmul(a2,14) ^ gmul(a3,11));
                st(s,3,c) = (uint8_t)(gmul(a0,11) ^ gmul(a1,13) ^ gmul(a2,9) ^ gmul(a3,14));
            }
        }
    }
    std::memcpy(out, s, 16);
}

inline void ecb_encrypt(const uint8_t key[16], const uint8_t* data, size_t len, std::vector<uint8_t>& out) {
    uint8_t rk[176];
    expand_key128(key, rk);
    size_t pad = 16 - (len % 16);
    std::vector<uint8_t> buf(data, data + len);
    buf.resize(len + pad, (uint8_t)pad); // PKCS7
    out.resize(buf.size());
    for (size_t i = 0; i < buf.size(); i += 16)
        encrypt_block(rk, buf.data() + i, out.data() + i);
}

// 返回 false 表示解密失败（长度不对 / PKCS7 填充非法）
inline bool ecb_decrypt(const uint8_t key[16], const uint8_t* data, size_t len, std::vector<uint8_t>& out) {
    if (len == 0 || len % 16 != 0) return false;
    uint8_t rk[176];
    expand_key128(key, rk);
    out.resize(len);
    for (size_t i = 0; i < len; i += 16)
        decrypt_block(rk, data + i, out.data() + i);
    uint8_t pad = out[len - 1];
    if (pad < 1 || pad > 16 || pad > len) return false;
    for (size_t i = len - pad; i < len; i++)
        if (out[i] != pad) return false;
    out.resize(len - pad);
    return true;
}

} // namespace detail

// ---------- base64 ----------
inline std::string base64_encode(const uint8_t* data, size_t len) {
    static const char* tab = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    std::string out;
    out.reserve((len + 2) / 3 * 4);
    for (size_t i = 0; i < len; i += 3) {
        uint32_t n = (uint32_t)data[i] << 16;
        if (i + 1 < len) n |= (uint32_t)data[i + 1] << 8;
        if (i + 2 < len) n |= data[i + 2];
        out.push_back(tab[(n >> 18) & 63]);
        out.push_back(tab[(n >> 12) & 63]);
        out.push_back(i + 1 < len ? tab[(n >> 6) & 63] : '=');
        out.push_back(i + 2 < len ? tab[n & 63] : '=');
    }
    return out;
}

inline bool base64_decode(const std::string& in, std::vector<uint8_t>& out) {
    auto val = [](char c) -> int {
        if (c >= 'A' && c <= 'Z') return c - 'A';
        if (c >= 'a' && c <= 'z') return c - 'a' + 26;
        if (c >= '0' && c <= '9') return c - '0' + 52;
        if (c == '+') return 62;
        if (c == '/') return 63;
        return -1;
    };
    out.clear();
    out.reserve(in.size() / 4 * 3);
    uint32_t acc = 0;
    int bits = 0;
    for (char c : in) {
        if (c == '=' || c == '\r' || c == '\n' || c == ' ' || c == '\t') continue;
        int v = val(c);
        if (v < 0) return false;
        acc = (acc << 6) | (uint32_t)v;
        bits += 6;
        if (bits >= 8) {
            bits -= 8;
            out.push_back((uint8_t)(acc >> bits));
        }
    }
    return true;
}

} // namespace jscx
