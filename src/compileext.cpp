// compileext.cpp — cx-code-encryption / CompileExt.node 的开源实现
//
// 与闭源版 ABI 兼容：导出相同的两个函数
//   RunFile(filename, dirname, exports, require, module, process, global, proDirPath)
//   GetDbKey(dbname, require)
// 并附加三个便于工具链使用的导出：
//   DecryptFile(filename)            -> 明文源码字符串
//   EncryptSource(source, basename)  -> .jscx 密文字符串（base64，无换行）
//   GetEncodeKey(name, [isDb])       -> 16 字符密钥
//   SelfTest()                       -> MD5/AES 已知答案自检，全部通过返回 true
//
// 加密方案（逆向还原，已验证）:
//   .jscx 文件内容 == base64( AES-128-ECB + PKCS7 ( JS 模块体, key ) )
//   key = derive(basename)（见 derive.h）
// 模块执行语义与 Node CommonJS 一致：
//   (function (exports, require, module, __filename, __dirname, process, global, proDirPath) { ... })
//
// SPDX-License-Identifier: MIT

#include <node_api.h>

#include <cstdint>
#include <cstdio>
#include <fstream>
#include <sstream>
#include <string>
#include <vector>

#include "aes.h"
#include "derive.h"
#include "md5.h"

namespace {

// ---------- 小工具 ----------

std::string napi_to_string(napi_env env, napi_value v) {
    size_t len = 0;
    napi_get_value_string_utf8(env, v, nullptr, 0, &len);
    std::string s(len, '\0');
    napi_get_value_string_utf8(env, v, s.data(), len + 1, &len);
    return s;
}

napi_value napi_from_string(napi_env env, const std::string& s) {
    napi_value out = nullptr;
    napi_create_string_utf8(env, s.data(), s.size(), &out);
    return out;
}

bool read_file(const std::string& path, std::string& out) {
    std::ifstream f(path.c_str(), std::ios::binary);
    if (!f.is_open()) return false;
    std::ostringstream ss;
    ss << f.rdbuf();
    out = ss.str();
    return true;
}

// 去掉 base64 里的所有空白字符（原版客户端写出的 .jscx 无换行，这里宽容处理）
std::string strip_ws(const std::string& s) {
    std::string out;
    out.reserve(s.size());
    for (char c : s)
        if (c != '\r' && c != '\n' && c != ' ' && c != '\t') out.push_back(c);
    return out;
}

// 解密一个 .jscx 文件，返回 JS 源码；失败时抛 C++ 异常由调用方转 NAPI 异常
std::string decrypt_jscx(const std::string& filename) {
    std::string raw;
    if (!read_file(filename, raw)) throw std::runtime_error("cannot read file: " + filename);
    std::string b64 = strip_ws(raw);
    std::vector<uint8_t> cipher;
    if (!jscx::base64_decode(b64, cipher)) throw std::runtime_error("invalid base64 in: " + filename);
    std::string name = jscx::basename_of(filename);
    std::string key = jscx::derive_key(name);
    std::vector<uint8_t> plain;
    if (!jscx::detail::ecb_decrypt((const uint8_t*)key.data(), cipher.data(), cipher.size(), plain))
        throw std::runtime_error("AES decrypt failed (wrong key or corrupted file): " + filename);
    return std::string(plain.begin(), plain.end());
}

// ---------- 导出的 NAPI 函数 ----------

// RunFile(filename, dirname, exports, require, module, process, global, proDirPath)
napi_value RunFile(napi_env env, napi_callback_info info) {
    size_t argc = 8;
    napi_value argv[8];
    napi_get_cb_info(env, info, &argc, argv, nullptr, nullptr);
    if (argc < 8) {
        napi_throw_type_error(env, nullptr, "RunFile expects 8 arguments");
        return nullptr;
    }

    std::string filename = napi_to_string(env, argv[0]);
    std::string source;
    try {
        source = decrypt_jscx(filename);
    } catch (const std::exception& e) {
        napi_throw_error(env, nullptr, e.what());
        return nullptr;
    }

    // 与 Node CommonJS 包装一致的函数体，通过 napi_run_script 编译后调用
    std::string script =
        "(function (exports, require, module, __filename, __dirname, process, global, proDirPath) {\n" +
        source + "\n})";
    napi_value fn = nullptr;
    if (napi_run_script(env, napi_from_string(env, script), &fn) != napi_ok) return nullptr;

    napi_value this_arg = argv[2]; // exports
    // 调用实参顺序: (exports, require, module, __filename, __dirname, process, global, proDirPath)
    napi_value call_args[8] = {argv[2], argv[3], argv[4], argv[0], argv[1], argv[5], argv[6], argv[7]};
    napi_value result = nullptr;
    if (napi_call_function(env, this_arg, fn, 8, call_args, &result) != napi_ok) return nullptr;
    return result;
}

// GetDbKey(dbname, require) -> string
napi_value GetDbKey(napi_env env, napi_callback_info info) {
    size_t argc = 2;
    napi_value argv[2];
    napi_get_cb_info(env, info, &argc, argv, nullptr, nullptr);
    if (argc < 1) {
        napi_throw_type_error(env, nullptr, "GetDbKey expects (dbname, require)");
        return nullptr;
    }
    std::string dbname = napi_to_string(env, argv[0]);
    return napi_from_string(env, jscx::derive_key("ksiUIN" + dbname));
}

// DecryptFile(filename) -> string   [附加导出]
napi_value DecryptFile(napi_env env, napi_callback_info info) {
    size_t argc = 1;
    napi_value argv[1];
    napi_get_cb_info(env, info, &argc, argv, nullptr, nullptr);
    if (argc < 1) {
        napi_throw_type_error(env, nullptr, "DecryptFile expects (filename)");
        return nullptr;
    }
    try {
        return napi_from_string(env, decrypt_jscx(napi_to_string(env, argv[0])));
    } catch (const std::exception& e) {
        napi_throw_error(env, nullptr, e.what());
        return nullptr;
    }
}

// EncryptSource(source, basename) -> string   [附加导出]
// 注意：重加密后的文件必须保持原 basename（密钥按文件名派生）
napi_value EncryptSource(napi_env env, napi_callback_info info) {
    size_t argc = 2;
    napi_value argv[2];
    napi_get_cb_info(env, info, &argc, argv, nullptr, nullptr);
    if (argc < 2) {
        napi_throw_type_error(env, nullptr, "EncryptSource expects (source, basename)");
        return nullptr;
    }
    std::string source = napi_to_string(env, argv[0]);
    std::string key = jscx::derive_key(napi_to_string(env, argv[1]));
    std::vector<uint8_t> cipher;
    jscx::detail::ecb_encrypt((const uint8_t*)key.data(), (const uint8_t*)source.data(),
                              source.size(), cipher);
    return napi_from_string(env, jscx::base64_encode(cipher.data(), cipher.size()));
}

// GetEncodeKey(name, [isDb]) -> string   [附加导出]
napi_value GetEncodeKey(napi_env env, napi_callback_info info) {
    size_t argc = 2;
    napi_value argv[2];
    napi_get_cb_info(env, info, &argc, argv, nullptr, nullptr);
    if (argc < 1) {
        napi_throw_type_error(env, nullptr, "GetEncodeKey expects (name, isDb?)");
        return nullptr;
    }
    bool is_db = false;
    if (argc >= 2) napi_get_value_bool(env, argv[1], &is_db);
    std::string name = napi_to_string(env, argv[0]);
    return napi_from_string(env, jscx::derive_key(is_db ? ("ksiUIN" + name) : name));
}

// SelfTest() -> bool   [附加导出]：MD5 + AES-128 FIPS-197 已知答案
napi_value SelfTest(napi_env env, napi_callback_info info) {
    bool ok = true;
    // MD5 向量
    ok = ok && jscx::md5_hex("") == "d41d8cd98f00b204e9800998ecf8427e";
    ok = ok && jscx::md5_hex("abc") == "900150983cd24fb0d6963f7d28e17f72";
    ok = ok && jscx::md5_hex("The quick brown fox jumps over the lazy dog") ==
                     "9e107d9d372bb6826bd81d3542a419d6";
    // AES-128 FIPS-197 附录 C.1
    {
        const uint8_t key[16] = {0x00,0x01,0x02,0x03,0x04,0x05,0x06,0x07,
                                 0x08,0x09,0x0a,0x0b,0x0c,0x0d,0x0e,0x0f};
        const uint8_t pt[16]  = {0x00,0x11,0x22,0x33,0x44,0x55,0x66,0x77,
                                 0x88,0x99,0xaa,0xbb,0xcc,0xdd,0xee,0xff};
        const uint8_t ct[16]  = {0x69,0xc4,0xe0,0xd8,0x6a,0x7b,0x04,0x30,
                                 0xd8,0xcd,0xb7,0x80,0x70,0xb4,0xc5,0x5a};
        uint8_t rk[176], out[16], back[16];
        jscx::detail::expand_key128(key, rk);
        jscx::detail::encrypt_block(rk, pt, out);
        jscx::detail::decrypt_block(rk, out, back);
        ok = ok && std::memcmp(out, ct, 16) == 0 && std::memcmp(back, pt, 16) == 0;
    }
    // 密钥派生向量（来自真实客户端 oracle）
    ok = ok && jscx::derive_key("UninstApp.jscx") == "8bb3.730*c400de9";
    ok = ok && jscx::derive_key("TrayHelper.jscx") == "7e4b.048*a525377";
    ok = ok && jscx::derive_key("ksiUINtest.db") == "8b24.729*5aa2551";
    ok = ok && jscx::derive_key("ksiUINa/b/c/任意名字.db") == "da78.fa5*238c354";
    ok = ok && jscx::derive_key("ksiUINother.db") == "1fb3.8e6*f204df9";

    napi_value out = nullptr;
    napi_get_boolean(env, ok, &out);
    return out;
}

napi_value Init(napi_env env, napi_value exports) {
    const struct { const char* name; napi_callback fn; } fns[] = {
        {"RunFile", RunFile},           {"GetDbKey", GetDbKey},
        {"DecryptFile", DecryptFile},   {"EncryptSource", EncryptSource},
        {"GetEncodeKey", GetEncodeKey}, {"SelfTest", SelfTest},
    };
    for (auto& f : fns) {
        napi_value v = nullptr;
        napi_create_function(env, f.name, NAPI_AUTO_LENGTH, f.fn, nullptr, &v);
        napi_set_named_property(env, exports, f.name, v);
    }
    return exports;
}

} // namespace

NAPI_MODULE(NODE_GYP_MODULE_NAME, Init)
