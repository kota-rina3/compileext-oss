// derive.h — cx-code-encryption 密钥派生算法（逆向还原）
// 验证：302/302 个 .jscx 样本 + GetDbKey oracle（含含路径的非 ASCII 名字）全部命中。
//
// 统一公式（getEncodeKey 与 GetDbKey 共用）:
//       h1 = md5( basename(name) + "_chenxi" )      // 先取最后一个 '/' 或 '\\' 之后的部分
//       h2 = md5( "chaoxing_" + h1 )
//       key = h2[1:5] + "." + h1[7:10] + "*" + h2[12:19]   // 16 字符
//
//   .jscx 脚本:  name = 文件全路径
//   GetDbKey:    name = "ksiUIN" + dbname   （先拼前缀，再同样取 basename）
//     —— 因此 GetDbKey("test.db") 实际是 md5("ksiUINtest.db_chenxi")，
//        而 GetDbKey("a/b/任意名字.db") 是 md5("任意名字.db_chenxi")。
#pragma once

#include <string>
#include "md5.h"

namespace jscx {

// 取路径的 basename，兼容 '/' 与 '\\'（与原版 rfind 逻辑一致）
inline std::string basename_of(const std::string& path) {
    size_t p1 = path.rfind('/');
    size_t p2 = path.rfind('\\');
    size_t p = std::string::npos;
    if (p1 != std::string::npos) p = p1;
    if (p2 != std::string::npos && (p == std::string::npos || p2 > p)) p = p2;
    return (p == std::string::npos) ? path : path.substr(p + 1);
}

inline std::string derive_key(const std::string& name) {
    std::string h1 = md5_hex(basename_of(name) + "_chenxi");
    std::string h2 = md5_hex("chaoxing_" + h1);
    return h2.substr(1, 4) + "." + h1.substr(7, 3) + "*" + h2.substr(12, 7);
}

} // namespace jscx
