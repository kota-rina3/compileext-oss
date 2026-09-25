# compileext-oss — 学习通 `CompileExt.node` 的开源实现

对超星学习通客户端（cxstudy）脚本加密模块 `cx-code-encryption` 的原生扩展
`CompileExt.node` 进行的**完整开源还原**。与闭源版 ABI 兼容（相同的两个导出函数），
可在 Linux / macOS / Windows、x64 / arm64 / 任意 N-API 平台编译。

- License: MIT
- 依赖：无（内置 MD5 与 AES-128 实现，零第三方库）
- ABI：N-API（node_api），Node ≥ 12 与 Electron 均可加载

---

## 一、还原的加密方案（逆向成果）

```
.jscx 文件内容 == base64( AES-128-ECB + PKCS7 ( JS 模块体, key ) )
```

密钥派生（`getEncodeKey` 与 `GetDbKey` 共用同一条链，只取 basename）：

```
h1  = md5( basename(name) + "_chenxi" )
h2  = md5( "chaoxing_" + h1 )
key = h2[1:5] + "." + h1[7:10] + "*" + h2[12:19]      // 16 字符，如 7e4b.048*a525377
```

| 调用场景 | name 的取值 |
|---|---|
| `RunFile`（加载 .jscx） | 文件全路径（先取最后一个 `/` 或 `\` 之后的 basename） |
| `GetDbKey(dbname)` | `"ksiUIN" + dbname`（先拼前缀，再同样取 basename） |

验证情况：

- 302 个真实 `.jscx` 密钥样本 302/302 命中；
- `GetDbKey` 与闭源模块对 5 组名字（含含路径的非 ASCII 名字）输出完全一致；
- 全量 302 个文件用本实现解密，与既有解密树逐字节 diff 为 0。

## 二、导出接口

| 导出 | 签名 | 说明 |
|---|---|---|
| `RunFile` | `(filename, dirname, exports, require, module, process, global, proDirPath)` | 与原版一致：解密并按 CommonJS 语义执行 .jscx 模块 |
| `GetDbKey` | `(dbname, require)` | 与原版一致：返回 16 字符数据库密钥 |
| `DecryptFile` | `(filename)` → string | 【附加】解密 .jscx 返回源码 |
| `EncryptSource` | `(source, name)` → string | 【附加】加密为 .jscx 密文（base64 无换行） |
| `GetEncodeKey` | `(name, isDb?)` → string | 【附加】直接取派生密钥 |
| `SelfTest` | `()` → bool | 【附加】MD5/AES FIPS-197 已知答案 + 派生向量自检 |

## 三、构建

```bash
# 需要 CMake ≥ 3.15 与任意 C++17 编译器；无需安装 Node.js
cmake -B build -DCMAKE_BUILD_TYPE=Release
cmake --build build --parallel
# 产物: build/CompileExt.node
```

CMake 按以下顺序获取 N-API 头文件：

1. `-DNODE_HEADERS_DIR=/path/to/include/node` 手动指定；
2. 系统路径（`/usr/include/node` 等）自动查找；
3. 都没有则自动从 nodejs.org 下载官方头文件包（默认 node 22.21.1，可用 `-DNODE_VERSION=` 改）。

### 替换进客户端（drop-in）

```bash
NAT=/path/to/resources/app/node_modules/cx-code-encryption/native/linux_x64
cp $NAT/CompileExt.node $NAT/CompileExt.node.orig   # 备份原版
cp build/CompileExt.node $NAT/CompileExt.node       # 换入开源版
# 回滚: cp $NAT/CompileExt.node.orig $NAT/CompileExt.node
```

模块名必须是 `CompileExt`（CMake 已固定），`dist/CompileUtil.js` 按名字加载。

### 纯 JS fallback（不想编译时）

`fallback/compileext.js` 是行为一致的纯 JS 实现（用 Node 内置 crypto），
API 与 C++ 版相同，可直接 `require` 使用，也可改 `CompileUtil.js` 的加载路径指向它。

## 四、测试

```bash
node test/test.js [appRoot]   # 或用 Electron: ELECTRON_RUN_AS_NODE=1 ./cxstudy test/test.js
```

覆盖：SelfTest 已知答案 → GetDbKey 已知答案 → 与闭源原版对照 → 真实文件明文对照 →
加密/解密回环 → RunFile CommonJS 语义（`__filename`/`__dirname`/`require`/`process`/`global`）→
全量 302 文件对照。当前 **13/13 PASS**。

## 五、CI

`.github/workflows/build.yml` 提供 GitHub Actions 矩阵：
ubuntu x64 / arm64、macOS arm64 / x64、Windows x64，产物自动上传。

## 六、逆向过程摘要

1. 运行时钩子 `crypto.createDecipheriv` 确认 AES-128-ECB + base64 方案；
2. 302 组「路径→密钥」样本发现密钥只依赖 basename；
3. 哈希切片/带盐/HMAC 穷举失败后转向反汇编：
   `getCodeKey` 是 125 字符硬编码字母表（干扰项），真正派生在 `getEncodeKey`：
   两次 md5（盐 `_chenxi` / `chaoxing_`）+ 特定下标切片 + 固定 `.` `*` 定位；
4. `GetDbKey` 通过钩住 JS 侧 `crypto.createHash` 抓到输入，确认 `ksiUIN` 前缀 + 同一公式；
5. 以原版模块为 oracle 逐项验证（含非 ASCII 名字走 basename 的行为）。

细节见本仓库 `src/derive.h` 注释。
