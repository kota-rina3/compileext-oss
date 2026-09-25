// fallback/compileext.js — CompileExt.node 的纯 JS 实现（无需编译，任何 Node/Electron 可用）
// API 与开源 C++ 版一致：RunFile / GetDbKey / DecryptFile / EncryptSource / GetEncodeKey / SelfTest
//
// 加密方案: .jscx == base64( AES-128-ECB + PKCS7 ( JS 模块体, key ) )
// key = md5x2 派生（见 derive），只取决于 basename。
"use strict";
const fs = require("fs");
const path = require("path");
const crypto = require("crypto");
const vm = require("vm");
const Module = require("module");

function md5hex(s) {
    return crypto.createHash("md5").update(s, "utf8").digest("hex");
}

// basename：取最后一个 '/' 或 '\\' 之后的部分
function basenameOf(p) {
    const i = Math.max(p.lastIndexOf("/"), p.lastIndexOf("\\"));
    return i === -1 ? p : p.slice(i + 1);
}

// 统一派生公式（302/302 样本验证）:
//   h1 = md5( basename + "_chenxi" )
//   h2 = md5( "chaoxing_" + h1 )
//   key = h2[1:5] + "." + h1[7:10] + "*" + h2[12:19]
function deriveKey(name) {
    const base = basenameOf(name);
    const h1 = md5hex(base + "_chenxi");
    const h2 = md5hex("chaoxing_" + h1);
    return h2.slice(1, 5) + "." + h1.slice(7, 10) + "*" + h2.slice(12, 19);
}

function decryptJscx(filename) {
    const b64 = fs.readFileSync(filename, "utf8").replace(/\s+/g, "");
    const key = deriveKey(filename);
    const d = crypto.createDecipheriv("aes-128-ecb", Buffer.from(key, "utf8"), "");
    let pt = d.update(b64, "base64", "utf8");
    pt += d.final("utf8");
    return pt;
}

function RunFile(filename, dirname, exports, require_, module, process_, global_, proDirPath) {
    const source = decryptJscx(filename);
    const wrapper = new Function(
        "exports", "require", "module", "__filename", "__dirname",
        "process", "global", "proDirPath",
        source
    );
    return wrapper.call(exports, exports, require_, module, filename, dirname, process_, global_, proDirPath);
}

function GetDbKey(dbname /*, require */) {
    return deriveKey("ksiUIN" + dbname);
}

function EncryptSource(source, name) {
    const key = deriveKey(name);
    const c = crypto.createCipheriv("aes-128-ecb", Buffer.from(key, "utf8"), "");
    let ct = c.update(source, "utf8", "base64");
    ct += c.final("base64");
    return ct;
}

function DecryptFile(filename) {
    return decryptJscx(filename);
}

function GetEncodeKey(name, isDb) {
    return deriveKey(isDb ? "ksiUIN" + name : name);
}

function SelfTest() {
    const ok = (a, b) => a === b;
    const vectors = [
        [deriveKey("UninstApp.jscx"), "8bb3.730*c400de9"],
        [deriveKey("TrayHelper.jscx"), "7e4b.048*a525377"],
        [deriveKey("ksiUINtest.db"), "8b24.729*5aa2551"],
        [deriveKey("ksiUINa/b/c/任意名字.db"), "da78.fa5*238c354"],
        [md5hex("abc"), "900150983cd24fb0d6963f7d28e17f72"],
    ];
    return vectors.every(([a, b]) => ok(a, b));
}

module.exports = { RunFile, GetDbKey, DecryptFile, EncryptSource, GetEncodeKey, SelfTest, deriveKey, basenameOf };
