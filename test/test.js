// test/test.js — compileext-oss 验证脚本
// 用法: node test/test.js [appRoot]
//   appRoot: 学习通 resources/app 目录（可选，提供后进行全量对照）
"use strict";
const fs = require("fs");
const path = require("path");
const os = require("os");

const OSS = require(path.join(__dirname, "../build/CompileExt.node"));
let pass = 0, fail = 0;
function check(name, cond, extra) {
    if (cond) { pass++; console.log("  ✅", name); }
    else { fail++; console.log("  ❌", name, extra || ""); }
}

console.log("== 1. 自检（MD5/AES 已知答案 + 密钥派生向量）==");
check("SelfTest()", OSS.SelfTest() === true);

console.log("== 2. GetDbKey 已知答案（真实客户端 oracle）==");
check("GetDbKey('test.db')", OSS.GetDbKey("test.db") === "8b24.729*5aa2551", OSS.GetDbKey("test.db"));
check("GetDbKey('other.db')", OSS.GetDbKey("other.db") === "1fb3.8e6*f204df9", OSS.GetDbKey("other.db"));

console.log("== 3. 与闭源原版模块对照（若存在）==");
const ORIG_PATHS = [
    "/home/ricer/Desktop/XXT64/resources/app/node_modules/cx-code-encryption/native/linux_x64/CompileExt",
];
let orig = null;
for (const p of ORIG_PATHS) {
    try { orig = require(p); break; } catch (e) { /* 不存在则跳过 */ }
}
if (orig) {
    const names = ["test.db", "other.db", "cxstudy.db", "a/b/c/任意名字.db", "msg_2026.db"];
    let allEq = true;
    for (const n of names) {
        const a = orig.GetDbKey(n, require), b = OSS.GetDbKey(n);
        if (a !== b) { allEq = false; console.log("    差异:", n, a, b); }
    }
    check("GetDbKey 与原版一致 (" + names.length + " 个样本)", allEq);
} else {
    console.log("  (未找到原版模块，跳过)");
}

console.log("== 4. DecryptFile 与已知明文对照 ==");
const APP = process.argv[2] || "/home/ricer/Desktop/XXT64/resources/app";
const tray = path.join(APP, "electron/main/TrayHelper.jscx");
const known = "/home/ricer/Desktop/XXT64/resources/.workbuddy/jscx/out/TrayHelper.dec.js";
if (fs.existsSync(tray)) {
    const got = OSS.DecryptFile(tray);
    if (fs.existsSync(known)) {
        check("TrayHelper.jscx 明文与已知解密结果一致", got === fs.readFileSync(known, "utf8"));
    } else {
        check("TrayHelper.jscx 可解密且含 initTray", got.includes("initTray"));
    }
}

console.log("== 5. 加密→解密回环 ==");
{
    const src = "// test module\nmodule.exports.add=(a,b)=>a+b;\nmodule.exports.hello='你好,jscx';\n";
    const cipher = OSS.EncryptSource(src, "zz_roundtrip_test.jscx");
    const back = OSS.DecryptSource
        ? null
        : (() => {
              const f = path.join(os.tmpdir(), "zz_roundtrip_test.jscx");
              fs.writeFileSync(f, cipher);
              const out = OSS.DecryptFile(f);
              fs.unlinkSync(f);
              return out;
          })();
    check("EncryptSource→DecryptFile 往返一致", back === src);
    check("密文无结尾换行", !/[\r\n]$/.test(cipher));
}

console.log("== 6. RunFile 模块执行（CommonJS 语义）==");
{
    const src = [
        "const path = require('path');",
        "module.exports.add = (a, b) => a + b;",
        "module.exports.filename = __filename;",
        "module.exports.dirname = __dirname;",
        "module.exports.hasProcess = typeof process === 'object';",
        "module.exports.hasGlobal = typeof global === 'object';",
        "module.exports.basename = path.basename(__filename);",
    ].join("\n");
    const dir = fs.mkdtempSync(path.join(os.tmpdir(), "jscx-run-"));
    const file = path.join(dir, "zz_run_test.jscx");
    fs.writeFileSync(file, OSS.EncryptSource(src, "zz_run_test.jscx"));

    const fakeModule = { exports: {} };
    const fakeRequire = (id) => require(id);
    fakeRequire.resolve = require.resolve;
    OSS.RunFile(file, dir, fakeModule.exports, fakeRequire, fakeModule, process, global, dir);
    const m = fakeModule.exports;
    check("add(2,3) == 5", m.add && m.add(2, 3) === 5);
    check("__filename 正确", m.filename === file);
    check("__dirname 正确", m.dirname === dir);
    check("process/global 可见", m.hasProcess && m.hasGlobal);
    check("module 内 require 可用", m.basename === "zz_run_test.jscx");
    fs.rmSync(dir, { recursive: true, force: true });
}

console.log("== 7. 全量对照：app 内全部 .jscx vs 既有解密树 ==");
{
    const REF = "/home/ricer/Desktop/XXT64/resources/.workbuddy/jscx/dec";
    if (fs.existsSync(REF)) {
        let n = 0, bad = 0;
        const walk = (root, cb) => {
            for (const e of fs.readdirSync(root, { withFileTypes: true })) {
                const p = path.join(root, e.name);
                if (e.isDirectory()) walk(p, cb);
                else if (e.name.endsWith(".jscx")) cb(p);
            }
        };
        walk(APP, (p) => {
            try {
                const got = OSS.DecryptFile(p);
                const ref = path.join(REF, path.relative(APP, p).replace(/\.jscx$/, ".dec.js"));
                if (fs.existsSync(ref) && fs.readFileSync(ref, "utf8") !== got) bad++;
                n++;
            } catch (e) {
                bad++;
                console.log("    失败:", p, e.message);
            }
        });
        check(`全量解密 ${n} 个文件, 与 JS 工具解密树不一致 ${bad} 个`, bad === 0);
    } else {
        console.log("  (无参考解密树，跳过)");
    }
}

console.log(`\n结果: PASS ${pass} / FAIL ${fail}`);
process.exit(fail ? 1 : 0);
