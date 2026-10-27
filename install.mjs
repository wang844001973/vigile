#!/usr/bin/env node
// vigile 安装器（Node 版）— 把 vigile/vig 双入口装到用户 PATH
//
// Linux/macOS: ~/.local/bin/vigile, ~/.local/bin/vig
// Windows:     %LOCALAPPDATA%\Programs\vigile\{vigile,vig}.cmd
//
// 与 Python 版不同：无需复制脚本——入口直接指向仓库内 bin/vigile.js，
// node 已是 agent 用户的先决依赖（5 agent 的 hook 全以 node 运行）。

import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import { fileURLToPath } from "node:url";

const HERE = path.dirname(fileURLToPath(import.meta.url));
const TARGET = path.join(HERE, "bin", "vigile.js");

function binDir() {
  return os.platform() === "win32"
    ? path.join(process.env.LOCALAPPDATA || os.homedir(), "Programs", "vigile")
    : path.join(os.homedir(), ".local", "bin");
}

function entries(dir) {
  return os.platform() === "win32"
    ? [path.join(dir, "vigile.cmd"), path.join(dir, "vig.cmd")]
    : [path.join(dir, "vigile"), path.join(dir, "vig")];
}

function inPath(dir) {
  const parts = (process.env.PATH || "").split(path.delimiter);
  const norm = (p) => path.normalize(p.toLowerCase().replace(/[/\\]+$/, ""));
  return parts.filter(Boolean).some(p => norm(p) === norm(dir));
}

const argv = process.argv.slice(2);
const uninstall = argv.includes("--uninstall");
const dry = argv.includes("--dry-run");
const dir = binDir();

if (uninstall) {
  for (const t of entries(dir)) {
    if (fs.existsSync(t)) {
      console.log(`${dry ? "[dry-run] 将删除" : "删除"} ${t}`);
      if (!dry) fs.rmSync(t);
    } else {
      console.log(`不存在，跳过: ${t}`);
    }
  }
  process.exit(0);
}

console.log(`Node: ${process.execPath}`);
console.log(`安装目录: ${dir}`);
for (const t of entries(dir)) {
  console.log(`${dry ? "[dry-run] 将写入" : "写入"} ${t}`);
  if (!dry) {
    fs.mkdirSync(path.dirname(t), { recursive: true });
    if (t.endsWith(".cmd")) {
      fs.writeFileSync(t, `@echo off\r\n"${process.execPath}" "${TARGET}" %*\r\n`);
    } else {
      fs.writeFileSync(t, `#!/bin/sh\nexec "${process.execPath}" "${TARGET}" "$@"\n`);
      fs.chmodSync(t, 0o755);
    }
  }
}

if (!dry) console.log("安装完成。");
if (!inPath(dir)) {
  console.log("\n⚠ 该目录不在 PATH 中，请加入：");
  if (os.platform() === "win32") {
    console.log(`   setx PATH "%PATH%;${dir}"`);
  } else {
    console.log(`   export PATH="${dir}:$PATH"  （建议写进 ~/.bashrc）`);
  }
} else {
  console.log("PATH 已包含该目录，可直接运行: vig --help");
}
console.log("\n下一步:");
console.log("  vig --help          全部命令");
console.log("  vig setup --install --agent all   给 agent 装 hook");
