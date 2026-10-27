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

// Windows 下清理 Git Bash 时代遗留的无扩展名 shim。
// 那类文件是 sh 脚本，PowerShell 会把它当"文档"执行并报
// 「无法在管道中间运行文档」；而它若在 PATH 中排在 .cmd 之前，
// 还会遮蔽掉正确的入口 —— CMD 里敲 vig 也一起坏掉。
if (os.platform() === "win32") {
  for (const legacy of ["vig", "vigile"]) {
    const p = path.join(dir, legacy);
    if (!fs.existsSync(p)) continue;
    let head = "";
    try { head = fs.readFileSync(p, "utf8").slice(0, 40); } catch { continue; }
    if (!head.startsWith("#!")) continue;   // 不是 sh 脚本就别动
    console.log(`${dry ? "[dry-run] 将删除" : "清理遗留 shim"} ${p}`);
    if (!dry) { try { fs.rmSync(p); } catch { /* 权限不足就算了，下面会警告 */ } }
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

// PATH 里若还有别的 vig/vigile（常见于 Git Bash 时代的 ~/.local/bin），
// 谁排在前面谁生效 —— 排在 .cmd 之前的 sh 脚本会让 PowerShell 报错、
// 在 CMD 里也可能遮蔽正确入口。这里主动查出来告诉用户。
if (os.platform() === "win32") {
  const conflicts = [];
  for (const part of (process.env.PATH || "").split(path.delimiter)) {
    if (!part) continue;
    if (path.normalize(part.toLowerCase()) === path.normalize(dir.toLowerCase())) continue;
    for (const name of ["vig", "vigile"]) {
      const p = path.join(part, name);
      if (fs.existsSync(p)) conflicts.push(p);
    }
  }
  if (conflicts.length) {
    console.log("\n⚠ 发现其他 vig/vigile 入口，可能遮蔽本安装（按 PATH 顺序先生效）：");
    for (const c of conflicts) console.log(`   ${c}`);
    console.log("   建议删除上面这些旧入口（多为早期 Git Bash 版 sh 脚本），");
    console.log("   PowerShell 遇到无扩展名的 sh 脚本会报「无法在管道中间运行文档」。");
  }
}

console.log("\n下一步:");
console.log("  vig --help          全部命令");
console.log("  vig setup --install --agent all   给 agent 装 hook");
