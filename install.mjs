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
  if (parts.filter(Boolean).some(p => norm(p) === norm(dir))) return true;
  // 当前 shell 进程可能是装 PATH 之前启动的（改完注册表老终端看不到），
  // 再查一次注册表里的持久 User PATH。
  if (os.platform() === "win32") {
    try {
      const r = execFileSync("powershell", ["-NoProfile", "-Command",
        "[Environment]::GetEnvironmentVariable('PATH','User')"], { encoding: "utf8" });
      return r.split(";").filter(Boolean).some(p => norm(p) === norm(dir));
    } catch { return false; }
  }
  return false;
}

// Windows：确保本目录在用户 PATH 里排在所有含 vig/vigile 的其他目录之前
// （尤其 ~/.local/bin —— Git Bash 版 sh 脚本在那里）。改的是注册表级
// User PATH，不碰 Machine（无需管理员）。
import { execFileSync } from "node:child_process";
function ensureUserPathFirst(dir) {
  const target = dir.replace(/'/g, "''");
  const script = [
    "$ErrorActionPreference='Stop'",
    `$dir = '${target}'`,
    "$cur = [Environment]::GetEnvironmentVariable('PATH','User') -split ';' | Where-Object { $_ -and $_ -ne $dir }",
    "$first = @($dir) + $cur",
    "[Environment]::SetEnvironmentVariable('PATH', ($first -join ';'), 'User')",
    "Write-Output 'ok'",
  ].join("\n");
  try {
    const r = execFileSync("powershell", ["-NoProfile", "-Command", script], { encoding: "utf8" });
    if (r.includes("ok")) console.log("已将本目录挪到用户 PATH 首位（防 Git Bash sh 脚本遮蔽 .cmd）");
  } catch (e) {
    console.log("⚠ 自动调整 PATH 顺序失败（不影响本次使用，可手动把目录挪前）：");
    console.log("  " + String(e.message).split("\n")[0]);
  }
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

// Windows 双入口策略：CMD/PowerShell 用 Programs\vigile\*.cmd（上面已生成），
// Git Bash 需要无扩展名 sh 脚本 —— 放 ~/.local/bin 并由本安装器接管生成。
// 之前采用删除 sh shim 的做法修 PowerShell 报错，结果删掉过 Git Bash 的
// 唯一入口，属于误伤；正确姿势是接管生成 + 把 .cmd 目录挪到 PATH 首位。
if (os.platform() === "win32") {
  const bashDir = path.join(os.homedir(), ".local", "bin");
  for (const name of ["vigile", "vig"]) {
    const p = path.join(bashDir, name);
    console.log(`${dry ? "[dry-run] 将写入" : "写入"} ${p}  （Git Bash 入口）`);
    if (!dry) {
      fs.mkdirSync(bashDir, { recursive: true });
      fs.writeFileSync(p, `#!/bin/sh\nexec "${process.execPath}" "${TARGET}" "$@"\n`);
      fs.chmodSync(p, 0o755);
    }
  }
}

if (!dry) console.log("安装完成。");
if (!inPath(dir)) {
  console.log("\n⚠ 该目录不在 PATH 中，请加入：");
  if (os.platform() === "win32") {
    console.log(`   setx PATH "${dir};%PATH%"    （注意放最前，理由见下）`);
  } else {
    console.log(`   export PATH="${dir}:$PATH"  （建议写进 ~/.bashrc）`);
  }
} else if (os.platform() === "win32") {
  // Windows 顺序很关键：~/.local/bin 里若有 Git Bash 版无扩展名 sh 脚本
  // （给 Git Bash 用的入口就放那里），它排在前面时 PowerShell 会把它
  // 当"文档"执行报错。把自己挪到用户 PATH 首位，.cmd 在所有 shell 优先。
  if (!dry) ensureUserPathFirst(dir);
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
    console.log("\nℹ PATH 中还有其他 vig/vigile 入口（如 Git Bash 用的 ~/.local/bin sh 脚本）。");
    console.log("   本安装器已把自己挪到用户 PATH 首位，.cmd 在 CMD/PowerShell 优先命中；");
    console.log("   sh 入口留给 Git Bash。若发现仍有遮蔽，检查目录顺序。");
  }
}

console.log("\n下一步:");
console.log("  vig --help          全部命令");
console.log("  vig setup --install --agent all   给 agent 装 hook");
