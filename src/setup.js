// agent hook 安装器 — 为 Claude/Codex/ZCode/dsh/OpenCode 装卸 vigile hook。
// 与 bin/vigile.js 同语言；五 agent 的注册协议各不相同，集中在此维护。

import fs from "node:fs";
import path from "node:path";
import os from "node:os";
import { fileURLToPath } from "node:url";

const HERE = path.dirname(fileURLToPath(import.meta.url));
const HOOK_PATH = path.join(path.dirname(HERE), "hooks", "vigile-hook.js");
const NODE = process.execPath;

function home(...parts) { return path.join(os.homedir(), ...parts); }

// ---------------------------------------------------------------- ZCode：config.json，process 型
function zcodeCfg() { return home(".zcode", "cli", "config.json"); }
function hasVigileArg(e) {
  return (e.hooks || []).some(h => String(h.args || []).includes("vigile-hook.js"));
}

const REGISTRY = {};
REGISTRY.zcode = {
  detect: () => fs.existsSync(zcodeCfg()),
  install() {
    const p = zcodeCfg();
    const d = JSON.parse(fs.readFileSync(p, "utf8"));
    d.hooks = d.hooks || {}; d.hooks.enabled = true;
    d.hooks.events = d.hooks.events || {};
    const ev = d.hooks.events;
    ev.PreToolUse = ev.PreToolUse || [];
    if (!ev.PreToolUse.some(hasVigileArg)) {
      ev.PreToolUse.push({ matcher: "Bash", hooks: [{ type: "process", command: NODE, args: [HOOK_PATH], timeoutMs: 4000 }] });
    }
    ev.PostToolUse = ev.PostToolUse || [];
    if (!ev.PostToolUse.some(hasVigileArg)) {
      ev.PostToolUse.push({ matcher: "Edit|Write|ApplyPatch", hooks: [{ type: "process", command: NODE, args: [HOOK_PATH, "--post"], timeoutMs: 4000 }] });
    }
    fs.writeFileSync(p, JSON.stringify(d, null, 2));
    return "已注册（PreToolUse 拦截 + PostToolUse 文件变更 diff）";
  },
  uninstall() {
    const p = zcodeCfg();
    if (!fs.existsSync(p)) return "配置不存在";
    const d = JSON.parse(fs.readFileSync(p, "utf8"));
    let n = 0;
    const ev = d.hooks && d.hooks.events ? d.hooks.events : {};
    for (const key of ["PreToolUse", "PostToolUse"]) {
      const lst = ev[key] || [];
      const keep = lst.filter(e => !hasVigileArg(e));
      n += lst.length - keep.length;
      ev[key] = keep;
    }
    fs.writeFileSync(p, JSON.stringify(d, null, 2));
    return `移除 ${n} 条`;
  },
  status() {
    if (!fs.existsSync(zcodeCfg())) return "未检测到";
    const d = JSON.parse(fs.readFileSync(zcodeCfg(), "utf8"));
    const pre = (d.hooks && d.hooks.events && d.hooks.events.PreToolUse) || [];
    return pre.some(hasVigileArg) ? "已安装" : "未安装";
  },
};

// ---------------------------------------------------------------- Claude/Codex：command 型
function makeCompat(sub, file) {
  const cfg = () => home(sub, file);
  const hasVigileCmd = (e) => (e.hooks || []).some(h => (h.command || "").includes("vigile-hook.js"));
  return {
    detect: () => fs.existsSync(cfg()),
    install() {
      const p = cfg();
      const d = JSON.parse(fs.readFileSync(p, "utf8"));
      d.hooks = d.hooks || {};
      d.hooks.PreToolUse = d.hooks.PreToolUse || [];
      if (!d.hooks.PreToolUse.some(hasVigileCmd)) {
        d.hooks.PreToolUse.unshift({ matcher: "Bash", hooks: [{ type: "command", command: `VIGILE_HOOK_MODE=claude "${NODE}" "${HOOK_PATH}"` }] });
      }
      d.hooks.PostToolUse = d.hooks.PostToolUse || [];
      if (!d.hooks.PostToolUse.some(hasVigileCmd)) {
        d.hooks.PostToolUse.unshift({ matcher: "Edit|Write|ApplyPatch", hooks: [{ type: "command", command: `"${NODE}" "${HOOK_PATH}" --post` }] });
      }
      fs.writeFileSync(p, JSON.stringify(d, null, 2));
      return "已注册（PreToolUse 强制改写 + deny；PostToolUse 文件变更 diff）";
    },
    uninstall() {
      const p = cfg();
      if (!fs.existsSync(p)) return "配置不存在";
      const d = JSON.parse(fs.readFileSync(p, "utf8"));
      let n = 0;
      for (const key of ["PreToolUse", "PostToolUse"]) {
        const lst = (d.hooks && d.hooks[key]) || [];
        const keep = lst.filter(e => !hasVigileCmd(e));
        n += lst.length - keep.length;
        if (d.hooks) d.hooks[key] = keep;
      }
      fs.writeFileSync(p, JSON.stringify(d, null, 2));
      return `移除 ${n} 条`;
    },
    status() {
      if (!fs.existsSync(cfg())) return "未检测到";
      const d = JSON.parse(fs.readFileSync(cfg(), "utf8"));
      const pre = (d.hooks && d.hooks.PreToolUse) || [];
      return pre.some(hasVigileCmd) ? "已安装" : "未安装";
    },
  };
}
REGISTRY.claude = makeCompat(".claude", "settings.json");
REGISTRY.codex = makeCompat(".codex", "hooks.json");

// ---------------------------------------------------------------- dsh：桥插件
function dshProfiles() {
  const root = home(".dsh", "profiles");
  if (!fs.existsSync(root)) return [];
  return fs.readdirSync(root).filter(n =>
    fs.existsSync(path.join(root, n, "cordis.patch.yml")));
}

REGISTRY.dsh = {
  detect: () => fs.existsSync(home(".dsh", "profiles")),
  install() {
    const profiles = dshProfiles();
    if (!profiles.length) return "未找到任何 dsh profile";
    let n = 0;
    for (const prof of profiles) {
      const p = path.join(home(".dsh"), "profiles", prof, "cordis.patch.yml");
      if (fs.readFileSync(p, "utf8").includes("dsh-hooks-claude-code")) continue;
      fs.appendFileSync(p, `- id: vigile-hooks-bridge\n  name: '@deepseek-ai/dsh-hooks-claude-code'\n  config:\n    configPath: ${home(".claude", "settings.json")}\n`);
      n++;
    }
    return `已在 ${n}/${profiles.length} 个 profile 挂载 hooks 桥（复用 Claude 配置）`;
  },
  uninstall() {
    let n = 0;
    for (const prof of dshProfiles()) {
      const p = path.join(home(".dsh"), "profiles", prof, "cordis.patch.yml");
      const lines = fs.readFileSync(p, "utf8").split("\n");
      const out = [];
      let skip = false;
      for (const line of lines) {
        if (line.startsWith("- id: vigile-hooks-bridge")) { skip = true; n++; continue; }
        if (skip && (line.startsWith("  ") || line.trim() === "")) continue;
        skip = false;
        out.push(line);
      }
      fs.writeFileSync(p, out.join("\n"));
    }
    return `已从 ${n} 处移除`;
  },
  status() {
    for (const prof of dshProfiles()) {
      const text = fs.readFileSync(path.join(home(".dsh"), "profiles", prof, "cordis.patch.yml"), "utf8");
      if (text.includes("dsh-hooks-claude-code")) return "已安装";
    }
    return "未安装";
  },
};

// ---------------------------------------------------------------- OpenCode：仅规则
REGISTRY.opencode = {
  detect: () => fs.existsSync(home(".config", "opencode")),
  install() {
    const dir = home(".config", "opencode");
    const p = path.join(dir, "AGENTS.md");
    fs.mkdirSync(dir, { recursive: true });
    const existing = fs.existsSync(p) ? fs.readFileSync(p, "utf8") : "";
    if (existing.includes("vigile run --")) return "规则已存在，跳过";
    fs.appendFileSync(p, "\n## vigile 规则（强制）\n\n所有内部系统调用必须用 `vigile run -- <命令>` 包装（简写 `vig`）。危险命令会被直接拒绝。\n");
    return "已写入 AGENTS.md 规则（OpenCode 无 hook 机制）";
  },
  uninstall() {
    const p = home(".config", "opencode", "AGENTS.md");
    if (!fs.existsSync(p)) return "配置不存在";
    const s = fs.readFileSync(p, "utf8");
    const idx = s.indexOf("## vigile 规则");
    if (idx < 0) return "未找到条目";
    fs.writeFileSync(p, s.slice(0, idx).trimEnd() + "\n");
    return "已移除规则";
  },
  status() {
    const p = home(".config", "opencode", "AGENTS.md");
    return fs.existsSync(p) && fs.readFileSync(p, "utf8").includes("vigile run --") ? "已写入规则" : "未安装";
  },
};

// ---------------------------------------------------------------- 入口
export function setupMain(args) {
  const agents = args.agent ? [].concat(args.agent) : [];
  const names = agents.includes("all") ? Object.keys(REGISTRY) : agents;

  if (args.list || (!args.install && !args.uninstall && !args.status)) {
    console.log("支持的 agent：");
    for (const [name, reg] of Object.entries(REGISTRY)) {
      const avail = reg.detect() ? "✅" : "❌ 未检测到";
      console.log(`  ${name.padEnd(12)} ${avail}  状态: ${reg.status()}`);
    }
    console.log("\n用法: vigile setup --install --agent claude --agent codex / --agent all");
    return 0;
  }
  if (!names.length) { console.error("请指定 --agent"); return 2; }
  if (args.status) {
    for (const n of names) console.log(`${n.padEnd(12)} ${REGISTRY[n].status()}`);
    return 0;
  }
  const action = args.install ? "install" : "uninstall";
  for (const n of names) {
    const reg = REGISTRY[n];
    if (!reg.detect()) { console.log(`[${n}] ❌ 未检测到该 agent 的配置目录，跳过`); continue; }
    try {
      console.log(`[${n}] ✅ ${reg[action]()}`);
    } catch (e) {
      console.log(`[${n}] ❌ 失败: ${e.message}`);
    }
  }
  return 0;
}
