// vigile 策略引擎 + 推断层 —— 主程序与 hook 共享的唯一实现。
// 回退 Go 时本层语义需整体翻译；所有函数均为纯函数（除 blastRadius 读文件系统）。

import fs from "node:fs";
import path from "node:path";
import { execFileSync } from "node:child_process";
import { readFileSync } from "node:fs";
import { redact } from "./core.js";

// ---------------------------------------------------------------- 默认规则（与 Python 版对齐）
export const DEFAULT_DENY_RULES = [
  { id: "rm_recursive", pattern: /\brm\s+(-[a-zA-Z]*r[a-zA-Z]*f?|--recursive)\b/,
    message: "禁止递归删除（rm -r / rm -rf）。该操作不可逆，可能删除大量数据。",
    hint: "确需删除请逐个文件操作，或先 mv 到备份目录。" },
  { id: "rm_force_recursive", pattern: /\brm\s+-[a-zA-Z]*f[a-zA-Z]*r/,
    message: "禁止强制递归删除（rm -fr）。",
    hint: "同上：避免递归，先确认目标路径。" },
  { id: "system_power", pattern: /\b(shutdown|reboot|halt|poweroff)\b/,
    message: "禁止关停/重启系统。会中断所有服务与正在运行的排查任务。",
    hint: "如需重启服务，用进程管理或编排工具重启单个服务。" },
  { id: "mkfs", pattern: /\bmkfs(\.\w+)?\b/,
    message: "禁止格式化磁盘。会清空整个分区数据。",
    hint: "格式化是不可恢复操作，需人工在控制台执行并二次确认。" },
  { id: "dd_to_device", pattern: /\bdd\s+if=.*of=\/dev/,
    message: "禁止用 dd 直接写块设备。可能覆盖引导或分区表。",
    hint: "写镜像请用专用工具并明确目标文件。" },
  { id: "redirect_to_disk", pattern: />\s*\/dev\/sd[a-z]/,
    message: "禁止直接重定向写入磁盘设备。",
    hint: "确认要写的是文件而不是设备节点。" },
  { id: "delete_without_where", pattern: /\bdelete\s+from\s+\S+\s*$/i,
    message: "禁止无 WHERE 条件的 DELETE。会清空整张表。",
    hint: "加上 WHERE 精确限定范围；先 SELECT 确认影响行数。" },
  { id: "update_without_where", pattern: /\bupdate\s+\S+\s+set\b(?![^;]*\bwhere\b)[^;]*$/i,
    message: "禁止无 WHERE 条件的 UPDATE。会改写整张表。",
    hint: "加上 WHERE 限定范围；先 SELECT 验证条件命中行数。" },
  { id: "drop_object", pattern: /\bdrop\s+(table|database|index|column)\b/i,
    message: "禁止 DROP 表/库/索引/列。对象与数据将被永久删除。",
    hint: "结构性变更走变更流程；先备份。" },
  { id: "truncate", pattern: /\btruncate\s+(table\s+)?\S+/i,
    message: "禁止 TRUNCATE。整表数据会被清空且通常不可回滚。",
    hint: "用带条件的 DELETE 分批清理。" },
  { id: "alter_drop", pattern: /\balter\s+table\s+\S+\s+drop\b/i,
    message: "禁止 ALTER TABLE ... DROP。会删除列或约束。",
    hint: "结构变更应走迁移脚本与评审。" },
  { id: "grant_all", pattern: /\bgrant\s+all\b/i,
    message: "禁止 GRANT ALL。会导致权限过度放大。",
    hint: "按最小权限原则逐项授权。" },
  { id: "redis_flushall", pattern: /\bflushall\b/i,
    message: "禁止 FLUSHALL。会清空整个 Redis 实例的所有库。",
    hint: "按 key 精确删除。" },
  { id: "fsck", pattern: /\bfsck\b/i,
    message: "禁止 fsck。运行中可能损坏文件系统。",
    hint: "文件系统检查需停机并在控制台执行。" },
];

export const DEFAULT_ASK_RULES = [
  { id: "delete_with_where", pattern: /\bdelete\s+from\b/i,
    message: "即将执行 DELETE。请确认 WHERE 条件与影响行数。",
    hint: "先跑同条件 SELECT COUNT(*) 确认范围。" },
  { id: "update_statement", pattern: /\bupdate\s+\S+\s+set\b/i,
    message: "即将执行 UPDATE。请确认 WHERE 条件与字段。",
    hint: "先 SELECT 出目标行，确认无误再更新。" },
  { id: "insert_statement", pattern: /\binsert\s+into\b/i,
    message: "即将写入数据。请确认表名与字段。",
    hint: "确认不是误写到生产库。" },
  { id: "kubectl_destructive", pattern: /\bkubectl\s+(delete|scale|rollout\s+undo)\b/i,
    message: "即将执行 kubectl 破坏性操作（delete/scale/rollout undo）。",
    hint: "确认 namespace 与目标资源。" },
  { id: "helm_uninstall", pattern: /\bhelm\s+(uninstall|rollback)\b/i,
    message: "即将卸载或回滚 Helm release。",
    hint: "确认 release 名称与目标环境。" },
  { id: "git_force_push", pattern: /\bgit\s+push\s+--force\b/i,
    message: "即将强制推送，会覆盖远端历史。",
    hint: "优先用 --force-with-lease；确认不是共享分支。" },
  { id: "git_reset_hard", pattern: /\bgit\s+reset\s+--hard\b/i,
    message: "即将丢弃工作区未提交改动。",
    hint: "先 git stash 或确认无需保留。" },
  { id: "docker_remove", pattern: /\bdocker\s+(rm|rmi)\b/i,
    message: "即将删除容器或镜像。",
    hint: "确认容器不是运行中服务。" },
];

// ---------------------------------------------------------------- 规则加载（含用户覆盖/追加/旧格式兼容）
function normalizeRule(raw, index) {
  if (typeof raw === "string") {
    if (!raw) return null;
    return { id: `rule_${index}`, pattern: new RegExp(raw),
      message: `命中危险模式：${raw}`, hint: "" };
  }
  if (raw && typeof raw === "object" && raw.pattern) {
    return { id: String(raw.id || `rule_${index}`),
      pattern: new RegExp(raw.pattern),
      message: String(raw.message || `命中危险模式：${raw.pattern}`),
      hint: String(raw.hint || "") };
  }
  return null;
}

let _policy = undefined;

export function loadPolicy(force = false) {
  if (_policy !== undefined && !force) return _policy;
  let deny = DEFAULT_DENY_RULES.map(r => ({ ...r }));
  let ask = DEFAULT_ASK_RULES.map(r => ({ ...r }));
  const allowTools = [], denyTools = [];
  const p = policyFile();
  if (fs.existsSync(p)) {
    try {
      const user = JSON.parse(readFileSync(p, "utf8"));
      for (const [key, bucket] of [["deny", deny], ["ask", ask]]) {
        (user[key] || []).forEach((raw, i) => {
          const rule = normalizeRule(raw, i);
          if (!rule) return;
          const j = bucket.findIndex(r => r.id === rule.id);
          if (j >= 0) bucket[j] = rule; else bucket.push(rule);
        });
      }
      if (Array.isArray(user.allow_tools)) allowTools.push(...user.allow_tools.map(String.toLowerCase));
      if (Array.isArray(user.deny_tools)) denyTools.push(...user.deny_tools.map(String.toLowerCase));
    } catch { /* 配置损坏退回默认，内置危险规则仍生效 */ }
  }
  _policy = { deny, ask, allowTools, denyTools };
  return _policy;
}

import { policyPath } from "./core.js";
function policyFile() { return policyPath(); }

// ---------------------------------------------------------------- 判定
export function evaluate(tool, argv, argsText) {
  const base = path.basename(String(tool)).toLowerCase().replace(/\.exe$/, "");
  const policy = loadPolicy();
  const text = argsText || argv.join(" ");

  if (policy.allowTools.includes(base)) {
    return { decision: "allow", ruleId: `allow_tools:${base}`, message: "", hint: "" };
  }
  if (policy.denyTools.includes(base)) {
    return { decision: "deny", ruleId: `deny_tools:${base}`,
      message: `工具「${base}」已被列入禁用名单。`,
      hint: "如需使用，从 policy.json 的 deny_tools 移除。" };
  }
  for (const rule of policy.deny) {
    const m = rule.pattern.exec(text);
    if (m) return hit(rule, "deny", base, text, m);
  }
  for (const rule of policy.ask) {
    const m = rule.pattern.exec(text);
    if (m) return hit(rule, "ask", base, text, m);
  }
  return { decision: "allow", ruleId: "default", message: "", hint: "" };
}

function hit(rule, decision, tool, text, m) {
  const match = (m && m[0]) ? m[0].slice(0, 120) : "";
  const msg = String(rule.message)
    .replaceAll("{tool}", tool)
    .replaceAll("{command}", text.slice(0, 200))
    .replaceAll("{match}", match);
  return { decision, ruleId: rule.id, message: msg, hint: rule.hint || "", match };
}

// ---------------------------------------------------------------- 工具分类/风险推断
const DEFAULT_TOOL_CATEGORY = {
  kubectl: "k8s", helm: "k8s", docker: "k8s",
  psql: "sql", mysql: "sql", sqlite3: "sql", "clickhouse-client": "sql",
  mongo: "mongo", mongosh: "mongo", mongoexport: "mongo",
  git: "git", glab: "git", gh: "git",
  curl: "http", wget: "http",
  jq: "file", grep: "file", cat: "file", less: "file", tail: "file",
};
const WRITE_HINTS = /\b(create|update|delete|drop|truncate|insert|alter|restart|publish|transition|modify|add-comment|worklog|apply|push|merge|set|patch|put|post)\b/i;

let _rules = undefined;
export function loadRules(force = false) {
  if (_rules !== undefined && !force) return _rules;
  const merged = { tools: { ...DEFAULT_TOOL_CATEGORY }, write: {}, readOnly: [] };
  const p = rulesFile();
  if (fs.existsSync(p)) {
    try {
      const user = JSON.parse(readFileSync(p, "utf8"));
      Object.assign(merged.tools, user.tools || {});
      merged.write = user.write || {};
      merged.readOnly = (user.read_only || []).map(String.toLowerCase);
    } catch { /* 坏配置退默认 */ }
  }
  _rules = merged;
  return merged;
}

import { rulesPath } from "./core.js";
function rulesFile() { return rulesPath(); }

export function inferCategory(tool, args = "") {
  const base = path.basename(String(tool)).toLowerCase().replace(/\.exe$/, "");
  const tools = loadRules().tools;
  if (tools[base]) return tools[base];
  if (base.endsWith(".py")) return tools[base.slice(0, -3)] || "other";
  const joined = `${base} ${args}`.toLowerCase();
  if (/mongo|\$set|find\(/.test(joined)) return "mongo";
  if (/\b(select|insert|update|delete|explain|desc)\b/.test(joined)) return "sql";
  if (/\b(kubectl|k8s|deployment|pod)\b/.test(joined)) return "k8s";
  return "other";
}

export function inferRisk(tool, args = "") {
  const base = path.basename(String(tool)).toLowerCase().replace(/\.exe$/, "");
  const rules = loadRules();
  if (rules.readOnly.includes(base)) return "read";
  const words = rules.write[base];
  if (words && new RegExp(`\\b(${words.map(w => w.replace(/[.*+?^${}()|[\]\\]/g, "\\$&")).join("|")})\\b`, "i").test(args || "")) return "write";
  if (/\b(insert|update|delete|drop|truncate|alter)\b/i.test(args || "")) return "write";
  if (WRITE_HINTS.test(args || "")) return "write";
  return "read";
}

// ---------------------------------------------------------------- blast radius
function safeRun(cmd, cwd) {
  try {
    return execFileSync(cmd[0], cmd.slice(1), { encoding: "utf8", timeout: 5000, cwd });
  } catch { return null; }
}

export function msysPath(p) {
  if (process.platform !== "win32" || !p.startsWith("/")) return p;
  if (p.startsWith("/tmp/") || p === "/tmp") {
    return path.join(process.env.TEMP || "/tmp", p.length > 5 ? p.slice(5) : "");
  }
  if (p.startsWith("/var/tmp/")) {
    return path.join(process.env.TEMP || "/tmp", p.slice(9));
  }
  const m = /^\/([a-zA-Z])\/(.*)$/.exec(p);
  if (m) return `${m[1].toUpperCase()}:/${m[2]}`;
  return p;
}

export function blastRadius(argv) {
  const text = argv.join(" ");
  try {
    if (/\brm\s+(-[a-zA-Z]*r[a-zA-Z]*f?|--recursive)\b/.test(text)) return rmImpact(argv);
    if (/git\s+push\s+.*(--force\b|-f\b|\+\S+)/.test(text)) return gitPushForceImpact();
    if (/git\s+reset\s+--hard/.test(text)) return gitResetImpact();
    const m = /\b(drop|truncate)\s+(table\s+)?(\S+)/i.exec(text);
    if (m) return `目标对象：${m[3]}（数据将永久丢失）`;
  } catch { return null; }
  return null;
}

function rmImpact(argv) {
  const targets = argv.slice(1).filter(a => !a.startsWith("-") && !a.startsWith("$")).map(msysPath);
  if (!targets.length) return null;
  let files = 0, size = 0; const shown = [];
  for (const t of targets) {
    try {
      const st = fs.statSync(t);
      if (st.isDirectory()) {
        for (const root of [t]) {
          walk(root, f => { files++; size += fs.statSync(f).size; if (shown.length < 5) shown.push(f); });
        }
      } else { files++; size += st.size; shown.push(t); }
    } catch { /* 目标不存在 */ }
  }
  if (!files) return null;
  const sizeH = size < 1024 * 1024 ? `${(size / 1024).toFixed(0)} KB` : `${(size / 1048576).toFixed(1)} MB`;
  let out = `将删除 ${files} 个文件，共约 ${sizeH}`;
  if (shown.length) out += `\n  示例：${shown.slice(0, 3).join("\n        ")}`;
  return out;
}

function walk(dir, cb) {
  let entries;
  try { entries = fs.readdirSync(dir, { withFileTypes: true }); } catch { return; }
  for (const e of entries) {
    const p = path.join(dir, e.name);
    if (e.isDirectory()) walk(p, cb); else cb(p);
  }
}

function gitPushForceImpact() {
  const branch = safeRun(["git", "rev-parse", "--abbrev-ref", "HEAD"]);
  if (!branch) return null;
  const b = branch.trim();
  const ahead = safeRun(["git", "rev-list", "--count", `origin/${b}..HEAD`]);
  const behind = safeRun(["git", "rev-list", "--count", `HEAD..origin/${b}`]);
  if (ahead === null || behind === null) return null;
  const parts = [`分支 ${b}`];
  const behindN = parseInt(behind) || 0, aheadN = parseInt(ahead) || 0;
  if (behindN) {
    parts.push(`远端领先的 ${behindN} 个提交将被覆盖丢弃`);
    const dropped = safeRun(["git", "log", "--oneline", "-3", `HEAD..origin/${b}`]);
    if (dropped) for (const line of dropped.trim().split("\n").slice(0, 3)) parts.push(`  丢弃: ${line}`);
  }
  if (aheadN) parts.push(`本地待推送 ${aheadN} 个提交`);
  return parts.join("\n");
}

function gitResetImpact() {
  const status = safeRun(["git", "status", "--porcelain"]);
  if (!status) return null;
  const lines = status.trim().split("\n").filter(Boolean);
  if (!lines.length) return null;
  let out = `将丢弃 ${lines.length} 个未提交改动：`;
  for (const l of lines.slice(0, 5)) out += `\n  ${l.trim()}`;
  if (lines.length > 5) out += `\n  … 共 ${lines.length} 个`;
  return out;
}

export { redact };
