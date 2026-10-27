#!/usr/bin/env node
// vigile PreToolUse / PostToolUse hook
//
// 切 Node 的核心收益：hook 直接 import 策略引擎与规则表 ——
// 与主程序共用同一份实现，不会再出现"主程序认识某工具而 hook 不认识"的逻辑漂移，
// 且策略判定从"spawn 子进程 250ms"降为进程内函数调用（~1ms）。
//
// 用法:
//   node vigile-hook.js            # PreToolUse（Bash 拦截/改写）
//   node vigile-hook.js --post     # PostToolUse（Edit/Write 文件变更 diff）
//   VIGILE_HOOK_MODE=claude        # Claude 系（支持 updatedInput 改写）；默认 zcode（仅提醒+deny）

import fs from "node:fs";
import path from "node:path";
import { spawnSync } from "node:child_process";
import { fileURLToPath } from "node:url";
import { evaluate } from "../src/engine.js";

const HERE = path.dirname(fileURLToPath(import.meta.url));
const VIGILE_SCRIPT = process.env.VIGILE_SCRIPT
  || path.join(path.dirname(HERE), "bin", "vigile.js");

const IS_POST = process.argv.includes("--post");
const MODE = process.env.VIGILE_HOOK_MODE
  || (process.env.CLAUDE_PROJECT_DIR && !process.env.ZCODE_PROJECT_DIR ? "claude" : "zcode");

// ---------------------------------------------------------------- 需审计的工具
const AUDIT_TOOLS = new Set([
  "log-query", "online-log-query",
  "bigdata-query", "dbq", "redash", "psql", "mysql", "clickhouse-client",
  "shandian", "mongosh", "mongo", "mongoexport",
  "jira", "jira-transition", "jira_transition",
  "goods-center", "order-center", "knowledge-base", "workflow-debug",
  "agentos", "client-log-fetch", "grafana-cli",
  "kubectl", "helm",
]);
const AUDIT_SCRIPTS = /(?:^|[/\\])(ticket_intake|jira|jira_transition|dialog_query|order_center|prometheus|redash|glab|agentos_execution|kb_\w+|badcase_ticket)\.py$/i;
const COMPLEX = /[|;&><`]|\$\(|\|\||&&/;

function firstToken(cmd) {
  const trimmed = cmd.trim();
  if (!trimmed) return "";
  const parts = trimmed.split(/\s+/);
  let i = 0;
  while (i < parts.length && /^[A-Za-z_][A-Za-z0-9_]*=/.test(parts[i])) i++;
  return parts[i] || "";
}

function baseName(token) {
  return token.replace(/^["']|["']$/g, "").split(/[/\\]/).pop().toLowerCase().replace(/\.exe$/, "");
}

function needsGate(cmd) {
  const tok = firstToken(cmd);
  if (!tok) return false;
  const base = baseName(tok);
  if (base === "vigile" || base === "vig") return false;   // 已过闸
  if (base === "rtk") {
    const after = cmd.trim().split(/\s+/).slice(1);
    return after.length ? AUDIT_TOOLS.has(baseName(after[0])) : false;
  }
  if (AUDIT_TOOLS.has(base)) return true;
  if (base === "python" || base === "python3") {
    const m = cmd.match(/python3?\s+(?:"[^"]+"|'[^']+'|\S+)/);
    if (m && AUDIT_SCRIPTS.test(m[0])) return true;
  }
  return false;
}

function deny(reason) {
  process.stdout.write(JSON.stringify({
    hookSpecificOutput: {
      hookEventName: "PreToolUse",
      permissionDecision: "deny",
      permissionDecisionReason: reason,
    },
  }));
  process.exit(0);
}

// ---------------------------------------------------------------- PostToolUse：文件变更 diff
function diffLines(before, after) {
  const a = String(before || "").split("\n");
  const b = String(after || "").split("\n");
  if (a.length * b.length > 4000000) {
    return { text: "（文件较大，diff 省略）", added: b.length, removed: a.length };
  }
  const n = a.length, m = b.length;
  const dp = Array.from({ length: n + 1 }, () => new Uint32Array(m + 1));
  for (let i = n - 1; i >= 0; i--) {
    for (let j = m - 1; j >= 0; j--) {
      dp[i][j] = a[i] === b[j] ? dp[i + 1][j + 1] + 1 : Math.max(dp[i + 1][j], dp[i][j + 1]);
    }
  }
  const out = [];
  let added = 0, removed = 0, i = 0, j = 0;
  while (i < n && j < m) {
    if (a[i] === b[j]) { out.push(" " + b[j]); i++; j++; }
    else if (dp[i + 1][j] >= dp[i][j + 1]) { out.push("-" + a[i]); removed++; i++; }
    else { out.push("+" + b[j]); added++; j++; }
  }
  while (i < n) { out.push("-" + a[i++]); removed++; }
  while (j < m) { out.push("+" + b[j++]); added++; }
  return { text: out.slice(0, 200).join("\n").slice(0, 4000), added, removed };
}

function handlePostToolUse(payload) {
  const ti = payload.tool_input || {};
  const filePath = ti.file_path || ti.notebook_path;
  if (!filePath) return;
  let after = null;
  try { after = fs.readFileSync(filePath, "utf8"); } catch { return; }

  let before = null;
  if (payload.tool_name === "Edit" && ti.new_string && after.includes(ti.new_string)) {
    before = after.replace(ti.new_string, ti.old_string || "");
  }
  spawnSync(process.execPath, [VIGILE_SCRIPT, "call-file-change",
    "--file", filePath,
    "--op", payload.tool_name === "Write" ? "write" : "edit",
    "--before", before || "",
    "--after", after], { timeout: 4000, stdio: "ignore" });
}

// ---------------------------------------------------------------- 主流程
let buf = "";
process.stdin.setEncoding("utf8");
process.stdin.on("data", d => { buf += d; });
process.stdin.on("end", () => decide(buf));
process.stdin.on("error", () => process.exit(0));
const guard = setTimeout(() => process.exit(0), 4000);

function decide(raw) {
  clearTimeout(guard);
  let payload = {};
  try { payload = JSON.parse(raw); } catch { return process.exit(0); }

  if (IS_POST || payload.hook_event_name === "PostToolUse" || payload.event === "PostToolUse") {
    try { handlePostToolUse(payload); } catch { /* 永不影响主流程 */ }
    return process.exit(0);
  }

  if ((payload.tool_name || "") !== "Bash") return process.exit(0);
  const input = payload.tool_input || {};
  const cmd = input.command || "";
  if (!cmd) return process.exit(0);
  if (COMPLEX.test(cmd)) return process.exit(0);
  if (!needsGate(cmd)) return process.exit(0);

  // 策略审核：直接调用共享引擎（进程内，~1ms）
  const parts = cmd.trim().split(/\s+/);
  const verdict = evaluate(parts[0] || "", parts, cmd);
  if (verdict.decision === "deny") {
    deny(`[vigile 策略拒绝] ${verdict.message}${verdict.hint ? " 建议：" + verdict.hint : ""}`);
  }

  const rewritten = `vigile run --quiet -- ${cmd}`;
  if (MODE === "claude") {
    process.stdout.write(JSON.stringify({
      hookSpecificOutput: {
        hookEventName: "PreToolUse",
        permissionDecision: "allow",
        permissionDecisionReason: "vigile auto-wrap",
        updatedInput: { ...input, command: rewritten },
      },
    }));
  } else {
    process.stdout.write(JSON.stringify({
      hookSpecificOutput: {
        hookEventName: "PreToolUse",
        permissionDecision: "allow",
        additionalContext: `[vigile] 该命令访问内部系统但未包装。请改用：${rewritten}`,
      },
    }));
  }
  process.exit(0);
}
