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
import os from "node:os";
import path from "node:path";
import { spawnSync } from "node:child_process";
import { fileURLToPath } from "node:url";
import { evaluate } from "../src/engine.js";

const HERE = path.dirname(fileURLToPath(import.meta.url));
const VIGILE_SCRIPT = process.env.VIGILE_SCRIPT
  || path.join(path.dirname(HERE), "bin", "vigile.js");

const IS_POST = process.argv.includes("--post");
// 宿主能力模式（决定 hook 能做什么，见 decide() 里的降级分支）：
//   claude / zcode —— 支持 PreToolUse 的 updatedInput，可改写命令 → 完整审计
//   dsh            —— 桥不支持 updatedInput/additionalContext → 仅旁路记录意图 + deny
// 默认按环境推断；dsh 时通常会带 MULTICA_* 或 dsh 相关变量。
const MODE = process.env.VIGILE_HOOK_MODE
  || (process.env.CLAUDE_PROJECT_DIR && !process.env.ZCODE_PROJECT_DIR ? "claude"
    : process.env.DSH_PROFILE || process.env.DSH_HOME ? "dsh"
    : "zcode");

// 改写后的命令必须以一个可解析的命令开头，否则被拦截的命令会变成
// "command not found" —— 那等于是 hook 把用户的正常命令弄坏了。
// 优先用 `vig`（短，rtk 式手感）；PATH 上没有就退回 node + 绝对脚本路径，
// 两者都拿不到时返回空串，由调用方降级为旁路记录（并警告）。
// 探测结果落磁盘缓存（OS 临时目录）：hook 是每次调用新起的进程，
// 进程内缓存无效，每次 spawn `where` 又白付 ~50ms（rtk 同款思路）。
const PREFIX_CACHE = path.join(os.tmpdir(), "vigile-prefix.cache");
function vigilePrefix() {
  try {
    const hit = fs.readFileSync(PREFIX_CACHE, "utf8").trim();
    if (hit === "none") return "";
    if (hit && (hit === "vigile" || hit === "vig")) return hit;
  } catch { /* 无缓存则探测 */ }
  let found = "";
  const probe = process.platform === "win32" ? "where" : "which";
  for (const name of ["vig", "vigile"]) {
    const r = spawnSync(probe, [name], { encoding: "utf8", timeout: 2000, windowsHide: true });
    if (r.status === 0 && (r.stdout || "").trim()) { found = name; break; }
  }
  if (!found && fs.existsSync(VIGILE_SCRIPT)) {
    // PATH 上没有 shim 时退回绝对路径调用 —— 前缀要带引号（路径可能含空格）。
    found = "";
    writePrefixCache("abs");
    return `"${process.execPath}" "${VIGILE_SCRIPT}"`;
  }
  writePrefixCache(found || "none");
  return found;
}
function writePrefixCache(v) {
  try { fs.writeFileSync(PREFIX_CACHE, v); } catch { /* 缓存写不进就每次探测 */ }
}

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

function ask(reason, updatedInput) {
  const out = {
    hookEventName: "PreToolUse",
    permissionDecision: "ask",
    permissionDecisionReason: reason,
  };
  // 带上改写后，用户批准时执行的仍是 vigile run —— 否则命令按原样执行，
  // 审计库里只剩"曾经问过"，没有任何执行结果。
  if (updatedInput) out.updatedInput = updatedInput;
  process.stdout.write(JSON.stringify({ hookSpecificOutput: out }));
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
try{fs.appendFileSync(require("node:path").join(process.env.TEMP||"/tmp","vigile-hook-trace.log"),new Date().toISOString())}catch{}
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

  // 运行时判别宿主能力：dsh 的桥 payload 里 transcript_path 恒为空串
  // （Claude Code 会给真实路径）。同一份 settings.json 被两边共用，
  // 无法靠静态 VIGILE_HOOK_MODE 区分，必须在收到 payload 后判定。
  const hostMode = detectHostMode(payload);

  // 策略审核必须先于一切早退：拒绝判定与是否为"内部工具"无关。
  // 早退放在前面会让 rm -rf /、DROP TABLE 这类系统级危险命令直通。
  const parts = cmd.trim().split(/\s+/);
  const verdict = evaluate(parts[0] || "", parts, cmd);
  if (verdict.decision === "deny") {
    // 被拒也要留痕：命令不会执行，但"有人试图执行"是重要审计事实
    recordIntent(cmd, "denied", `[策略拒绝/${verdict.ruleId}] ${verdict.message}`, hostMode);
    deny(`[vigile 策略拒绝] ${verdict.message}${verdict.hint ? " 建议：" + verdict.hint : ""}`);
  }

  const prefix = vigilePrefix();
  const canRewrite = (hostMode === "claude" || hostMode === "zcode") && Boolean(prefix);
  const isComplex = COMPLEX.test(cmd);
  // 代理形态：vig kubectl version（rtk 式），比 "vigile run --quiet --" 短且自然。
  // 消毒（rtk 同款）：VIGILE_CONFIRM 会自动通过 ask 档确认，shell 环境里残留的
  // 值（rc 文件、.envrc、CI 注入）不得穿透到 hook 改写的命令 —— hook 本身会把
  // 命令转成显式 allow，等于这个通道放松了审批门，必须在改写时剥掉。
  const scrub = "env -u VIGILE_CONFIRM -u GATE_CONFIRM -u AUDIT_CONFIRM";
  const rewritten = `${scrub} ${prefix} ${cmd}`;

  // ask 档交给宿主弹确认：hook 自己无法交互，只能把判定转成宿主的"询问"。
  // 若同时能用改写，批准后弹出的命令仍是 vigile run —— 否则审计库里只剩
  // "曾经问过"，拿不到任何执行结果，等于批准后的调用完全没被审计。
  if (verdict.decision === "ask") {
    if (hostMode === "dsh") {
      recordIntent(cmd, "ok", `[需确认/${verdict.ruleId}] ${verdict.message}`, hostMode);
    } else {
      ask(`[vigile 需确认] ${verdict.message}${verdict.hint ? " 建议：" + verdict.hint : ""}`,
        canRewrite && !isComplex ? { ...input, command: rewritten } : null);
    }
  }

  // 复合命令无法安全改写或精确判定，但其首段仍要过 deny 检查（已在上面完成）。
  if (isComplex) return process.exit(0);
  if (!needsGate(cmd)) return process.exit(0);

  // 两种宿主能力，逐级降级：
  //   claude / zcode —— 支持 PreToolUse 的 updatedInput，改写为 vig 代理后
  //                     由主程序完整审计（含真实 exit_code / 耗时 / 输出摘要）。
  //   dsh            —— 桥不支持 updatedInput（官方 README 明确：logged + warned
  //                     but not honored），也忽略 additionalContext；只能由 hook
  //                     自己旁路记录"意图"，且拿不到执行结果。
  if (canRewrite) {
    process.stdout.write(JSON.stringify({
      hookSpecificOutput: {
        hookEventName: "PreToolUse",
        permissionDecision: "allow",
        permissionDecisionReason: "vigile auto-wrap",
        updatedInput: { ...input, command: rewritten },
      },
    }));
  } else {
    // fail-open，但不静默：拿不到可执行前缀时命令照原样执行（审计降级为
    // 意图记录）。静默放行会让用户以为"还在被审计"，stderr 警告一次。
    process.stderr.write("[vigile] 警告：vigile 不在 PATH 上且脚本不可达，本次命令不经完整审计（仅记意图）。\n");
    recordIntent(cmd, "ok", null, hostMode);
  }
  process.exit(0);
}

/** 运行时判别宿主能力。
 *  dsh 桥的 payload 特性（官方 README）：transcript_path 恒为空串、
 *  且不带 permission_mode / prompt_id。Claude Code 会给真实路径。
 *  返回 "claude"（可改写）或 "dsh"（只能旁路记录）。 */
function detectHostMode(payload) {
  if (process.env.VIGILE_HOOK_MODE === "dsh") return "dsh";
  if (process.env.VIGILE_HOOK_MODE === "zcode") return "zcode";
  // 显式指定 claude 也要复核：dsh 复用同一份 settings.json
  if (payload && payload.transcript_path === "") return "dsh";
  if (MODE === "claude") return "claude";
  return MODE;
}

/** 旁路记录：宿主不支持命令改写时，由 hook 直接写入审计库。 */
function recordIntent(cmd, status, error, host) {
  try {
    const parts = cmd.trim().split(/\s+/);
    spawnSync(process.execPath, [VIGILE_SCRIPT, "call",
      "--source", "hook",
      "--tool", baseName(parts[0] || "unknown"),
      "--action", parts[1] || "",
      "--category", "other",
      "--status", status,
      "--duration", "0",
      "--risk", "unknown",
      "--args", JSON.stringify({ argv: parts, mode: MODE }),
      "--meta", JSON.stringify({ source: "hook-bypass", host: host || MODE }),
      ...(error ? ["--error", error] : []),
    ], { timeout: 5000, stdio: "ignore" });
  } catch { /* 审计失败绝不影响主流程 */ }
}
