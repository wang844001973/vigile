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
//   node vigile-hook.js --mode claude   # Claude 系（支持 updatedInput 改写）
//   node vigile-hook.js --mode dsh      # dsh 桥（仅旁路记录）
//   不传则按环境推断，默认 zcode

import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import { spawnSync } from "node:child_process";
import { fileURLToPath } from "node:url";
import { evaluate, inferCategory, inferRisk } from "../src/engine.js";

const HERE = path.dirname(fileURLToPath(import.meta.url));
const VIGILE_SCRIPT = process.env.VIGILE_SCRIPT
  || path.join(path.dirname(HERE), "bin", "vigile.js");

const IS_POST = process.argv.includes("--post");
// 宿主能力模式（决定 hook 能做什么，见 decide() 里的降级分支）：
//   claude / zcode —— 支持 PreToolUse 的 updatedInput，可改写命令 → 完整审计
//   dsh            —— 桥不支持 updatedInput/additionalContext → 仅旁路记录意图 + deny
// 优先取 --mode 参数：Windows 的 cmd.exe 不认 `VAR=value cmd` 前缀，把模式
// 塞进环境变量会让 hook 整条失效（而且错误被吞掉）。参数形式跨 shell 通用。
const ARG_MODE = (() => {
  const i = process.argv.indexOf("--mode");
  return i >= 0 ? process.argv[i + 1] : "";
})();
const MODE = process.env.VIGILE_HOOK_MODE || ARG_MODE
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

// 全量审计模式（rules.json: audit_mode = "all" | "whitelist"，默认 all）：
// 白名单外的命令也旁路记一条意图，做到"任何终端调用都有记录"。
// 噪声名单（rules.json: noise 数组）是高频纯只读命令——记它们只会把库
// 灌满，默认排除；置空数组 [] 即可全记。
function loadRulesJson() {
  try {
    return JSON.parse(fs.readFileSync(
      path.join(os.homedir(), ".vigile", "rules.json"), "utf8"));
  } catch { return {}; }
}
function auditMode() {
  return loadRulesJson().audit_mode === "whitelist" ? "whitelist" : "all";
}
function isNoise(cmd) {
  const noise = loadRulesJson().noise;
  if (!Array.isArray(noise)) return DEFAULT_NOISE.has(baseName(firstToken(cmd) || ""));
  if (!noise.length) return false;                    // 置空 = 全记
  return noise.map(s => String(s).toLowerCase()).includes(baseName(firstToken(cmd) || ""));
}
const DEFAULT_NOISE = new Set(["ls", "pwd", "cat", "head", "tail", "grep", "find",
  "which", "where", "whoami", "date", "echo", "wc", "stat", "file", "du", "df",
  // 管道里的文本处理段：`... | tr -d '\r'` 这类只是格式化输出，不是调用本身
  "tr", "sed", "awk", "cut", "sort", "uniq", "xargs", "tee", "jq", "column", "iconv"]);

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
    // 归属到真正违规的命令段，而不是整条复合命令的首段。
    // 否则 `cd /tmp && rm -rf x` 会被记成"cd 被拒绝"，看日志的人一头雾水。
    const culprit = culpritOf(cmd, verdict);
    recordIntent(cmd, "denied",
      `[策略拒绝/${verdict.ruleId}] ${verdict.message}`, hostMode,
      { tool: culprit.tool, action: culprit.action, target: culprit.target,
        fullCommand: cmd, attributed: true });
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

  // 复合命令（含 | & > < ; && ||）不能改写成 `vig <整条命令>` —— 那会让管道
  // 作用在 vigile 上，破坏原语义。但"不改写"绝不等于"不记录"：
  // 曾经这里直接 return，导致 `shandian ... 2>&1 | tr -d '\r'` 这类带管道的
  // 内部调用完全不留审计痕迹（真实漏审事故）。现在改为逐段记录后放行。
  if (isComplex) {
    recordComplex(cmd, hostMode);
    return process.exit(0);
  }

  // 全量审计：白名单只决定"是否改写拿到完整结果"；记录面默认覆盖一切命令
  // （rules.json 的 audit_mode=all）。噪声名单（ls/cat/pwd 等高频只读）可关。
  // 白名单外不改写 → 旁路记一条意图，命令照原样执行，行为零影响。
  if (!needsGate(cmd)) {
    if (auditMode() === "all" && !isNoise(cmd)) recordIntent(cmd, "ok", null, hostMode);
    return process.exit(0);
  }

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
  // MODE 已含 --mode 参数（Windows 下靠参数而非环境变量传宿主）
  if (MODE === "dsh") return "dsh";
  if (MODE === "zcode") return "zcode";
  // 显式指定 claude 也要复核：dsh 复用同一份 settings.json
  if (payload && payload.transcript_path === "") return "dsh";
  if (MODE === "claude") return "claude";
  return MODE;
}

/** 在一整条命令里定位真正触发策略的那一段。
 *  复合命令 `cd /tmp && rm -rf x` 的首段是 cd，但违规的是 rm -rf；
 *  审计里必须记 rm，否则"cd 被拒绝"这类记录会彻底误导排查。
 *  依据 verdict.match（引擎已返回的正则命中片段）在命令中定位，
 *  取该片段所在的那一个 shell 段。 */
function culpritOf(cmd, verdict) {
  const fallback = { tool: baseName(firstToken(cmd) || "unknown"),
    action: cmd.trim().split(/\s+/)[1] || "", target: "" };
  const match = (verdict && verdict.match) ? String(verdict.match).trim() : "";
  if (!match) return fallback;
  const at = cmd.indexOf(match);
  if (at < 0) return fallback;

  // 按 shell 分隔符切段（&& || ; | 换行），保留各段起止位置
  const segs = [];
  let start = 0;
  for (let i = 0; i < cmd.length; i++) {
    const two = cmd.slice(i, i + 2);
    if (two === "&&" || two === "||") { segs.push([start, i]); i++; start = i + 1; }
    else if (cmd[i] === ";" || cmd[i] === "|" || cmd[i] === "\n") { segs.push([start, i]); start = i + 1; }
  }
  segs.push([start, cmd.length]);

  const seg = segs.find(([a, b]) => at >= a && at < b);
  if (!seg) return fallback;
  const text = cmd.slice(seg[0], seg[1]).trim();
  if (!text) return fallback;
  const toks = text.split(/\s+/).map(t => t.replace(/^["']|["']$/g, ""));
  const tool = baseName(toks[0] || "unknown");
  return {
    tool,
    action: toks[1] || "",
    // target：动作之后的第一个非选项参数（rm -rf /tmp/x → /tmp/x）
    target: (toks.slice(2).find(t => t && !t.startsWith("-")) || "").slice(0, 200),
  };
}

/** 复合命令的审计：不改写（保持管道/重定向语义），但逐段记录内部工具调用。
 *  `shandian lane service-detail ... 2>&1 | tr -d '\r'` 必须留下 shandian 的痕迹，
 *  否则带管道的调用整类是审计盲区。只记"值得记"的段：
 *    内部工具（白名单）→ 必记
 *    audit_mode=all 时的其他命令 → 记（噪声名单除外）
 *  纯文本处理段（tr/grep/head/sort/awk 等）→ 当噪声跳过
 *  meta 里保留整条命令，便于还原上下文。 */
function recordComplex(cmd, host) {
  const segs = splitSegments(cmd);
  const full = cmd.slice(0, 1000);
  const rows = [];
  for (const text of segs) {
    const trimmed = text.trim();
    if (!trimmed) continue;
    const tok = firstToken(trimmed);
    if (!tok) continue;
    const base = baseName(tok);
    // 跳过段内的纯 shell 关键字与非命令段
    if (["for", "do", "done", "if", "then", "else", "fi", "while", "export", "set"].includes(base)) continue;

    const gated = needsGate(trimmed);
    if (!gated && (auditMode() !== "all" || isNoise(trimmed))) continue;

    const toks = trimmed.split(/\s+/).map(t => t.replace(/^["']|["']$/g, ""));
    rows.push({
      source: "hook", status: "ok", duration: 0,
      tool: base,
      action: toks[1] || "",
      target: (toks.slice(2).find(t => t && !t.startsWith("-")) || "").slice(0, 200),
      category: inferCategory(base, trimmed),
      risk: inferRisk(base, trimmed),
      args: JSON.stringify({ argv: toks, mode: MODE }),
      meta: JSON.stringify({ source: "hook-bypass", host: host || MODE,
        segment: trimmed.slice(0, 500), full_command: full }),
    });
    if (rows.length >= 20) break;   // 防御：超长命令不无限记
  }
  // 一条都没匹配上但整条命令里含内部工具（例如工具在管道后被 shell 包裹）→ 记整条
  if (!rows.length && needsGate(cmd)) {
    rows.push({
      source: "hook", status: "ok", duration: 0,
      tool: baseName(firstToken(cmd) || "unknown"),
      action: "", category: inferCategory(firstToken(cmd) || "", cmd),
      risk: inferRisk(firstToken(cmd) || "", cmd),
      args: JSON.stringify({ argv: cmd.trim().split(/\s+/), mode: MODE }),
      meta: JSON.stringify({ source: "hook-bypass", host: host || MODE, full_command: full }),
    });
  }
  if (!rows.length) return;
  // 批量写入：一次进程落 N 条（逐条 spawn 在长管道上会撞 4s 守护超时）
  try {
    spawnSync(process.execPath, [VIGILE_SCRIPT, "call-batch",
      "--records", JSON.stringify(rows)], { timeout: 3000, stdio: "ignore" });
  } catch { /* 审计失败绝不影响主流程 */ }
}

/** 按 shell 分隔符切段：&& || ; | 换行。重定向（2>&1、>）留在段内不切。 */
function splitSegments(cmd) {
  const segs = [];
  let start = 0;
  for (let i = 0; i < cmd.length; i++) {
    const two = cmd.slice(i, i + 2);
    if (two === "&&" || two === "||") { segs.push(cmd.slice(start, i)); i++; start = i + 1; }
    else if (cmd[i] === ";" || cmd[i] === "|" || cmd[i] === "\n") { segs.push(cmd.slice(start, i)); start = i + 1; }
  }
  segs.push(cmd.slice(start));
  return segs;
}

/** 旁路记录：宿主不支持命令改写时，由 hook 直接写入审计库。
 *  override 允许把记录归属到具体违规段（见 culpritOf）。 */
function recordIntent(cmd, status, error, host, override) {
  try {
    const parts = cmd.trim().split(/\s+/);
    const tool = (override && override.tool) || baseName(parts[0] || "unknown");
    spawnSync(process.execPath, [VIGILE_SCRIPT, "call",
      "--source", "hook",
      "--tool", tool,
      "--action", (override && override.action !== undefined) ? override.action : (parts[1] || ""),
      "--category", inferCategory(tool, cmd),
      "--status", status,
      "--duration", "0",
      "--risk", inferRisk(tool, cmd),
      ...((override && override.target) ? ["--target", override.target] : []),
      "--args", JSON.stringify({ argv: parts, mode: MODE }),
      "--meta", JSON.stringify({
        source: "hook-bypass", host: host || MODE,
        // 逐段记录时把整条命令带上，便于还原上下文；
        // 归因场景（culpritOf）额外标出真正违规的是哪一段。
        ...((override && (override.fullCommand || override.tool))
          ? {
              full_command: (override.fullCommand || cmd).slice(0, 1000),
              ...(override.attributed ? { attributed_to: override.tool } : {}),
            }
          : {}),
      }),
      ...(error ? ["--error", error] : []),
    ], { timeout: 5000, stdio: "ignore" });
  } catch { /* 审计失败绝不影响主流程 */ }
}
