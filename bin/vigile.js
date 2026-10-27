#!/usr/bin/env node
// vigile CLI — 守夜人：AI agent 内部调用的统一入口（审计 + 执行前审核）
// 零依赖（node ≥ 22.5，使用内置 node:sqlite）

import { spawnSync } from "node:child_process";
import fs from "node:fs";
import path from "node:path";
import os from "node:os";
import { fileURLToPath } from "node:url";

import {
  redact, redactArgv, record, recordFileChange, connect, verifyChain,
  dbPath, policyPath, rulesPath, sessionId, defaultActor, orchestratorContext,
} from "../src/core.js";
import {
  evaluate, blastRadius, inferCategory, inferRisk, loadPolicy, loadRules,
  DEFAULT_DENY_RULES, DEFAULT_ASK_RULES,
} from "../src/engine.js";

const EXIT_OK = 0, EXIT_USAGE = 2, EXIT_DENIED = 3;

// ---------------------------------------------------------------- 版本闸
const [maj, min] = process.versions.node.split(".").map(Number);
if (maj < 22 || (maj === 22 && min < 5)) {
  console.error(`vigile 需要 Node.js >= 22.5（内置 node:sqlite）。当前 ${process.versions.node}`);
  console.error("升级：https://nodejs.org/ 或 nvm install 22");
  process.exit(1);
}

// ---------------------------------------------------------------- 工具函数
const out = (...a) => process.stdout.write(a.join(" ") + "\n");
const err = (...a) => process.stderr.write(a.join(" ") + "\n");
const jsonOut = (o) => out(JSON.stringify(o, null, 2));

function parseSince(text) {
  const rel = /^(\d+)([mhd])$/.exec(text);
  if (rel) {
    const n = +rel[1], mul = { m: 60, h: 3600, d: 86400 }[rel[2]];
    return Date.now() - n * mul * 1000;
  }
  const t = Date.parse(text.replace(" ", "T") + "+08:00");
  if (!isNaN(t)) return t;
  throw new UsageError(`无法解析时间: ${text}（支持 30m/2h/7d 或 2026-10-27 12:00:00）`);
}
class UsageError extends Error {}

const STATUS_MARK = { ok: "✓", failed: "✗", timeout: "⏱", blocked: "⊘", denied: "⛔" };

function fmtRow(r) {
  const ts = (r.ts || "").slice(11, 23);
  const dur = r.duration_ms != null ? `${r.duration_ms}ms` : "-";
  let line = `#${String(r.id).padEnd(6)} ${ts} ${String(r.status).padEnd(7)} `
    + `${String(r.tool).padEnd(16)} ${String(r.action || "").padEnd(12)} ${dur.padStart(8)}`;
  const extra = r.target || r.error || "";
  if (extra) line += `  ${String(extra).slice(0, 96)}`;
  return line;
}

function buildFilters(args) {
  const where = [], params = [];
  if (args.tool) { where.push("tool = ?"); params.push(args.tool); }
  if (args.category) { where.push("category = ?"); params.push(args.category); }
  if (args.status) { where.push("status = ?"); params.push(args.status); }
  if (args.case) { where.push("case_name = ?"); params.push(args.case); }
  if (args.ticket) { where.push("ticket = ?"); params.push(args.ticket); }
  if (args.risk) { where.push("risk = ?"); params.push(args.risk); }
  if (args.since) { where.push("ts_epoch >= ?"); params.push(parseSince(args.since)); }
  if (args.keyword) {
    where.push("(args_json LIKE ? OR output_digest LIKE ? OR error LIKE ? OR target LIKE ? OR session LIKE ? OR actor LIKE ?)");
    const k = `%${args.keyword}%`;
    params.push(k, k, k, k, k, k);
  }
  return { clause: where.length ? " WHERE " + where.join(" AND ") : "", params };
}

// ---------------------------------------------------------------- run（核心）
function cmdRun(args) {
  let argv = args.rest;
  if (argv[0] === "--") argv = argv.slice(1);
  if (!argv.length) { err("用法: vigile run [--case X] [--ticket Y] -- <命令...>"); return EXIT_USAGE; }

  const tool = argv[0];
  const argsText = argv.join(" ");
  const category = inferCategory(tool, argsText);
  const risk = inferRisk(tool, argsText);

  if (!args.noPolicy) {
    const verdict = evaluate(tool, argv, argsText);
    if (verdict.decision === "deny" || verdict.decision === "ask") {
      const confirmed = args.yes
        || ["yes", "y", "1", "true"].includes(
          (process.env.VIGILE_CONFIRM || process.env.GATE_CONFIRM || process.env.AUDIT_CONFIRM || "").toLowerCase());
      if (verdict.decision === "deny" || !confirmed) {
        const label = verdict.decision === "deny" ? "已拒绝执行" : "需要确认（未确认，拒绝执行）";
        err(`[vigile] ${label}（规则 ${verdict.ruleId}）`);
        err(`[vigile] ${verdict.message}`);
        if (verdict.hint) err(`[vigile] 建议：${verdict.hint}`);
        const impact = blastRadius(argv);
        if (impact) err(`[vigile] 影响预览：${impact}`);
        err(verdict.decision === "deny" ? "[vigile] 命令未运行。" : "[vigile] 确认无误后加 -y 或 VIGILE_CONFIRM=yes 执行。");
        record({ source: "cli", category, tool: path.basename(tool),
          action: argv[1] || path.basename(tool), target: "",
          argsJson: JSON.stringify({ argv: redactArgv(argv), cwd: process.cwd() }),
          status: "denied", durationMs: 0, risk: "write",
          error: `[${verdict.decision === "deny" ? "策略拒绝" : "需确认未确认"}/${verdict.ruleId}] ${verdict.message}`,
          caseName: args.case, ticket: args.ticket,
          metaJson: JSON.stringify({ policy_rule: verdict.ruleId, impact: impact || null }) });
        return EXIT_DENIED;
      }
    }
  }

  const started = Date.now();
  const res = spawnSync(argv[0], argv.slice(1), { encoding: "utf8", shell: false, maxBuffer: 64 * 1024 * 1024 });
  const durationMs = Date.now() - started;
  const stdout = res.stdout || "", stderr = res.stderr || "";
  let status = "ok", errorText = "", exitCode = res.status;
  if (res.error) {
    status = res.error.code === "ENOENT" ? "failed" : "failed";
    errorText = res.error.code === "ENOENT" ? `命令不存在: ${tool}` : String(res.error.message);
    exitCode = res.error.code === "ENOENT" ? 127 : 1;
  } else if (exitCode !== 0) {
    status = /timeout|超时|deadline/i.test(stderr) ? "timeout" : "failed";
    errorText = stderr.slice(0, 1000);
  }

  const rid = record({ source: "cli", category, tool: path.basename(tool),
    action: argv[1] || path.basename(tool), target: "",
    argsJson: JSON.stringify({ argv: redactArgv(argv), cwd: process.cwd() }),
    status, exitCode, durationMs,
    resultSize: Buffer.byteLength(stdout),
    outputDigest: redact(stdout).slice(0, 2000) || null,
    error: redact(errorText) || null, risk,
    caseName: args.case, ticket: args.ticket });

  if (stdout) process.stdout.write(stdout);
  if (stderr) process.stderr.write(stderr);
  if (!args.quiet) err(`\n[vigile] #${rid} ${status} ${durationMs}ms → ${dbPath()}`);
  return exitCode ?? 1;
}

// ---------------------------------------------------------------- 查询类命令
function cmdLogs(args) {
  const db = connect();
  const { clause, params } = buildFilters(args);
  const rows = db.prepare(`SELECT * FROM audit_log${clause} ORDER BY ts_epoch DESC LIMIT ?`)
    .all(...params, args.limit);
  if (args.json) return jsonOut(rows);
  if (!rows.length) return out("（无记录）");
  rows.forEach(r => out(fmtRow(r)));
  return EXIT_OK;
}

function cmdGet(args) {
  const row = connect().prepare("SELECT * FROM audit_log WHERE id = ?").get(args.id);
  if (!row) { err(`未找到 #${args.id}`); return EXIT_USAGE; }
  jsonOut(row);
  return EXIT_OK;
}

function cmdStats(args) {
  const db = connect();
  const { clause, params } = buildFilters(args);
  const total = db.prepare(`SELECT COUNT(*) c FROM audit_log${clause}`).get(...params).c;
  if (!total) return out("（无记录）");
  out(`总调用 ${total} 次`);
  out("\n按工具：");
  for (const r of db.prepare(`SELECT tool, COUNT(*) c, SUM(status='ok') ok, SUM(status!='ok') bad,
      ROUND(AVG(duration_ms)) avg_ms, MAX(duration_ms) max_ms FROM audit_log${clause}
      GROUP BY tool ORDER BY c DESC LIMIT 20`).all(...params)) {
    out(`  ${String(r.tool).padEnd(18)} ${String(r.c).padStart(5)}次  ok=${String(r.ok).padEnd(5)} bad=${String(r.bad).padEnd(4)} 平均${r.avg_ms || 0}ms 最慢${r.max_ms || 0}ms`);
  }
  out("\n按状态：");
  for (const r of db.prepare(`SELECT status, COUNT(*) c FROM audit_log${clause} GROUP BY status ORDER BY c DESC`).all(...params))
    out(`  ${String(r.status).padEnd(10)} ${r.c}`);
  out("\n按分类：");
  for (const r of db.prepare(`SELECT category, COUNT(*) c FROM audit_log${clause} GROUP BY category ORDER BY c DESC`).all(...params))
    out(`  ${String(r.category).padEnd(12)} ${r.c}`);
  out("\n按风险：");
  for (const r of db.prepare(`SELECT COALESCE(risk,'-') r, COUNT(*) c FROM audit_log${clause} GROUP BY r ORDER BY c DESC`).all(...params))
    out(`  ${String(r.r).padEnd(10)} ${r.c}`);
  return EXIT_OK;
}

function cmdSlow(args) {
  const db = connect();
  const { clause, params } = buildFilters(args);
  const c = clause ? `${clause} AND duration_ms IS NOT NULL` : " WHERE duration_ms IS NOT NULL";
  const rows = db.prepare(`SELECT * FROM audit_log${c} ORDER BY duration_ms DESC LIMIT ?`).all(...params, args.limit);
  if (!rows.length) return out("（无记录）");
  rows.forEach(r => out(`${String(r.duration_ms).padStart(8)}ms  ${String(r.tool).padEnd(16)} ${String(r.action || "").padEnd(12)} ${String(r.status).padEnd(8)} ${String(r.target || "").slice(0, 60)}`));
  return EXIT_OK;
}

function cmdErrors(args) {
  const db = connect();
  const { clause, params } = buildFilters(args);
  const c = clause ? `${clause} AND status != 'ok'` : " WHERE status != 'ok'";
  const rows = db.prepare(`SELECT tool, status, COUNT(*) c, MIN(ts) first_ts, MAX(ts) last_ts,
      SUBSTR(COALESCE(error,''),1,80) err FROM audit_log${c}
      GROUP BY tool, status, err ORDER BY c DESC LIMIT ?`).all(...params, args.limit);
  if (!rows.length) return out("（无失败记录）");
  rows.forEach(r => {
    out(`${String(r.c).padStart(4)}次  ${String(r.tool).padEnd(16)} ${String(r.status).padEnd(8)} ${String(r.err || "").trim().slice(0, 70)}`);
    out(`       首次 ${r.first_ts}  最近 ${r.last_ts}`);
  });
  return EXIT_OK;
}

function cmdByCase(args) {
  const rows = connect().prepare(`SELECT COALESCE(case_name,'(未关联)') c, COUNT(*) n,
    MIN(ts) first_ts, MAX(ts) last_ts, GROUP_CONCAT(DISTINCT tool) tools
    FROM audit_log GROUP BY c ORDER BY n DESC LIMIT ?`).all(args.limit);
  rows.forEach(r => {
    out(`${String(r.n).padStart(5)}次  ${String(r.c).padEnd(28)} ${String(r.first_ts).slice(0, 19)} ~ ${String(r.last_ts).slice(11, 19)}`);
    out(`        工具: ${String(r.tools || "").slice(0, 90)}`);
  });
  return EXIT_OK;
}

function cmdTimeline(args) {
  const db = connect();
  const { clause, params } = buildFilters(args);
  const rows = db.prepare(`SELECT * FROM audit_log${clause} ORDER BY ts_epoch ASC LIMIT ?`).all(...params, args.limit);
  rows.forEach(r => out(`${String(r.ts).slice(11, 19)} ${STATUS_MARK[r.status] || "?"} ${String(r.tool).padEnd(16)}${String(r.action || "").padEnd(12)}${String(r.target || "").slice(0, 40).padEnd(42)}${String(r.duration_ms || 0).padStart(7)}ms`));
  return EXIT_OK;
}

function cmdExport(args) {
  const db = connect();
  const { clause, params } = buildFilters(args);
  const rows = db.prepare(`SELECT * FROM audit_log${clause} ORDER BY ts_epoch`).all(...params);
  if (args.format === "csv") {
    if (!rows.length) { err("（无记录）"); return EXIT_OK; }
    const cols = Object.keys(rows[0]);
    const esc = (v) => v == null ? "" : `"${String(v).replace(/"/g, '""')}"`;
    out(cols.join(","));
    rows.forEach(r => out(cols.map(c => esc(r[c])).join(",")));
  } else {
    const text = JSON.stringify(rows, null, 2);
    if (args.out) fs.writeFileSync(args.out, text, "utf8");
    out(text);
  }
  return EXIT_OK;
}

function cmdVerify() {
  const v = verifyChain();
  if (v.ok) {
    const legacy = v.legacy ? `（${v.legacy} 条为 hash 链启用前的旧记录，跳过校验）` : "";
    out(`✅ ${v.total} 条记录${legacy}，hash 链完整（未被篡改/删除）`);
    return EXIT_OK;
  }
  v.broken.forEach(b => out(`  ❌ #${b.id} ${b.reason}`));
  err(`❌ ${v.broken.length}/${v.total - v.legacy} 条链上记录异常`);
  return 1;
}

function cmdDiff(args) {
  const db = connect();
  const where = [], params = [];
  if (args.file) { where.push("file_path LIKE ?"); params.push(`%${args.file}%`); }
  if (args.case) { where.push("case_name = ?"); params.push(args.case); }
  const clause = where.length ? " WHERE " + where.join(" AND ") : "";
  const rows = db.prepare(`SELECT * FROM file_changes${clause} ORDER BY ts_epoch DESC LIMIT ?`).all(...params, args.limit);
  if (!rows.length) return out("（无变更记录）");
  rows.forEach(r => {
    out(`#${r.id} ${String(r.ts).slice(11, 19)} ${String(r.op).padEnd(6)} +${r.added_lines}/-${r.removed_lines}  ${r.file_path}`);
    if (args.show) { out(r.diff || "  （无 diff）"); out(""); }
  });
  return EXIT_OK;
}

function cmdSession(args) {
  const db = connect();
  if (!args.id) {
    const rows = db.prepare(`SELECT session, COUNT(*) n, MIN(ts) first_ts, MAX(ts) last_ts,
      SUM(status!='ok') bad, SUM(COALESCE(risk,'')='write') writes
      FROM audit_log GROUP BY session ORDER BY MAX(ts_epoch) DESC LIMIT ?`).all(args.limit);
    if (!rows.length) return out("（无记录）");
    out(`${"会话".padEnd(26)}${"次数".padStart(4)}${"写".padStart(4)}${"失败".padStart(4)}  时间范围`);
    rows.forEach(r => out(`${String(r.session || "-").slice(0, 26).padEnd(26)}${String(r.n).padStart(4)}${String(r.writes || 0).padStart(4)}${String(r.bad || 0).padStart(4)}  ${String(r.first_ts).slice(5, 19)} ~ ${String(r.last_ts).slice(11, 19)}`));
    out("\n用 vigile session <id> 查看详情");
    return EXIT_OK;
  }
  const calls = db.prepare("SELECT * FROM audit_log WHERE session = ? ORDER BY ts_epoch").all(args.id);
  const changes = db.prepare("SELECT * FROM file_changes WHERE session = ? ORDER BY ts_epoch").all(args.id);
  if (!calls.length && !changes.length) return out(`会话 ${args.id} 无记录`);
  const events = [...calls.map(r => ["call", r]), ...changes.map(r => ["file", r])]
    .sort((a, b) => a[1].ts_epoch - b[1].ts_epoch);
  out(`会话 ${args.id}：${calls.length} 次调用，${changes.length} 次文件变更\n`);
  for (const [kind, r] of events) {
    const ts = String(r.ts).slice(11, 19);
    if (kind === "call") {
      out(`${ts} ${STATUS_MARK[r.status] || "?"} ${String(r.tool).padEnd(16)}${String(r.action || "").padEnd(12)}${String(r.target || "").slice(0, 44).padEnd(46)}${String(r.duration_ms || 0).padStart(6)}ms`);
    } else {
      out(`${ts} ✎ ${String(r.op).padEnd(6)} +${r.added_lines}/-${r.removed_lines}  ${r.file_path}`);
    }
  }
  return EXIT_OK;
}

function cmdPolicy(args) {
  if (args.test) {
    const parts = args.test.split(/\s+/);
    const v = evaluate(parts[0] || "", parts, args.test);
    jsonOut({ command: args.test, ...v });
    return v.decision === "deny" ? EXIT_DENIED : EXIT_OK;
  }
  if (args.init) {
    const p = policyPath();
    if (fs.existsSync(p) && !args.force) { err(`已存在: ${p}（加 --force 覆盖）`); return EXIT_USAGE; }
    fs.mkdirSync(path.dirname(p), { recursive: true });
    const tmpl = {
      _comment: "每条规则：id / pattern(正则字符串) / message(支持 {command} {tool} {match}) / hint",
      deny: DEFAULT_DENY_RULES.map(r => ({ id: r.id, pattern: r.pattern.source, message: r.message, hint: r.hint })),
      ask: DEFAULT_ASK_RULES.map(r => ({ id: r.id, pattern: r.pattern.source, message: r.message, hint: r.hint })),
      allow_tools: [], deny_tools: [],
    };
    fs.writeFileSync(p, JSON.stringify(tmpl, null, 2), "utf8");
    out(`已生成策略模板: ${p}`);
    return EXIT_OK;
  }
  const pol = loadPolicy(true);
  jsonOut({ policy_file: policyPath(), exists: fs.existsSync(policyPath()),
    deny_rules: pol.deny.map(r => ({ id: r.id, message: r.message, hint: r.hint })),
    ask_rules: pol.ask.map(r => ({ id: r.id, message: r.message, hint: r.hint })),
    allow_tools: pol.allowTools, deny_tools: pol.denyTools });
  return EXIT_OK;
}

function cmdRules(args) {
  if (args.init) {
    const p = rulesPath();
    if (fs.existsSync(p) && !args.force) { err(`已存在: ${p}（加 --force 覆盖）`); return EXIT_USAGE; }
    fs.mkdirSync(path.dirname(p), { recursive: true });
    fs.writeFileSync(p, JSON.stringify({
      _comment: "工具名 -> 分类（log/sql/mongo/k8s/http/git/file/other）",
      tools: { mytool: "sql" },
      _comment_write: "工具名 -> 判为写操作的动作词",
      write: { kubectl: ["apply", "delete", "create", "edit", "patch", "scale", "rollout"] },
      _comment_read_only: "永远判为只读的工具名",
      read_only: [],
    }, null, 2), "utf8");
    out(`已生成规则模板: ${p}`);
    return EXIT_OK;
  }
  const r = loadRules(true);
  jsonOut({ rules_file: rulesPath(), exists: fs.existsSync(rulesPath()), tools: r.tools, write: r.write, read_only: r.readOnly });
  return EXIT_OK;
}

function cmdCall(args) {
  // 默认 python：call 的主要调用方是各技能内的 Python 脚本。
  // hook 旁路记录必须显式传 --source hook 才能与真实脚本调用区分。
  const id = record({ source: args.source || "python", category: args.category, tool: args.tool,
    action: args.action, target: args.target,
    argsJson: args.args ? redact(args.args) : null,
    status: args.status, exitCode: args.exitCode, durationMs: args.duration,
    rows: args.rows, resultSize: args.resultSize,
    outputDigest: args.output ? redact(args.output).slice(0, 2000) : null,
    error: args.error ? redact(args.error) : null, risk: args.risk,
    caseName: args.case, ticket: args.ticket, metaJson: args.meta ? redact(args.meta) : null });
  jsonOut({ id, db: dbPath() });
  return EXIT_OK;
}

function cmdCallFileChange(args) {
  const id = recordFileChange({ filePath: args.file, op: args.op,
    before: args.before || null, after: args.after || null,
    caseName: args.case, ticket: args.ticket });
  jsonOut({ id });
  return EXIT_OK;
}

function cmdPrune(args) {
  const cutoff = parseSince(args.keep);
  const db = connect();
  const r = db.prepare("DELETE FROM audit_log WHERE ts_epoch < ?").run(cutoff);
  db.exec("VACUUM");
  out(`已清理 ${r.changes} 条（保留 ${args.keep} 内）`);
  return EXIT_OK;
}

function cmdTail(args) {
  const db = connect();
  let last = db.prepare("SELECT COALESCE(MAX(id),0) m FROM audit_log").get().m;
  if (!args.noExisting) {
    db.prepare("SELECT * FROM audit_log ORDER BY id DESC LIMIT ?").all(args.lines)
      .reverse().forEach(r => out(fmtRow(r)));
  }
  err(`[vigile] 跟踪中（Ctrl+C 退出）… ${dbPath()}`);
  const timer = setInterval(() => {
    const rows = db.prepare("SELECT * FROM audit_log WHERE id > ? ORDER BY id LIMIT 200").all(last);
    for (const r of rows) { out(fmtRow(r)); last = r.id; }
  }, Math.max(200, args.interval * 1000));
  process.on("SIGINT", () => { clearInterval(timer); process.exit(0); });
  return new Promise(() => {}); // 长驻
}

function cmdSetup(args) {
  // 复用 JS 版 setup（与 agent 注册逻辑同语言）
  return import("../src/setup.js").then(m => m.setupMain(args));
}

// ---------------------------------------------------------------- 参数解析（极简，无依赖）
function parseArgs(argv) {
  const [cmd, ...rest] = argv;
  const args = { _: [], rest: [] };
  const flags = {
    "-y": ["yes", true], "--yes": ["yes", true], "--quiet": ["quiet", true],
    "--json": ["json", true], "--show": ["show", true], "--init": ["init", true],
    "--force": ["force", true], "--no-policy": ["noPolicy", true],
    "--no-existing": ["noExisting", true], "--list": ["list", true],
    "--install": ["install", true], "--uninstall": ["uninstall", true],
    "--setup-status": ["status", true],
  };
  const valued = {
    "--case": "case", "--ticket": "ticket", "--tool": "tool", "--action": "action",
    "--target": "target", "--category": "category", "--status": "status",
    "--duration": "duration", "--exit-code": "exitCode", "--rows": "rows",
    "--result-size": "resultSize", "--args": "args", "--output": "output",
    "--error": "error", "--risk": "risk", "--meta": "meta", "--limit": "limit",
    "--since": "since", "--keyword": "keyword", "--file": "file", "--op": "op",
    "--before": "before", "--after": "after", "--keep": "keep", "--format": "format",
    "--out": "out", "--interval": "interval", "--lines": "lines", "--agent": "agent",
    "--test": "test", "--filename": "filename", "--source": "source",
  };
  for (let i = 0; i < rest.length; i++) {
    const a = rest[i];
    if (a === "--") { args.rest = rest.slice(i); break; }
    if (flags[a]) { args[flags[a][0]] = flags[a][1]; continue; }
    const numArg = ["duration", "exitCode", "rows", "resultSize", "limit", "interval", "lines"].includes(valued[a]);
    if (valued[a]) { const v = rest[++i]; args[valued[a]] = numArg ? Number(v) : v; continue; }
    args._.push(a);
    args.rest.push(a);
  }
  // rest 里去掉前面的 _（run 用原始参数）
  if (cmd === "run") {
    const idx = rest.indexOf("--");
    args.rest = idx >= 0 ? rest.slice(idx + 1) : [];
  }
  if (args.limit === undefined) args.limit = 50;
  if (args.interval === undefined) args.interval = 1;
  if (args.lines === undefined) args.lines = 10;
  if (args.format === undefined) args.format = "json";
  if (args.status === undefined) args.status = undefined;
  return { cmd, args };
}

const HELP = `vigile — 守夜人：AI agent 内部调用的统一入口（审计 + 执行前审核）

用法: vigile <命令> [选项]

审计:  run / call / call-file-change / logs / tail / get / export
分析:  stats / slow / errors / by-case / timeline / session / diff
安全:  policy / verify
配置:  rules / setup / prune

常用:
  vigile run -- <命令>              过闸：执行 + 审计 + 审核
  vigile run --case X --ticket Y -- <命令>
  vigile tail                       实时跟踪
  vigile logs --since 2h            查询
  vigile policy --test "rm -rf /"   只看判定
  vigile setup --install --agent all
`;

async function main() {
  const argv = process.argv.slice(2);
  if (!argv.length || argv[0] === "-h" || argv[0] === "--help" || argv[0] === "help") {
    out(HELP); return EXIT_OK;
  }
  if (argv[0] === "--version" || argv[0] === "-V") { out("vigile 1.0.0"); return EXIT_OK; }

  const { cmd, args } = parseArgs(argv);
  try {
    switch (cmd) {
      case "run": return cmdRun(args);
      case "logs": return cmdLogs(args);
      case "get": return cmdGet({ ...args, id: Number(args._[0]) });
      case "stats": return cmdStats(args);
      case "slow": return cmdSlow(args);
      case "errors": return cmdErrors(args);
      case "by-case": return cmdByCase(args);
      case "timeline": return cmdTimeline(args);
      case "export": return cmdExport(args);
      case "verify": return cmdVerify(args);
      case "diff": return cmdDiff(args);
      case "session": return cmdSession({ ...args, id: args._[0] });
      case "policy": return cmdPolicy(args);
      case "rules": return cmdRules(args);
      case "call": return cmdCall(args);
      case "call-file-change": return cmdCallFileChange(args);
      case "prune": return cmdPrune(args);
      case "tail": return cmdTail(args);
      case "setup": return await cmdSetup(args);
      default:
        err(`未知命令: ${cmd}\n`);
        out(HELP);
        return EXIT_USAGE;
    }
  } catch (e) {
    if (e instanceof UsageError) { err(`参数错误: ${e.message}`); return EXIT_USAGE; }
    throw e;
  }
}

main().then(code => { if (typeof code === "number") process.exit(code); })
  .catch(e => { err(`vigile 错误: ${e.stack || e.message}`); process.exit(1); });
