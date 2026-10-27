// vigile 核心层：db + hash 链 + 脱敏
// 独立模块、零依赖（node:sqlite）。将来若回退 Go，本层即"需要重写的全部"——
// 上层 CLI 与 hook 只依赖这里的函数签名。

import { DatabaseSync } from "node:sqlite";
import { createHash } from "node:crypto";
import os from "node:os";
import path from "node:path";
import fs from "node:fs";

// ---------------------------------------------------------------- 环境与路径
export function dbPath() {
  return process.env.VIGILE_DB || process.env.GATE_DB || process.env.AUDIT_DB
    || path.join(os.homedir(), ".vigile", "vigile.db");
}

export function policyPath() {
  return process.env.VIGILE_POLICY || process.env.GATE_POLICY || process.env.AUDIT_POLICY
    || path.join(path.dirname(dbPath()), "policy.json");
}

export function rulesPath() {
  return process.env.VIGILE_RULES || process.env.GATE_RULES || process.env.AUDIT_RULES
    || path.join(path.dirname(dbPath()), "rules.json");
}

// ---------------------------------------------------------------- 脱敏
const REDACT_PATTERNS = [
  [/(JIRA_TOKEN|JIRA_PASS|AGENTOS_TOKEN|GKB_OPENAPI_TOKEN|WORKFLOW_API_TOKEN|RAW_MSG_BASIC_AUTH|GOODS_CENTER_AUTHORIZATION|KBASE_TOKEN|REDASH_\w*API_KEY|SHANDIAN_PASSWORD|CLIENT_LOG_MQTT_PASSWORD)\s*[=:]\s*\S+/gi, "$1=***"],
  [/(Authorization\s*:\s*\w+\s+)\S+/gi, "$1***"],
  [/\bpat_[A-Za-z0-9_-]{8,}/g, "pat_***"],
  [/(api[_-]?key=)[^\s&]+/gi, "$1***"],
  [/(Basic\s+)[A-Za-z0-9+/=]{16,}/gi, "$1***"],
];
const SECRET_FLAGS = /^--?(password|passwd|token|secret|p|api-key|apikey|auth)$/i;

export function redact(text) {
  if (!text) return "";
  let out = String(text);
  for (const [re, repl] of REDACT_PATTERNS) out = out.replace(re, repl);
  return out;
}

/** argv 列表脱敏：处理 --token=x 与 --token x 两种形态。 */
export function redactArgv(argv) {
  const out = [];
  let hideNext = false;
  for (const token of argv) {
    if (hideNext) { out.push("***"); hideNext = false; continue; }
    if (SECRET_FLAGS.test(token)) { out.push(token); hideNext = true; continue; }
    if (token.startsWith("-") && token.includes("=")) {
      const [flag] = token.split("=");
      if (SECRET_FLAGS.test(flag)) { out.push(`${flag}=***`); continue; }
    }
    out.push(redact(token));
  }
  return out;
}

// ---------------------------------------------------------------- 时间
export function nowCST() {
  const d = new Date();
  // ISO 带北京时区偏移（与原 Python CST=UTC+8 一致）
  const t = d.getTime() + 8 * 3600 * 1000;
  const iso = new Date(t).toISOString().replace("Z", "+08:00");
  return { ts: iso.slice(0, 23), tsEpoch: d.getTime() };
}

// ---------------------------------------------------------------- db
let _db = null;

export function connect() {
  if (_db) return _db;
  const p = dbPath();
  fs.mkdirSync(path.dirname(p), { recursive: true });
  _db = new DatabaseSync(p);
  _db.exec(`
    PRAGMA journal_mode=WAL;
    PRAGMA synchronous=NORMAL;
    CREATE TABLE IF NOT EXISTS audit_log (
      id            INTEGER PRIMARY KEY AUTOINCREMENT,
      ts            TEXT    NOT NULL,
      ts_epoch      INTEGER NOT NULL,
      session       TEXT,
      actor         TEXT,
      source        TEXT    NOT NULL,
      category      TEXT    NOT NULL,
      tool          TEXT    NOT NULL,
      action        TEXT,
      target        TEXT,
      args_json     TEXT,
      status        TEXT    NOT NULL,
      exit_code     INTEGER,
      duration_ms   INTEGER,
      rows          INTEGER,
      result_size   INTEGER,
      output_digest TEXT,
      error         TEXT,
      case_name     TEXT,
      ticket        TEXT,
      risk          TEXT,
      meta_json     TEXT,
      prev_hash     TEXT,
      hash          TEXT
    );
    CREATE INDEX IF NOT EXISTS idx_audit_ts     ON audit_log(ts_epoch);
    CREATE INDEX IF NOT EXISTS idx_audit_tool   ON audit_log(tool, ts_epoch);
    CREATE INDEX IF NOT EXISTS idx_audit_case   ON audit_log(case_name, ts_epoch);
    CREATE INDEX IF NOT EXISTS idx_audit_status ON audit_log(status, ts_epoch);
    CREATE INDEX IF NOT EXISTS idx_audit_cat    ON audit_log(category, ts_epoch);
    CREATE TABLE IF NOT EXISTS file_changes (
      id            INTEGER PRIMARY KEY AUTOINCREMENT,
      ts            TEXT    NOT NULL,
      ts_epoch      INTEGER NOT NULL,
      session       TEXT,
      file_path     TEXT    NOT NULL,
      op            TEXT,
      before_hash   TEXT,
      after_hash    TEXT,
      before_size   INTEGER,
      after_size    INTEGER,
      diff          TEXT,
      added_lines   INTEGER,
      removed_lines INTEGER,
      case_name     TEXT,
      ticket        TEXT
    );
    CREATE INDEX IF NOT EXISTS idx_fc_ts   ON file_changes(ts_epoch);
    CREATE INDEX IF NOT EXISTS idx_fc_file ON file_changes(file_path, ts_epoch);
    CREATE INDEX IF NOT EXISTS idx_fc_case ON file_changes(case_name, ts_epoch);
  `);
  return _db;
}

// ---------------------------------------------------------------- hash 链
function chainHash(prev, row) {
  // 字段语义必须与"从 DB 读回"完全一致：NULL 参与 hash 时记为空串。
  // 写入侧构造 full 时已把 null 显式传给 SQLite（存 NULL），读回也是 null，
  // 两侧统一 (val ?? "") 归一。
  const norm = (v) => (v === null || v === undefined) ? "" : String(v);
  const fields = [norm(row.ts), norm(row.tool), norm(row.action), norm(row.target),
    norm(row.status), norm(row.exit_code), norm(row.duration_ms)];
  return createHash("sha256").update((prev || "") + fields.join("|")).digest("hex");
}

export function record(row) {
  const db = connect();
  const { ts, tsEpoch } = nowCST();
  const prev = db.prepare(
    "SELECT hash FROM audit_log WHERE hash IS NOT NULL ORDER BY id DESC LIMIT 1").get();
  const prevHash = prev ? prev.hash : null;
  const full = {
    ts, tsEpoch, session: row.session || sessionId(), actor: row.actor || orchestratorActor() || defaultActor(),
    source: row.source || "cli", category: row.category || "other",
    tool: row.tool || "unknown", action: row.action ?? null, target: row.target ?? null,
    argsJson: row.argsJson ?? null, status: row.status || "ok",
    exitCode: row.exitCode ?? null, durationMs: row.durationMs ?? null,
    rows: row.rows ?? null, resultSize: row.resultSize ?? null,
    outputDigest: row.outputDigest ?? null, error: row.error ?? null,
    caseName: row.caseName ?? process.env.VIGILE_CASE ?? process.env.GATE_CASE ?? process.env.AUDIT_CASE ?? null,
    ticket: row.ticket ?? process.env.VIGILE_TICKET ?? process.env.GATE_TICKET ?? process.env.AUDIT_TICKET ?? null,
    risk: row.risk ?? null, metaJson: row.metaJson ?? null,
    prevHash, hash: null,
  };
  // hash 计算用与 DB 行同构的字段名（snake_case），保证写入与读回两侧一致
  full.hash = chainHash(prevHash, {
    ts: full.ts, tool: full.tool, action: full.action, target: full.target,
    status: full.status, exit_code: full.exitCode, duration_ms: full.durationMs,
  });
  // node:sqlite 拒绝 undefined 绑定（CLI 可选参数未传时是 undefined 而非 null），
  // 绑定前统一归一；null 语义为"该字段本次调用不涉及"。
  const b = (v) => (v === undefined ? null : v);
  const r = db.prepare(`INSERT INTO audit_log
    (ts,ts_epoch,session,actor,source,category,tool,action,target,args_json,status,
     exit_code,duration_ms,rows,result_size,output_digest,error,case_name,ticket,risk,meta_json,prev_hash,hash)
    VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)`)
    .run(b(full.ts), b(full.tsEpoch), b(full.session), b(full.actor), b(full.source), b(full.category),
      b(full.tool), b(full.action), b(full.target), b(full.argsJson), b(full.status),
      b(full.exitCode), b(full.durationMs), b(full.rows), b(full.resultSize), b(full.outputDigest),
      b(full.error), b(full.caseName), b(full.ticket), b(full.risk), b(full.metaJson),
      b(full.prevHash), b(full.hash));
  return Number(r.lastInsertRowid);
}

export function recordFileChange(fc) {
  const db = connect();
  const { ts, tsEpoch } = nowCST();
  const r = db.prepare(`INSERT INTO file_changes
    (ts,ts_epoch,session,file_path,op,before_hash,after_hash,before_size,after_size,
     diff,added_lines,removed_lines,case_name,ticket)
    VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?)`)
    .run(ts, tsEpoch, sessionId(), fc.filePath, fc.op || "edit",
      fc.before ? sha256(fc.before) : null, fc.after ? sha256(fc.after) : null,
      fc.before ? Buffer.byteLength(fc.before) : 0, fc.after ? Buffer.byteLength(fc.after) : 0,
      fc.diff ?? "", fc.added ?? 0, fc.removed ?? 0, fc.caseName ?? null, fc.ticket ?? null);
  return Number(r.lastInsertRowid);
}

function sha256(text) {
  return createHash("sha256").update(String(text), "utf8").digest("hex");
}

/** Python 版算法的等价实现（兼容迁移前的历史记录）。
 *  Python 用 `str(row.get(k) or "")`：0、空串、None 全部归一为空串。
 *  Node 新算法保留 0 的语义更正确，但历史记录按 Python 算法写入，
 *  校验时两种都接受，否则迁移会被误判为"被篡改"。 */
function chainHashLegacy(prev, row) {
  const orEmpty = (v) => (v === null || v === undefined || v === 0 || v === "") ? "" : String(v);
  const fields = [orEmpty(row.ts), orEmpty(row.tool), orEmpty(row.action),
    orEmpty(row.target), orEmpty(row.status), orEmpty(row.exit_code),
    orEmpty(row.duration_ms)];
  return createHash("sha256").update((prev || "") + fields.join("|")).digest("hex");
}

/** 验证 hash 链完整性。返回 {ok, total, broken: [{id, reason}], legacy}。 */
export function verifyChain() {
  const db = connect();
  const rows = db.prepare(
    "SELECT id, ts, tool, action, target, status, exit_code, duration_ms, prev_hash, hash FROM audit_log ORDER BY id").all();
  let prevHash = null, broken = [], legacy = 0;
  for (const r of rows) {
    if (!r.hash) { legacy++; prevHash = null; continue; }
    const ok = r.hash === chainHash(r.prev_hash, r)
      || r.hash === chainHashLegacy(r.prev_hash, r);
    const chainOk = (r.prev_hash === prevHash) || (prevHash === null && r.prev_hash === null);
    if (!ok || !chainOk) {
      broken.push({ id: r.id, reason: "hash 不匹配（记录可能被篡改或前后被删）" });
    }
    prevHash = r.hash;
  }
  return { ok: broken.length === 0, total: rows.length, legacy, broken };
}

// ---------------------------------------------------------------- 会话/执行者
export function sessionId() {
  const base = process.env.VIGILE_SESSION || process.env.GATE_SESSION || process.env.AUDIT_SESSION;
  if (base) return base;
  const suffix = orchestratorSessionSuffix();
  const core = `${os.userInfo().username}@${process.pid}`;
  return suffix ? `${core}/${suffix}` : core;
}

export function defaultActor() {
  return process.env.VIGILE_ACTOR || process.env.GATE_ACTOR || process.env.AUDIT_ACTOR
    || os.userInfo().username;
}

// ---------------------------------------------------------------- 编排层（Multica 等）
const MULTICA_KEYS = ["MULTICA_TASK_ID", "MULTICA_AGENT_NAME", "MULTICA_AGENT_ID",
  "MULTICA_WORKSPACE_ID", "MULTICA_DAEMON_DEVICE_NAME", "MULTICA_SERVER_URL"];

export function orchestratorContext() {
  const ctx = {};
  for (const k of MULTICA_KEYS) {
    const v = (process.env[k] || "").trim();
    if (v) ctx[k] = v;
  }
  return ctx;
}

export function orchestratorActor() {
  const ctx = orchestratorContext();
  if (!Object.keys(ctx).length) return null;
  const agent = ctx.MULTICA_AGENT_NAME || ctx.MULTICA_AGENT_ID || "agent";
  const task = ctx.MULTICA_TASK_ID || "";
  return `multica/${agent}${task ? ` (${task})` : ""}`;
}

export function orchestratorSessionSuffix() {
  const ctx = orchestratorContext();
  if (!Object.keys(ctx).length) return "";
  return `multica:${ctx.MULTICA_TASK_ID || ctx.MULTICA_AGENT_ID || "?"}`;
}
