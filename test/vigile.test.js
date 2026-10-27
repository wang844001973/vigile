// vigile Node 版测试 — 对齐原 Python 81+19 用例集的关键子集
// 运行: node --test test/

import { test } from "node:test";
import assert from "node:assert";
import fs from "node:fs";
import path from "node:path";
import os from "node:os";
import { spawnSync } from "node:child_process";
import { fileURLToPath } from "node:url";

process.env.VIGILE_DB = path.join(os.tmpdir(), "vigile-node-test.db");
fs.rmSync(process.env.VIGILE_DB, { force: true });

const ROOT = path.dirname(fileURLToPath(import.meta.url));
const BIN = path.join(ROOT, "..", "bin", "vigile.js");

import { DatabaseSync } from "node:sqlite";
const core = await import("../src/core.js");
const engine = await import("../src/engine.js");

function cli(args, input) {
  const res = spawnSync(process.execPath, [BIN, ...args], { encoding: "utf8", input });
  return { code: res.status, out: res.stdout, err: res.stderr };
}

// ================================================================ 脱敏
test("脱敏: 环境变量形态", () => {
  assert.doesNotMatch(core.redact("JIRA_TOKEN=abc123"), /abc123/);
});
test("脱敏: password 参数分开传", () => {
  assert.doesNotMatch(core.redactArgv(["tool", "-p", "Secret9"]).join(" "), /Secret9/);
});
test("脱敏: --token=x 形态", () => {
  assert.doesNotMatch(core.redactArgv(["tool", "--token=x"]).join(" "), /=x/);
});
test("脱敏: pat_ token", () => {
  assert.doesNotMatch(core.redact("x pat_abcdefgh12345678 y"), /abcdefgh12345678/);
});
test("脱敏: Authorization 头", () => {
  assert.doesNotMatch(core.redact("Authorization: Bearer eyJhbGciOiJIzzz"), /eyJhbGciOiJIzzz/);
});
test("脱敏: 正常内容不误伤", () => {
  assert.strictEqual(core.redact("log-query trace abc --app xqc"), "log-query trace abc --app xqc");
});

// ================================================================ hash 链
// 破坏类测试用独立库（node:test 顺序执行，篡改后主库链会保持断裂，
// 影响 CLI verify 的断言——这正是共享库的顺序陷阱）
test("hash 链: 完整/篡改/删除（独立库）", () => {
  const breakDb = path.join(os.tmpdir(), "vigile-node-break.db");
  fs.rmSync(breakDb, { force: true });
  const savedDb = process.env.VIGILE_DB;
  // core 模块缓存了连接与库路径，破坏测试通过 CLI 子进程做（子进程拿新路径）
  process.env.VIGILE_DB = breakDb;
  const run = (args) => spawnSync(process.execPath, [BIN, ...args],
    { encoding: "utf8", env: { ...process.env } });
  // 三条记录
  for (const t of ["a", "b", "c"]) {
    run(["call", "--tool", t, "--status", "ok"]);
  }
  let r = run(["verify"]);
  assert.match(r.stdout, /hash 链完整/);
  // 篡改 b
  const db = new DatabaseSync(breakDb);
  db.exec("UPDATE audit_log SET status='hacked' WHERE tool='b'");
  r = run(["verify"]);
  assert.ok(r.status !== 0);
  assert.match(r.stdout, /#2/);
  // 删除 c → 断链
  db.exec("DELETE FROM audit_log WHERE tool='c'");
  r = run(["verify"]);
  assert.ok(r.status !== 0);
  db.close();
  fs.rmSync(breakDb, { force: true, retryDelayMS: 100 });
  process.env.VIGILE_DB = savedDb;
});

// ================================================================ 策略引擎
test("策略: rm -rf → deny", () => {
  assert.equal(engine.evaluate("rm", ["rm", "-rf", "/x"], "rm -rf /x").decision, "deny");
});
test("策略: drop table → deny", () => {
  assert.equal(engine.evaluate("psql", [], "psql -c 'drop table t'").decision, "deny");
});
test("策略: 无 WHERE delete → deny", () => {
  assert.equal(engine.evaluate("x", [], "delete from users").decision, "deny");
});
test("策略: 无 WHERE update → deny", () => {
  assert.equal(engine.evaluate("x", [], "update users set a=1").decision, "deny");
});
test("策略: 带 WHERE delete → ask", () => {
  assert.equal(engine.evaluate("x", [], "delete from t where id=1").decision, "ask");
});
test("策略: 带 WHERE update → ask", () => {
  assert.equal(engine.evaluate("x", [], "update t set a=1 where id=2").decision, "ask");
});
test("策略: 只读命令 → allow", () => {
  assert.equal(engine.evaluate("shandian", [], "shandian status").decision, "allow");
});
test("策略: 自定义提示语返回", () => {
  const v = engine.evaluate("rm", ["rm", "-rf"], "rm -rf /x");
  assert.equal(v.ruleId, "rm_recursive");
  assert.match(v.message, /递归删除/);
  assert.ok(v.hint);
});
test("策略: ask 输出带占位符 message", () => {
  const v = engine.evaluate("psql", [], "delete from t where id=1");
  assert.equal(v.decision, "ask");
  assert.match(v.message, /DELETE/);
});

// ================================================================ 推断层
test("分类: kubectl → k8s", () => {
  assert.equal(engine.inferCategory("kubectl", "get pods"), "k8s");
});
test("分类: psql → sql", () => {
  assert.equal(engine.inferCategory("psql", "-c select"), "sql");
});
test("分类: 未知+mongo 特征 → mongo", () => {
  assert.equal(engine.inferCategory("xtool", "db.orders.find()"), "mongo");
});
test("风险: select → read", () => {
  assert.equal(engine.inferRisk("psql", "select 1"), "read");
});
test("风险: delete 语句 → write", () => {
  assert.equal(engine.inferRisk("psql", "delete from t where id=1"), "write");
});

// ================================================================ blast radius
test("影响预览: rm 统计文件", () => {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), "vig-br-"));
  fs.writeFileSync(path.join(dir, "a.txt"), "x".repeat(100));
  const v = engine.blastRadius(["rm", "-rf", dir]);
  assert.ok(v && v.includes("1 个文件"));
  fs.rmSync(dir, { recursive: true });
});
test("影响预览: drop table 给出对象", () => {
  const v = engine.blastRadius(["psql", "-c", "drop table users"]);
  assert.ok(v && v.includes("users"));
});

// ================================================================ 编排层
test("Multica: 无环境变量时无归属", () => {
  for (const k of ["MULTICA_TASK_ID", "MULTICA_AGENT_NAME"]) delete process.env[k];
  assert.equal(Object.keys(core.orchestratorContext()).length, 0);
  assert.equal(core.orchestratorActor(), null);
});
test("Multica: 识别任务上下文", () => {
  process.env.MULTICA_TASK_ID = "T-100";
  process.env.MULTICA_AGENT_NAME = "claude-7";
  try {
    assert.equal(core.orchestratorActor(), "multica/claude-7 (T-100)");
    assert.equal(core.orchestratorSessionSuffix(), "multica:T-100");
  } finally {
    delete process.env.MULTICA_TASK_ID;
    delete process.env.MULTICA_AGENT_NAME;
  }
});

// ================================================================ CLI 集成
test("CLI: run 拒绝危险命令且不执行", () => {
  const r = cli(["run", "--quiet", "--", "rm", "-rf", path.join(os.tmpdir(), "no-such-vigile")]);
  assert.equal(r.code, 3);
  assert.match(r.err, /已拒绝执行/);
});
test("CLI: run 正常命令透传", () => {
  const r = cli(["run", "--quiet", "--", "echo", "hello-cli"]);
  assert.equal(r.code, 0);
  assert.match(r.out, /hello-cli/);
});
test("CLI: logs 可查", () => {
  const r = cli(["logs", "--limit", "5"]);
  assert.equal(r.code, 0);
  assert.match(r.out, /#/);
});
test("CLI: policy --test 只判不执行", () => {
  const r = cli(["policy", "--test", "rm -rf /"]);
  assert.equal(r.code, 3);
  assert.match(r.out, /deny/);
});
test("CLI: verify 报告链状态", () => {
  const r = cli(["verify"]);
  assert.match(r.out, /hash 链/);   // 完整或异常都要给出明确结论
});
test("CLI: setup --list 列出五 agent", () => {
  const r = cli(["setup", "--list"]);
  assert.equal(r.code, 0);
  for (const a of ["zcode", "claude", "codex", "dsh", "opencode"]) {
    assert.match(r.out, new RegExp(a));
  }
});
