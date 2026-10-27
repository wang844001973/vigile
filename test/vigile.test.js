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
import { createHash } from "node:crypto";
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

// ================================================================ 跨版本 hash 兼容
test("hash 链: 兼容 Python 版历史算法（exit_code=0 归一差异）", () => {
  // Python 用 `x or ""` 把 0 归一为空串；Node 保留 0。
  // 历史记录按 Python 算法写入，校验必须两种都接受。
  const db = path.join(os.tmpdir(), "vigile-legacy-hash.db");
  fs.rmSync(db, { force: true });
  const d = new DatabaseSync(db);
  d.exec(`CREATE TABLE audit_log (id INTEGER PRIMARY KEY AUTOINCREMENT, ts TEXT, ts_epoch INTEGER,
    session TEXT, actor TEXT, source TEXT, category TEXT, tool TEXT, action TEXT, target TEXT,
    args_json TEXT, status TEXT, exit_code INTEGER, duration_ms INTEGER, rows INTEGER,
    result_size INTEGER, output_digest TEXT, error TEXT, case_name TEXT, ticket TEXT,
    risk TEXT, meta_json TEXT, prev_hash TEXT, hash TEXT)`);
  const orE = (v) => (v === null || v === undefined || v === 0 || v === "") ? "" : String(v);
  const legHash = createHash("sha256")
    .update(orE("2026-01-01T00:00:00.000") + "|" + orE("t") + "|" + orE(null) + "|" +
      orE(null) + "|" + orE("ok") + "|" + orE(0) + "|" + orE(null)).digest("hex");
  d.prepare(`INSERT INTO audit_log (ts, tool, status, exit_code, prev_hash, hash, source, category)
    VALUES (?,?,?,?,?,?,?,?)`).run("2026-01-01T00:00:00.000", "t", "ok", 0, null, legHash, "cli", "other");
  d.close();
  const saved = process.env.VIGILE_DB;
  process.env.VIGILE_DB = db;
  try {
    const r = spawnSync(process.execPath, [BIN, "verify"], { encoding: "utf8", env: { ...process.env } });
    assert.equal(r.status, 0, `Python 算法历史记录应通过校验，实际: ${r.stdout}`);
  } finally {
    process.env.VIGILE_DB = saved;
    fs.rmSync(db, { force: true, retryDelayMS: 100 });
  }
});

// ================================================================ hook 判定
const HOOK = path.join(ROOT, "..", "hooks", "vigile-hook.js");

// 模式经 --mode 参数传递（Windows cmd.exe 不认 `VAR=value cmd` 前缀，那会让
// 整条 hook 静默失效）。runHook 默认走参数形式，与安装器写出的命令一致。
function runHook(command, mode = "zcode", extraEnv = {}) {
  const payload = JSON.stringify({
    hook_event_name: "PreToolUse", tool_name: "Bash",
    tool_input: { command }, transcript_path: "C:/tmp/x.jsonl",
  });
  const r = spawnSync(process.execPath, [HOOK, "--mode", mode], {
    encoding: "utf8", input: payload,
    env: { ...process.env, VIGILE_HOOK_MODE: "", ...extraEnv },
  });
  let parsed = null;
  try { parsed = JSON.parse(r.stdout); } catch { /* 空输出即"不干预" */ }
  return { code: r.status, out: r.stdout, decision: parsed?.hookSpecificOutput?.permissionDecision ?? null,
    reason: parsed?.hookSpecificOutput?.permissionDecisionReason ?? "",
    updated: parsed?.hookSpecificOutput?.updatedInput?.command ?? null };
}

// deny 规则必须对"非内部工具"同样生效。曾经的实现先判 needsGate 再判策略，
// 导致 rm -rf / 这类系统级危险命令根本到不了策略引擎、被直接放行。
test("hook: 非内部工具的危险命令也要 deny（rm -rf /）", () => {
  const r = runHook("rm -rf /");
  assert.equal(r.decision, "deny");
  assert.match(r.reason, /rm -rf/);
});
test("hook: 危险命令 deny 时带定制提示语", () => {
  const r = runHook("DROP TABLE orders");
  assert.equal(r.decision, "deny");
  assert.match(r.reason, /DROP/);
});
// ask 档在 hook 路径上曾整条被忽略（只处理 deny），等于确认机制不存在。
test("hook: ask 规则转成宿主确认（git reset --hard）", () => {
  const r = runHook("git reset --hard");
  assert.equal(r.decision, "ask");
  assert.match(r.reason, /丢弃|工作区/);
});
// 只返回 ask 不带改写时，用户批准后命令按原样执行，审计库只剩"曾经问过"。
// ask 与 updatedInput 可以共存（zcode 先应用改写再做权限判定），批准后仍走 vig 代理。
test("hook: ask 同时带改写，批准后仍会被审计", () => {
  const r = runHook("git reset --hard");
  assert.equal(r.decision, "ask");
  assert.match(r.updated || "", /vig.*git reset --hard$/);
});
test("hook: ask 的破坏性 kubectl 也带改写", () => {
  const r = runHook("kubectl delete pod x");
  assert.equal(r.decision, "ask");
  assert.match(r.updated || "", /vig.*kubectl delete pod x$/);
});
// 复合命令不能改写，ask 也就不该带改写（否则会改变管道语义）。
test("hook: 复合命令的 ask 不带改写", () => {
  const r = runHook("git reset --hard && echo done");
  assert.equal(r.updated, null);
});
// 内部工具命令要被改写成 vig 代理，才能真正拿到 exit_code/耗时/输出摘要。
test("hook: 内部工具命令改写为 vig 代理", () => {
  const r = runHook("shandian status");
  assert.equal(r.decision, "allow");
  assert.match(r.updated || "", /vig.*shandian status$/);
});
// VIGILE_CONFIRM 会自动通过 ask 档；hook 把命令转成显式 allow，等于放松审批门。
// 继承自 shell 环境的该变量必须在改写时剥掉（rtk 同款消毒）。
test("hook: 改写串消毒 VIGILE_CONFIRM（防环境穿透）", () => {
  const r = runHook("shandian status");
  assert.match(r.updated || "", /^env -u VIGILE_CONFIRM -u GATE_CONFIRM -u AUDIT_CONFIRM /);
});
// 改写串污染了环境也必须仍然可执行：env -u 在 bash 下有效，命令本身用 bash -c 语义检验。
test("hook: 改写串是可执行的 shell 形态（首词是 env）", () => {
  const r = runHook("shandian status");
  const first = (r.updated || "").split(/\s+/)[0];
  assert.equal(first, "env");
});
test("hook: 复合命令不改写（避免破坏管道语义）", () => {
  const r = runHook("kubectl get pods | head -5");
  assert.equal(r.out.trim(), "");
});
test("hook: 无关命令不干预", () => {
  const r = runHook("git log -3");
  assert.equal(r.out.trim(), "");
});
// dsh 桥不支持 updatedInput，必须降级为旁路记录而非改写。
test("hook: dsh 模式不改写命令", () => {
  const r = runHook("shandian status", "dsh");
  assert.equal(r.out.trim(), "");
});
// claude 模式经 --mode 参数生效（不依赖环境变量）。
test("hook: --mode claude 使能改写（参数形式，跨 shell 通用）", () => {
  const r = runHook("shandian status", "claude");
  assert.equal(r.decision, "allow");
  assert.match(r.updated || "", /vig.*shandian status$/);
});

// 安装器写出的 hook 命令必须跨 shell 可用：不得含 `VAR=value cmd` 前缀
// （Windows cmd.exe 不认，会让 hook 静默失效）。
test("setup: claude hook 命令用 --mode 参数而非环境变量前缀", () => {
  const setup = fs.readFileSync(path.join(ROOT, "..", "src", "setup.js"), "utf8");
  assert.match(setup, /--mode \$\{hostMode\}/);
  assert.doesNotMatch(setup, /VIGILE_HOOK_MODE=/);
});

// ================================================================ vig 代理形态
// vig shandian status == vigile run --quiet -- shandian status（rtk 式用法）。
// 危险模式拆开构造，避免本测试源码里的字面量被真实 hook 拦截。
test("CLI 代理: 不命中子命令即执行并审计", () => {
  const r = cli(["kubectl", "version", "--client"]);
  assert.equal(r.code, 0);
  assert.match(r.out, /Client Version/);
});
test("CLI 代理: 撞名逃逸（-- 前缀强制代理）", () => {
  const r = cli(["--", "git", "status"]);
  assert.equal(r.code, 0);   // E:/Code/work 非 git 仓库也没关系，只要不是用法错误
});
test("CLI 代理: 危险命令照样被策略拒绝", () => {
  const bad = ["rm", "-r" + "f", "/definitely/nonexistent"];
  const r = cli(bad);
  assert.equal(r.code, 3);
  assert.match(r.err, /策略拒绝|已拒绝/);
});
test("CLI 代理: 子命令仍走原分支", () => {
  const r = cli(["policy", "--test", "kubectl get pods"]);
  assert.equal(r.code, 0);
  assert.match(r.out, /allow/);
});

// ================================================================ vig init
// vig init 是 rtk 式入口：等价 setup --install --agent all，装完给出验证指引。
test("CLI init: 一键装 hook 并输出验证指引", () => {
  const r = cli(["init"]);
  assert.equal(r.code, 0);
  assert.match(r.out, /初始化完成|已注册/);
  assert.match(r.out, /vig logs/);
});
test("CLI init: init 在保留子命令列表中（不被代理形态吞掉）", () => {
  const r = cli(["init"]);
  assert.doesNotMatch(r.out, /未知命令/);
});
// install.sh 是一键安装的载体：关键环节缺一不可。
test("install.sh: 覆盖 node 版本检查/tar 安全/真实下载地址", () => {
  const sh = fs.readFileSync(path.join(ROOT, "..", "install.sh"), "utf8");
  assert.match(sh, /node.*22/);                              // node >= 22.5 检查
  assert.match(sh, /archive\/\$\{REF\}\.tar\.gz/);           // GitHub tarball
  assert.match(sh, /tar -tzf.*grep -qE/);                    // tar 路径穿越检查存在
  assert.match(sh, /releases\/latest/);                      // 版本发现
});

// Windows 上无扩展名的 sh 脚本 shim 会被 PowerShell 当"文档"执行并报
// 「无法在管道中间运行文档」；若它排在 .cmd 之前，CMD 也会被遮蔽。
// 安装器必须清理自己目录里的这类遗留，并报告 PATH 中其他冲突入口。
test("install.mjs: Windows 清理遗留 sh shim 并报告 PATH 冲突", () => {
  const m = fs.readFileSync(path.join(ROOT, "..", "install.mjs"), "utf8");
  assert.match(m, /startsWith\("#!"\)/);                     // 只删 sh 脚本
  assert.match(m, /发现其他 vig\/vigile 入口/);               // 冲突报告
});

// ================================================================ Web 控制台
// 页面 HTML 内嵌在模板字符串里：任何 \x 转义都会改变页面侧脚本语义。
// 曾经 /\+08:00$/ 被 \+ 吃掉变成 /+08:00$/，页面整个 script 语法错误、
// 停在"加载中…"。这里用与浏览器相同的方式（new Function）做语法级把关。
test("web: 页面脚本能通过 JS 语法检查（无模板转义事故）", () => {
  const web = fs.readFileSync(path.join(ROOT, "..", "src", "web.js"), "utf8");
  const html = web.slice(web.indexOf("const PAGE_HTML"));
  const script = html.match(/<script>([\s\S]*)<\/script>/)[1];
  assert.doesNotThrow(() => new Function(script));           // 浏览器同款语法检查
});
test("web: 服务含五个 API 端点且仅绑 127.0.0.1", () => {
  const web = fs.readFileSync(path.join(ROOT, "..", "src", "web.js"), "utf8");
  for (const ep of ["/api/rows", "/api/stats", "/api/get", "/api/files", "/api/verify"])
    assert.ok(web.includes(`"${ep}"`), ep);
  assert.match(web, /host = "127\.0\.0\.1"/);                 // 审计数据不出本机
});
