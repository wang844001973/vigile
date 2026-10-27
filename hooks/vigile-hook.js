#!/usr/bin/env node
// ZCode PreToolUse hook: 自动把内部系统命令包装成 audit run，实现全量审计。
//
// 原理（参考 rtk hook 的 updatedInput 改写机制）：
//   拦截 Bash 调用 → 分析命令 → 若是需要审计的内部调用且尚未包装
//   → 返回 updatedInput 把命令改写成 `vigile run --quiet -- <原命令>`
//   → ZCode 执行改写后的命令，审计自动落库
//
// 设计约束：
//   1. 失败即放行（fail-open）：任何解析/异常都不阻断原命令，审计不能影响排查。
//   2. 幂等：已经带 audit run 的命令不重复包装。
//   3. 只包装单条命令；含管道/重定向/分号/逻辑符的复合命令不改写，
//      避免语义变化（宁可漏审计，不可改行为）。
//   4. 只包装「访问本机以外内部系统」的命令，本地只读操作不动。

const { execFileSync } = require('child_process');

const HOOK_TIMEOUT = setTimeout(() => process.exit(0), 3000);

// 平台模式：claude（支持命令改写）| zcode/其他（只提醒）
// 可用 VIGILE_HOOK_MODE 覆盖；默认按 hook 来源判断
function detectMode() {
  if (process.env.VIGILE_HOOK_MODE) return process.env.VIGILE_HOOK_MODE;
  if (process.env.CLAUDE_PROJECT_DIR && !process.env.ZCODE_PROJECT_DIR) return 'claude';
  return 'zcode';
}
const MODE = detectMode();

// vigile 脚本路径：优先环境变量；否则从 hook 自身位置向上推导
// （hooks/vigile-hook.js → 上两级 = 仓库根 → scripts/vigile.py），
// 与 clone 到哪里无关，Windows/WSL/macOS 通用。
const VIGILE_SCRIPT = process.env.VIGILE_SCRIPT || (() => {
  const here = __dirname.replace(/\\/g, '/');
  return require('path').join(here, '..', 'scripts', 'vigile.py');
})();
// 解释器：Windows 上 python3 常是 WindowsApps 空壳，故默认 python；
// Linux/macOS 惯例是 python3。可用 VIGILE_PYTHON 覆盖。
const PYTHON = process.env.VIGILE_PYTHON
  || (process.platform === 'win32' ? 'python' : 'python3');

// ---- 需要审计的命令（工具名 → 是否需要包装） ----
// 匹配命令的第一个 token（允许带路径与 .exe）
const VIGILE_TOOLS = new Set([
  // 日志
  'log-query', 'online-log-query',
  // 数据库
  'bigdata-query', 'dbq', 'redash', 'psql', 'mysql', 'clickhouse-client',
  // Mongo / 数据平台
  'shandian', 'mongosh', 'mongo', 'mongoexport',
  // 工单
  'jira', 'jira-transition', 'jira_transition',
  // 内部业务 CLI
  'goods-center', 'order-center', 'knowledge-base', 'workflow-debug',
  'agentos', 'client-log-fetch', 'grafana-cli',
  // 运维
  'kubectl', 'helm',
]);

// Python 脚本形式的内部工具（判断脚本名）
const VIGILE_SCRIPTS = /(?:^|[/\\])(ticket_intake|jira|jira_transition|dialog_query|order_center|prometheus|redash|glab|agentos_execution|kb_\w+|badcase_ticket|ticket_intake)\.py$/i;

// 复合命令特征：出现则不改写（保持原语义）
const COMPLEX = /[|;&><`]|\$\(|\|\||&&/;

let buf = '';
process.stdin.setEncoding('utf8');
process.stdin.on('data', d => { buf += d; });
process.stdin.on('end', () => { clearTimeout(HOOK_TIMEOUT); decide(buf); });
process.stdin.on('error', () => { clearTimeout(HOOK_TIMEOUT); process.exit(0); });

function firstToken(cmd) {
  const trimmed = cmd.trim();
  if (!trimmed) return '';
  // 去掉前缀环境变量赋值，如 FOO=1 mycmd
  const parts = trimmed.split(/\s+/);
  let i = 0;
  while (i < parts.length && /^[A-Za-z_][A-Za-z0-9_]*=/.test(parts[i])) i++;
  return parts[i] || '';
}

function baseName(token) {
  return token.replace(/^["']|["']$/g, '').split(/[/\\]/).pop().toLowerCase().replace(/\.exe$/, '');
}

function needsGate(cmd) {
  const tok = firstToken(cmd);
  if (!tok) return false;
  const base = baseName(tok);

  // 已包装过 → 幂等跳过
  if (base === 'gate') return false;
  // rtk 代理：命令在 rtk 之后，检查它代理的真实工具
  if (base === 'rtk') {
    const after = cmd.trim().split(/\s+/).slice(1);
    if (!after.length) return false;
    return VIGILE_TOOLS.has(baseName(after[0]));
  }
  if (VIGILE_TOOLS.has(base)) return true;
  // python xxx.py 形式
  if (base === 'python' || base === 'python3') {
    const m = cmd.match(/python3?\s+(?:"[^"]+"|'[^']+'|\S+)/);
    if (m && VIGILE_SCRIPTS.test(m[0])) return true;
  }
  return false;
}

// 调 audit.py policy --test 做判定；调用失败按 allow 处理（fail-open），
// 但 audit run 自己还会再拦一道（双保险）。
function policyCheck(cmd) {
  try {
    const out = execFileSync(PYTHON, [
      VIGILE_SCRIPT, 'policy', '--test', cmd,
    ], {
      encoding: 'utf8', timeout: 2500,
      env: { ...process.env },
      input: '',
    });
    return JSON.parse(out);
  } catch (e) {
    const out = (e.stdout || '').toString();
    if (out.trim().startsWith('{')) {
      try { return JSON.parse(out); } catch (_) {}
    }
    return { decision: 'allow', reason: '策略引擎不可用', rule: 'fail-open' };
  }
}

function deny(reason) {
  // deny 对两个平台都是标准能力（ZCode 文档明确支持 deny；Claude 同样）
  process.stdout.write(JSON.stringify({
    hookSpecificOutput: {
      hookEventName: 'PreToolUse',
      permissionDecision: 'deny',
      permissionDecisionReason: reason,
    },
  }));
  process.exit(0);
}

const IS_POST = process.argv.includes('--post');

function decide(raw) {
  let payload = {};
  try { payload = JSON.parse(raw); } catch { return process.exit(0); }

  // --post 模式或 PostToolUse 事件：记录文件变更差异（只读旁路，绝不阻塞）
  if (IS_POST || payload.hook_event_name === 'PostToolUse'
      || payload.event === 'PostToolUse') {
    try { handlePostToolUse(payload); } catch (e) { /* 永不影响主流程 */ }
    process.exit(0);
  }

  if ((payload.tool_name || '') !== 'Bash') return process.exit(0);

  const input = payload.tool_input || {};
  const cmd = input.command || '';
  if (!cmd) return process.exit(0);

  // 复合命令不改写，避免改变语义
  if (COMPLEX.test(cmd)) return process.exit(0);

  if (!needsGate(cmd)) return process.exit(0);

  // ---- 策略审核（与 audit.py 同一套规则） ----
  // 让 audit.py 判定，hook 只负责按平台表达结果。
  const verdict = policyCheck(cmd);
  if (verdict.decision === 'deny') {
    deny(`[audit 策略拒绝] ${verdict.reason}。命令未执行；调整 ~/.audit/policy.json 可修改规则。`);
  }

  const rewritten = `vigile run --quiet -- ${cmd}`;

  // 平台能力差异（实测）：
  //   Claude 支持 updatedInput，可真正改写命令 → 强制审计
  //   ZCode 不支持 updatedInput（文档仅允许 additionalContext + permissionDecision），
  //         只能注入提醒，靠 agent 自觉遵守
  if (MODE === 'claude') {
    process.stdout.write(JSON.stringify({
      hookSpecificOutput: {
        hookEventName: 'PreToolUse',
        permissionDecision: 'allow',
        permissionDecisionReason: 'vigile auto-wrap',
        updatedInput: { ...input, command: rewritten },
      },
    }));
  } else {
    process.stdout.write(JSON.stringify({
      hookSpecificOutput: {
        hookEventName: 'PreToolUse',
        permissionDecision: 'allow',
        additionalContext:
          `[gate] 该命令访问内部系统但未包装。请改用：${rewritten}`,
      },
    }));
  }
  process.exit(0);
}

// ================= PostToolUse：文件变更差异记录 =================
// agent 用 Edit/Write 改完文件后，把改前/改后内容交给 gate 记 diff。
// 协议（各 agent 一致）：stdin 收 { tool_name, tool_input, tool_response }
// Edit 的 tool_input: { file_path, old_string, new_string }
// Write 的 tool_input: { file_path, content }
function handlePostToolUse(p) {
  const ti = p.tool_input || {};
  const path = ti.file_path || ti.notebook_path;
  if (!path) return;

  if (p.tool_name === 'Edit') {
    // 改前 = 文件当前内容 - old_string + new_string 已应用后
    // PostToolUse 时文件已是改后状态；改前可由 new_string 反推：
    // before = after.replace(new_string, old_string)（单次出现时精确）
    try {
      const fs = require('fs');
      let after = null;
      try { after = fs.readFileSync(path, 'utf8'); } catch (e) { /* 文件可能被移走 */ }
      let before = null;
      if (after !== null && ti.new_string && after.includes(ti.new_string)) {
        before = after.replace(ti.new_string, ti.old_string || '');
      }
      execFileSync(PYTHON, [VIGILE_SCRIPT, 'call-file-change',
        '--file', path, '--op', 'edit',
        '--before', before || '', '--after', after || ''], { timeout: 3000 });
    } catch (e) { /* 差异记录失败不影响主流程 */ }
  } else if (p.tool_name === 'Write') {
    try {
      const fs = require('fs');
      let after = null;
      try { after = fs.readFileSync(path, 'utf8'); } catch (e) {}
      // Write 是整文件覆盖；before 无法从 input 推断，留空（新增文件场景）
      execFileSync(PYTHON, [VIGILE_SCRIPT, 'call-file-change',
        '--file', path, '--op', 'write',
        '--before', '', '--after', after || ''], { timeout: 3000 });
    } catch (e) {}
  }
}
