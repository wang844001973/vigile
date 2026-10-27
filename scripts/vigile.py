#!/usr/bin/env python3
"""审计系统（audit）：记录所有内部系统调用，单库集中，支持实时查看与事后分析。

## 设计要点

**1. 单库集中**
所有审计落到一个 SQLite 文件 `~/.audit/audit.db`（可用 AUDIT_DB 覆盖）。
选 SQLite 而非 MySQL/PG：零依赖、单文件、可随案件目录迁移、支持 JSON 字段与索引，
对「本机排查场景」足够；需要跨机器汇总时再导出。

**2. 三种接入方式，覆盖所有调用形态**
- `audit run -- <任意命令>`：**包装器**，无差别覆盖二进制工具
  （企业内部 CLI / kubectl / psql / mongosh 等），不改源码。
- `audit call`：程序内埋点，Python 脚本用它记录单次 API 调用（含请求参数与响应摘要）。
- `audit import`：事后补齐，从已有日志文件导入。

**3. 记录什么**
每次调用一条记录：谁（agent/session）、什么时候、哪个工具、什么动作类型、
完整参数、耗时、结果状态、退出码、输出摘要、错误、影响行数、关联案件/工单。
参数与结果都做**脱敏**（token/密码/Authorization 一律替换）。

**4. 实时查看**
`audit tail` 持续输出；`audit watch` 按秒轮询新增；`audit live` 显示实时统计。
因为写库是即时的，任何进程查都能看到。

**5. 事后分析**
`stats`（工具/动作/状态/耗时分布）、`slow`（最慢调用）、`errors`（失败聚类）、
`by-case`（按案件汇总）、`timeline`（时间线）、`export`（CSV/JSON 供 BI）。

**6. 与案件/问题册联动**
`--case` 关联 ticket-intake 的案件目录，`--ticket` 关联工单号，
形成「问题 → 案件 → 审计流水」的完整链路。

## 表结构

audit_log:
  id            自增主键
  ts            发生时间（ISO8601，带时区）
  ts_epoch      毫秒时间戳（便于范围查询与索引）
  session       会话 ID（可用 AUDIT_SESSION 固定）
  actor         执行者（默认当前 OS 用户，可 --actor 覆盖）
  source        cli / python / import
  category      jira / sql / mongo / log / k8s / http / git / file / other
  tool          工具名（mycli / psql / kubectl / mongosh …）
  action        动作（search / query / trace / get / transition …）
  target        作用对象（表名 / 工单号 / 服务名 / URL host+path）
  args_json     完整参数（已脱敏，JSON）
  status        ok / failed / blocked / timeout / denied
  exit_code     子进程退出码（无则 NULL）
  duration_ms   耗时毫秒
  rows          影响/返回行数（能拿到时）
  result_size   输出字节数
  output_digest 输出摘要（前 2000 字，已脱敏）
  error         错误信息（已脱敏）
  case_name     关联案件
  ticket        关联工单
  risk          read / write / unknown
  meta_json     扩展字段
"""
import argparse
import getpass
import hashlib
import json
import os
import re
import shlex
import shutil
import sqlite3
import subprocess
import sys
import tempfile
import time
from datetime import datetime, timezone, timedelta
from typing import Any, Dict, List, Optional, Sequence, Tuple

CST = timezone(timedelta(hours=8))
EXIT_OK = 0
EXIT_USAGE = 2
EXIT_DENIED = 3   # 策略拒绝：命令未执行

SCHEMA = """
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
CREATE TABLE IF NOT EXISTS file_changes (
    id            INTEGER PRIMARY KEY AUTOINCREMENT,
    ts            TEXT    NOT NULL,
    ts_epoch      INTEGER NOT NULL,
    session       TEXT,
    file_path     TEXT    NOT NULL,
    op            TEXT,               -- edit / write / notebook
    before_hash   TEXT,               -- 改前内容 SHA-256（不存全文，防泄漏）
    after_hash    TEXT,
    before_size   INTEGER,
    after_size    INTEGER,
    diff          TEXT,               -- unified diff（截断到 4000 字）
    added_lines   INTEGER,
    removed_lines INTEGER,
    case_name     TEXT,
    ticket        TEXT
);
CREATE INDEX IF NOT EXISTS idx_fc_ts    ON file_changes(ts_epoch);
CREATE INDEX IF NOT EXISTS idx_fc_file  ON file_changes(file_path, ts_epoch);
CREATE INDEX IF NOT EXISTS idx_fc_case  ON file_changes(case_name, ts_epoch);
CREATE INDEX IF NOT EXISTS idx_audit_ts     ON audit_log(ts_epoch);
CREATE INDEX IF NOT EXISTS idx_audit_tool   ON audit_log(tool, ts_epoch);
CREATE INDEX IF NOT EXISTS idx_audit_case   ON audit_log(case_name, ts_epoch);
CREATE INDEX IF NOT EXISTS idx_audit_status ON audit_log(status, ts_epoch);
CREATE INDEX IF NOT EXISTS idx_audit_cat    ON audit_log(category, ts_epoch);
"""

# ---- 脱敏：只匹配明确的凭证形态，避免误伤正常参数 ----
REDACT_PATTERNS = [
    (re.compile(r"(?i)(JIRA_TOKEN|JIRA_PASS|AGENTOS_TOKEN|GKB_OPENAPI_TOKEN|"
                r"WORKFLOW_API_TOKEN|RAW_MSG_BASIC_AUTH|GOODS_CENTER_AUTHORIZATION|"
                r"KBASE_TOKEN|REDASH_\w*API_KEY|SHANDIAN_PASSWORD|CLIENT_LOG_MQTT_PASSWORD)"
                r"\s*[=:]\s*\S+"), r"\1=***"),
    (re.compile(r"(?i)(Authorization\s*:\s*\w+\s+)\S+"), r"\1***"),
    (re.compile(r"(?i)(--?(?:password|passwd|token|secret|p)\s+)\S+"), r"\1***"),
    (re.compile(r"\bpat_[A-Za-z0-9_\-]{8,}"), "pat_***"),
    (re.compile(r"(?i)(api[_-]?key=)[^\s&]+"), r"\1***"),
    (re.compile(r"(?i)(Basic\s+)[A-Za-z0-9+/=]{16,}"), r"\1***"),
]

# ---- 分类推断：从工具名/命令特征判断调用类别与读写风险 ----
# 通用默认规则（任何组织都适用）；组织特有工具通过 rules.json 覆盖，见 load_rules()
DEFAULT_TOOL_CATEGORY = {
    "kubectl": "k8s", "helm": "k8s", "docker": "k8s",
    "psql": "sql", "mysql": "sql", "sqlite3": "sql", "clickhouse-client": "sql",
    "mongo": "mongo", "mongosh": "mongo", "mongoexport": "mongo",
    "git": "git", "glab": "git", "gh": "git",
    "curl": "http", "wget": "http",
    "jq": "file", "grep": "file", "cat": "file", "less": "file", "tail": "file",
}
WRITE_HINTS = re.compile(
    r"(?i)\b(create|update|delete|drop|truncate|insert|alter|restart|publish|"
    r"transition|modify|add-comment|worklog|apply|push|merge|set|patch|put|post)\b")

_RULES_CACHE: Optional[Dict[str, Any]] = None


def rules_path() -> str:
    """规则文件：默认与审计库同目录的 rules.json，可用 AUDIT_RULES 覆盖。"""
    return (os.environ.get("VIGILE_RULES") or os.environ.get("GATE_RULES") or os.environ.get("AUDIT_RULES")
            or os.path.join(os.path.dirname(audit_db()), "rules.json"))


def load_rules() -> Dict[str, Any]:
    """加载分类/风险规则；文件不存在则用内置默认，保证开箱即用。

    rules.json（全部字段可选）:
      {
        "tools":     {"mytool": "sql"},          # 工具名 -> 分类
        "write":     {"mytool": ["deploy"]},     # 工具名 -> 判为写的动作词
        "read_only": ["mytool"]                  # 永远只读
      }
    """
    global _RULES_CACHE
    if _RULES_CACHE is not None:
        return _RULES_CACHE
    merged: Dict[str, Any] = {"tools": dict(DEFAULT_TOOL_CATEGORY),
                              "write": {}, "read_only": []}
    path = rules_path()
    if os.path.exists(path):
        try:
            with open(path, "r", encoding="utf-8") as fh:
                user = json.load(fh)
            if isinstance(user.get("tools"), dict):
                merged["tools"].update(user["tools"])
            if isinstance(user.get("write"), dict):
                merged["write"] = user["write"]
            if isinstance(user.get("read_only"), list):
                merged["read_only"] = user["read_only"]
        except (json.JSONDecodeError, OSError):
            pass  # 规则坏了就用默认，绝不因配置问题阻断审计
    _RULES_CACHE = merged
    return merged


def now_cst() -> Tuple[str, int]:
    dt = datetime.now(CST)
    return dt.isoformat(timespec="milliseconds"), int(dt.timestamp() * 1000)


def audit_db() -> str:
    """审计库路径。GATE_DB 优先，兼容旧的 AUDIT_DB。"""
    return (os.environ.get("VIGILE_DB") or os.environ.get("GATE_DB") or os.environ.get("AUDIT_DB")
            or os.path.join(os.path.expanduser("~"), ".vigile", "vigile.db"))


def session_id() -> str:
    return (os.environ.get("VIGILE_SESSION") or os.environ.get("GATE_SESSION") or os.environ.get("AUDIT_SESSION")
            or f"{getpass.getuser()}@{os.getpid()}")


def default_actor() -> str:
    return (os.environ.get("VIGILE_ACTOR") or os.environ.get("GATE_ACTOR") or os.environ.get("AUDIT_ACTOR")
            or getpass.getuser())


# ---- 多 agent 编排层上下文自动识别（目前支持 Multica）----
# 编排层（如 Multica）派发任务时会给子进程注入任务标识。
# 识别到时：审计记录的 actor/session 自动带上任务标识，
# 复盘时用 vig logs --keyword "multica:T-123" 即可按任务筛。
# 依据 Multica 官方文档（daemon 注入的环境变量）：
#   MULTICA_TASK_ID / MULTICA_AGENT_NAME / MULTICA_AGENT_ID / MULTICA_WORKSPACE_ID
#   MULTICA_DAEMON_DEVICE_NAME / MULTICA_SERVER_URL 等

MULTICA_ENV_KEYS = (
    "MULTICA_TASK_ID", "MULTICA_AGENT_NAME", "MULTICA_AGENT_ID",
    "MULTICA_WORKSPACE_ID", "MULTICA_DAEMON_DEVICE_NAME", "MULTICA_SERVER_URL",
)


def orchestrator_context() -> Dict[str, str]:
    """检测当前是否跑在某个编排层的任务进程里。返回其上下文（已脱敏键）。"""
    ctx: Dict[str, str] = {}
    for key in MULTICA_ENV_KEYS:
        val = os.environ.get(key, "").strip()
        if val:
            ctx[key] = val
    return ctx


def orchestrator_actor() -> Optional[str]:
    """在编排层任务里返回更有意义的执行者名，如 'multica/claude-1 (T-456)'。"""
    ctx = orchestrator_context()
    if not ctx:
        return None
    agent = ctx.get("MULTICA_AGENT_NAME") or ctx.get("MULTICA_AGENT_ID") or "agent"
    task = ctx.get("MULTICA_TASK_ID") or ""
    who = f"multica/{agent}"
    if task:
        who += f" ({task})"
    return who


def orchestrator_session_suffix() -> str:
    """编排层任务的 session 后缀，同一任务的多条记录归入同一会话。"""
    ctx = orchestrator_context()
    if not ctx:
        return ""
    return f"multica:{ctx.get('MULTICA_TASK_ID') or ctx.get('MULTICA_AGENT_ID') or '?'}"


SECRET_FLAGS = re.compile(
    r"(?i)^(--?(?:password|passwd|token|secret|p|api-key|apikey|auth))$")


def redact_argv(argv: Sequence[str]) -> List[str]:
    """对 argv 列表脱敏：既处理 `--token=x`，也处理 `--token x` 分开传值。"""
    out: List[str] = []
    hide_next = False
    for token in argv:
        if hide_next:
            out.append("***")
            hide_next = False
            continue
        if SECRET_FLAGS.match(token):
            out.append(token)
            hide_next = True
            continue
        if token.startswith("-") and "=" in token:
            flag, _, _ = token.partition("=")
            if SECRET_FLAGS.match(flag):
                out.append(f"{flag}=***")
                continue
        out.append(redact(token))
    return out


def redact(text: Optional[str]) -> str:
    if not text:
        return ""
    out = text
    for pattern, repl in REDACT_PATTERNS:
        out = pattern.sub(repl, out)
    return out


def connect() -> sqlite3.Connection:
    path = audit_db()
    os.makedirs(os.path.dirname(path), exist_ok=True)
    conn = sqlite3.connect(path, timeout=10)
    conn.row_factory = sqlite3.Row
    conn.executescript(SCHEMA)
    # WAL 让并发写入与实时读取互不阻塞
    # 旧库迁移：为已有的 audit_log 补 hash 链列
    try:
        existing = [r[1] for r in conn.execute("PRAGMA table_info(audit_log)")]
        if existing and "hash" not in existing:
            conn.execute("ALTER TABLE audit_log ADD COLUMN prev_hash TEXT")
            conn.execute("ALTER TABLE audit_log ADD COLUMN hash TEXT")
            conn.commit()
    except sqlite3.Error:
        pass
    conn.execute("PRAGMA journal_mode=WAL")
    conn.execute("PRAGMA synchronous=NORMAL")
    return conn


def infer_category(tool: str, args: str = "") -> str:
    base = os.path.basename(tool).lower().replace(".exe", "")
    tools = load_rules()["tools"]
    if base in tools:
        return tools[base]
    if base.endswith(".py"):
        return tools.get(base[:-3], "other")
    joined = f"{base} {args}".lower()
    if "mongo" in joined or "$set" in joined or "find(" in joined:
        return "mongo"
    if re.search(r"\b(select|insert|update|delete|explain|desc)\b", joined):
        return "sql"
    if re.search(r"\b(kubectl|k8s|deployment|pod)\b", joined):
        return "k8s"
    return "other"


def infer_risk(tool: str, args: str = "") -> str:
    base = os.path.basename(tool).lower().replace(".exe", "")
    rules = load_rules()
    if base in rules["read_only"]:
        return "read"
    words = rules["write"].get(base)
    if words and re.search(r"(?i)\b(" + "|".join(re.escape(w) for w in words) + r")\b",
                           args or ""):
        return "write"
    if re.search(r"(?i)\b(insert|update|delete|drop|truncate|alter)\b", args or ""):
        return "write"
    if WRITE_HINTS.search(args or ""):
        return "write"
    return "read"


def infer_action(tool: str, argv: Sequence[str]) -> str:
    """从命令行里挑出『子命令/动作』位：跳过 argv[0] 本身、选项与路径。"""
    tokens = list(argv)
    # argv[0] 是工具自身（可能带路径），不能当动作
    if tokens:
        tokens = tokens[1:]
    for token in tokens[:4]:
        if not token or token.startswith("-"):
            continue
        if os.sep in token or token.endswith((".py", ".exe", ".sh", ".ps1")):
            continue
        if re.fullmatch(r"[A-Z][A-Z0-9]+-\d+", token):   # 工单号不是动作
            continue
        return token[:60]
    base = os.path.basename(tool).lower().replace(".exe", "")
    return base


def infer_target(tool: str, argv: Sequence[str], args_text: str) -> str:
    """尽量提取作用对象：表名、工单号、服务名、URL host。"""
    m = re.search(r"\b([A-Z][A-Z0-9]+-\d+)\b", args_text)
    if m:
        return m.group(1)
    m = re.search(r"(?i)\bfrom\s+([\w.]+)", args_text)
    if m:
        return m.group(1)
    m = re.search(r"(?i)db\.([\w]+)\.", args_text)
    if m:
        return m.group(1)
    m = re.search(r"https?://([^/\s]+)", args_text)
    if m:
        return m.group(1)
    for token in argv:
        if re.fullmatch(r"\d{4,}", token or ""):
            continue
        if re.fullmatch(r"[A-Za-z0-9_\-\.]{3,60}", token or "") and not token.startswith("-"):
            continue
    return ""


# ---------------------------------------------------------------- 写入
def _chain_hash(prev: Optional[str], row: Dict[str, Any]) -> str:
    """hash chain：本条 hash = SHA256(上一条 hash + 本条关键字段)。

    任何记录被删改后，其后所有记录的 hash 都无法对上，
    用 `gate verify` 即可发现断链。
    """
    fields = [row.get("ts") or "", row.get("tool") or "", row.get("action") or "",
              row.get("target") or "", row.get("status") or "",
              str(row.get("exit_code") or ""), str(row.get("duration_ms") or "")]
    payload = (prev or "") + "|".join(fields)
    return hashlib.sha256(payload.encode("utf-8")).hexdigest()


def record(conn: sqlite3.Connection, **kw: Any) -> int:
    ts, epoch = now_cst()
    row = {
        "ts": ts, "ts_epoch": epoch,
        "session": kw.get("session") or (
            session_id() + ("" if not orchestrator_session_suffix()
                            else f"/{orchestrator_session_suffix()}")),
        "actor": kw.get("actor") or orchestrator_actor() or default_actor(),
        "source": kw.get("source") or "cli",
        "category": kw.get("category") or "other",
        "tool": kw.get("tool") or "unknown",
        "action": kw.get("action"),
        "target": kw.get("target"),
        "args_json": kw.get("args_json"),
        "status": kw.get("status") or "ok",
        "exit_code": kw.get("exit_code"),
        "duration_ms": kw.get("duration_ms"),
        "rows": kw.get("rows"),
        "result_size": kw.get("result_size"),
        "output_digest": kw.get("output_digest"),
        "error": kw.get("error"),
        "case_name": kw.get("case_name") or (os.environ.get("VIGILE_CASE") or os.environ.get("GATE_CASE") or os.environ.get("AUDIT_CASE")),
        "ticket": kw.get("ticket") or (os.environ.get("VIGILE_TICKET") or os.environ.get("GATE_TICKET") or os.environ.get("AUDIT_TICKET")),
        "risk": kw.get("risk"),
        "meta_json": kw.get("meta_json"),
    }
    # 编排层上下文并入 meta（不覆盖用户自带 meta）
    if orchestrator_session_suffix():
        try:
            meta = json.loads(row["meta_json"]) if row["meta_json"] else {}
        except (json.JSONDecodeError, TypeError):
            meta = {}
        meta.setdefault("orchestrator", orchestrator_context())
        row["meta_json"] = json.dumps(meta, ensure_ascii=False)
    # hash 链：取上一条的 hash 作为本条的前驱
    try:
        prev = conn.execute(
            "SELECT hash FROM audit_log WHERE hash IS NOT NULL "
            "ORDER BY id DESC LIMIT 1").fetchone()
        prev_hash = prev[0] if prev else None
    except sqlite3.Error:
        prev_hash = None
    row["prev_hash"] = prev_hash
    row["hash"] = _chain_hash(prev_hash, row)

    cols = ", ".join(row)
    marks = ", ".join("?" * len(row))
    cur = conn.execute(f"INSERT INTO audit_log ({cols}) VALUES ({marks})", list(row.values()))
    conn.commit()
    return int(cur.lastrowid)


# ---------------------------------------------------------------- 影响预览（blast radius）
# 拒绝/确认时不只说“危险”，还要告诉用户具体会影响什么。
# 参考 Anthropic blast-radius mod 的思路：用工具自身的 dry-run/status 能力测影响。

def _msys_path(path: str) -> str:
    """Git Bash/MSYS 传来的 /tmp、/c/... 转成 Windows 实际路径。

    仅在 Windows 上生效：Linux/macOS 上 /tmp 就是真临时目录、/c/... 就是普通绝对路径，
    原样返回才是正确行为。
    """
    if os.name != "nt" or not path.startswith("/"):
        return path
    # /tmp 与 /var/tmp → 用户临时目录
    if path.startswith("/tmp/") or path == "/tmp":
        return os.path.join(os.environ.get("TEMP", tempfile.gettempdir()),
                            path[5:] if len(path) > 5 else "")
    if path.startswith("/var/tmp/"):
        return os.path.join(os.environ.get("TEMP", tempfile.gettempdir()), path[9:])
    # /c/... → C:\...
    m = re.match(r"^/([a-zA-Z])/(.*)$", path)
    if m:
        return f"{m.group(1).upper()}:/{m.group(2)}"
    return path


def blast_radius(argv: Sequence[str]) -> Optional[str]:
    """对已知危险命令计算影响面。返回人类可读的影响描述；无法计算时返回 None。"""
    text = " ".join(argv)
    try:
        m = re.search(r"rm\s+(-[a-zA-Z]*r[a-zA-Z]*f?|--recursive)\b", text)
        if m:
            return _rm_impact(argv)
        m = re.search(r"git\s+push\s+.*(--force\b|-f\b|\+\S+)", text)
        if m:
            return _git_push_force_impact(argv)
        m = re.search(r"git\s+reset\s+--hard", text)
        if m:
            return _git_reset_impact()
        m = re.search(r"(?i)\b(drop|truncate)\s+(table\s+)?(\S+)", text)
        if m:
            return f"目标对象：{m.group(3)}（数据将永久丢失）"
    except Exception:
        return None
    return None


def _safe_run(cmd: Sequence[str], cwd: Optional[str] = None) -> Optional[str]:
    try:
        r = subprocess.run(cmd, capture_output=True, text=True, timeout=5,
                           encoding="utf-8", errors="replace", cwd=cwd)
        if r.returncode == 0:
            return r.stdout
    except Exception:
        pass
    return None


def _rm_impact(argv: Sequence[str]) -> Optional[str]:
    """rm -r 的影响：统计将删除的文件数与总大小（最多展示前几个路径）。"""
    targets = [_msys_path(a) for a in argv[1:]
               if not a.startswith("-") and not a.startswith("$")]
    if not targets:
        return None
    files = 0
    size = 0
    shown: List[str] = []
    for t in targets:
        if os.path.isdir(t):
            for root, _dirs, fs in os.walk(t):
                for f in fs:
                    files += 1
                    try:
                        size += os.path.getsize(os.path.join(root, f))
                    except OSError:
                        pass
                    if len(shown) < 5:
                        shown.append(os.path.join(root, f))
        elif os.path.exists(t):
            files += 1
            try:
                size += os.path.getsize(t)
            except OSError:
                pass
            shown.append(t)
    if not files:
        return None
    size_h = f"{size / 1024:.0f} KB" if size < 1024 * 1024 else f"{size / 1024 / 1024:.1f} MB"
    out = f"将删除 {files} 个文件，共约 {size_h}"
    if shown:
        out += "\n  示例：" + "\n        ".join(shown[:3])
    return out


def _git_push_force_impact(argv: Sequence[str]) -> Optional[str]:
    """force push 的影响：远端有而本地没有的提交（会被丢弃）。"""
    branch = _safe_run(["git", "rev-parse", "--abbrev-ref", "HEAD"])
    if not branch:
        return None
    branch = branch.strip()
    ahead = _safe_run(["git", "rev-list", "--count", f"origin/{branch}..HEAD"])
    behind = _safe_run(["git", "rev-list", "--count", f"HEAD..origin/{branch}"])
    if ahead is None or behind is None:
        return None
    ahead_n = int(ahead.strip() or 0)
    behind_n = int(behind.strip() or 0)
    parts = [f"分支 {branch}"]
    if behind_n:
        parts.append(f"远端领先的 {behind_n} 个提交将被覆盖丢弃")
        dropped = _safe_run(["git", "log", "--oneline", "-3", f"HEAD..origin/{branch}"])
        if dropped:
            for line in dropped.strip().splitlines()[:3]:
                parts.append(f"  丢弃: {line}")
    if ahead_n:
        parts.append(f"本地待推送 {ahead_n} 个提交")
    return "\n".join(parts)


def _git_reset_impact() -> Optional[str]:
    """git reset --hard 的影响：工作区未提交改动将被丢弃。"""
    status = _safe_run(["git", "status", "--porcelain"])
    if not status:
        return None
    lines = [l for l in status.strip().splitlines() if l.strip()]
    if not lines:
        return None
    out = f"将丢弃 {len(lines)} 个未提交改动："
    for l in lines[:5]:
        out += f"\n  {l.strip()}"
    if len(lines) > 5:
        out += f"\n  … 共 {len(lines)} 个"
    return out


# ---------------------------------------------------------------- 策略引擎
# 执行前审核：allow / ask / deny。deny 时命令不执行，记录进审计库（status=denied）。
# 策略文件 ~/.audit/policy.json，可用 AUDIT_POLICY 覆盖。

# 内置危险模式：命中即 deny（默认策略，无需配置）
# 每条规则是一个对象：id / pattern（正则）/ message（拒绝提示）/ hint（怎么改）
# message 支持占位符：{command} {tool} {match}
DEFAULT_DENY_RULES = [
    {
        "id": "rm_recursive",
        "pattern": r"\brm\s+(-[a-zA-Z]*r[a-zA-Z]*f?|--recursive)\b",
        "message": "禁止递归删除（rm -r / rm -rf）。该操作不可逆，可能删除大量数据。",
        "hint": "确需删除请逐个文件操作，或先 mv 到备份目录；清理临时文件用明确路径 + 非递归。",
    },
    {
        "id": "rm_force_recursive",
        "pattern": r"\brm\s+-[a-zA-Z]*f[a-zA-Z]*r",
        "message": "禁止强制递归删除（rm -fr）。",
        "hint": "同上：避免递归，先确认目标路径。",
    },
    {
        "id": "system_power",
        "pattern": r"\b(shutdown|reboot|halt|poweroff)\b",
        "message": "禁止关停/重启系统。会中断所有服务与正在运行的排查任务。",
        "hint": "如需重启服务，用进程管理或编排工具重启单个服务，不要重启整机。",
    },
    {
        "id": "mkfs",
        "pattern": r"\bmkfs(\.\w+)?\b",
        "message": "禁止格式化磁盘。会清空整个分区数据。",
        "hint": "格式化是不可恢复操作，需人工在控制台执行并二次确认。",
    },
    {
        "id": "dd_to_device",
        "pattern": r"\bdd\s+if=.*of=/dev/",
        "message": "禁止用 dd 直接写块设备。可能覆盖引导或分区表。",
        "hint": "写镜像请用专用工具并明确目标文件，不要直写 /dev/。",
    },
    {
        "id": "redirect_to_disk",
        "pattern": r">\s*/dev/sd[a-z]",
        "message": "禁止直接重定向写入磁盘设备。",
        "hint": "确认要写的是文件而不是设备节点。",
    },
    {
        "id": "delete_without_where",
        "pattern": r"(?i)\bdelete\s+from\s+\S+\s*$",
        "message": "禁止无 WHERE 条件的 DELETE。会清空整张表。",
        "hint": "加上 WHERE 精确限定范围；批量清理请分页并先 SELECT 确认影响行数。",
    },
    {
        "id": "update_without_where",
        "pattern": r"(?i)\bupdate\s+\S+\s+set\b(?![^;]*\bwhere\b)[^;]*$",
        "message": "禁止无 WHERE 条件的 UPDATE。会改写整张表。",
        "hint": "加上 WHERE 限定范围；先用 SELECT 验证条件命中行数。",
    },
    {
        "id": "drop_object",
        "pattern": r"(?i)\bdrop\s+(table|database|index|column)\b",
        "message": "禁止 DROP 表/库/索引/列。对象与数据将被永久删除。",
        "hint": "结构性变更走变更流程；先备份，或在测试环境验证。",
    },
    {
        "id": "truncate",
        "pattern": r"(?i)\btruncate\s+(table\s+)?\S+",
        "message": "禁止 TRUNCATE。整表数据会被清空且通常不可回滚。",
        "hint": "用带条件的 DELETE 分批清理，或走数据治理流程。",
    },
    {
        "id": "alter_drop",
        "pattern": r"(?i)\balter\s+table\s+\S+\s+drop\b",
        "message": "禁止 ALTER TABLE ... DROP。会删除列或约束。",
        "hint": "结构变更应走迁移脚本与评审，不要在排查中直接执行。",
    },
    {
        "id": "grant_all",
        "pattern": r"(?i)\bgrant\s+all\b",
        "message": "禁止 GRANT ALL。会导致权限过度放大。",
        "hint": "按最小权限原则逐项授权，并记录授权依据。",
    },
    {
        "id": "redis_flushall",
        "pattern": r"(?i)\bflushall\b",
        "message": "禁止 FLUSHALL。会清空整个 Redis 实例的所有库。",
        "hint": "按 key 精确删除；确认目标库再操作。",
    },
    {
        "id": "fsck",
        "pattern": r"(?i)\bfsck\b",
        "message": "禁止 fsck。运行中可能损坏文件系统。",
        "hint": "文件系统检查需停机并在控制台执行。",
    },
]

DEFAULT_ASK_RULES = [
    {
        "id": "delete_with_where",
        "pattern": r"(?i)\bdelete\s+from\b",
        "message": "即将执行 DELETE。请确认 WHERE 条件与影响行数。",
        "hint": "建议先跑同条件 SELECT COUNT(*) 确认范围。",
    },
    {
        "id": "update_statement",
        "pattern": r"(?i)\bupdate\s+\S+\s+set\b",
        "message": "即将执行 UPDATE。请确认 WHERE 条件与字段。",
        "hint": "建议先 SELECT 出目标行，确认无误再更新。",
    },
    {
        "id": "insert_statement",
        "pattern": r"(?i)\binsert\s+into\b",
        "message": "即将写入数据。请确认表名与字段。",
        "hint": "确认不是误写到生产库；测试数据请写测试环境。",
    },
    {
        "id": "kubectl_破坏性",
        "pattern": r"(?i)\bkubectl\s+(delete|scale|rollout\s+undo)\b",
        "message": "即将执行 kubectl 破坏性操作（delete/scale/rollout undo）。",
        "hint": "确认 namespace 与目标资源；生产集群建议走发布流程。",
    },
    {
        "id": "helm_uninstall",
        "pattern": r"(?i)\bhelm\s+(uninstall|rollback)\b",
        "message": "即将卸载或回滚 Helm release。",
        "hint": "确认 release 名称与目标环境。",
    },
    {
        "id": "git_force_push",
        "pattern": r"(?i)\bgit\s+push\s+--force\b",
        "message": "即将强制推送，会覆盖远端历史。",
        "hint": "优先用 --force-with-lease；确认分支不是共享分支。",
    },
    {
        "id": "git_reset_hard",
        "pattern": r"(?i)\bgit\s+reset\s+--hard\b",
        "message": "即将丢弃工作区未提交改动。",
        "hint": "先 git stash 或确认无需保留。",
    },
    {
        "id": "docker_remove",
        "pattern": r"(?i)\bdocker\s+(rm|rmi)\b",
        "message": "即将删除容器或镜像。",
        "hint": "确认容器不是运行中服务；镜像可重新拉取。",
    },
]

# 兼容旧字段名
DEFAULT_DENY_PATTERNS = [r["pattern"] for r in DEFAULT_DENY_RULES]
DEFAULT_ASK_PATTERNS = [r["pattern"] for r in DEFAULT_ASK_RULES]

_POLICY_CACHE: Optional[Dict[str, Any]] = None


def policy_path() -> str:
    return (os.environ.get("VIGILE_POLICY") or os.environ.get("GATE_POLICY") or os.environ.get("AUDIT_POLICY")
            or os.path.join(os.path.dirname(audit_db()), "policy.json"))


def normalize_rule(raw: Any, index: int) -> Optional[Dict[str, Any]]:
    """把规则归一化为 {id, pattern, message, hint}。

    兼容两种写法：
      "\\brm -rf\\b"                              # 旧：纯正则字符串
      {"id":..., "pattern":..., "message":..., "hint":...}  # 新：规则对象
    """
    if isinstance(raw, str):
        if not raw:
            return None
        return {"id": f"rule_{index}", "pattern": raw,
                "message": f"命中危险模式：{raw}", "hint": ""}
    if isinstance(raw, dict):
        pattern = raw.get("pattern") or ""
        if not pattern:
            return None
        return {
            "id": str(raw.get("id") or f"rule_{index}"),
            "pattern": pattern,
            "message": str(raw.get("message") or f"命中危险模式：{pattern}"),
            "hint": str(raw.get("hint") or ""),
        }
    return None


def load_policy() -> Dict[str, Any]:
    """加载策略。文件不存在时用内置默认；结构损坏时退回内置默认。

    内置危险规则始终生效（即使配置文件损坏或用户只补了部分规则）。
    """
    global _POLICY_CACHE
    if _POLICY_CACHE is not None:
        return _POLICY_CACHE

    deny_rules = [dict(r) for r in DEFAULT_DENY_RULES]
    ask_rules = [dict(r) for r in DEFAULT_ASK_RULES]
    allow_tools: List[str] = []
    deny_tools: List[str] = []

    path = policy_path()
    if os.path.exists(path):
        try:
            with open(path, "r", encoding="utf-8") as fh:
                user = json.load(fh)
            # 用户规则**追加**在内置之后，可覆盖同名 id
            for key, bucket in (("deny", deny_rules), ("ask", ask_rules)):
                for i, raw in enumerate(user.get(key) or []):
                    rule = normalize_rule(raw, i)
                    if not rule:
                        continue
                    for j, existing in enumerate(bucket):
                        if existing.get("id") == rule["id"]:
                            bucket[j] = rule
                            break
                    else:
                        bucket.append(rule)
            if isinstance(user.get("allow_tools"), list):
                allow_tools = [str(t).lower() for t in user["allow_tools"]]
            if isinstance(user.get("deny_tools"), list):
                deny_tools = [str(t).lower() for t in user["deny_tools"]]
        except (json.JSONDecodeError, OSError):
            pass

    _POLICY_CACHE = {
        "deny_rules": deny_rules,
        "ask_rules": ask_rules,
        "allow_tools": allow_tools,
        "deny_tools": deny_tools,
    }
    return _POLICY_CACHE


class Denied(Exception):
    """策略拒绝。message 是给 agent/人看的拒绝理由。"""

    def __init__(self, reason: str, rule: str, decision: str = "deny"):
        super().__init__(reason)
        self.reason = reason
        self.rule = rule
        self.decision = decision


def evaluate(tool: str, argv: Sequence[str], args_text: str = "") -> Dict[str, Any]:
    """执行前审核。返回 {decision, reason, rule}。

    判定顺序（先命中先生效）：
      1. allow_tools 白名单 → allow
      2. deny_tools 黑名单 → deny
      3. deny 模式（含内置危险模式）→ deny
      4. ask 模式 → ask（需确认）
      5. 默认 → allow
    """
    base = os.path.basename(tool).lower().replace(".exe", "")
    policy = load_policy()
    text = args_text or " ".join(argv)

    if base in policy["allow_tools"]:
        return {"decision": "allow", "reason": "白名单工具", "rule": f"allow_tools:{base}",
                "rule_id": f"allow_tools:{base}", "message": "", "hint": ""}

    if base in policy["deny_tools"]:
        return {"decision": "deny",
                "reason": f"工具 {base} 在黑名单，禁止调用",
                "rule": f"deny_tools:{base}",
                "rule_id": f"deny_tools:{base}",
                "message": f"工具「{base}」已被列入禁用名单，本机不允许调用。",
                "hint": "如确需使用，请从 ~/.audit/policy.json 的 deny_tools 中移除。"}

    def hit(rule: Dict[str, Any], decision: str) -> Dict[str, Any]:
        match = ""
        try:
            m = re.search(rule["pattern"], text)
            match = m.group(0)[:120] if m else ""
        except re.error:
            pass
        msg = (rule["message"]
               .replace("{tool}", base)
               .replace("{command}", text[:200])
               .replace("{match}", match))
        return {"decision": decision, "reason": msg,
                "rule": f"{decision}:{rule['id']}", "rule_id": rule["id"],
                "message": msg, "hint": rule.get("hint", ""), "match": match}

    import warnings
    with warnings.catch_warnings():
        # 用户自定义正则可能把 (?i) 写在中间，Python 会告警但不影响匹配
        warnings.simplefilter("ignore", DeprecationWarning)
        for rule in policy["deny_rules"]:
            try:
                if re.search(rule["pattern"], text):
                    return hit(rule, "deny")
            except re.error:
                continue

        for rule in policy["ask_rules"]:
            try:
                if re.search(rule["pattern"], text):
                    return hit(rule, "ask")
            except re.error:
                continue

    return {"decision": "allow", "reason": "默认放行", "rule": "default",
            "rule_id": "default", "message": "", "hint": ""}


def confirm_prompt(verdict: Dict[str, Any], argv: Sequence[str]) -> bool:
    """ask 决策的确认。非交互（无 tty / AUDIT_CONFIRM）时默认拒绝——宁可拒绝不可误放。"""
    env = (os.environ.get("VIGILE_CONFIRM") or os.environ.get("GATE_CONFIRM") or os.environ.get("AUDIT_CONFIRM", "")).strip().lower()
    if env in ("yes", "y", "1", "true"):
        return True
    if not sys.stdin.isatty():
        return False  # agent 调用无终端，必须显式 AUDIT_CONFIRM
    try:
        print(f"[vigile] 需要确认: {verdict.get('message') or verdict['reason']}", file=sys.stderr)
        if verdict.get("hint"):
            print(f"[vigile] 建议: {verdict['hint']}", file=sys.stderr)
        print(f"[vigile] 命令: {' '.join(argv)}", file=sys.stderr)
        answer = input("[vigile] 确认执行? 输入 yes 执行: ").strip().lower()
        return answer in ("yes", "y")
    except (EOFError, KeyboardInterrupt):
        return False


# ---------------------------------------------------------------- audit run
def cmd_run(args: argparse.Namespace) -> int:
    """包装任意命令：先审核，再执行，全程审计，透传 stdout/stderr 与退出码。"""
    argv = args.command
    if not argv:
        print("用法: audit run [--case X] [--ticket Y] -- <命令...>", file=sys.stderr)
        return EXIT_USAGE
    # 允许 `--` 之后的命令里带自己的参数
    if argv and argv[0] == "--":
        argv = argv[1:]

    tool = argv[0]
    resolved = shutil.which(tool) or tool
    args_text = " ".join(shlex.quote(a) for a in argv)
    category = infer_category(tool, args_text)
    risk = infer_risk(tool, args_text)
    action = infer_action(tool, argv)
    target = infer_target(tool, argv, args_text)

    conn = connect()

    # ---- 执行前审核（核心：拒绝的命令根本不会运行）----
    if not args.no_policy:
        verdict = evaluate(tool, argv, args_text)
        if verdict["decision"] == "deny":
            record(conn, source="cli", category=category,
                   tool=os.path.basename(tool), action=action, target=target,
                   args_json=json.dumps({"argv": redact_argv(argv), "cwd": os.getcwd()},
                                        ensure_ascii=False),
                   status="denied", duration_ms=0, risk="write",
                   error=f"[策略拒绝/{verdict.get('rule_id')}] {verdict.get('message') or verdict['reason']}",
                   case_name=args.case, ticket=args.ticket,
                   meta_json=json.dumps({"policy_rule": verdict["rule"]},
                                        ensure_ascii=False))
            print(f"[vigile] 已拒绝执行（规则 {verdict.get('rule_id')}）", file=sys.stderr)
            print(f"[vigile] {verdict.get('message') or verdict['reason']}", file=sys.stderr)
            if verdict.get("hint"):
                print(f"[vigile] 建议：{verdict['hint']}", file=sys.stderr)
            impact = blast_radius(argv)
            if impact:
                print(f"[vigile] 影响预览：{impact}", file=sys.stderr)
            print(f"[vigile] 命令未运行。", file=sys.stderr)
            return EXIT_DENIED
        if verdict["decision"] == "ask":
            if not args.yes and not confirm_prompt(verdict, argv):
                record(conn, source="cli", category=category,
                       tool=os.path.basename(tool), action=action, target=target,
                       args_json=json.dumps({"argv": redact_argv(argv), "cwd": os.getcwd()},
                                            ensure_ascii=False),
                       status="denied", duration_ms=0, risk="write",
                       error=f"[需确认未确认/{verdict.get('rule_id')}] {verdict.get('message') or verdict['reason']}",
                       case_name=args.case, ticket=args.ticket,
                       meta_json=json.dumps({"policy_rule": verdict["rule"]},
                                            ensure_ascii=False))
                print(f"[vigile] 需要确认（未确认，拒绝执行）规则 {verdict.get('rule_id')}",
                      file=sys.stderr)
                print(f"[vigile] {verdict.get('message') or verdict['reason']}", file=sys.stderr)
                if verdict.get("hint"):
                    print(f"[vigile] 建议：{verdict['hint']}", file=sys.stderr)
                impact = blast_radius(argv)
                if impact:
                    print(f"[vigile] 影响预览：{impact}", file=sys.stderr)
                print("[vigile] 确认无误后加 -y 或 GATE_CONFIRM=yes 执行。", file=sys.stderr)
                return EXIT_DENIED

    started = time.time()
    out_chunks: List[str] = []
    err_chunks: List[str] = []
    exit_code: Optional[int] = None
    status = "ok"
    error_text = ""
    try:
        proc = subprocess.run(argv, capture_output=True, text=True, encoding="utf-8",
                              errors="replace", shell=False)
        exit_code = proc.returncode
        out_chunks.append(proc.stdout or "")
        err_chunks.append(proc.stderr or "")
        if proc.returncode != 0:
            status = "failed"
            error_text = (proc.stderr or "")[:1000]
    except FileNotFoundError:
        status = "failed"
        error_text = f"命令不存在: {tool}"
        exit_code = 127
    except subprocess.TimeoutExpired:
        status = "timeout"
        error_text = "命令超时"
        exit_code = 124
    except KeyboardInterrupt:
        status = "blocked"
        error_text = "用户中断"
        exit_code = 130
    duration_ms = int((time.time() - started) * 1000)

    stdout_text = "".join(out_chunks)
    stderr_text = "".join(err_chunks)
    # 超时/限流类错误要单独归类，便于后续统计
    if status == "failed" and re.search(r"(?i)(timeout|超时|deadline)", error_text):
        status = "timeout"

    rid = record(
        conn, source="cli", category=category, tool=os.path.basename(tool),
        action=action, target=target,
        args_json=json.dumps({"argv": redact_argv(argv), "cwd": os.getcwd()},
                             ensure_ascii=False),
        status=status, exit_code=exit_code, duration_ms=duration_ms,
        result_size=len(stdout_text.encode("utf-8", "replace")),
        output_digest=redact(stdout_text)[:2000] or None,
        error=redact(error_text) or None,
        risk=risk, case_name=args.case, ticket=args.ticket,
    )
    # 原样透传输出，不改变工具行为
    if stdout_text:
        sys.stdout.write(stdout_text)
    if stderr_text:
        sys.stderr.write(stderr_text)
    if not args.quiet:
        print(f"\n[audit] #{rid} {status} {duration_ms}ms → {audit_db()}", file=sys.stderr)
    return exit_code if exit_code is not None else 1


# ---------------------------------------------------------------- audit call（程序内埋点）
def cmd_call(args: argparse.Namespace) -> int:
    conn = connect()
    rid = record(
        conn, source="python", category=args.category, tool=args.tool,
        action=args.action, target=args.target,
        args_json=redact(args.args) if args.args else None,
        status=args.status, exit_code=args.exit_code, duration_ms=args.duration,
        rows=args.rows, result_size=args.result_size,
        output_digest=redact(args.output)[:2000] if args.output else None,
        error=redact(args.error), risk=args.risk,
        case_name=args.case, ticket=args.ticket,
        meta_json=redact(args.meta) if args.meta else None,
    )
    print(json.dumps({"id": rid, "db": audit_db()}, ensure_ascii=False))
    return EXIT_OK


def log_call(tool: str, action: str = "", **kw: Any) -> int:
    """供其它脚本直接 import 使用的埋点函数。"""
    conn = connect()
    return record(conn, source="python", tool=tool, action=action, **kw)


# ---------------------------------------------------------------- 查询
def build_filters(args: argparse.Namespace) -> Tuple[str, List[Any]]:
    where: List[str] = []
    params: List[Any] = []
    if getattr(args, "tool", None):
        where.append("tool = ?")
        params.append(args.tool)
    if getattr(args, "category", None):
        where.append("category = ?")
        params.append(args.category)
    if getattr(args, "status", None):
        where.append("status = ?")
        params.append(args.status)
    if getattr(args, "case", None):
        where.append("case_name = ?")
        params.append(args.case)
    if getattr(args, "ticket", None):
        where.append("ticket = ?")
        params.append(args.ticket)
    if getattr(args, "risk", None):
        where.append("risk = ?")
        params.append(args.risk)
    if getattr(args, "since", None):
        where.append("ts_epoch >= ?")
        params.append(parse_since(args.since))
    if getattr(args, "keyword", None):
        where.append("(args_json LIKE ? OR output_digest LIKE ? OR error LIKE ? "
                     "OR target LIKE ? OR session LIKE ? OR actor LIKE ?)")
        k = f"%{args.keyword}%"
        params += [k, k, k, k, k, k]
    return (" WHERE " + " AND ".join(where)) if where else "", params


def parse_since(text: str) -> int:
    """支持 30m / 2h / 7d / 2026-10-27 12:00:00。"""
    m = re.fullmatch(r"(\d+)([mhd])", text.strip())
    if m:
        n, unit = int(m.group(1)), m.group(2)
        sec = n * {"m": 60, "h": 3600, "d": 86400}[unit]
        return int((time.time() - sec) * 1000)
    for fmt in ("%Y-%m-%d %H:%M:%S", "%Y-%m-%d"):
        try:
            dt = datetime.strptime(text, fmt).replace(tzinfo=CST)
            return int(dt.timestamp() * 1000)
        except ValueError:
            continue
    raise UsageError(f"无法解析时间: {text}（支持 30m/2h/7d 或 2026-10-27 12:00:00）")


class UsageError(Exception):
    pass


def fmt_row(r: sqlite3.Row, width: int = 96) -> str:
    ts = (r["ts"] or "")[11:23]
    dur = f"{r['duration_ms']}ms" if r["duration_ms"] is not None else "-"
    bits = [f"#{r['id']:<6}", ts, f"{(r['status'] or ''):<7}", f"{(r['tool'] or ''):<16}",
            f"{(r['action'] or ''):<12}", f"{dur:>8}"]
    line = " ".join(bits)
    extra = r["target"] or r["error"] or ""
    if extra:
        line += f"  {str(extra)[:width]}"
    return line


def cmd_logs(args: argparse.Namespace) -> int:
    conn = connect()
    where, params = build_filters(args)
    sql = f"SELECT * FROM audit_log{where} ORDER BY ts_epoch DESC LIMIT ?"
    params = params + [args.limit]
    rows = conn.execute(sql, params).fetchall()
    if args.json:
        print(json.dumps([dict(r) for r in rows], ensure_ascii=False, indent=2))
        return EXIT_OK
    if not rows:
        print("（无记录）")
        return EXIT_OK
    for r in rows:
        print(fmt_row(r))
    return EXIT_OK


def cmd_tail(args: argparse.Namespace) -> int:
    """实时跟踪新增记录。"""
    conn = connect()
    last = conn.execute("SELECT COALESCE(MAX(id),0) AS m FROM audit_log").fetchone()["m"]
    if not args.no_existing:
        for r in conn.execute(
                "SELECT * FROM audit_log ORDER BY id DESC LIMIT ?", (args.lines,)).fetchall()[::-1]:
            print(fmt_row(r), flush=True)
    print(f"[vigile] 跟踪中（Ctrl+C 退出）… {audit_db()}", file=sys.stderr, flush=True)
    try:
        while True:
            rows = conn.execute(
                "SELECT * FROM audit_log WHERE id > ? ORDER BY id LIMIT 200", (last,)).fetchall()
            for r in rows:
                print(fmt_row(r), flush=True)
                last = r["id"]
            time.sleep(args.interval)
    except KeyboardInterrupt:
        return EXIT_OK


def cmd_stats(args: argparse.Namespace) -> int:
    conn = connect()
    where, params = build_filters(args)
    def q(sql: str) -> List[sqlite3.Row]:
        return conn.execute(sql.replace("{W}", where), params).fetchall()

    total = q("SELECT COUNT(*) c FROM audit_log{W}")[0]["c"]
    if not total:
        print("（无记录）")
        return EXIT_OK
    print(f"总调用 {total} 次")
    print("\n按工具：")
    for r in q("SELECT tool, COUNT(*) c, SUM(status='ok') ok, SUM(status!='ok') bad,"
               " ROUND(AVG(duration_ms)) avg_ms, MAX(duration_ms) max_ms"
               " FROM audit_log{W} GROUP BY tool ORDER BY c DESC LIMIT 20"):
        print(f"  {r['tool']:<18} {r['c']:>5}次  ok={r['ok']:<5} bad={r['bad']:<4}"
              f" 平均{r['avg_ms'] or 0}ms 最慢{r['max_ms'] or 0}ms")
    print("\n按状态：")
    for r in q("SELECT status, COUNT(*) c FROM audit_log{W} GROUP BY status ORDER BY c DESC"):
        print(f"  {r['status']:<10} {r['c']}")
    print("\n按分类：")
    for r in q("SELECT category, COUNT(*) c FROM audit_log{W} GROUP BY category ORDER BY c DESC"):
        print(f"  {r['category']:<12} {r['c']}")
    print("\n按风险：")
    for r in q("SELECT COALESCE(risk,'-') r, COUNT(*) c FROM audit_log{W} GROUP BY r ORDER BY c DESC"):
        print(f"  {r['r']:<10} {r['c']}")
    return EXIT_OK


def cmd_slow(args: argparse.Namespace) -> int:
    conn = connect()
    where, params = build_filters(args)
    clause = (where + " AND duration_ms IS NOT NULL") if where else " WHERE duration_ms IS NOT NULL"
    rows = conn.execute(
        f"SELECT * FROM audit_log{clause} "
        f"ORDER BY duration_ms DESC LIMIT ?", params + [args.limit]).fetchall()
    if not rows:
        print("（无记录）")
        return EXIT_OK
    for r in rows:
        print(f"{r['duration_ms']:>8}ms  {(r['tool'] or ''):<16} {(r['action'] or ''):<12}"
              f" {r['status']:<8} {(r['target'] or '')[:60]}")
    return EXIT_OK


def cmd_errors(args: argparse.Namespace) -> int:
    conn = connect()
    where, params = build_filters(args)
    clause = (where + " AND status != 'ok'") if where else " WHERE status != 'ok'"
    rows = conn.execute(
        f"SELECT tool, status, COUNT(*) c, MIN(ts) first_ts, MAX(ts) last_ts,"
        f" SUBSTR(COALESCE(error,''),1,80) err"
        f" FROM audit_log{clause}"
        f" GROUP BY tool, status, err ORDER BY c DESC LIMIT ?", params + [args.limit]).fetchall()
    if not rows:
        print("（无失败记录）")
        return EXIT_OK
    for r in rows:
        print(f"{r['c']:>4}次  {r['tool']:<16} {r['status']:<8} {(r['err'] or '').strip()[:70]}")
        print(f"       首次 {r['first_ts']}  最近 {r['last_ts']}")
    return EXIT_OK


def cmd_by_case(args: argparse.Namespace) -> int:
    conn = connect()
    rows = conn.execute(
        "SELECT COALESCE(case_name,'(未关联)') c, COUNT(*) n,"
        " MIN(ts) first_ts, MAX(ts) last_ts,"
        " GROUP_CONCAT(DISTINCT tool) tools"
        " FROM audit_log GROUP BY c ORDER BY n DESC LIMIT ?", (args.limit,)).fetchall()
    for r in rows:
        print(f"{r['n']:>5}次  {r['c']:<28} {r['first_ts'][:19]} ~ {r['last_ts'][11:19]}")
        print(f"        工具: {(r['tools'] or '')[:90]}")
    return EXIT_OK


def cmd_timeline(args: argparse.Namespace) -> int:
    conn = connect()
    where, params = build_filters(args)
    rows = conn.execute(
        f"SELECT * FROM audit_log{where} ORDER BY ts_epoch ASC LIMIT ?",
        params + [args.limit]).fetchall()
    for r in rows:
        mark = {"ok": "✓", "failed": "✗", "timeout": "⏱", "blocked": "⊘", "denied": "⛔"}.get(
            r["status"], "?")
        print(f"{(r['ts'] or '')[11:19]} {mark} {(r['tool'] or ''):<16}"
              f"{(r['action'] or ''):<12}{(r['target'] or '')[:40]:<42}"
              f"{r['duration_ms'] or 0:>7}ms")
    return EXIT_OK


def cmd_export(args: argparse.Namespace) -> int:
    conn = connect()
    where, params = build_filters(args)
    rows = conn.execute(f"SELECT * FROM audit_log{where} ORDER BY ts_epoch",
                        params).fetchall()
    data = [dict(r) for r in rows]
    if args.format == "csv":
        import csv
        if not data:
            print("（无记录）", file=sys.stderr)
            return EXIT_OK
        writer = csv.DictWriter(sys.stdout, fieldnames=list(data[0].keys()))
        writer.writeheader()
        writer.writerows(data)
    else:
        print(json.dumps(data, ensure_ascii=False, indent=2))
    if args.out and args.format != "csv":
        with open(args.out, "w", encoding="utf-8") as fh:
            json.dump(data, fh, ensure_ascii=False, indent=2)
    return EXIT_OK


def cmd_get(args: argparse.Namespace) -> int:
    conn = connect()
    row = conn.execute("SELECT * FROM audit_log WHERE id = ?", (args.id,)).fetchone()
    if not row:
        print(f"未找到 #{args.id}", file=sys.stderr)
        return EXIT_USAGE
    print(json.dumps(dict(row), ensure_ascii=False, indent=2))
    return EXIT_OK


def cmd_policy(args: argparse.Namespace) -> int:
    """查看 / 初始化 / 测试执行策略。"""
    if args.test:
        parts = args.test.split()
        tool = parts[0] if parts else ""
        argv = parts
        text = " ".join(parts)
        verdict = evaluate(tool, argv, text)
        print(json.dumps({"command": args.test, **verdict}, ensure_ascii=False, indent=2))
        return EXIT_OK if verdict["decision"] != "deny" else EXIT_DENIED

    if args.init:
        path = policy_path()
        if os.path.exists(path) and not args.force:
            print(f"已存在: {path}（加 --force 覆盖）", file=sys.stderr)
            return EXIT_USAGE
        os.makedirs(os.path.dirname(path) or ".", exist_ok=True)
        template = {
            "_comment": ("执行策略。每条规则：id（唯一标识）/ pattern（正则）/"
                         "message（拒绝提示，支持 {command} {tool} {match}）/"
                         "hint（整改建议）。用户规则追加在内置之后，同 id 会覆盖内置。"),
            "deny": [dict(r) for r in DEFAULT_DENY_RULES],
            "ask": [dict(r) for r in DEFAULT_ASK_RULES],
            "allow_tools": [],
            "deny_tools": [],
        }
        with open(path, "w", encoding="utf-8") as fh:
            json.dump(template, fh, ensure_ascii=False, indent=2)
        print(f"已生成策略模板: {path}")
        return EXIT_OK

    policy = load_policy()
    print(json.dumps({
        "policy_file": policy_path(),
        "exists": os.path.exists(policy_path()),
        "deny_rules": [
            {"id": r["id"], "message": r["message"], "hint": r.get("hint", "")}
            for r in policy["deny_rules"]
        ],
        "ask_rules": [
            {"id": r["id"], "message": r["message"], "hint": r.get("hint", "")}
            for r in policy["ask_rules"]
        ],
        "allow_tools": policy["allow_tools"],
        "deny_tools": policy["deny_tools"],
    }, ensure_ascii=False, indent=2))
    return EXIT_OK


def cmd_setup(args: argparse.Namespace) -> int:
    """转发给 vigile_setup.py（保持主命令单文件入口）。"""
    import vigile_setup
    argv = []
    if args.install: argv.append("--install")
    if args.uninstall: argv.append("--uninstall")
    if args.status: argv.append("--status")
    if args.list: argv.append("--list")
    for a in args.agents or []:
        argv += ["--agent", a]
    return vigile_setup.main(argv)


def cmd_verify(args: argparse.Namespace) -> int:
    """验证审计链完整性：逐条重算 hash，检测任何被删除/篡改的记录。"""
    conn = connect()
    rows = conn.execute(
        "SELECT id, ts, tool, action, target, status, exit_code, duration_ms, "
        "prev_hash, hash FROM audit_log ORDER BY id").fetchall()
    if not rows:
        print("（无记录）")
        return EXIT_OK

    prev_hash: Optional[str] = None
    broken = 0
    legacy = 0   # hash 链启用前的旧记录（无 hash），不算篡改
    for r in rows:
        if r["hash"] is None:
            legacy += 1
            prev_hash = None
            continue
        expected = _chain_hash(r["prev_hash"], {
            "ts": r["ts"], "tool": r["tool"], "action": r["action"],
            "target": r["target"], "status": r["status"],
            "exit_code": r["exit_code"], "duration_ms": r["duration_ms"],
        })
        chain_ok = (r["prev_hash"] == prev_hash) if prev_hash or r["prev_hash"] else True
        if r["hash"] != expected or not chain_ok:
            broken += 1
            print(f"  ❌ #{r['id']} hash 不匹配（记录可能被篡改或前后被删）")
        prev_hash = r["hash"]
    total = len(rows)
    chained = total - legacy
    if not broken:
        msg = f"✅ {total} 条记录"
        if legacy:
            msg += f"（{legacy} 条为 hash 链启用前的旧记录，跳过校验）"
        msg += f"，hash 链完整（未被篡改/删除）"
        print(msg)
        return EXIT_OK
    print(f"❌ {broken}/{chained} 条链上记录异常", file=sys.stderr)
    return 1


# ---------------------------------------------------------------- 文件变更（post-tool diff）
import difflib


def record_file_change(file_path: str, op: str, before: Optional[str],
                       after: Optional[str],
                       case_name: Optional[str] = None,
                       ticket: Optional[str] = None) -> int:
    """记录一次文件改动。内容只存 SHA-256 与截断的 unified diff，不存全文。"""
    conn = connect()
    ts, epoch = now_cst()
    diff_lines = list(difflib.unified_diff(
        (before or "").splitlines(keepends=True),
        (after or "").splitlines(keepends=True),
        fromfile=f"a/{os.path.basename(file_path)}",
        tofile=f"b/{os.path.basename(file_path)}", n=3))
    diff_text = "".join(diff_lines)[:4000]
    added = sum(1 for l in diff_lines if l.startswith("+") and not l.startswith("+++"))
    removed = sum(1 for l in diff_lines if l.startswith("-") and not l.startswith("---"))
    cur = conn.execute(
        "INSERT INTO file_changes (ts, ts_epoch, session, file_path, op, "
        "before_hash, after_hash, before_size, after_size, diff, "
        "added_lines, removed_lines, case_name, ticket) "
        "VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?)",
        (ts, epoch, session_id(), file_path, op,
         hashlib.sha256((before or "").encode("utf-8", "replace")).hexdigest() if before else None,
         hashlib.sha256((after or "").encode("utf-8", "replace")).hexdigest() if after else None,
         len((before or "").encode("utf-8", "replace")),
         len((after or "").encode("utf-8", "replace")),
         diff_text, added, removed,
         case_name or os.environ.get("GATE_CASE"),
         ticket or os.environ.get("GATE_TICKET")))
    conn.commit()
    return int(cur.lastrowid)


def cmd_call_file_change(args: argparse.Namespace) -> int:
    """hook 从 PostToolUse 调用：记录文件改前/改后。"""
    rid = record_file_change(args.file, args.op,
                             args.before or None, args.after or None,
                             case_name=args.case, ticket=args.ticket)
    print(json.dumps({"id": rid}, ensure_ascii=False))
    return EXIT_OK


def cmd_diff(args: argparse.Namespace) -> int:
    """查看文件变更记录（post-tool diff）。"""
    conn = connect()
    where, params = [], []
    if args.file:
        where.append("file_path LIKE ?")
        params.append(f"%{args.file}%")
    if args.case:
        where.append("case_name = ?")
        params.append(args.case)
    clause = (" WHERE " + " AND ".join(where)) if where else ""
    rows = conn.execute(
        f"SELECT * FROM file_changes{clause} ORDER BY ts_epoch DESC LIMIT ?",
        params + [args.limit]).fetchall()
    if not rows:
        print("（无变更记录）")
        return EXIT_OK
    for r in rows:
        print(f"#{r['id']} {(r['ts'] or '')[11:19]} {r['op']:<6} "
              f"+{r['added_lines']}/-{r['removed_lines']}  {r['file_path']}")
        if args.show:
            print(r["diff"] or "  （无 diff）")
            print()
    return EXIT_OK


def cmd_session(args: argparse.Namespace) -> int:
    """会话视图：一次会话的全部调用 + 文件变更，按时间线展示。

    不给 id 时列出最近会话。"""
    conn = connect()
    if not args.id:
        rows = conn.execute(
            "SELECT session, COUNT(*) n, MIN(ts) first_ts, MAX(ts) last_ts, "
            "SUM(status!='ok') bad, "
            "SUM(COALESCE(risk,'')='write') writes "
            "FROM audit_log GROUP BY session ORDER BY MAX(ts_epoch) DESC LIMIT ?",
            (args.limit,)).fetchall()
        if not rows:
            print("（无记录）")
            return EXIT_OK
        print(f"{'会话':<24}{'次数':>4}{'写':>4}{'失败':>4}  时间范围")
        for r in rows:
            print(f"{(r['session'] or '-')[:24]:<24}{r['n']:>4}{r['writes'] or 0:>4}"
                  f"{r['bad'] or 0:>4}  {(r['first_ts'] or '')[5:19]} ~ {(r['last_ts'] or '')[11:19]}")
        print("\n用 gate session <id> 查看详情")
        return EXIT_OK

    sid = args.id
    calls = conn.execute(
        "SELECT * FROM audit_log WHERE session = ? ORDER BY ts_epoch",
        (sid,)).fetchall()
    changes = conn.execute(
        "SELECT * FROM file_changes WHERE session = ? ORDER BY ts_epoch",
        (sid,)).fetchall()
    if not calls and not changes:
        print(f"会话 {sid} 无记录")
        return EXIT_OK

    # 合并时间线
    events = [("call", r) for r in calls] + [("file", r) for r in changes]
    events.sort(key=lambda x: x[1]["ts_epoch"])
    print(f"会话 {sid}：{len(calls)} 次调用，{len(changes)} 次文件变更\n")
    for kind, r in events:
        ts = (r["ts"] or "")[11:19]
        if kind == "call":
            mark = {"ok": "✓", "failed": "✗", "timeout": "⏱",
                    "blocked": "⊘", "denied": "⛔"}.get(r["status"], "?")
            print(f"{ts} {mark} {(r['tool'] or ''):<16}{(r['action'] or ''):<12}"
                  f"{(r['target'] or '')[:44]:<46}{r['duration_ms'] or 0:>6}ms")
        else:
            print(f"{ts} ✎ {(r['op'] or ''):<6} +{r['added_lines']}/-{r['removed_lines']}"
                  f"  {r['file_path']}")
    return EXIT_OK


def cmd_rules(args: argparse.Namespace) -> int:
    """查看当前生效规则；--init 生成模板供填写组织特有工具。"""
    rules = load_rules()
    if args.init:
        path = rules_path()
        if os.path.exists(path) and not args.force:
            print(f"已存在: {path}（加 --force 覆盖）", file=sys.stderr)
            return EXIT_USAGE
        os.makedirs(os.path.dirname(path) or ".", exist_ok=True)
        template = {
            "_comment": "工具名 -> 分类（log/sql/mongo/k8s/http/git/file/other）",
            "tools": {"mytool": "sql", "mycli": "http"},
            "_comment_write": "工具名 -> 判为写操作的动作词（其余按通用规则）",
            "write": {"kubectl": ["apply", "delete", "create", "edit", "patch",
                                  "scale", "rollout"]},
            "_comment_read_only": "永远判为只读的工具名",
            "read_only": [],
        }
        with open(path, "w", encoding="utf-8") as fh:
            json.dump(template, fh, ensure_ascii=False, indent=2)
        print(f"已生成模板: {path}")
        print("按需填写后自动生效（下次调用即读取）。")
        return EXIT_OK
    print(json.dumps({"rules_file": rules_path(),
                      "exists": os.path.exists(rules_path()),
                      "tools": rules["tools"],
                      "write": rules["write"],
                      "read_only": rules["read_only"]},
                     ensure_ascii=False, indent=2))
    return EXIT_OK


def cmd_prune(args: argparse.Namespace) -> int:
    conn = connect()
    cutoff = parse_since(args.keep)
    n = conn.execute("DELETE FROM audit_log WHERE ts_epoch < ?", (cutoff,)).rowcount
    conn.commit()
    conn.execute("VACUUM")
    print(f"已清理 {n} 条（保留 {args.keep} 内）")
    return EXIT_OK


# ---------------------------------------------------------------- CLI
EXAMPLES = """示例:
  # 包装任意命令（推荐：无需改工具源码）
  audit run --case case-001 -- mycli trace abc123
  audit run --ticket PROJ-123 -- myq sql "select * from dwd.orders limit 10"
  audit run -- mongosh --eval "db.orders.find({status:'new'}).limit(5)" \\
      

  # 程序内埋点
  audit call --tool jira --action get --target PROJ-123 \\
      --category jira --status ok --duration 320 --rows 1

  # 查看与分析
  audit logs --since 2h                # 最近 2 小时
  audit logs --tool mycli --limit 20
  audit tail                           # 实时跟踪
  audit stats --since 7d
  audit slow --limit 10                # 最慢调用
  audit errors                         # 失败聚类
  audit by-case                        # 按案件汇总
  audit timeline --case case-001
  audit get 42                         # 单条详情
  audit export --format csv --since 7d > audit.csv
  audit prune --keep 90d               # 清理 90 天前
"""


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        prog="vigile", description="vigile — 守夜人：内部系统调用的统一入口（审计 + 执行前审核）",
        epilog=EXAMPLES, formatter_class=argparse.RawDescriptionHelpFormatter)
    sub = p.add_subparsers(dest="command", metavar="<command>")
    sub.required = True

    def filt(sp: argparse.ArgumentParser) -> None:
        sp.add_argument("--tool")
        sp.add_argument("--category")
        sp.add_argument("--status")
        sp.add_argument("--case", dest="case")
        sp.add_argument("--ticket")
        sp.add_argument("--risk")
        sp.add_argument("--since", help="30m / 2h / 7d / '2026-10-27 12:00:00'")
        sp.add_argument("--keyword")

    r = sub.add_parser("run", help="包装并审计任意命令（推荐）")
    r.add_argument("--case", help="关联案件")
    r.add_argument("--ticket", help="关联工单")
    r.add_argument("--quiet", action="store_true", help="不打印审计摘要行")
    r.add_argument("-y", "--yes", action="store_true",
                   help="对 ask 级别的操作显式确认（deny 级别永远不可 -y 越过）")
    r.add_argument("--no-policy", action="store_true", help="跳过策略审核（仅调试用）")
    r.add_argument("command", nargs=argparse.REMAINDER, help="-- 之后的命令")
    r.set_defaults(func=cmd_run)

    c = sub.add_parser("call", help="程序内埋点：记录一次 API 调用")
    c.add_argument("--tool", required=True)
    c.add_argument("--action", default="")
    c.add_argument("--target", default="")
    c.add_argument("--category", default="http")
    c.add_argument("--status", default="ok")
    c.add_argument("--duration", type=int, help="耗时毫秒")
    c.add_argument("--exit-code", type=int)
    c.add_argument("--rows", type=int)
    c.add_argument("--result-size", type=int)
    c.add_argument("--args", help="请求参数（自动脱敏）")
    c.add_argument("--output", help="响应摘要（自动脱敏）")
    c.add_argument("--error")
    c.add_argument("--risk", default="read")
    c.add_argument("--case", dest="case")
    c.add_argument("--ticket")
    c.add_argument("--meta")
    c.set_defaults(func=cmd_call)

    l = sub.add_parser("logs", help="查询记录")
    filt(l)
    l.add_argument("--limit", type=int, default=50)
    l.add_argument("--json", action="store_true")
    l.set_defaults(func=cmd_logs)

    t = sub.add_parser("tail", help="实时跟踪")
    t.add_argument("--interval", type=float, default=1.0)
    t.add_argument("--lines", type=int, default=10)
    t.add_argument("--no-existing", action="store_true")
    t.set_defaults(func=cmd_tail)

    s = sub.add_parser("stats", help="汇总统计")
    filt(s)
    s.set_defaults(func=cmd_stats)

    sl = sub.add_parser("slow", help="最慢调用")
    filt(sl)
    sl.add_argument("--limit", type=int, default=20)
    sl.set_defaults(func=cmd_slow)

    e = sub.add_parser("errors", help="失败聚类")
    filt(e)
    e.add_argument("--limit", type=int, default=20)
    e.set_defaults(func=cmd_errors)

    bc = sub.add_parser("by-case", help="按案件汇总")
    bc.add_argument("--limit", type=int, default=30)
    bc.set_defaults(func=cmd_by_case)

    tl = sub.add_parser("timeline", help="时间线")
    filt(tl)
    tl.add_argument("--limit", type=int, default=200)
    tl.set_defaults(func=cmd_timeline)

    ex = sub.add_parser("export", help="导出 CSV/JSON")
    filt(ex)
    ex.add_argument("--format", choices=("json", "csv"), default="json")
    ex.add_argument("--out")
    ex.set_defaults(func=cmd_export)

    g = sub.add_parser("get", help="单条详情")
    g.add_argument("id", type=int)
    g.set_defaults(func=cmd_get)

    po = sub.add_parser("policy", help="查看/初始化/测试执行策略")
    po.add_argument("--init", action="store_true", help="生成策略模板到 policy.json")
    po.add_argument("--force", action="store_true", help="覆盖已有策略文件")
    po.add_argument("--test", help="测试一条命令会得到什么判定（不执行）")
    po.set_defaults(func=cmd_policy)

    ru = sub.add_parser("rules", help="查看/初始化分类规则文件")
    ru.add_argument("--init", action="store_true", help="生成规则模板到 rules.json")
    ru.add_argument("--force", action="store_true", help="覆盖已有规则文件")
    ru.set_defaults(func=cmd_rules)

    stp = sub.add_parser("setup", help="为指定 agent 安装/卸载 hook")
    stp.add_argument("--install", action="store_true")
    stp.add_argument("--uninstall", action="store_true")
    stp.add_argument("--status", action="store_true")
    stp.add_argument("--list", action="store_true")
    stp.add_argument("--agent", action="append", dest="agents",
                     help="目标 agent，可重复；all=全部")
    stp.set_defaults(func=cmd_setup)

    cfc = sub.add_parser("call-file-change", help="记录一次文件变更（供 hook 调用）")
    cfc.add_argument("--file", required=True)
    cfc.add_argument("--op", default="edit")
    cfc.add_argument("--before", default="")
    cfc.add_argument("--after", default="")
    cfc.add_argument("--case", dest="case")
    cfc.add_argument("--ticket")
    cfc.set_defaults(func=cmd_call_file_change)

    sn = sub.add_parser("session", help="会话视图：一次会话的全部调用与文件变更")
    sn.add_argument("id", nargs="?", help="会话 ID（缺省列出最近会话）")
    sn.add_argument("--limit", type=int, default=20)
    sn.set_defaults(func=cmd_session)

    df = sub.add_parser("diff", help="查看文件变更记录（post-tool）")
    df.add_argument("--file", help="按文件路径筛（子串）")
    df.add_argument("--case", dest="case", help="按案件筛")
    df.add_argument("--limit", type=int, default=30)
    df.add_argument("--show", action="store_true", help="显示 diff 内容")
    df.set_defaults(func=cmd_diff)

    vf = sub.add_parser("verify", help="验证审计链完整性（防篡改）")
    vf.set_defaults(func=cmd_verify)

    pr = sub.add_parser("prune", help="清理历史")
    pr.add_argument("--keep", default="90d", help="保留多久，如 90d")
    pr.set_defaults(func=cmd_prune)
    return p


def main(argv: Optional[Sequence[str]] = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    try:
        return args.func(args)
    except UsageError as exc:
        print(f"参数错误: {exc}", file=sys.stderr)
        return EXIT_USAGE
    except sqlite3.Error as exc:
        print(f"审计库错误: {exc}", file=sys.stderr)
        return EXIT_USAGE


if __name__ == "__main__":
    sys.exit(main())
