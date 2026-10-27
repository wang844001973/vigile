---
name: vigile
description: 内部系统调用的统一入口——所有 Jira、SQL/Doris、Mongo/XQL、日志、K8s、HTTP 调用都必须经 `vigile run -- <命令>` 过闸。闸负责审计（参数、结果摘要、成功失败、耗时、退出码、读写风险，统一落 SQLite 单库）与执行前审核（allow/ask/deny 三档，危险命令直接拒绝且不运行）。支持实时跟踪 tail 与事后分析 stats/slow/errors/by-case/timeline/export，每条拒绝规则的提示语可自定义。当需要追踪"到底调了什么、花了多久、哪步失败"、防止危险操作、或做调用合规审计时使用。
metadata:
  short-description: 调用审计 + 执行前审核的统一闸门
---

# vigile

**守夜人：记录一切，鉴真一切，拦截危险。** 所有对内部系统的调用都要经过 `vigile run --`。

## 为什么是这个设计

**1. 包装器，不改源码** — 内部工具多是编译好的二进制（自研 CLI、`kubectl`、`psql`、`mongosh`…），改不了源码加埋点。`vigile run -- <命令>` 是唯一能做到无差别覆盖的方式，且天然透传 stdout/stderr/退出码。

**2. 审计与审核一体** — 只记录不拦截是事后追责；只拦截不记录无法复盘。闸门同时做两件事：执行前判定，执行后落库。

**3. 单库集中** — `~/.vigile/vigile.db`（SQLite）。零依赖、单文件、可迁移；WAL 模式让并发读写互不阻塞。

## 三种过闸方式

| 方式 | 适用 | 例子 |
|---|---|---|
| `vigile run -- <命令>` | 二进制工具、任何命令 | `vigile run -- log-query trace abc` |
| `vigile call ...` | Python 脚本内单次 API 调用 | 记录一次 HTTP 请求 |
| `from vigile import log_call` | 代码埋点 | 在被审计脚本里直接调用 |

## 快速开始

```bash
# 过闸（推荐）
vigile run -- mycli trace abc123
vigile run --case BUG-123 --ticket BUG-123 -- myq sql "select * from dwd.orders limit 10"

# 程序内埋点
vigile call --tool jira --action get --target PROJ-123 \
    --category jira --status ok --duration 320 --rows 1

# 查看与分析
vigile tail                        # 实时跟踪
vigile logs --since 2h             # 最近 2 小时
vigile stats --since 7d
vigile verify                        # 验证审计链

vigile diff / session                # 文件变更 / 会话视图

vigile slow / errors / by-case / timeline
```

`vigile run` 会在 stderr 打一行摘要，不影响 stdout：

```text
[vigile] #42 ok 411ms → ~/.vigile/vigile.db
```

## 执行前审核（自动拒绝危险操作）

| 判定 | 行为 | 退出码 |
|---|---|---|
| `allow` | 执行并记录 | 命令自身退出码 |
| `ask` | 需确认；无终端时**默认拒绝** | 3 |
| `deny` | **命令不执行**，记录 `status=denied` | 3 |

```bash
vigile run -- rm -rf /data                           # deny，不执行
vigile run -- psql -c "drop table users"             # deny
vigile run -- psql -c "delete from t where id=1"     # ask，无终端则拒绝
vigile run -y -- psql -c "delete from t where id=1"  # 确认后执行
```

**`deny` 永远不能被 `-y` 或 `VIGILE_CONFIRM=yes` 越过**，只有 `ask` 级可确认。

### 影响预览（Blast Radius）

拒绝/确认时算出具体影响：`rm -r` → 文件数/大小/示例；`git push --force` → 将丢弃的远端提交；
`git reset --hard` → 未提交改动清单；`drop/truncate` → 目标对象。MSYS 路径自动转换。

### 文件变更差异（post-tool）

`vigile setup` 安装的 PostToolUse hook 自动记录 Edit/Write 的前后 unified diff
（内容只存 SHA-256 + 截断 diff，不存全文）。查看：`vigile diff [--show] [--file x]`

### 会话视图

`vigile session` 列最近会话；`vigile session <id>` 合并展示该会话的调用与文件变更时间线。

### 防篡改 hash 链

每条记录 hash 含前一条 hash，`vigile verify` 检测任何删除/篡改（断链后续全部报异常）。
hash 链启用前的旧记录自动跳过。

### 内置危险规则（15 条 deny + 8 条 ask）

- 破坏性操作：`rm -rf`、`mkfs`、`dd of=/dev/`、`shutdown`/`reboot`、`fsck`
- 危险 SQL：`drop table/database/index`、`truncate`、`alter table ... drop`、**无 WHERE 的 delete/update**、`grant all`
- 缓存/大规模：`flushall`
- ask 级：带 WHERE 的 delete/update、`insert into`、`kubectl delete/scale`、`helm uninstall/rollback`、`git push --force`、`git reset --hard`、`docker rm/rmi`

## 自定义策略与提示语

```bash
vigile policy --init              # 生成 ~/.vigile/policy.json
vigile policy                     # 列出每条规则的 id 与提示语
vigile policy --test "rm -rf /"   # 只看判定，不执行
```

每条规则是对象，**提示语完全可自定义**：

```json
{
  "deny": [
    {
      "id": "rm_recursive",
      "pattern": "\\brm\\s+-rf\\b",
      "message": "【公司红线】严禁在服务器执行 rm -rf，请走数据清理流程。",
      "hint": "提交运维工单，或先 mv 到 /tmp/trash"
    },
    {
      "id": "no_prod_mongo",
      "pattern": "prod-mongo|生产库",
      "message": "禁止直接连接生产 Mongo（检测到 {match}）",
      "hint": "改用只读从库，或审批后再操作"
    }
  ],
  "ask": [],
  "allow_tools": ["mycli"],
  "deny_tools": ["dangerous-cli"]
}
```

**占位符**：`{command}`（完整命令，截断 200 字）、`{tool}`（工具名）、`{match}`（正则命中片段）。

- 相同 `id` → **覆盖**内置规则
- 新 `id` → **追加**自定义规则
- 旧的纯正则字符串写法仍兼容

判定顺序：`allow_tools` → `deny_tools` → `deny` → `ask` → 默认 `allow`。
策略文件损坏时退回内置默认，**内置危险规则始终生效**。

### 拒绝时的输出

```text
[vigile] 已拒绝执行（规则 rm_recursive）
[vigile] 【公司红线】严禁在服务器执行 rm -rf，请走数据清理流程。
[vigile] 建议：提交运维工单，或先 mv 到 /tmp/trash
[vigile] 命令未运行。
```

被拒记录以 `status=denied` 落库，含 `meta_json.policy_rule`：

```bash
vigile logs --status denied
```

## 自定义工具分类

```bash
vigile rules --init               # 生成 ~/.vigile/rules.json
```

```json
{
  "tools":     {"mycli": "sql", "myq": "http"},
  "write":     {"deploytool": ["apply", "rollback"]},
  "read_only": ["readonly-cli"]
}
```

内置规则覆盖通用命令（`kubectl`/`psql`/`mongosh`/`git`/`curl`…），自研工具在此配置。

## 记录字段

| 字段 | 说明 |
|---|---|
| `ts` / `ts_epoch` | 时间（ISO8601 + 毫秒戳） |
| `actor` / `session` | 执行者、会话 |
| `category` | `jira`/`sql`/`mongo`/`log`/`k8s`/`http`/`git`/`file`/`other`（自动推断） |
| `tool` / `action` / `target` | 工具、动作、作用对象（自动提取） |
| `args_json` | 完整参数（**已脱敏**） |
| `status` | `ok`/`failed`/`timeout`/`blocked`/`denied` |
| `exit_code` / `duration_ms` | 退出码、耗时 |
| `rows` / `result_size` | 影响行数、输出字节数 |
| `output_digest` | 输出摘要（前 2000 字） |
| `error` | 错误信息 |
| `case_name` / `ticket` | 关联案件与工单 |
| `risk` | `read` / `write`（自动判断） |

## 环境变量

| 变量 | 默认 | 用途 |
|---|---|---|
| `VIGILE_DB` | `~/.vigile/vigile.db` | 数据库路径 |
| `VIGILE_ACTOR` | 系统用户 | 执行者 |
| `VIGILE_SESSION` | `用户@pid` | 会话 ID |
| `VIGILE_CASE` / `VIGILE_TICKET` | 空 | 默认关联 |
| `VIGILE_RULES` / `VIGILE_POLICY` | 与库同目录 | 规则与策略文件 |
| `VIGILE_CONFIRM` | 空 | `yes` 自动确认 ask 级 |

> 旧的 `AUDIT_*` 变量兼容。

## 自动化：给 agent 装 hook（rtk 风格）

```bash
vigile setup --list                        # 看支持哪些 agent、当前状态
vigile setup --install --agent claude      # 指定 agent 安装
vigile setup --install --agent all        # 全部安装
vigile setup --uninstall --agent codex     # 卸载
```

各 agent 能力（实测）：

| agent | 能力 |
|---|---|
| Claude Code | **强制改写**命令为 `vigile run --` + deny 拦截 |
| Codex | **强制改写** + deny 拦截（hooks.json 同 Claude 协议） |
| dsh | 经 dsh-hooks-claude-code 桥**复用 Claude 配置**（改写+deny） |
| ZCode | deny 拦截 + 提醒（不支持命令改写） |
| OpenCode | 仅规则约束（无原生 hook） |

安装自动备份（`.bak-vigile`）、幂等、只动 vigile 条目不影响 rtk 等其它 hook、
vigile 插在最前保证先于代理执行。

## 与其它技能的关系

```text
problems（问题册）      跨案件的问题结论、根因
      ↑
journal（案件流水）     单案件内的判断与动作
      ↑
vigile.db（闸门流水）     每一次真实调用的参数/结果/耗时 ← 本技能
```

三层互补：`vigile` 记录**机器层面发生了什么**，`journal` 记录**人/agent 的判断**，`problems` 沉淀**最终结论**。通过 `case_name` / `ticket` 关联。

## 编排层自动识别（Multica）

Multica 等聚合平台**无需单独适配**：hook 装在底层 agent（Claude/Codex/OpenCode）配置层，
平台派发的任务执行时天然过闸。进程若带 `MULTICA_TASK_ID` 等环境变量，记录的
`actor` 自动变为 `multica/<agent> (<task>)`、session 归并到 `multica:<task>`，
按任务筛：`vigile logs --keyword "multica:T-123"`。

## 硬约束

- **审计失败不能影响主流程**：写库失败时仍执行原命令并透传结果，只在 stderr 提示。
- **参数必须脱敏后再落库**：凭据绝不进数据库。
- **不改工具行为**：包装器只旁观，不注入参数、不篡改输出、不吞退出码。
- **`deny` 不可被确认越过**：只有 `ask` 可确认，这是安全底线。

## 常见问题

| 现象 | 处理 |
|---|---|
| 记录为空 | 检查 `VIGILE_DB`；确认用 `vigile run --` 而非直接调工具 |
| 命令被拒但确需执行 | 调整 `policy.json` 规则，或用 `--no-policy`（仅调试） |
| `action` 识别不准 | 启发式规则，用 `logs --keyword` 按参数找更准 |
| 库变大 | `vigile prune --keep 90d`，会 VACUUM |
| 并发写冲突 | 已开 WAL + 10s busy timeout |
