# vigile

> **守夜人。** 中世纪城市的守夜人整夜巡逻：记录一切见闻，火情第一时间敲钟，危险拦在城门之外。
> 本工具之于 AI agent，正是这个角色——记录每一次内部调用，鉴真每一次凭据，拦下每一条危险命令。

**简写 `vig`**（安装器自动配置），与 `git` 同级手感。

```
vig run -- mycli trace abc123     → 过闸：审计 + 执行前审核
vig tail                           → 实时看到每一次调用
vig verify                        → 审计链完整性（防篡改）
```

## 一句话

所有对内部系统的调用都必须**经过守夜人**：他负责记录，也负责说"不行"。

## 解决什么问题

AI agent 排查线上问题时会调用大量工具：查日志、查数据库、调接口、改文件。三个风险随之而来：

1. **不可追溯**——事后无法回答"agent 到底跑了什么、花了多久、哪步失败"
2. **不可鉴真**——审计日志本身可能被篡改或删除，失去证据价值
3. **不可拦截**——一条 `rm -rf`、一个无 WHERE 的 DELETE，执行了就来不及了

`vigile` 三件事一起解决：

| 能力 | 说明 |
|---|---|
| **全量审计** | 每次调用的参数、结果摘要、耗时、退出码、读/写风险 |
| **执行前审核** | `allow` / `ask` / `deny` 三档，`deny` 命令**根本不会运行** |
| **影响预览** | 拒绝时算出具体影响：会删哪些文件、会丢哪些提交 |
| **防篡改链** | 每条记录 hash 锁定前一条，删改任何记录都会断链被发现 |
| **文件变更 diff** | agent 每次改文件的前后差异自动落库 |
| **可定制** | 每条拒绝规则的提示语可改为团队自己的说法 |

## 安装

Python 3.7+，**无第三方依赖**。

```bash
git clone <this-repo> vigile
cd vigile
python install.py            # 装好 vigile 与 vig 双入口
```

## 快速开始

```bash
# 过闸
vig run -- kubectl get pods
vig run --case BUG-123 --ticket BUG-123 -- bigdata-query sql "select ... limit 10"

# 看
vig tail                     # 实时
vig logs --since 2h         # 事后
vig logs --status denied     # 只看被拒的
vig get 42                   # 单条全部 22 个字段

# 分析
vig stats --since 7d
vig slow / errors / by-case / session <id>
vig diff --show              # 文件改了什么

# 验证审计链
vig verify
```

## 执行前审核

| 判定 | 行为 | 退出码 |
|---|---|---|
| `allow` | 执行并记录 | 命令自身退出码 |
| `ask` | 需确认；无终端时**默认拒绝** | 3 |
| `deny` | **命令不执行**，记录 `status=denied` | 3 |

```bash
$ vig run -- rm -rf ./data
[ vigil ] 已拒绝执行（规则 rm_recursive）
[vigile] 影响预览：将删除 128 个文件，共约 3.4 MB
[vigile] 命令未运行。
```

**`deny` 不可被 `-y` 越过**——只有 `ask` 可确认，这是安全底线。

内置 15 条 deny（`rm -rf`、`mkfs`、`drop table`、无 WHERE 的 delete/update、`shutdown`…）
+ 8 条 ask（带 WHERE 的 delete、`git push --force`、`kubectl delete`…）。

## 给 agent 装 hook

```bash
vig setup --list                       # 看支持哪些 agent
vig setup --install --agent all       # 一键全装
vig setup --uninstall --agent codex   # 卸载
```

| agent | 能力 |
|---|---|
| Claude Code | **强制改写**命令为 `vig run --` + deny（无法绕过） |
| Codex | **强制改写** + deny |
| dsh | 经 dsh-hooks-claude-code 桥**复用 Claude 配置** |
| ZCode | deny 拦截 + 提醒 |
| OpenCode | 规则约束（无原生 hook） |

## 自定义策略与提示语

```bash
vig policy --init              # 生成 ~/.vigile/policy.json
vig policy --test "rm -rf /"   # 只看判定不执行
```

```json
{
  "deny": [{
    "id": "rm_recursive",
    "pattern": "\\brm\\s+-rf\\b",
    "message": "【公司红线】严禁 rm -rf，请走数据清理流程。",
    "hint": "提交运维工单，或先 mv 到 /tmp/trash"
  }]
}
```

占位符 `{command}` / `{tool}` / `{match}`。同 id 覆盖内置，新 id 追加。

## 编排层自动识别（Multica 等）

Multica 这类聚合平台**不需要单独适配**——它派发的任务最终由 Claude Code / Codex 等底层 agent
执行，而 vigile 的 hook 装在这些 agent 的配置层，天然覆盖。

vigile 会自动识别编排层注入的任务上下文：Multica 派发的进程带有 `MULTICA_TASK_ID` 等
环境变量，识别后审计记录自动归属到任务：

```text
actor   : multica/claude-7 (T-9876)          ← 哪个 agent、哪个任务干的
session : 84400@pid/multica:T-9876           ← 同一任务的记录归入同一会话
meta    : {"orchestrator": {"MULTICA_TASK_ID": "T-9876", ...}}
```

复盘某个 Multica 任务的全部调用：

```bash
vig logs --keyword "multica:T-9876"
vig session 84400@123/multica:T-9876
```

普通进程（无编排层变量）行为完全不变。

## 环境变量

`VIGILE_DB` / `VIGILE_ACTOR` / `VIGILE_SESSION` / `VIGILE_CASE` / `VIGILE_TICKET`
/ `VIGILE_POLICY` / `VIGILE_RULES` / `VIGILE_CONFIRM`（默认 `~/.vigile/vigile.db`）。
旧 `GATE_*` / `AUDIT_*` 仍兼容。

## 为什么用 SQLite

零依赖、单文件、WAL 并发读写不阻塞。单次调用约 1-2 KB，每天 1000 次约 1.5 MB/月。
跨机汇总用 `vig export`。

## 测试

```bash
cd scripts && python -m unittest _test_vigile _test_vigile_setup
```

100 个测试。

## License

MIT
