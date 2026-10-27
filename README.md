# vigile

> **守夜人。** 中世纪城市的守夜人整夜巡逻：记录一切见闻，火情第一时间敲钟，危险拦在城门之外。
> 本工具之于 AI agent，正是这个角色——记录每一次内部调用，鉴真每一次凭据，拦下每一条危险命令。

**简写 `vig`**（安装器自动配置），与 `git` 同级手感。**rtk 式代理用法**：不命中子命令时直接执行——

```
vig shandian status               → 代理：审计 + 执行前审核（推荐日常形态）
vig kubectl get pods              → 同上，无需 run --
vig tail                          → 实时看到每一次调用
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

Node.js 22.5+（内置 `node:sqlite`），**无 npm 依赖**。

**一键安装**（Linux / macOS / WSL / Git Bash）：

```bash
curl -fsSL https://raw.githubusercontent.com/wang844001973/vigile/refs/heads/master/install.sh | sh
```

装好 `vigile` / `vig` 双入口到 `~/.local/bin`（本体在 `~/.local/vigile`），
然后一条命令给所有 agent 装 hook：

```bash
vig init --global
```

可定制：`VIGILE_DIR=~/tools VIGILE_BRANCH=develop sh install.sh`。

**Windows（CMD / PowerShell）**——`curl | sh` 不适用，用 git 直接装：

```powershell
git clone https://github.com/wang844001973/vigile.git "$env:LOCALAPPDATA\Programs\vigile-src"
node "$env:LOCALAPPDATA\Programs\vigile-src\install.mjs"
```

install.mjs 在 Windows 上做三件事：

- 生成 `%LOCALAPPDATA%\Programs\vigile\{vigile,vig}.cmd`（CMD / PowerShell 入口）
- 生成 `~/.local/bin/{vigile,vig}` sh 脚本（Git Bash 入口）
- 把 .cmd 目录**挪到用户 PATH 首位**——顺序很关键：`.local\bin` 若排在前面，
  PowerShell 会命中那里的 sh 脚本并报「无法在管道中间运行文档」

装完**重开终端**（PATH 改动只对新进程生效）。

> 常见坑：`vib` 不是本工具，命令是 `vig`（v-i-g）；
> 端口被占（EADDRINUSE）说明已有一个控制台在跑，浏览器直接开
> http://127.0.0.1:8433 或 `--port` 换端口。

**从源码**（开发者）：

```bash
git clone https://github.com/wang844001973/vigile.git
cd vigile && node install.mjs
```

**平台支持**：Linux ✅、Windows ✅（含 CMD/Git Bash 双入口）、macOS ✅。

## 快速开始

```bash
# 代理（推荐——rtk 式，命令名直接跟在 vig 后面）
vig kubectl get pods
vig bigdata-query sql "select ... limit 10"
vig --case BUG-123 --ticket BUG-123 kubectl get pods   # 带工单上下文

# 初始化（装完第一件事）
vig init --global             # 给所有 agent 装 hook

# 显式过闸（命令名撞子命令时用 -- 逃逸）
vig run -- logs get x
vig -- kubectl version

# 看
vig tail                     # 实时
vig logs --since 2h         # 事后
vig logs --status denied     # 只看被拒的
vig get 42                   # 单条全部 22 个字段

# Web 控制台（浏览器里看/筛/钻取整个审计库）
vig logs --web               # http://127.0.0.1:8433，仅本机可访问
vig logs --web --port 9000   # 换端口

# 分析
vig stats --since 7d
vig slow / errors / by-case / session <id>
vig diff --show              # 文件改了什么

# 验证审计链
vig verify
```

### Web 控制台

`vig logs --web` 在本机起一个零依赖站点（纯 Node `node:http`，无 npm 包），三个页面：

- **调用日志** — 统计卡片（总数/状态/分类/风险）+ 关键词/工具/状态/分类筛选 + 表格，
  点任意行弹出该记录全部 22 个字段（含 args、输出摘要、hash 链值）
- **统计分析** — 按小时分布柱状图、按工具的成功/失败对比、平均与最慢耗时
- **文件变更** — agent 每次改文件的列表，点行看带颜色高亮的 diff

页签间筛选条件联动，3 秒自动刷新（可关），hash 链异常会在页顶出红色告警条。
只绑定 `127.0.0.1` —— 审计数据含内部系统调用细节，绝不对局域网开放。

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
| Claude Code | **强制改写**命令为 `vig <命令>` + deny/ask（无法绕过） |
| ZCode | **强制改写**（PreToolUse `updatedInput`）+ deny/ask |
| Codex | **强制改写** + deny |
| dsh | 经 dsh-hooks-claude-code 桥**复用 Claude 配置**（桥不支持改写时旁路记录） |
| OpenCode | 规则约束（无原生 hook） |

hook 的改写串带环境消毒（`env -u VIGILE_CONFIRM …`）：shell 环境残留的确认变量
不会穿透到 hook 改写的命令——hook 已把命令转成显式 allow，这个通道必须封死。
fail-open 时 stderr 出警告，绝不静默放行。

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

## 全量审计（任何终端命令都有记录）

默认 `audit_mode: "all"`：**白名单只决定"是否改写拿到完整结果"，记录面覆盖一切命令**。

- 白名单内（shandian/kubectl/jira…）→ hook 改写为 `vig` 代理 → 完整审计
  （exit_code / 耗时 / 输出摘要，`source=cli`）
- 白名单外（git/npm/node/cargo…）→ 命令照原样执行，旁路记一条意图
  （`source=hook`，`meta.source=hook-bypass`）——行为零影响，但库里可查
- 复合命令（含管道/`&&`）→ 首段过策略检查后旁路记录

高频纯只读命令在**噪声名单**里，不记录（防止灌库）：`ls / pwd / cat / head /
tail / grep / find / which / whoami / date / echo / wc / stat / du / df`。

`~/.vigile/rules.json` 可调：

```json
{
  "audit_mode": "all",        // all = 全量（默认）；whitelist = 只记内部工具
  "noise": ["ls", "cat"]      // 噪声名单；置 [] = 一条不漏全记
}
```

改完即生效（hook 每次调用都重读配置，无需重启 agent）。

## 环境变量

`VIGILE_DB` / `VIGILE_ACTOR` / `VIGILE_SESSION` / `VIGILE_CASE` / `VIGILE_TICKET`
/ `VIGILE_POLICY` / `VIGILE_RULES` / `VIGILE_CONFIRM`（数据库默认 `~/.vigile/vigile.db`）。
注意 `VIGILE_CONFIRM` 只对**手工**调用有效——hook 改写的命令会先剥掉它，防止环境残留值静默通过 ask 档。
旧 `GATE_*` / `AUDIT_*` 仍兼容。

## 为什么用 SQLite

零依赖、单文件、WAL 并发读写不阻塞。单次调用约 1-2 KB，每天 1000 次约 1.5 MB/月。
跨机汇总用 `vig export`。

## 测试

```bash
npm test        # 或 node --test test/vigile.test.js
```

48 个测试（脱敏 / 策略三档 / hook 判定 / vig 代理形态 / hash 链跨版本兼容 / CLI 集成）。

## License

MIT
