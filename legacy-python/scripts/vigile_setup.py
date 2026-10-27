#!/usr/bin/env python3
"""gate setup：为指定的 agent 安装/卸载 PreToolUse hook。

用法:
  vigile-setup.py --list                     列出支持的 agent 及当前状态
  vigile-setup.py --install --agent claude    给指定 agent 安装 hook
  vigile-setup.py --install --agent all       给所有支持的 agent 安装
  vigile-setup.py --uninstall --agent zcode   卸载指定 agent 的 hook
  vigile-setup.py --status                    查看各 agent 安装状态

支持多选: --agent claude --agent codex

设计:
- 每个 agent 的 hook 协议不同，这里集中维护一份注册表（HOOK_REGISTRY）
- 安装前自动备份原配置文件（.bak-gate）
- 幂等：重复安装不产生重复条目
- 卸载只删 gate 的条目，不动其它 hook（如 rtk）
"""
import argparse
import json
import os
import shutil
import sys
from typing import Any, Dict, List, Optional

EXIT_OK = 0
EXIT_USAGE = 2

VIGILE_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
HOOK_PATH = os.path.join(VIGILE_ROOT, "hooks", "vigile-hook.js")
NODE = shutil.which("node") or "node"


def home(*parts: str) -> str:
    return os.path.join(os.path.expanduser("~"), *parts)


def q(path: str) -> str:
    """给路径加引号（路径含空格时必需）。"""
    return f'"{path}"'


# ---------------------------------------------------------------- 各 agent 注册表
# 每项: name / 可用性检测 / 安装 / 卸载 / 状态
HOOK_REGISTRY: Dict[str, Dict[str, Any]] = {}


def _detect_zcode() -> bool:
    return os.path.exists(home(".zcode", "cli", "config.json"))


def _cfg_zcode() -> str:
    return home(".zcode", "cli", "config.json")


def _zcode_entry() -> Dict[str, Any]:
    return {
        "matcher": "Bash",
        "hooks": [{
            "type": "process",
            "command": NODE,
            "args": [HOOK_PATH],
            "timeoutMs": 4000,
        }],
    }


def _zcode_post_entry() -> Dict[str, Any]:
    return {
        "matcher": "Edit|Write|ApplyPatch",
        "hooks": [{
            "type": "process",
            "command": NODE,
            "args": [HOOK_PATH, "--post"],
            "timeoutMs": 4000,
        }],
    }


def _install_zcode() -> str:
    path = _cfg_zcode()
    d = json.load(open(path, encoding="utf-8"))
    d.setdefault("hooks", {})
    d["hooks"]["enabled"] = True
    events = d["hooks"].setdefault("events", {})
    # PreToolUse（Bash 拦截）
    pre = events.setdefault("PreToolUse", [])
    already = any(("vigile-hook.js" in str(h.get("args", []))
                   or "vigile-hook.js" in str(h.get("args", [])))
                  for e in pre for h in e.get("hooks", []))
    if not already:
        pre.append(_zcode_entry())
    # PostToolUse（文件变更 diff）
    post = events.setdefault("PostToolUse", [])
    if not any("vigile-hook.js" in str(h.get("args", [])) for e in post for h in e.get("hooks", [])):
        post.append(_zcode_post_entry())
    json.dump(d, open(path, "w", encoding="utf-8"), ensure_ascii=False, indent=2)
    return "已注册（PreToolUse 拦截 + PostToolUse 文件变更 diff）"


def _uninstall_zcode() -> str:
    path = _cfg_zcode()
    if not os.path.exists(path):
        return "配置不存在"
    d = json.load(open(path, encoding="utf-8"))
    removed = 0
    events = d.get("hooks", {}).get("events", {})
    for key in ("PreToolUse", "PostToolUse"):
        lst = events.get(key, [])
        before = len(lst)
        lst[:] = [e for e in lst
                  if not any(("vigile-hook.js" in str(h.get("args", []))
                              or "vigile-hook.js" in str(h.get("args", [])))
                             for h in e.get("hooks", []))]
        removed += before - len(lst)
    json.dump(d, open(path, "w", encoding="utf-8"), ensure_ascii=False, indent=2)
    return f"移除 {removed} 条" if removed else "未找到条目"


def _status_zcode() -> Optional[str]:
    path = _cfg_zcode()
    if not os.path.exists(path):
        return None
    d = json.load(open(path, encoding="utf-8"))
    for e in d.get("hooks", {}).get("events", {}).get("PreToolUse", []):
        for h in e.get("hooks", []):
            if "vigile-hook.js" in str(h.get("args", [])) or "vigile-hook.js" in str(h.get("args", [])):
                return "已安装"
    return "未安装"


HOOK_REGISTRY["zcode"] = {
    "detect": _detect_zcode, "install": _install_zcode,
    "uninstall": _uninstall_zcode, "status": _status_zcode,
    "capability": "deny 拦截 + additionalContext 提醒（不支持命令改写）",
}


def _detect_claude() -> bool:
    return os.path.exists(home(".claude", "settings.json"))


def _cfg_claude() -> str:
    return home(".claude", "settings.json")


def _claude_entry() -> Dict[str, Any]:
    return {
        "matcher": "Bash",
        "hooks": [{
            "type": "command",
            "command": f"VIGILE_HOOK_MODE=claude {NODE} {q(HOOK_PATH)}",
        }],
    }


def _claude_post_entry() -> Dict[str, Any]:
    return {
        "matcher": "Edit|Write|ApplyPatch",
        "hooks": [{
            "type": "command",
            "command": f"{NODE} {q(HOOK_PATH)} --post",
        }],
    }


def _install_claude() -> str:
    path = _cfg_claude()
    d = json.load(open(path, encoding="utf-8"))
    hooks = d.setdefault("hooks", {})
    pre = hooks.setdefault("PreToolUse", [])
    already = any("vigile-hook.js" in h.get("command", "")
                  for e in pre for h in e.get("hooks", []))
    if not already:
        pre.insert(0, _claude_entry())   # 放最前，先于 rtk 等其它 hook
    post = hooks.setdefault("PostToolUse", [])
    if not any("vigile-hook.js" in h.get("command", "")
               for e in post for h in e.get("hooks", [])):
        post.insert(0, _claude_post_entry())
    json.dump(d, open(path, "w", encoding="utf-8"), ensure_ascii=False, indent=2)
    return "已注册（PreToolUse 强制改写 + deny；PostToolUse 文件变更 diff）"


def _uninstall_claude() -> str:
    path = _cfg_claude()
    if not os.path.exists(path):
        return "配置不存在"
    d = json.load(open(path, encoding="utf-8"))
    removed = 0
    for key in ("PreToolUse", "PostToolUse"):
        lst = d.get("hooks", {}).get(key, [])
        before = len(lst)
        lst[:] = [e for e in lst
                  if not any("vigile-hook.js" in h.get("command", "")
                             for h in e.get("hooks", []))]
        removed += before - len(lst)
    json.dump(d, open(path, "w", encoding="utf-8"), ensure_ascii=False, indent=2)
    return f"移除 {removed} 条" if removed else "未找到条目"


def _status_claude() -> Optional[str]:
    path = _cfg_claude()
    if not os.path.exists(path):
        return None
    d = json.load(open(path, encoding="utf-8"))
    for e in d.get("hooks", {}).get("PreToolUse", []):
        for h in e.get("hooks", []):
            if "vigile-hook.js" in h.get("command", ""):
                return "已安装"
    return "未安装"


HOOK_REGISTRY["claude"] = {
    "detect": _detect_claude, "install": _install_claude,
    "uninstall": _uninstall_claude, "status": _status_claude,
    "capability": "updatedInput 强制改写 + deny 拦截",
}


def _detect_codex() -> bool:
    return os.path.exists(home(".codex", "hooks.json"))


def _cfg_codex() -> str:
    return home(".codex", "hooks.json")


def _install_codex() -> str:
    """Codex 的 hooks.json 与 Claude 的 settings.json 同构（rtk 也这么注册）。"""
    path = _cfg_codex()
    d = json.load(open(path, encoding="utf-8"))
    hooks = d.setdefault("hooks", {})
    pre = hooks.setdefault("PreToolUse", [])
    already = any("vigile-hook.js" in h.get("command", "")
                  for e in pre for h in e.get("hooks", []))
    if not already:
        pre.insert(0, _claude_entry())
    post = hooks.setdefault("PostToolUse", [])
    if not any("vigile-hook.js" in h.get("command", "")
               for e in post for h in e.get("hooks", [])):
        post.insert(0, _claude_post_entry())
    json.dump(d, open(path, "w", encoding="utf-8"), ensure_ascii=False, indent=2)
    return "已注册（PreToolUse 强制改写 + deny；PostToolUse 文件变更 diff）"


def _uninstall_codex() -> str:
    path = _cfg_codex()
    if not os.path.exists(path):
        return "配置不存在"
    d = json.load(open(path, encoding="utf-8"))
    removed = 0
    for key in ("PreToolUse", "PostToolUse"):
        lst = d.get("hooks", {}).get(key, [])
        before = len(lst)
        lst[:] = [e for e in lst
                  if not any("vigile-hook.js" in h.get("command", "")
                             for h in e.get("hooks", []))]
        removed += before - len(lst)
    json.dump(d, open(path, "w", encoding="utf-8"), ensure_ascii=False, indent=2)
    return f"移除 {removed} 条" if removed else "未找到条目"


def _status_codex() -> Optional[str]:
    path = _cfg_codex()
    if not os.path.exists(path):
        return None
    d = json.load(open(path, encoding="utf-8"))
    for e in d.get("hooks", {}).get("PreToolUse", []):
        for h in e.get("hooks", []):
            if "vigile-hook.js" in h.get("command", ""):
                return "已安装"
    return "未安装"


HOOK_REGISTRY["codex"] = {
    "detect": _detect_codex, "install": _install_codex,
    "uninstall": _uninstall_codex, "status": _status_codex,
    "capability": "updatedInput 强制改写 + deny 拦截（hooks.json 同 Claude 协议）",
}


def _detect_dsh() -> bool:
    return os.path.exists(home(".dsh", "profiles"))


def _dsh_profiles() -> List[str]:
    """列出 ~/.dsh/profiles 下有 cordis.patch.yml 的 profile。"""
    root = home(".dsh", "profiles")
    if not os.path.isdir(root):
        return []
    return [n for n in sorted(os.listdir(root))
            if os.path.exists(os.path.join(root, n, "cordis.patch.yml"))]


def _install_dsh() -> str:
    """dsh 通过 dsh-hooks-claude-code 桥跑 Claude hook 配置。

    往每个 profile 的 cordis.patch.yml 追加桥插件条目，指向
    ~/.claude/settings.json（gate 的 hook 已注册在那里）。
    """
    import re as _re
    claude_cfg = _cfg_claude()
    profiles = _dsh_profiles()
    if not profiles:
        return "未找到任何 dsh profile"
    touched = 0
    for prof in profiles:
        path = home(".dsh", "profiles", prof, "cordis.patch.yml")
        text = open(path, encoding="utf-8").read()
        if "dsh-hooks-claude-code" in text:
            continue
        entry = (
            f"- id: vigile-hooks-bridge\n"
            f"  name: '@deepseek-ai/dsh-hooks-claude-code'\n"
            f"  config:\n"
            f"    configPath: {claude_cfg}\n"
        )
        with open(path, "a", encoding="utf-8", newline="\n") as fh:
            fh.write(entry)
        touched += 1
    return f"已在 {touched}/{len(profiles)} 个 profile 挂载 hooks 桥（复用 Claude 配置）"


def _uninstall_dsh() -> str:
    profiles = _dsh_profiles()
    removed = 0
    for prof in profiles:
        path = home(".dsh", "profiles", prof, "cordis.patch.yml")
        if not os.path.exists(path):
            continue
        lines = open(path, encoding="utf-8").read().split("\n")
        out, skip = [], False
        for line in lines:
            if line.startswith("- id: vigile-hooks-bridge"):
                skip = True
                removed += 1
                continue
            if skip:
                # 桥条目占 4 行（id/name/config/configPath）
                if line.startswith("  ") or line.strip() == "":
                    continue
                skip = False
            out.append(line)
        open(path, "w", encoding="utf-8", newline="\n").write("\n".join(out))
    return f"已从 {removed} 处移除" if removed else "未找到条目"


def _status_dsh() -> Optional[str]:
    for prof in _dsh_profiles():
        path = home(".dsh", "profiles", prof, "cordis.patch.yml")
        if os.path.exists(path) and "dsh-hooks-claude-code" in open(path, encoding="utf-8").read():
            return "已安装"
    return "未安装"


def _install_opencode() -> str:
    """OpenCode 无原生 hook 机制，规则写进 AGENTS.md。"""
    path = home(".config", "opencode", "AGENTS.md")
    marker = "vigile run --"
    if os.path.exists(path) and marker in open(path, encoding="utf-8").read():
        return "规则已存在，跳过"
    rule = """

## vigile 规则（强制）

OpenCode 无原生 hook，**所有内部系统调用必须手动用 `vigile run -- <命令>` 包装**。
危险命令（rm -rf / drop table 等）会被 gate 直接拒绝。详见 ~/.zcode/VIGILE_RULES.md。
"""
    with open(path, "a", encoding="utf-8") as fh:
        fh.write(rule)
    return "已写入 AGENTS.md 规则（OpenCode 无 hook 机制，靠规则约束）"


def _uninstall_opencode() -> str:
    path = home(".config", "opencode", "AGENTS.md")
    if not os.path.exists(path):
        return "配置不存在"
    s = open(path, encoding="utf-8").read()
    marker = "## vigile 规则（强制）"
    if marker not in s:
        return "未找到条目"
    idx = s.index(marker)
    s = s[:idx].rstrip() + "\n"
    open(path, "w", encoding="utf-8", newline="\n").write(s)
    return "已移除规则"


def _status_opencode() -> Optional[str]:
    path = home(".config", "opencode", "AGENTS.md")
    if not os.path.exists(path):
        return None
    return "已写入规则" if "vigile run --" in open(path, encoding="utf-8").read() else "未安装"


HOOK_REGISTRY["dsh"] = {
    "detect": _detect_dsh, "install": _install_dsh,
    "uninstall": _uninstall_dsh, "status": _status_dsh,
    "capability": "经 dsh-hooks-claude-code 桥复用 Claude hook 配置（改写+deny）",
}


HOOK_REGISTRY["opencode"] = {
    "detect": lambda: os.path.exists(home(".config", "opencode")),
    "install": _install_opencode,
    "uninstall": _uninstall_opencode, "status": _status_opencode,
    "capability": "仅 AGENTS.md 规则（无 hook 机制）",
}


# ---------------------------------------------------------------- 备份
def backup_config(path: str) -> None:
    if os.path.exists(path):
        bak = path + ".bak-gate"
        shutil.copy2(path, bak)


# ---------------------------------------------------------------- 主流程
def main(argv: Optional[List[str]] = None) -> int:
    p = argparse.ArgumentParser(
        prog="vigile-setup",
        description="为指定 agent 安装/卸载 gate 的 PreToolUse hook")
    p.add_argument("--install", action="store_true", help="安装")
    p.add_argument("--uninstall", action="store_true", help="卸载")
    p.add_argument("--status", action="store_true", help="查看状态")
    p.add_argument("--list", action="store_true", help="列出支持的 agent")
    p.add_argument("--agent", action="append", dest="agents",
                    choices=list(HOOK_REGISTRY) + ["all"],
                    help="目标 agent，可重复指定；all = 全部")
    args = p.parse_args(argv)

    if args.list or (not args.install and not args.uninstall and not args.status):
        print("支持的 agent：")
        for name, reg in HOOK_REGISTRY.items():
            avail = "✅" if reg["detect"]() else "❌ 未检测到"
            st = reg["status"]() or "-"
            print(f"  {name:<12} {avail}  状态: {st}")
            print(f"  {'':<12} 能力: {reg['capability']}")
        print("\n用法: vigile-setup.py --install --agent claude --agent codex")
        return EXIT_OK

    if not args.agents:
        print("请指定 --agent（可多次）或 --agent all", file=sys.stderr)
        return EXIT_USAGE

    names = list(HOOK_REGISTRY) if "all" in args.agents else args.agents
    action = "install" if args.install else "uninstall"

    if args.status:
        for name in names:
            reg = HOOK_REGISTRY[name]
            st = reg["status"]()
            print(f"{name:<12} {st or '未检测到'}")
        return EXIT_OK

    for name in names:
        reg = HOOK_REGISTRY[name]
        if not reg["detect"]():
            print(f"[{name}] ❌ 未检测到该 agent 的配置目录，跳过")
            continue
        # 备份（对配置文件型 agent）
        cfgs = {"zcode": _cfg_zcode, "claude": _cfg_claude, "codex": _cfg_codex}
        if name in cfgs and args.install:
            backup_config(cfgs[name]())
        try:
            result = reg[action]()
            print(f"[{name}] ✅ {result}")
        except Exception as exc:
            print(f"[{name}] ❌ 失败: {exc}")
    return EXIT_OK


if __name__ == "__main__":
    sys.exit(main())
