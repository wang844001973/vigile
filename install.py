#!/usr/bin/env python3
"""跨平台安装脚本：把 vigile CLI 装到用户 PATH。

用法:
    python install.py              # 安装
    python install.py --uninstall  # 卸载
    python install.py --dry-run    # 只看会做什么

做的事:
1. 选择可写的用户级 bin 目录（Linux/macOS: ~/.local/bin；Windows: %LOCALAPPDATA%\\Programs\\audit）
2. 生成入口脚本（Unix 用 sh，Windows 用 .cmd），指向本仓库的 audit.py
3. 提示把 bin 目录加进 PATH

不修改系统目录、不写注册表、不需要 root。
"""
import os
import stat
import sys
from typing import Optional, Tuple

MIN_PY = (3, 7)


def bin_dir() -> str:
    if os.name == "nt":
        base = os.environ.get("LOCALAPPDATA") or os.path.expanduser("~")
        return os.path.join(base, "Programs", "vigile")
    return os.path.join(os.path.expanduser("~"), ".local", "bin")


def entry_paths(bdir: str) -> Tuple[str, ...]:
    if os.name == "nt":
        return (os.path.join(bdir, "vigile.cmd"), os.path.join(bdir, "vig.cmd"))
    return (os.path.join(bdir, "vigile"), os.path.join(bdir, "vig"))


def script_path() -> str:
    return os.path.join(os.path.dirname(os.path.abspath(__file__)), "scripts", "vigile.py")


def write_entry(target: str, py: str) -> None:
    """生成 CLI 入口。同时把 vigile.py 复制到安装目录，使入口独立于仓库位置——
    仓库移动/删除后命令仍可用（升级方式：仓库里重新 python install.py）。"""
    os.makedirs(os.path.dirname(target), exist_ok=True)
    bdir = os.path.dirname(target)
    local_py = os.path.join(bdir, "vigile.py")
    shutil.copyfile(script_path(), local_py)
    if target.endswith(".cmd"):
        content = f'@echo off\r\n"{py}" "{local_py}" %*\r\n'
    else:
        content = f'#!/bin/sh\nexec "{py}" "{local_py}" "$@"\n'
    with open(target, "w", encoding="utf-8", newline="") as fh:
        fh.write(content)
    if not target.endswith(".cmd"):
        os.chmod(target, os.stat(target).st_mode | stat.S_IXUSR | stat.S_IXGRP | stat.S_IXOTH)


def in_path(directory: str) -> bool:
    parts = os.environ.get("PATH", "").split(os.pathsep)
    norm = lambda p: os.path.normcase(os.path.normpath(p.rstrip("/\\") or p))
    return any(norm(p) == norm(directory) for p in parts if p)


def main(argv: Optional[list] = None) -> int:
    argv = list(argv if argv is not None else sys.argv[1:])
    uninstall = "--uninstall" in argv
    dry = "--dry-run" in argv

    if sys.version_info < MIN_PY:
        print(f"需要 Python {MIN_PY[0]}.{MIN_PY[1]}+，当前 {sys.version.split()[0]}", file=sys.stderr)
        return 1

    bdir = bin_dir()
    py = sys.executable
    targets = entry_paths(bdir)

    if uninstall:
        for t in targets:
            if os.path.exists(t):
                print(f"{'[dry-run] 将删除' if dry else '删除'} {t}")
                if not dry:
                    os.remove(t)
            else:
                print(f"不存在，跳过: {t}")
        return 0

    print(f"Python: {py}")
    print(f"安装目录: {bdir}")
    for t in targets:
        print(f"{'[dry-run] 将写入' if dry else '写入'} {t}")
        if not dry:
            write_entry(t, py)

    if not dry:
        ok = all(os.path.exists(t) for t in targets)
        print("安装完成。" if ok else "安装可能失败，请检查权限。")
        if not ok:
            return 1

    if not in_path(bdir):
        print()
        print("⚠ 该目录不在 PATH 中，请手动加入：")
        if os.name == "nt":
            print(f'   setx PATH "%PATH%;{bdir}"')
            print("   （或：系统属性 → 环境变量 → 编辑用户 PATH，新增一行）")
        else:
            print(f'   export PATH="{bdir}:$PATH"')
            print("   （建议写进 ~/.bashrc 或 ~/.zshrc）")
    else:
        print("PATH 中已包含该目录，可直接运行: vigile --help")

    print()
    print("下一步：")
    print("  vigile --help           查看全部命令")
    print("  vigile tail             实时查看审计流水")
    return 0


if __name__ == "__main__":
    sys.exit(main())
