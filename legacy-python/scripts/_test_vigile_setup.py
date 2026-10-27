#!/usr/bin/env python3
"""vigile_setup.py 测试：安装/卸载/幂等/备份/其它 hook 不受影响。

用临时 HOME 隔离，不碰真实配置。

    python -m unittest _test_setup
"""
import json
import os
import shutil
import sys
import tempfile
import unittest

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import vigile_setup as gs  # noqa: E402


class Base(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.mkdtemp()
        self._home = os.environ.get("HOME") or os.path.expanduser("~")
        os.environ["HOME"] = self.tmp
        # Windows 下 expanduser 优先 USERPROFILE
        self._up = os.environ.get("USERPROFILE")
        os.environ["USERPROFILE"] = self.tmp
        # 重置 registry 里的函数缓存路径（它们用 home() 动态计算，无需重置）
        # 但 rtk/已有 hook 模拟数据要先写入
        self.mk_codex_with_rtk()

    def tearDown(self):
        os.environ["HOME"] = self._home
        if self._up:
            os.environ["USERPROFILE"] = self._up
        else:
            os.environ.pop("USERPROFILE", None)
        shutil.rmtree(self.tmp, ignore_errors=True)

    # ---- 帮助函数 ----
    def cfg(self, *parts):
        return os.path.join(self.tmp, *parts)

    def mk_codex_with_rtk(self):
        """模拟一个已带 rtk hook 的 codex 配置。"""
        os.makedirs(self.cfg(".codex"), exist_ok=True)
        d = {"hooks": {"PreToolUse": [
            {"matcher": "Bash", "hooks": [{"type": "command", "command": "rtk hook claude"}]},
        ]}}
        json.dump(d, open(self.cfg(".codex", "hooks.json"), "w", encoding="utf-8"))

    def mk_claude(self):
        os.makedirs(self.cfg(".claude"), exist_ok=True)
        d = {"hooks": {"PreToolUse": []}}
        json.dump(d, open(self.cfg(".claude", "settings.json"), "w", encoding="utf-8"))

    def mk_zcode(self):
        os.makedirs(self.cfg(".zcode", "cli"), exist_ok=True)
        d = {"hooks": {"enabled": True, "events": {"PreToolUse": []}}}
        json.dump(d, open(self.cfg(".zcode", "cli", "config.json"), "w", encoding="utf-8"))

    def mk_opencode(self):
        os.makedirs(self.cfg(".config", "opencode"), exist_ok=True)
        open(self.cfg(".config", "opencode", "AGENTS.md"), "w",
             encoding="utf-8").write("# rules\n")


class TestCodex(Base):
    def test_install_adds_entry_and_keeps_rtk(self):
        gs.main(["--install", "--agent", "codex"])
        d = json.load(open(self.cfg(".codex", "hooks.json"), encoding="utf-8"))
        cmds = [h.get("command", "")
                for e in d["hooks"]["PreToolUse"] for h in e["hooks"]]
        self.assertTrue(any("vigile-hook.js" in c for c in cmds))
        self.assertTrue(any("rtk" in c for c in cmds))          # rtk 不受影响

    def test_install_is_idempotent(self):
        gs.main(["--install", "--agent", "codex"])
        gs.main(["--install", "--agent", "codex"])
        d = json.load(open(self.cfg(".codex", "hooks.json"), encoding="utf-8"))
        vigile_count = sum(1 for e in d["hooks"]["PreToolUse"] for h in e["hooks"]
                         if "vigile-hook.js" in h.get("command", ""))
        self.assertEqual(vigile_count, 1)                          # 只有一条

    def test_vigile_entry_inserted_first(self):
        gs.main(["--install", "--agent", "codex"])
        d = json.load(open(self.cfg(".codex", "hooks.json"), encoding="utf-8"))
        first = d["hooks"]["PreToolUse"][0]["hooks"][0]["command"]
        self.assertIn("vigile-hook.js", first)                      # 先于 rtk

    def test_uninstall_removes_only_gate(self):
        gs.main(["--install", "--agent", "codex"])
        gs.main(["--uninstall", "--agent", "codex"])
        d = json.load(open(self.cfg(".codex", "hooks.json"), encoding="utf-8"))
        cmds = [h.get("command", "")
                for e in d["hooks"]["PreToolUse"] for h in e["hooks"]]
        self.assertFalse(any("vigile-hook" in c for c in cmds))
        self.assertTrue(any("rtk" in c for c in cmds))

    def test_backup_created(self):
        gs.main(["--install", "--agent", "codex"])
        self.assertTrue(os.path.exists(self.cfg(".codex", "hooks.json.bak-gate")))

    def test_uninstall_without_install(self):
        code = gs.main(["--uninstall", "--agent", "codex"])
        self.assertEqual(code, gs.EXIT_OK)


class TestClaude(Base):
    def test_install_and_status(self):
        self.mk_claude()
        gs.main(["--install", "--agent", "claude"])
        st = gs.HOOK_REGISTRY["claude"]["status"]()
        self.assertEqual(st, "已安装")

    def test_uninstall(self):
        self.mk_claude()
        gs.main(["--install", "--agent", "claude"])
        gs.main(["--uninstall", "--agent", "claude"])
        st = gs.HOOK_REGISTRY["claude"]["status"]()
        self.assertEqual(st, "未安装")


class TestZcode(Base):
    def test_install_enables_hooks(self):
        self.mk_zcode()
        gs.main(["--install", "--agent", "zcode"])
        d = json.load(open(self.cfg(".zcode", "cli", "config.json"), encoding="utf-8"))
        self.assertTrue(d["hooks"]["enabled"])
        entries = d["hooks"]["events"]["PreToolUse"]
        self.assertEqual(len(entries), 1)
        self.assertEqual(entries[0]["matcher"], "Bash")
        self.assertEqual(entries[0]["hooks"][0]["type"], "process")

    def test_uninstall(self):
        self.mk_zcode()
        gs.main(["--install", "--agent", "zcode"])
        gs.main(["--uninstall", "--agent", "zcode"])
        d = json.load(open(self.cfg(".zcode", "cli", "config.json"), encoding="utf-8"))
        self.assertEqual(d["hooks"]["events"]["PreToolUse"], [])


class TestOpenCode(Base):
    def test_rule_written_and_idempotent(self):
        self.mk_opencode()
        gs.main(["--install", "--agent", "opencode"])
        content = open(self.cfg(".config", "opencode", "AGENTS.md"), encoding="utf-8").read()
        self.assertIn("vigile run --", content)
        # 幂等：不重复追加
        gs.main(["--install", "--agent", "opencode"])
        self.assertEqual(content.count("## vigile 规则"), 1)

    def test_uninstall_removes_rule(self):
        self.mk_opencode()
        gs.main(["--install", "--agent", "opencode"])
        gs.main(["--uninstall", "--agent", "opencode"])
        content = open(self.cfg(".config", "opencode", "AGENTS.md"), encoding="utf-8").read()
        self.assertNotIn("## vigile 规则", content)


class TestDsh(Base):
    def setUp(self):
        super().setUp()
        # 需要 claude 配置存在（dsh 桥指向它）
        self.mk_claude()

    def mk_dsh_profile(self):
        os.makedirs(self.cfg(".dsh", "profiles", "desktop"), exist_ok=True)
        open(self.cfg(".dsh", "profiles", "desktop", "cordis.patch.yml"), "w",
             encoding="utf-8").write("- id: llm-deepseek\n  name: llm\n")

    def test_install_appends_bridge(self):
        self.mk_dsh_profile()
        gs.main(["--install", "--agent", "dsh"])
        text = open(self.cfg(".dsh", "profiles", "desktop", "cordis.patch.yml"),
                    encoding="utf-8").read()
        self.assertIn("dsh-hooks-claude-code", text)
        self.assertIn("settings.json", text)

    def test_install_idempotent(self):
        self.mk_dsh_profile()
        gs.main(["--install", "--agent", "dsh"])
        gs.main(["--install", "--agent", "dsh"])
        text = open(self.cfg(".dsh", "profiles", "desktop", "cordis.patch.yml"),
                    encoding="utf-8").read()
        self.assertEqual(text.count("vigile-hooks-bridge"), 1)

    def test_uninstall_removes_bridge(self):
        self.mk_dsh_profile()
        gs.main(["--install", "--agent", "dsh"])
        gs.main(["--uninstall", "--agent", "dsh"])
        text = open(self.cfg(".dsh", "profiles", "desktop", "cordis.patch.yml"),
                    encoding="utf-8").read()
        self.assertNotIn("dsh-hooks-claude-code", text)
        self.assertIn("llm-deepseek", text)   # 原有条目不受影响

    def test_no_profile_skips(self):
        code = gs.main(["--install", "--agent", "dsh"])
        self.assertEqual(code, gs.EXIT_OK)


class TestListAndAll(Base):
    def test_list_shows_all(self):
        import io
        from contextlib import redirect_stdout
        out = io.StringIO()
        with redirect_stdout(out):
            gs.main(["--list"])
        text = out.getvalue()
        for name in ("zcode", "claude", "codex", "opencode"):
            self.assertIn(name, text)

    def test_install_all(self):
        self.mk_claude(); self.mk_zcode(); self.mk_opencode()
        gs.main(["--install", "--agent", "all"])
        for name in ("claude", "zcode", "codex", "opencode"):
            st = gs.HOOK_REGISTRY[name]["status"]()
            self.assertIn(st, ("已安装", "已写入规则"), f"{name}: {st}")

    def test_install_missing_agent_skips(self):
        # 不创建 claude 配置 → 应跳过不崩
        code = gs.main(["--install", "--agent", "claude"])
        self.assertEqual(code, gs.EXIT_OK)


if __name__ == "__main__":
    unittest.main(verbosity=2)
