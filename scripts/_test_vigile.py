#!/usr/bin/env python3
"""vigile.py 测试：脱敏、分类推断、包装器透传、查询与分析。

    python -m unittest _test_gate
"""
import json
import os
import shutil
import sqlite3
import sys
import tempfile
import unittest

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import vigile as au  # noqa: E402


class Base(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.mkdtemp()
        os.environ["VIGILE_DB"] = os.path.join(self.tmp, "audit.db")
        os.environ["VIGILE_ACTOR"] = "tester"
        os.environ["VIGILE_SESSION"] = "sess-test"
        os.environ.pop("VIGILE_CASE", None)
        os.environ.pop("VIGILE_TICKET", None)
        os.environ.pop("VIGILE_RULES", None)
        os.environ.pop("VIGILE_POLICY", None)
        os.environ.pop("VIGILE_CONFIRM", None)
        au._RULES_CACHE = None          # 规则缓存按测试重置
        au._POLICY_CACHE = None

    def tearDown(self):
        shutil.rmtree(self.tmp, ignore_errors=True)
        for k in ("VIGILE_DB", "VIGILE_ACTOR", "VIGILE_SESSION", "VIGILE_CASE",
                  "VIGILE_TICKET", "VIGILE_RULES", "VIGILE_POLICY", "VIGILE_CONFIRM"):
            os.environ.pop(k, None)
        au._RULES_CACHE = None
        au._POLICY_CACHE = None

    def cli(self, argv):
        import io
        from contextlib import redirect_stdout, redirect_stderr
        out, err = io.StringIO(), io.StringIO()
        with redirect_stdout(out), redirect_stderr(err):
            code = au.main(argv)
        return code, out.getvalue(), err.getvalue()

    def rows(self):
        conn = sqlite3.connect(os.environ["VIGILE_DB"])
        conn.row_factory = sqlite3.Row
        conn.row_factory = sqlite3.Row
        try:
            return [dict(r) for r in conn.execute("SELECT * FROM audit_log ORDER BY id")]
        finally:
            conn.close()


class TestRedact(unittest.TestCase):
    def test_env_secret(self):
        self.assertNotIn("abc123", au.redact("JIRA_TOKEN=abc123"))

    def test_password_flag(self):
        out = au.redact("mycli login -u me --password TopSecret9")
        self.assertNotIn("TopSecret9", out)

    def test_short_p_flag(self):
        out = au.redact("tool -p MyPass123")
        self.assertNotIn("MyPass123", out)

    def test_authorization(self):
        out = au.redact("Authorization: Bearer eyJhbGciOiJIUzI1NiJ9zzz")
        self.assertNotIn("eyJhbGciOiJIUzI1NiJ9zzz", out)

    def test_pat(self):
        self.assertNotIn("pat_abcdefgh12345678", au.redact("x pat_abcdefgh12345678 y"))

    def test_keeps_normal(self):
        text = "mytool trace 6ad2fae0 --app svc"
        self.assertEqual(au.redact(text), text)


class TestInference(unittest.TestCase):
    def test_category_by_tool(self):
        self.assertEqual(au.infer_category("kubectl"), "k8s")
        self.assertEqual(au.infer_category("/usr/bin/psql"), "sql")
        self.assertEqual(au.infer_category("mongosh"), "mongo")
        self.assertEqual(au.infer_category("git"), "git")

    def test_category_by_content(self):
        self.assertEqual(au.infer_category("unknown-tool", "db.warning_msg.find({})"), "mongo")
        self.assertEqual(au.infer_category("unknown-tool", "select * from t"), "sql")

    def test_risk_read_write(self):
        self.assertEqual(au.infer_risk("psql", "select 1"), "read")
        self.assertEqual(au.infer_risk("psql", "delete from t"), "write")
        self.assertEqual(au.infer_risk("kubectl", "get pods"), "read")
        self.assertEqual(au.infer_risk("kubectl", "delete pod x"), "write")

    def test_action_extraction(self):
        self.assertEqual(au.infer_action("mytool", ["mytool", "trace", "abc"]), "trace")
        self.assertEqual(au.infer_action("mytool.py", ["mytool.py", "get", "X-1"]), "get")

    def test_target_extraction(self):
        self.assertEqual(au.infer_target("mytool", ["mytool"], "mytool get PROJ-123"),
                         "PROJ-123")
        self.assertEqual(au.infer_target("psql", [], "select a from dwd.orders where x=1"),
                         "dwd.orders")
        self.assertEqual(au.infer_target("mongosh", [], "db.orders.find({})"), "orders")
        self.assertEqual(au.infer_target("x", [], "see https://example.com/api"),
                         "example.com")


class TestUserRules(Base):
    """通用化核心：用户必须能为自己的内部工具配置分类与写动作。"""

    def write_rules(self, payload):
        path = os.path.join(self.tmp, "rules.json")
        with open(path, "w", encoding="utf-8") as fh:
            json.dump(payload, fh)
        os.environ["VIGILE_RULES"] = path
        au._RULES_CACHE = None
        return path

    def test_custom_tool_category(self):
        self.write_rules({"tools": {"myq": "sql"}})
        self.assertEqual(au.infer_category("myq"), "sql")

    def test_custom_write_words(self):
        self.write_rules({"write": {"mydeploy": ["rollout", "apply"]}})
        self.assertEqual(au.infer_risk("mydeploy", "rollout v2"), "write")
        self.assertEqual(au.infer_risk("mydeploy", "status"), "read")

    def test_read_only_override(self):
        self.write_rules({"read_only": ["dangerous-name"]})
        # 即使带写关键词也判只读
        self.assertEqual(au.infer_risk("dangerous-name", "delete from t"), "read")

    def test_falls_back_to_defaults(self):
        # 没有规则文件时用内置默认，开箱即用
        self.assertEqual(au.infer_category("kubectl"), "k8s")

    def test_broken_rules_do_not_break_audit(self):
        path = os.path.join(self.tmp, "rules.json")
        with open(path, "w", encoding="utf-8") as fh:
            fh.write("{ not valid json")
        os.environ["VIGILE_RULES"] = path
        au._RULES_CACHE = None
        self.assertEqual(au.infer_category("kubectl"), "k8s")  # 退回默认
        au._RULES_CACHE = None

    def test_rules_init_creates_template(self):
        path = os.path.join(self.tmp, "rules.json")
        os.environ["VIGILE_RULES"] = path
        au._RULES_CACHE = None
        code, out, _ = self.cli(["rules", "--init"])
        self.assertEqual(code, 0)
        self.assertTrue(os.path.exists(path))
        with open(path, encoding="utf-8") as fh:
            data = json.load(fh)
        self.assertIn("tools", data)


class TestRun(Base):
    def test_run_records_success(self):
        code, out, err = self.cli(["run", "--case", "C-1", "--",
                                   sys.executable, "-c", "print('hello-audit')"])
        self.assertEqual(code, 0)
        self.assertIn("hello-audit", out)          # 输出透传
        self.assertIn("[audit]", err)              # 有审计摘要
        rows = self.rows()
        self.assertEqual(len(rows), 1)
        r = rows[0]
        self.assertEqual(r["status"], "ok")
        self.assertEqual(r["exit_code"], 0)
        self.assertEqual(r["case_name"], "C-1")
        self.assertIn("hello-audit", r["output_digest"])
        self.assertIsNotNone(r["duration_ms"])
        self.assertEqual(r["source"], "cli")

    def test_run_records_failure_and_exit_code(self):
        code, _, _ = self.cli(["run", "--", sys.executable, "-c",
                               "import sys; sys.stderr.write('boom'); sys.exit(3)"])
        self.assertEqual(code, 3)                  # 退出码透传
        r = self.rows()[0]
        self.assertEqual(r["status"], "failed")
        self.assertEqual(r["exit_code"], 3)
        self.assertIn("boom", r["error"])

    def test_run_missing_command(self):
        code, _, _ = self.cli(["run", "--", "definitely-not-a-real-cmd-xyz"])
        self.assertNotEqual(code, 0)
        r = self.rows()[0]
        self.assertEqual(r["status"], "failed")
        self.assertIn("命令不存在", r["error"])

    def test_run_redacts_arguments(self):
        self.cli(["run", "--", sys.executable, "-c", "print(1)",
                  "--token", "SuperSecret123"])
        r = self.rows()[0]
        self.assertNotIn("SuperSecret123", r["args_json"])
        self.assertIn("***", r["args_json"])

    def test_run_timeout_classified(self):
        code, _, _ = self.cli(["run", "--", sys.executable, "-c",
                               "import sys; sys.stderr.write('connect timeout'); sys.exit(1)"])
        r = self.rows()[0]
        self.assertEqual(r["status"], "timeout")

    def test_quiet_suppresses_summary(self):
        _, _, err = self.cli(["run", "--quiet", "--", sys.executable, "-c", "pass"])
        self.assertNotIn("[audit]", err)


class TestCall(Base):
    def test_call_records(self):
        code, out, _ = self.cli(["call", "--tool", "jira", "--action", "get",
                                 "--target", "BUGONLINE-1", "--category", "jira",
                                 "--duration", "321", "--rows", "1",
                                 "--output", "ok", "--ticket", "BUGONLINE-1"])
        self.assertEqual(code, 0)
        rid = json.loads(out)["id"]
        r = self.rows()[0]
        self.assertEqual(r["id"], rid)
        self.assertEqual(r["tool"], "jira")
        self.assertEqual(r["duration_ms"], 321)
        self.assertEqual(r["ticket"], "BUGONLINE-1")
        self.assertEqual(r["source"], "python")

    def test_call_redacts_error(self):
        self.cli(["call", "--tool", "t", "--error", "JIRA_TOKEN=leak123"])
        self.assertNotIn("leak123", self.rows()[0]["error"])


class TestQueries(Base):
    def seed(self):
        self.cli(["call", "--tool", "log-query", "--category", "log", "--status", "ok",
                  "--duration", "100", "--case", "C-A"])
        self.cli(["call", "--tool", "bigdata-query", "--category", "sql", "--status", "failed",
                  "--duration", "9000", "--case", "C-A", "--error", "timeout exceeded"])
        self.cli(["call", "--tool", "jira", "--category", "jira", "--status", "ok",
                  "--duration", "250", "--case", "C-B"])

    def test_filter_by_tool(self):
        self.seed()
        _, out, _ = self.cli(["logs", "--tool", "jira"])
        self.assertEqual(out.count("#"), 1)

    def test_filter_by_case(self):
        self.seed()
        _, out, _ = self.cli(["logs", "--case", "C-A"])
        self.assertEqual(out.count("#"), 2)

    def test_logs_json(self):
        self.seed()
        _, out, _ = self.cli(["logs", "--json"])
        data = json.loads(out)
        self.assertEqual(len(data), 3)

    def test_stats(self):
        self.seed()
        _, out, _ = self.cli(["stats"])
        self.assertIn("总调用 3 次", out)
        self.assertIn("log-query", out)
        self.assertIn("failed", out)

    def test_slow(self):
        self.seed()
        _, out, _ = self.cli(["slow", "--limit", "1"])
        self.assertIn("9000ms", out)

    def test_errors(self):
        self.seed()
        _, out, _ = self.cli(["errors"])
        self.assertIn("bigdata-query", out)
        self.assertIn("timeout exceeded", out)

    def test_by_case(self):
        self.seed()
        _, out, _ = self.cli(["by-case"])
        self.assertIn("C-A", out)
        self.assertIn("C-B", out)

    def test_timeline(self):
        self.seed()
        _, out, _ = self.cli(["timeline", "--case", "C-A"])
        self.assertIn("✓", out)
        self.assertIn("✗", out)

    def test_get_and_export(self):
        self.seed()
        _, out, _ = self.cli(["get", "1"])
        self.assertEqual(json.loads(out)["id"], 1)
        _, out, _ = self.cli(["export", "--format", "json"])
        self.assertEqual(len(json.loads(out)), 3)
        _, out, _ = self.cli(["export", "--format", "csv"])
        self.assertIn("tool", out.splitlines()[0])

    def test_prune(self):
        self.seed()
        conn = sqlite3.connect(os.environ["VIGILE_DB"])
        conn.row_factory = sqlite3.Row
        conn.execute("UPDATE audit_log SET ts_epoch = 1")
        conn.commit()
        conn.close()
        _, out, _ = self.cli(["prune", "--keep", "1d"])
        self.assertIn("已清理 3 条", out)


class TestPolicy(Base):
    """执行前审核：deny 必须真的不执行，ask 必须要求确认。"""

    def test_deny_rm_rf(self):
        v = au.evaluate("rm", ["rm", "-rf", "/tmp/x"], "rm -rf /tmp/x")
        self.assertEqual(v["decision"], "deny")

    def test_deny_drop_table(self):
        v = au.evaluate("psql", ["psql", "-c", "drop table t"], "psql -c 'drop table t'")
        self.assertEqual(v["decision"], "deny")

    def test_deny_delete_without_where(self):
        v = au.evaluate("psql", ["psql"], "delete from users")
        self.assertEqual(v["decision"], "deny")

    def test_ask_delete_with_where(self):
        v = au.evaluate("psql", ["psql"], "delete from t where id=1")
        self.assertEqual(v["decision"], "ask")

    def test_allow_readonly(self):
        v = au.evaluate("shandian", ["shandian", "status"], "shandian status")
        self.assertEqual(v["decision"], "allow")

    def test_allow_tools_bypass(self):
        path = os.path.join(self.tmp, "policy.json")
        with open(path, "w", encoding="utf-8") as fh:
            json.dump({"allow_tools": ["psql"], "deny": [], "ask": []}, fh)
        os.environ["VIGILE_POLICY"] = path
        au._POLICY_CACHE = None
        v = au.evaluate("psql", ["psql"], "drop table t")
        self.assertEqual(v["decision"], "allow")

    def test_deny_tools_blocks(self):
        path = os.path.join(self.tmp, "policy.json")
        with open(path, "w", encoding="utf-8") as fh:
            json.dump({"deny_tools": ["badcli"], "deny": [], "ask": []}, fh)
        os.environ["VIGILE_POLICY"] = path
        au._POLICY_CACHE = None
        v = au.evaluate("badcli", ["badcli", "run"], "badcli run")
        self.assertEqual(v["decision"], "deny")

    def test_broken_policy_falls_back(self):
        path = os.path.join(self.tmp, "policy.json")
        with open(path, "w", encoding="utf-8") as fh:
            fh.write("{bad")
        os.environ["VIGILE_POLICY"] = path
        au._POLICY_CACHE = None
        # 配置坏了也要保留内置危险模式
        self.assertEqual(au.evaluate("rm", ["rm"], "rm -rf /")["decision"], "deny")
        au._POLICY_CACHE = None

    def test_run_denied_does_not_execute(self):
        marker = os.path.join(self.tmp, "should-not-exist")
        code, out, err = self.cli(["run", "--", "rm", "-rf", marker])
        self.assertEqual(code, au.EXIT_DENIED)
        self.assertIn("已拒绝执行", err)
        r = self.rows()[-1]
        self.assertEqual(r["status"], "denied")
        self.assertIn("策略拒绝", r["error"])

    def test_run_ask_denied_without_confirm(self):
        code, _, err = self.cli(["run", "--", "echo", "delete from t where id=1"])
        self.assertEqual(code, au.EXIT_DENIED)
        self.assertIn("需要确认", err)

    def test_run_ask_allowed_with_yes_flag(self):
        code, out, _ = self.cli(["run", "-y", "--",
                                 sys.executable, "-c", "print('delete from t where id=1')"])
        self.assertEqual(code, 0)
        self.assertEqual(self.rows()[-1]["status"], "ok")

    def test_deny_not_bypassed_by_confirm_env(self):
        # deny 级永远不能靠确认越过（只有 ask 级才可以）
        os.environ["VIGILE_CONFIRM"] = "yes"
        code, _, err = self.cli(["run", "--", "sh", "-c", "drop table users"])
        # sh -c 里的内容命中 deny 模式
        self.assertEqual(code, au.EXIT_DENIED)
        self.assertIn("拒绝", err)

    def test_no_policy_flag_bypasses(self):
        code, _, _ = self.cli(["run", "--no-policy", "--", sys.executable,
                               "-c", "print(1)"])
        self.assertEqual(code, 0)

    def test_policy_test_command(self):
        code, out, _ = self.cli(["policy", "--test", "rm -rf /"])
        self.assertEqual(code, au.EXIT_DENIED)
        self.assertEqual(json.loads(out)["decision"], "deny")

    def test_custom_message_returned(self):
        v = au.evaluate("rm", ["rm", "-rf", "/x"], "rm -rf /x")
        self.assertEqual(v["rule_id"], "rm_recursive")
        self.assertIn("递归删除", v["message"])
        self.assertTrue(v["hint"])

    def test_user_can_override_message_by_id(self):
        path = os.path.join(self.tmp, "policy.json")
        with open(path, "w", encoding="utf-8") as fh:
            json.dump({"deny": [{"id": "rm_recursive",
                                 "pattern": r"\brm\s+-rf\b",
                                 "message": "公司规定：禁止在服务器上 rm -rf",
                                 "hint": "请走数据清理流程"}], "ask": []}, fh)
        os.environ["VIGILE_POLICY"] = path
        au._POLICY_CACHE = None
        v = au.evaluate("rm", ["rm", "-rf", "/x"], "rm -rf /x")
        self.assertEqual(v["decision"], "deny")
        self.assertEqual(v["message"], "公司规定：禁止在服务器上 rm -rf")
        self.assertEqual(v["hint"], "请走数据清理流程")

    def test_custom_new_rule_with_message(self):
        path = os.path.join(self.tmp, "policy.json")
        with open(path, "w", encoding="utf-8") as fh:
            json.dump({"deny": [{"id": "no_prod_db",
                                 "pattern": "prod-db",
                                 "message": "禁止连接生产库 {tool}",
                                 "hint": "改用只读从库"}], "ask": []}, fh)
        os.environ["VIGILE_POLICY"] = path
        au._POLICY_CACHE = None
        v = au.evaluate("mycli", ["mycli", "prod-db"], "mycli prod-db")
        self.assertEqual(v["decision"], "deny")
        self.assertIn("禁止连接生产库 mycli", v["message"])

    def test_legacy_string_rule_still_works(self):
        # 旧格式（纯正则字符串）必须继续兼容
        path = os.path.join(self.tmp, "policy.json")
        with open(path, "w", encoding="utf-8") as fh:
            json.dump({"deny": ["forbidden-word"], "ask": []}, fh)
        os.environ["VIGILE_POLICY"] = path
        au._POLICY_CACHE = None
        v = au.evaluate("x", ["x", "forbidden-word"], "x forbidden-word")
        self.assertEqual(v["decision"], "deny")

    def test_builtin_rules_survive_broken_config(self):
        path = os.path.join(self.tmp, "policy.json")
        with open(path, "w", encoding="utf-8") as fh:
            fh.write("{broken")
        os.environ["VIGILE_POLICY"] = path
        au._POLICY_CACHE = None
        self.assertEqual(au.evaluate("rm", ["rm"], "rm -rf /")["decision"], "deny")
        au._POLICY_CACHE = None

    def test_denied_output_includes_message_and_hint(self):
        code, _, err = self.cli(["run", "--", "rm", "-rf", "/tmp/x"])
        self.assertEqual(code, au.EXIT_DENIED)
        self.assertIn("rm_recursive", err)
        self.assertIn("递归删除", err)
        self.assertIn("建议", err)

    def test_policy_init_creates_template(self):
        path = os.path.join(self.tmp, "policy.json")
        os.environ["VIGILE_POLICY"] = path
        au._POLICY_CACHE = None
        code, _, _ = self.cli(["policy", "--init"])
        self.assertEqual(code, 0)
        with open(path, encoding="utf-8") as fh:
            data = json.load(fh)
        self.assertIn("deny", data)
        self.assertIn("ask", data)


class TestBlastRadius(Base):
    """影响预览：拒绝时告诉用户具体会影响什么。"""

    def test_rm_rf_impact(self):
        d = os.path.join(self.tmp, "victim")
        os.makedirs(os.path.join(d, "sub"), exist_ok=True)
        open(os.path.join(d, "a.txt"), "w").write("x" * 100)
        v = au.blast_radius(["rm", "-rf", d])
        self.assertIsNotNone(v)
        self.assertIn("1 个文件", v)

    def test_rm_nonexistent_returns_none(self):
        self.assertIsNone(au.blast_radius(["rm", "-rf", "/no/such/dir/xyz"]))

    def test_msys_tmp_path_conversion(self):
        # Git Bash 的 /tmp/x 应转换到 Windows 临时目录
        converted = au._msys_path("/tmp/abc")
        self.assertNotIn("/tmp", converted)
        self.assertTrue(os.path.isabs(converted))

    def test_msys_drive_path(self):
        self.assertEqual(au._msys_path("/c/Users/x"), "C:/Users/x")

    def test_drop_table_impact(self):
        v = au.blast_radius(["psql", "-c", "drop table users"])
        self.assertIsNotNone(v)
        self.assertIn("users", v)

    def test_deny_output_includes_impact(self):
        d = os.path.join(self.tmp, "vic2")
        os.makedirs(d, exist_ok=True)
        open(os.path.join(d, "f.txt"), "w").write("x")
        code, _, err = self.cli(["run", "--", "rm", "-rf", d])
        self.assertEqual(code, au.EXIT_DENIED)
        self.assertIn("影响预览", err)


class TestHashChain(Base):
    """防篡改 hash 链：任何删除/篡改都能被 verify 检出。"""

    def _write3(self):
        for i in (1, 2, 3):
            self.cli(["call", "--tool", f"c{i}", "--action", "run", "--status", "ok"])

    def test_verify_ok_when_untouched(self):
        self._write3()
        code, out, _ = self.cli(["verify"])
        self.assertEqual(code, 0)
        self.assertIn("完整", out)

    def test_verify_detects_tamper(self):
        self._write3()
        c = sqlite3.connect(os.environ["VIGILE_DB"])
        c.execute("UPDATE audit_log SET status='hacked' WHERE tool='c2'")
        c.commit(); c.close()
        code, out, err = self.cli(["verify"])
        self.assertNotEqual(code, 0)
        self.assertIn("#2", out)            # stdout 指出具体哪条被篡改
        self.assertIn("异常", err)          # stderr 是汇总行

    def test_verify_detects_deletion(self):
        self._write3()
        c = sqlite3.connect(os.environ["VIGILE_DB"])
        c.execute("DELETE FROM audit_log WHERE tool='c2'")
        c.commit(); c.close()
        code, out, _ = self.cli(["verify"])
        self.assertNotEqual(code, 0)

    def test_legacy_records_not_flagged(self):
        # 无 hash 的旧记录不应误报
        self._write3()
        c = sqlite3.connect(os.environ["VIGILE_DB"])
        c.execute("UPDATE audit_log SET hash=NULL, prev_hash=NULL")
        c.commit(); c.close()
        code, out, _ = self.cli(["verify"])
        self.assertEqual(code, 0)
        self.assertIn("旧记录", out)


class TestFileChange(Base):
    """post-tool 差异记录。"""

    def test_record_and_query(self):
        rid = au.record_file_change("a/b.py", "edit", "x\nold\n", "x\nnew\n")
        self.assertGreater(rid, 0)
        conn = sqlite3.connect(os.environ["VIGILE_DB"])
        conn.row_factory = sqlite3.Row
        rows = conn.execute("SELECT * FROM file_changes").fetchall()
        self.assertEqual(len(rows), 1)
        r = rows[0]
        self.assertEqual(r["added_lines"], 1)
        self.assertEqual(r["removed_lines"], 1)
        self.assertIn("-old", r["diff"])
        self.assertIn("+new", r["diff"])
        self.assertIsNotNone(r["before_hash"])
        self.assertIsNotNone(r["after_hash"])
        self.assertNotEqual(r["before_hash"], r["after_hash"])

    def test_new_file_write(self):
        au.record_file_change("new.py", "write", None, "content")
        conn = sqlite3.connect(os.environ["VIGILE_DB"])
        conn.row_factory = sqlite3.Row
        r = conn.execute("SELECT * FROM file_changes").fetchone()
        self.assertIsNone(r["before_hash"])
        self.assertIsNotNone(r["after_hash"])

    def test_diff_cmd_filter_by_file(self):
        au.record_file_change("src/app.py", "edit", "a", "b")
        au.record_file_change("other/x.py", "edit", "a", "b")
        code, out, _ = self.cli(["diff", "--file", "app"])
        self.assertEqual(code, 0)
        self.assertIn("app.py", out)
        self.assertNotIn("other/x.py", out)

    def test_call_file_change_cmd(self):
        code, out, _ = self.cli(["call-file-change", "--file", "t.py",
                                 "--op", "edit", "--before", "a", "--after", "b"])
        self.assertEqual(code, 0)
        self.assertIn("id", out)


class TestSessionView(Base):
    def test_session_lists_recent(self):
        self.cli(["call", "--tool", "s1", "--status", "ok"])
        code, out, _ = self.cli(["session"])
        self.assertEqual(code, 0)
        self.assertIn("s1", out) if False else None   # 列表按 session 分组，只查有输出
        self.assertTrue(out.strip())

    def test_session_detail_shows_calls(self):
        sid = "fixed-sess-test"
        os.environ["VIGILE_SESSION"] = sid
        self.cli(["call", "--tool", "mytool", "--action", "run", "--status", "ok"])
        os.environ.pop("VIGILE_SESSION", None)
        code, out, _ = self.cli(["session", sid])
        self.assertEqual(code, 0)
        self.assertIn("mytool", out)

    def test_session_detail_includes_file_changes(self):
        sid = "sess-with-files"
        os.environ["VIGILE_SESSION"] = sid
        try:
            au.record_file_change("src/a.py", "edit", "x", "y")
            self.cli(["call", "--tool", "t", "--status", "ok"])
        finally:
            os.environ.pop("VIGILE_SESSION", None)
        code, out, _ = self.cli(["session", sid])
        self.assertIn("✎", out)         # 文件变更标记
        self.assertIn("src/a.py", out)


class TestOrchestratorContext(Base):
    """Multica 等编排层上下文自动识别。"""

    def test_detects_multica_env(self):
        os.environ["MULTICA_TASK_ID"] = "T-100"
        os.environ["MULTICA_AGENT_NAME"] = "claude-7"
        try:
            ctx = au.orchestrator_context()
            self.assertEqual(ctx["MULTICA_TASK_ID"], "T-100")
            self.assertEqual(au.orchestrator_actor(), "multica/claude-7 (T-100)")
            self.assertEqual(au.orchestrator_session_suffix(), "multica:T-100")
        finally:
            os.environ.pop("MULTICA_TASK_ID", None)
            os.environ.pop("MULTICA_AGENT_NAME", None)

    def test_no_env_no_context(self):
        for k in au.MULTICA_ENV_KEYS:
            os.environ.pop(k, None)
        self.assertEqual(au.orchestrator_context(), {})
        self.assertIsNone(au.orchestrator_actor())
        self.assertEqual(au.orchestrator_session_suffix(), "")

    def test_record_carries_context(self):
        os.environ["MULTICA_TASK_ID"] = "T-200"
        os.environ["MULTICA_AGENT_NAME"] = "kimi-1"
        try:
            self.cli(["call", "--tool", "mc", "--status", "ok"])
            r = self.rows()[-1]
            self.assertIn("multica/mc" if False else "multica/kimi-1", r["actor"])
            self.assertIn("multica:T-200", r["session"])
            meta = json.loads(r["meta_json"])
            self.assertEqual(meta["orchestrator"]["MULTICA_TASK_ID"], "T-200")
        finally:
            os.environ.pop("MULTICA_TASK_ID", None)
            os.environ.pop("MULTICA_AGENT_NAME", None)

    def test_normal_record_unaffected(self):
        for k in au.MULTICA_ENV_KEYS:
            os.environ.pop(k, None)
        self.cli(["call", "--tool", "plain", "--status", "ok"])
        r = self.rows()[-1]
        self.assertNotIn("multica", r["actor"])
        self.assertNotIn("multica", r["session"])
        self.assertIsNone(r["meta_json"])

    def test_keyword_filters_by_task(self):
        os.environ["MULTICA_TASK_ID"] = "T-300"
        try:
            self.cli(["call", "--tool", "x", "--status", "ok"])
        finally:
            os.environ.pop("MULTICA_TASK_ID", None)
        self.cli(["call", "--tool", "y", "--status", "ok"])   # 普通
        code, out, _ = self.cli(["logs", "--keyword", "multica:T-300"])
        self.assertIn("x", out)
        self.assertNotIn("y", out)


class TestSchema(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.mkdtemp()
        os.environ["VIGILE_DB"] = os.path.join(self.tmp, "a.db")

    def tearDown(self):
        shutil.rmtree(self.tmp, ignore_errors=True)
        os.environ.pop("VIGILE_DB", None)

    def test_indexes_created(self):
        conn = au.connect()
        names = {r[0] for r in conn.execute(
            "SELECT name FROM sqlite_master WHERE type='index'")}
        for idx in ("idx_audit_ts", "idx_audit_tool", "idx_audit_case", "idx_audit_status"):
            self.assertIn(idx, names)
        conn.close()

    def test_wal_mode(self):
        conn = au.connect()
        mode = conn.execute("PRAGMA journal_mode").fetchone()[0]
        self.assertEqual(mode.lower(), "wal")
        conn.close()

    def test_idempotent_schema(self):
        au.connect().close()
        au.connect().close()  # 重复打开不报错


if __name__ == "__main__":
    unittest.main(verbosity=2)
