"""Tests for lcscan. Run: python -m unittest test_lcscan -v"""
import json
import tempfile
import textwrap
import unittest
from pathlib import Path

import lcscan


def make_repo(files: dict) -> Path:
    root = Path(tempfile.mkdtemp()) / "repo"
    for rel, content in files.items():
        p = root / rel
        p.parent.mkdir(parents=True, exist_ok=True)
        p.write_text(textwrap.dedent(content))
    return root


class VersionClassification(unittest.TestCase):
    def test_boundaries(self):
        cases = {"0.3.80": "affected", "0.3.81": "fixed", "0.2.43": "affected", "0.1.0": "affected",
                 "1.0.0": "affected", "1.0.0a5": "affected", "1.1.9": "affected",
                 "1.2.4": "affected", "1.2.5": "fixed", "1.3.0": "fixed", "not-a-version": "unknown"}
        for v, expected in cases.items():
            self.assertEqual(lcscan.classify_core(v), expected, v)


class Dependencies(unittest.TestCase):
    def test_lockfile_wins_over_range(self):
        repo = make_repo({
            "pyproject.toml": '[project]\nname="x"\ndependencies=["langchain-core>=0.3"]\n',
            "uv.lock": '[[package]]\nname = "langchain-core"\nversion = "0.3.80"\n',
        })
        d = lcscan.scan_deps(repo)
        self.assertEqual((d["core_status"], d["core_evidence"]), ("affected", "lockfile"))

    def test_exact_pin_in_requirements(self):
        repo = make_repo({"requirements.txt": "langchain_core==1.2.5  # pinned\nopenai\n"})
        d = lcscan.scan_deps(repo)
        self.assertEqual((d["core_status"], d["core_evidence"]), ("fixed", "exact_pin"))

    def test_range_is_floating(self):
        repo = make_repo({"requirements.txt": "langchain-core>=0.3,<2\n"})
        self.assertEqual(lcscan.scan_deps(repo)["core_status"], "floating")

    def test_only_langchain_declared_is_transitive(self):
        repo = make_repo({"requirements.txt": "langchain>=0.3\nlanggraph\n"})
        self.assertEqual(lcscan.scan_deps(repo)["core_status"], "transitive_unresolved")

    def test_legacy_monolith(self):
        repo = make_repo({"requirements.txt": "langchain==0.0.300\n"})
        self.assertEqual(lcscan.scan_deps(repo)["core_status"], "legacy_pre_core")

    def test_poetry_bare_version_is_exact(self):
        repo = make_repo({"pyproject.toml": '[tool.poetry.dependencies]\npython="^3.11"\nlangchain-core="1.1.0"\n'})
        self.assertEqual(lcscan.scan_deps(repo)["core_status"], "affected")

    def test_poetry_caret_is_floating(self):
        repo = make_repo({"pyproject.toml": '[tool.poetry.dependencies]\nlangchain-core="^1.2.0"\n'})
        self.assertEqual(lcscan.scan_deps(repo)["core_status"], "floating")

    def test_pipfile_lock(self):
        repo = make_repo({"Pipfile.lock": json.dumps({"default": {"langchain-core": {"version": "==0.3.81"}}})})
        self.assertEqual(lcscan.scan_deps(repo)["core_status"], "fixed")

    def test_nothing(self):
        repo = make_repo({"requirements.txt": "flask\n"})
        self.assertEqual(lcscan.scan_deps(repo)["core_status"], "not_declared")

    def test_virtualenv_ignored(self):
        repo = make_repo({".venv/lib/requirements.txt": "langchain-core==0.1.0\n"})
        self.assertEqual(lcscan.scan_deps(repo)["core_status"], "not_declared")


class CodeSignals(unittest.TestCase):
    def scan(self, code: str) -> set:
        return set(lcscan.scan_repo(make_repo({"app.py": code}))["signals_present"])

    def test_exec_tool_and_agent(self):
        s = self.scan("""
            from langchain_experimental.tools import PythonREPLTool
            from langchain.agents import create_agent
            agent = create_agent(model, tools=[PythonREPLTool()])
        """)
        self.assertTrue({"exec_capability", "agent_construct"} <= s)
        self.assertNotIn("hitl_construct", s)

    def test_attribute_access_via_module_alias(self):
        s = self.scan("""
            import langchain_community.tools as lct
            t = lct.ShellTool()
        """)
        self.assertIn("exec_capability", s)

    def test_dangerous_optins(self):
        s = self.scan("""
            from langchain_community.vectorstores import FAISS
            db = FAISS.load_local("idx", emb, allow_dangerous_deserialization=True)
            agent = create_pandas_dataframe_agent(llm, df, allow_dangerous_code=True)
        """)
        self.assertTrue({"optin_dangerous_deserialization", "optin_dangerous_code"} <= s)

    def test_false_optin_not_counted(self):
        s = self.scan("""
            from langchain_community.vectorstores import FAISS
            FAISS.load_local("idx", emb, allow_dangerous_deserialization=False)
        """)
        self.assertNotIn("optin_dangerous_deserialization", s)

    def test_lc_deserialize_scoped_to_module(self):
        s = self.scan("""
            from langchain_core.load import loads
            from json import load
            obj = loads(data)
        """)
        self.assertIn("lc_deserialize", s)
        s2 = self.scan("""
            import langchain_core
            from json import loads
            loads(data)
        """)
        self.assertNotIn("lc_deserialize", s2)

    def test_interrupt_scoped_to_langgraph(self):
        self.assertIn("hitl_construct", self.scan("from langgraph.types import interrupt\n"))
        self.assertNotIn("hitl_construct", self.scan("import langchain\nfrom signal import interrupt\n"))

    def test_hitl_kwarg_and_loop_bound_in_config(self):
        s = self.scan("""
            from langgraph.graph import StateGraph
            app = g.compile(checkpointer=cp, interrupt_before=["tools"])
            app.invoke(x, {"recursion_limit": 10})
        """)
        self.assertTrue({"agent_construct", "hitl_construct", "loop_bound_set"} <= s)

    def test_interrupt_before_none_not_counted(self):
        s = self.scan("import langgraph\napp = g.compile(interrupt_before=None)\n")
        self.assertNotIn("hitl_construct", s)

    def test_jinja2_and_secrets_from_env(self):
        s = self.scan("""
            from langchain_core.prompts import PromptTemplate
            from langchain_core.load import load
            p = PromptTemplate.from_template(t, template_format="jinja2")
            load(obj, secrets_from_env=True)
        """)
        self.assertTrue({"jinja2_template", "secrets_from_env_true", "lc_deserialize"} <= s)

    def test_files_without_langchain_ignored(self):
        s = self.scan("app.invoke(x, {'recursion_limit': 5})\nf(allow_dangerous_code=True)\n")
        self.assertEqual(s, set())

    def test_syntax_error_counted_not_fatal(self):
        r = lcscan.scan_repo(make_repo({"bad.py": "def (:\n", "ok.py": "import langchain\n"}))
        self.assertEqual(r["stats"]["parse_errors"], 1)
        self.assertEqual(r["stats"]["lc_files"], 1)


class Summary(unittest.TestCase):
    def test_wilson_bounds(self):
        lo, hi = lcscan.wilson(20, 100)
        self.assertAlmostEqual(lo, 0.1333, places=3)
        self.assertAlmostEqual(hi, 0.2888, places=3)

    def test_summarize_runs(self):
        out = Path(tempfile.mkdtemp())
        for name, files in {"a": {"requirements.txt": "langchain-core==0.3.80\n", "x.py": "from langchain_experimental.tools import PythonREPLTool\n"},
                            "b": {"requirements.txt": "langchain-core==1.2.5\n", "x.py": "import langchain\n"}}.items():
            res = lcscan.scan_repo(make_repo(files).rename(make_repo({}).parent / name))
            (out / f"{name}.json").write_text(json.dumps(res))
        table = lcscan.summarize(sorted(out.glob("*.json")))
        self.assertIn("| langchain-core version affected by CVE-2025-68664 (of determinable) | 1 | 2 |", table)
        self.assertIn("| no HITL construct (of repos with exec_capability) | 1 | 1 |", table)


if __name__ == "__main__":
    unittest.main()
