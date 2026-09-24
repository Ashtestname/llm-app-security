#!/usr/bin/env python3
"""
lcscan: static signals of security-relevant LangChain usage in a Python repository.

Measurement instrument for the study described in ../PROTOCOL.md.

lcscan reports SIGNALS, not vulnerabilities. A signal means a construct is
present in the code or dependency files. It does not mean the construct is
reachable by an attacker, deployed, or exploitable.

Usage:
  python lcscan.py scan <repo_dir> [<repo_dir> ...] --out results/
  python lcscan.py summarize results/*.json
"""
from __future__ import annotations

import argparse
import ast
import json
import math
import re
import sys
from pathlib import Path

import tomllib
from packaging.requirements import InvalidRequirement, Requirement
from packaging.version import InvalidVersion, Version

SCANNER_VERSION = "0.1.0"
SKIP_DIRS = {".git", "node_modules", ".venv", "venv", "env", "site-packages",
             "__pycache__", ".tox", "build", "dist", ".mypy_cache"}
MAX_FILE_BYTES = 1_000_000
MAX_HITS_PER_SIGNAL = 20
LC_ROOTS = ("langchain", "langgraph")

# Names counted only when imported from (or accessed through) a langchain*/langgraph* module.
SIGNALS = {
    "exec_capability": {"PythonREPLTool", "PythonAstREPLTool", "ShellTool", "BashProcess",
                        "create_pandas_dataframe_agent", "create_csv_agent",
                        "create_spark_dataframe_agent", "create_python_agent"},
    "data_capability": {"create_sql_agent", "SQLDatabaseToolkit", "QuerySQLDatabaseTool",
                        "QuerySQLDataBaseTool", "FileManagementToolkit", "RequestsToolkit",
                        "RequestsGetTool", "RequestsPostTool"},
    "agent_construct": {"create_agent", "create_react_agent", "AgentExecutor", "initialize_agent",
                        "create_tool_calling_agent", "create_openai_functions_agent", "StateGraph"},
    "hitl_construct": {"HumanInTheLoopMiddleware", "HumanApprovalCallbackHandler"},
}
NAME_TO_SIGNAL = {n: s for s, names in SIGNALS.items() for n in names}

# Generic names that only count when they come from a specific module.
MODULE_SCOPED = {
    "interrupt": ("hitl_construct", ("langgraph",)),
    "load": ("lc_deserialize", ("langchain_core.load", "langchain.load")),
    "loads": ("lc_deserialize", ("langchain_core.load", "langchain.load")),
}

# Keyword arguments set to True (explicit opt-outs of a safety default).
TRUE_KWARGS = {
    "allow_dangerous_deserialization": "optin_dangerous_deserialization",
    "allow_dangerous_code": "optin_dangerous_code",
    "allow_dangerous_requests": "optin_dangerous_requests",
    "secrets_from_env": "secrets_from_env_true",
}
HITL_KWARGS = {"interrupt_before", "interrupt_after"}
BOUND_KEYS = {"recursion_limit", "max_iterations"}

ALL_SIGNALS = sorted(set(SIGNALS) | {s for s, _ in MODULE_SCOPED.values()} |
                     set(TRUE_KWARGS.values()) | {"jinja2_template", "loop_bound_set"})


def _is_lc_module(mod: str) -> bool:
    return mod.split(".")[0].startswith(LC_ROOTS)


class FileScan(ast.NodeVisitor):
    def __init__(self, rel: str):
        self.rel = rel
        self.mod_aliases: dict[str, str] = {}
        self.hits: list[tuple[str, str, int]] = []

    def _hit(self, signal: str, name: str, line: int):
        self.hits.append((signal, name, line))

    def _name_signal(self, name: str, module: str, line: int):
        if not _is_lc_module(module):
            return
        if name in NAME_TO_SIGNAL:
            self._hit(NAME_TO_SIGNAL[name], name, line)
        elif name in MODULE_SCOPED:
            signal, prefixes = MODULE_SCOPED[name]
            if any(module == p or module.startswith(p + ".") for p in prefixes):
                self._hit(signal, name, line)

    def visit_Import(self, node):
        for a in node.names:
            if _is_lc_module(a.name):
                local = a.asname or a.name.split(".")[0]
                self.mod_aliases[local] = a.name if a.asname else a.name.split(".")[0]

    def visit_ImportFrom(self, node):
        mod = node.module or ""
        if not _is_lc_module(mod):
            return
        for a in node.names:
            self._name_signal(a.name, mod, node.lineno)
            self.mod_aliases[a.asname or a.name] = f"{mod}.{a.name}"

    def visit_Attribute(self, node):
        parts, cur = [], node
        while isinstance(cur, ast.Attribute):
            parts.append(cur.attr)
            cur = cur.value
        if isinstance(cur, ast.Name) and cur.id in self.mod_aliases:
            parts.reverse()
            full = ".".join([self.mod_aliases[cur.id]] + parts)
            module, _, name = full.rpartition(".")
            self._name_signal(name, module, node.lineno)
        self.generic_visit(node)

    def visit_Call(self, node):
        for kw in node.keywords:
            v = kw.value
            if kw.arg in TRUE_KWARGS and isinstance(v, ast.Constant) and v.value is True:
                self._hit(TRUE_KWARGS[kw.arg], kw.arg, node.lineno)
            elif kw.arg == "template_format" and isinstance(v, ast.Constant) and v.value == "jinja2":
                self._hit("jinja2_template", kw.arg, node.lineno)
            elif kw.arg in HITL_KWARGS and not (isinstance(v, ast.Constant) and v.value is None):
                self._hit("hitl_construct", kw.arg, node.lineno)
            elif kw.arg in BOUND_KEYS:
                self._hit("loop_bound_set", kw.arg, node.lineno)
        self.generic_visit(node)

    def visit_Dict(self, node):
        for k in node.keys:
            if isinstance(k, ast.Constant) and k.value in BOUND_KEYS:
                self._hit("loop_bound_set", k.value, node.lineno)
        self.generic_visit(node)


def _imports_langchain(tree: ast.AST) -> bool:
    for n in ast.walk(tree):
        if isinstance(n, ast.Import) and any(_is_lc_module(a.name) for a in n.names):
            return True
        if isinstance(n, ast.ImportFrom) and _is_lc_module(n.module or ""):
            return True
    return False


def _iter_files(root: Path, pred):
    for p in root.rglob("*"):
        if any(part in SKIP_DIRS for part in p.relative_to(root).parts):
            continue
        if p.is_file() and pred(p):
            yield p


# ---------------------------------------------------------------- dependencies

def _norm(name: str) -> str:
    return re.sub(r"[-_.]+", "-", name).lower()


def _pin(spec: str) -> str | None:
    m = re.fullmatch(r"\s*===?\s*([^,;\s]+)\s*", spec or "")
    return m.group(1) if m else None


def _poetry_spec(val) -> str:
    s = val.get("version", "") if isinstance(val, dict) else str(val)
    return f"=={s}" if re.fullmatch(r"\d+(\.\d+)*", s.strip()) else s


def _declared(root: Path):
    """Yield (package, specifier, source_file) from manifest files."""
    for p in _iter_files(root, lambda p: re.fullmatch(r"requirements.*\.(txt|in)", p.name)):
        for line in p.read_text(errors="ignore").splitlines():
            line = re.split(r"\s+#", line)[0].strip()
            if not line or line.startswith(("#", "-")):
                continue
            try:
                r = Requirement(line)
            except InvalidRequirement:
                continue
            yield _norm(r.name), str(r.specifier), str(p.relative_to(root))
    for p in _iter_files(root, lambda p: p.name in ("pyproject.toml", "Pipfile")):
        try:
            data = tomllib.loads(p.read_text(errors="ignore"))
        except tomllib.TOMLDecodeError:
            continue
        rel = str(p.relative_to(root))
        proj = data.get("project", {})
        reqs = list(proj.get("dependencies", []))
        for group in proj.get("optional-dependencies", {}).values():
            reqs += group
        for s in reqs:
            try:
                r = Requirement(s)
                yield _norm(r.name), str(r.specifier), rel
            except InvalidRequirement:
                pass
        poetry = data.get("tool", {}).get("poetry", {})
        tables = [poetry.get("dependencies", {})] + [g.get("dependencies", {}) for g in poetry.get("group", {}).values()]
        tables += [data.get("packages", {}), data.get("dev-packages", {})]  # Pipfile
        for t in tables:
            for name, val in t.items():
                if name.lower() != "python":
                    yield _norm(name), _poetry_spec(val), rel


def _locked(root: Path):
    """Yield (package, version, source_file) from lockfiles."""
    for p in _iter_files(root, lambda p: p.name in ("poetry.lock", "uv.lock")):
        try:
            data = tomllib.loads(p.read_text(errors="ignore"))
        except tomllib.TOMLDecodeError:
            continue
        for pkg in data.get("package", []):
            if "name" in pkg and "version" in pkg:
                yield _norm(pkg["name"]), str(pkg["version"]), str(p.relative_to(root))
    for p in _iter_files(root, lambda p: p.name == "Pipfile.lock"):
        try:
            data = json.loads(p.read_text(errors="ignore"))
        except json.JSONDecodeError:
            continue
        for section in ("default", "develop"):
            for name, meta in data.get(section, {}).items():
                v = _pin(meta.get("version", "")) if isinstance(meta, dict) else None
                if v:
                    yield _norm(name), v, str(p.relative_to(root))


def classify_core(version: str) -> str:
    """CVE-2025-68664 affects langchain-core < 0.3.81 and >= 1.0.0, < 1.2.5."""
    try:
        v = Version(version)
    except InvalidVersion:
        return "unknown"
    if v.release >= (1, 0, 0):
        return "affected" if v < Version("1.2.5") else "fixed"
    return "affected" if v < Version("0.3.81") else "fixed"


def scan_deps(root: Path) -> dict:
    declared = list(_declared(root))
    locked = list(_locked(root))
    lc_declared = sorted({n for n, _, _ in declared if n.startswith(LC_ROOTS)})
    core_locked = sorted({v for n, v, _ in locked if n == "langchain-core"})
    core_pinned = sorted({_pin(s) for n, s, _ in declared if n == "langchain-core" and _pin(s)})
    core_ranged = any(n == "langchain-core" and not _pin(s) for n, s, _ in declared)
    lc_versions = sorted({v for n, v, _ in locked if n == "langchain"} |
                         {_pin(s) for n, s, _ in declared if n == "langchain" and _pin(s)})

    versions, evidence = (core_locked, "lockfile") if core_locked else (core_pinned, "exact_pin")
    if versions:
        classes = {classify_core(v) for v in versions}
        status = "affected" if "affected" in classes else ("fixed" if "fixed" in classes else "unknown")
    else:
        evidence = None
        legacy = False
        for v in lc_versions:
            try:
                legacy = legacy or Version(v) < Version("0.1")
            except InvalidVersion:
                pass
        if core_ranged:
            status, evidence = "floating", "range"
        elif legacy:
            status, evidence = "legacy_pre_core", "langchain_pin"
        elif lc_declared or any(n.startswith(LC_ROOTS) for n, _, _ in locked):
            status, evidence = "transitive_unresolved", "indirect"
        else:
            status = "not_declared"
    return {"langchain_packages_declared": lc_declared, "core_versions": versions,
            "core_status": status, "core_evidence": evidence, "langchain_versions": lc_versions}


# ---------------------------------------------------------------- repo scan

def scan_repo(root: Path) -> dict:
    root = root.resolve()
    signals: dict[str, list] = {s: [] for s in ALL_SIGNALS}
    stats = {"py_files": 0, "lc_files": 0, "parse_errors": 0, "skipped_large": 0}
    for p in _iter_files(root, lambda p: p.suffix == ".py"):
        stats["py_files"] += 1
        if p.stat().st_size > MAX_FILE_BYTES:
            stats["skipped_large"] += 1
            continue
        rel = str(p.relative_to(root))
        try:
            tree = ast.parse(p.read_text(errors="ignore"), filename=rel)
        except (SyntaxError, ValueError):
            stats["parse_errors"] += 1
            continue
        if not _imports_langchain(tree):
            continue
        stats["lc_files"] += 1
        fs = FileScan(rel)
        fs.visit(tree)
        seen = set()
        for signal, name, line in fs.hits:
            if (signal, name) in seen or len(signals[signal]) >= MAX_HITS_PER_SIGNAL:
                continue
            seen.add((signal, name))
            signals[signal].append({"file": rel, "line": line, "name": name})
    return {"scanner_version": SCANNER_VERSION, "repo": root.name, "stats": stats,
            "deps": scan_deps(root),
            "signals_present": sorted(s for s, h in signals.items() if h),
            "signals": {s: h for s, h in signals.items() if h}}


# ---------------------------------------------------------------- summary

def wilson(k: int, n: int, z: float = 1.96) -> tuple[float, float]:
    if n == 0:
        return (0.0, 0.0)
    p = k / n
    d = 1 + z * z / n
    c = (p + z * z / (2 * n)) / d
    h = z * math.sqrt(p * (1 - p) / n + z * z / (4 * n * n)) / d
    return (max(0.0, c - h), min(1.0, c + h))


def _row(label: str, k: int, n: int) -> str:
    lo, hi = wilson(k, n)
    pct = f"{100 * k / n:.1f}%" if n else "n/a"
    return f"| {label} | {k} | {n} | {pct} | {100 * lo:.1f}–{100 * hi:.1f}% |"


def summarize(paths: list[Path]) -> str:
    results = [json.loads(p.read_text()) for p in paths]
    out = ["| Measure | k | n | Share | 95% CI (Wilson) |", "|---|---|---|---|---|"]
    determinable = [r for r in results if r["deps"]["core_status"] in ("affected", "fixed")]
    out.append(_row("langchain-core version affected by CVE-2025-68664 (of determinable)",
                    sum(r["deps"]["core_status"] == "affected" for r in determinable), len(determinable)))
    statuses = sorted({r["deps"]["core_status"] for r in results})
    for s in statuses:
        out.append(_row(f"core_status = {s} (of all)", sum(r["deps"]["core_status"] == s for r in results), len(results)))
    with_code = [r for r in results if r["stats"]["lc_files"] > 0]
    for s in ALL_SIGNALS:
        out.append(_row(f"signal {s} (of repos with LangChain code)",
                        sum(s in r["signals_present"] for r in with_code), len(with_code)))
    ex = [r for r in with_code if "exec_capability" in r["signals_present"]]
    out.append(_row("no HITL construct (of repos with exec_capability)",
                    sum("hitl_construct" not in r["signals_present"] for r in ex), len(ex)))
    ag = [r for r in with_code if "agent_construct" in r["signals_present"]]
    out.append(_row("exec_capability (of repos with agent_construct)",
                    sum("exec_capability" in r["signals_present"] for r in ag), len(ag)))
    return "\n".join(out)


def main(argv=None):
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    sub = ap.add_subparsers(dest="cmd", required=True)
    s = sub.add_parser("scan")
    s.add_argument("repos", nargs="+", type=Path)
    s.add_argument("--out", type=Path, default=Path("results"))
    m = sub.add_parser("summarize")
    m.add_argument("files", nargs="+", type=Path)
    args = ap.parse_args(argv)
    if args.cmd == "scan":
        args.out.mkdir(parents=True, exist_ok=True)
        for repo in args.repos:
            res = scan_repo(repo)
            (args.out / f"{res['repo']}.json").write_text(json.dumps(res, indent=2))
            print(f"{res['repo']}: {res['deps']['core_status']}, signals={res['signals_present']}")
    else:
        print(summarize(args.files))


if __name__ == "__main__":
    sys.exit(main())
