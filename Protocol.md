# One year after LangGrinch: patch adoption and high-risk capability use in public LangChain projects

**Study protocol, version 0.9 (pre-registration draft)**
Author: Aishwarya Agarwal
Status: draft. Hypotheses (section 3) freeze when this file is committed and tagged `protocol-v0.9`. Measurement details (sections 4–6) freeze at `protocol-v1.0`, after the pilot and before main data collection.

---

## 1. Purpose

CVE-2025-68664 ("LangGrinch", CVSS 9.3) in `langchain-core` was publicly disclosed on 23 December 2025 and fixed in versions 0.3.81 and 1.2.5. This study measures, one year later:

1. how many public projects built on LangChain still resolve to an affected `langchain-core` version, and
2. how often those projects give models high-risk capabilities (code execution, shell, SQL, file system, arbitrary HTTP) and whether they pair those capabilities with human approval or explicit loop limits.

The goal is a small number of transparent, reproducible measurements that practitioners can cite, not a ranking of projects.

## 2. Prior work and what this adds

Liu et al., *Demystifying RCE Vulnerabilities in LLM-Integrated Apps* (ACM CCS 2024), searched GitHub for six code-execution APIs across LangChain, LlamaIndex and PandasAI, and validated exploits against live applications. Later work (for example arXiv 2608.10281, 2026) revisits classic web vulnerabilities in LLM-integrated applications.

This study differs in three ways:

- **Timing.** It measures the ecosystem after LangChain 1.x and after a specific, dated critical CVE, which allows a patch-adoption measurement.
- **Breadth of signals.** It covers dependency versions, explicit safety opt-outs, and the presence or absence of human-in-the-loop and loop-limit constructs, mapped to the OWASP Top 10 for LLM Applications (2026).
- **No live testing.** It is static analysis of public source code only. No deployed application is contacted.

## 3. Research questions and pre-registered hypotheses

| ID | Question | Hypothesis (prediction, stated before data collection) |
|---|---|---|
| RQ1 | Among projects whose `langchain-core` version can be determined, what share resolve to a version affected by CVE-2025-68664? | **H1:** In Tier A (maintained projects), at least 20% are affected. |
| RQ2 | Is the affected share higher in less-maintained projects? | **H2:** The affected share in Tier B exceeds Tier A. |
| RQ3 | Among projects that build agents, what share give the model a code or shell execution capability? | **H3:** At least 10% in Tier A. |
| RQ4 | Among projects with a code or shell execution capability, what share contain any human-in-the-loop construct? | **H4:** Fewer than 15%. |
| RQ5 | How often do projects explicitly opt out of LangChain safety defaults (`allow_dangerous_*=True`, `secrets_from_env=True`)? | Descriptive only. No hypothesis. |

All hypotheses will be reported as confirmed, not confirmed, or not testable, regardless of outcome. Any analysis not listed here is labelled **exploratory** in the report.

## 4. Population and sampling

**Population.** Public GitHub repositories whose dependency files declare at least one package whose name starts with `langchain` or `langgraph` (Python only).

**Discovery.** GitHub code search over `requirements*.txt`, `pyproject.toml`, `Pipfile`, `poetry.lock`, `uv.lock` and `Pipfile.lock` for those package names. Because search results are capped per query, queries are sliced by file size and repository creation date until each slice returns fewer results than the cap. Every query string and run date is logged.

**Base exclusions** (counts reported): forks; archived repositories; repositories owned by the `langchain-ai` organization; repositories whose name or description matches `tutorial|course|example|demo|workshop|cookbook|bootcamp|learn`.

**Tiers.**

- **Tier A, maintained:** at least 5 stars, at least 2 contributors, and a push to the default branch within 180 days of the snapshot date.
- **Tier B:** every other repository that passes the base exclusions.

Results are always reported per tier. No pooled headline figure is published without the tier breakdown.

**Sample.** All Tier A repositories up to 1,500, plus a uniform random sample of up to 1,500 Tier B repositories (fixed random seed, published). Each repository is shallow-cloned at its default branch, and the commit SHA is recorded.

**Snapshot date.** 16 November 2026. Repositories used in the pilot are excluded from the main sample.

## 5. Measurement

Measurement uses `lcscan` (this repository, `research/lcscan/`), version frozen at `protocol-v1.0`. It parses Python with the standard `ast` module and only analyses files that import a `langchain*` or `langgraph*` module.

| Signal | Detected when | OWASP LLM 2026 | Caveat |
|---|---|---|---|
| `core_status` | `langchain-core` version from a lockfile (preferred) or an exact pin, classified against CVE-2025-68664 ranges | LLM04 | Floating ranges and transitive dependencies are reported separately, never counted as affected |
| `exec_capability` | Import or use of Python REPL, shell, or dataframe/CSV/Spark agent constructs from LangChain modules | LLM03, LLM10 | Presence, not reachability |
| `data_capability` | SQL agent/toolkit, file-management toolkit, or requests tools | LLM03 | Presence, not privilege level |
| `agent_construct` | `create_agent`, `create_react_agent`, `AgentExecutor`, `initialize_agent`, tool-calling agent constructors, `StateGraph` | LLM03 | `StateGraph` includes non-agent workflows |
| `hitl_construct` | LangGraph `interrupt`, `interrupt_before` / `interrupt_after`, `HumanInTheLoopMiddleware`, `HumanApprovalCallbackHandler` | LLM03 | May guard a different step than the risky tool |
| `loop_bound_set` | `recursion_limit` or `max_iterations` set explicitly | LLM06 | Framework defaults exist. Absence does not mean unbounded |
| `optin_dangerous_*` | `allow_dangerous_deserialization`, `allow_dangerous_code` or `allow_dangerous_requests` set to `True` | LLM04, LLM10, LLM03 | Often required to use a feature at all |
| `secrets_from_env_true` | `secrets_from_env=True` passed to a call | LLM02 | Context-dependent |
| `lc_deserialize` | `load` / `loads` imported from `langchain_core.load` or `langchain.load` | LLM04 | Input source unknown |
| `jinja2_template` | `template_format="jinja2"` | LLM01, LLM10 | Template source unknown |

Explicitly **not measured:** hard-coded secrets (already covered by GitHub secret scanning, and ethically costly to handle), JavaScript/TypeScript projects, runtime behaviour, and deployed configuration.

## 6. Validation

- **Unit tests** define each detection rule (`test_lcscan.py`).
- **Pilot:** 200 repositories drawn from the discovered set before the snapshot, used only to fix detector defects. Hypotheses may not change after the pilot.
- **Precision:** for each signal, a random sample of 50 detections (or all, if fewer) is reviewed by hand against the definition in section 5. A second reviewer independently checks 20% of those. Precision is reported with a 95% Wilson interval. Signals with precision below 80% are dropped from headline results and reported only in an appendix.
- **Recall** is not measured systematically, and the report says so.

## 7. Analysis plan

- Proportions with 95% Wilson score intervals.
- Tier A versus Tier B difference for RQ1/RQ2 with a 95% confidence interval for the difference in proportions.
- Denominators are stated for every figure. "Of determinable" and "of all" are never mixed.
- No causal claims. Signals describe code, not deployed risk.

## 8. Ethics and disclosure

- Static analysis of publicly available source code only. No deployed application, API or model endpoint is contacted, probed or tested.
- The report presents aggregate results only. No repository is named in connection with a finding unless its maintainer agrees or the issue has been fixed.
- Released data replaces repository identifiers with salted hashes. The scanner is open source, so any team can check its own code.
- If manual review surfaces a likely exploitable issue in a Tier A repository with at least 100 stars, the maintainer is notified privately through the project's security policy. The issue is excluded from all examples until fixed or until 90 days have passed.
- The LangChain security team receives a courtesy summary about 7 days before publication. This is notice, not a request for approval.
- No automated or AI-generated vulnerability reports are filed with any project.

## 9. Known limitations

- Public repositories are not representative of private production code. Tiering reduces but does not remove this bias.
- A lockfile records a resolved version at commit time, not what is deployed.
- Import-based detection can count a capability that is imported but never used.
- GitHub code search indexes default branches and has size limits, so discovery is incomplete.

## 10. Outputs and citation

- **Report v1.0** as a web page and PDF, dated, with the snapshot date in the title.
- **Data:** aggregate tables plus per-repository signal rows with hashed identifiers, released under CC BY 4.0.
- **Code:** `lcscan` under the Apache License 2.0.
- **Archive:** a DOI minted through the Zenodo–GitHub integration on the tagged release.
- **Citation metadata:** `CITATION.cff` in the repository root.

Any change after a protocol tag is recorded in `research/CHANGELOG.md` with the date and reason.

## 11. Timeline

| Date (2026) | Milestone |
|---|---|
| Fri 2 Oct | Commit and tag `protocol-v0.9` (hypotheses frozen) |
| Wed 21 Oct | Pilot on 200 repositories complete; detector fixes merged |
| Fri 23 Oct | Tag `protocol-v1.0` (measurement frozen) |
| Mon 16 Nov | Snapshot; discovery and cloning |
| Mon 7 Dec | Scan, precision review and draft complete; external review begins; LangChain courtesy notice |
| Tue 15 Dec | Publish report v1.0 with DOI |
| Wed 23 Dec | One-year anniversary of disclosure |
