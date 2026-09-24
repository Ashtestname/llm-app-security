# LangChain attack surface explorer

An interactive map of where LangChain / LangGraph applications get attacked, mapped to the
OWASP Top 10 for LLM Applications (2026). Single static file, no build step, no tracking.

## Publish on GitHub Pages

1. Create a public repo, e.g. `llm-app-security`.
2. Add `index.html` and this `README.md` to the repo root and push to `main`.
3. Repo **Settings → Pages → Build and deployment**: Source = *Deploy from a branch*, Branch = `main`, folder = `/ (root)`. Save.
4. The site appears at `https://<your-username>.github.io/llm-app-security/` within a minute or two.

Optional: add a custom domain under the same Settings page once the company domain exists.

## Editing content

All content lives in three arrays near the bottom of `index.html`:
- `N` – diagram components (risks, controls, questions, OWASP mapping)
- `G` – glossary terms
- `C` – checklist items

## Sources

- OWASP GenAI LLM Top 10 2026 – https://genai.owasp.org/resource/owasp-genai-llm-top-10-2026/
- CVE-2025-68664 – https://nvd.nist.gov/vuln/detail/CVE-2025-68664
- CVE-2023-29374 – https://nvd.nist.gov/vuln/detail/CVE-2023-29374

Educational material. Not affiliated with LangChain or OWASP.
