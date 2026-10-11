# Show HN — Argus (copy/paste for news.ycombinator.com/submit)

## Title (pick one)

**Option A (recommended):**  
`Show HN: Argus – open-source security scanner + malware heuristics (MCP, SARIF, YAML rules)`

**Option B (contribute angle):**  
`Show HN: Argus – local DevSecOps scanner you can extend with YAML rules (MCP/CLI)`

**Option C (shorter):**  
`Show HN: Argus – one CLI + MCP for 20+ scanners, plus malware/miner detection`

---

## URL

```
https://github.com/argus-code-scanning/argus-codescan-mcp
```

---

## Post body (paste as first comment immediately after submitting)

Hi HN — I built **Argus**, an open-source security scanner that orchestrates 20+ tools (Semgrep, Trivy, Gitleaks, tfsec, Checkov, OWASP ZAP, etc.) behind one CLI and one **MCP server** for any MCP-compatible IDE or AI client (Cursor, VS Code, Claude Desktop, JetBrains, Windsurf, etc.).

**Problem:** Running DevSecOps locally means installing and wiring Semgrep, Trivy, Gitleaks, Checkov… separately. Most “AI security” products also want a subscription for the scanner itself.

**Argus approach:**
- **Free & local** — scans run on your machine; no Argus subscription
- **CLI** — `argus scan all .` for CI and terminals
- **MCP** — `argus mcp` so your AI assistant can run scans via natural language
- **Fix on request** — scans never auto-modify code; fixes only when you ask
- **New:** `argus scan malware` — crypto miners, reverse shells, BAT/PS1 droppers, web shells (heuristics, not AV)
- **v0.2:** SARIF (GitHub Code Scanning), `.argus.yml` policy, baseline diff, secret remediation, DB rules
- **Contribute:** most new checks are YAML rule packs under `bundled_rules/` — good first PRs welcome

**Quick start:**

```bash
pip install -U argus-scan
argus scan malware .
argus scan all . --fail-on high
argus scan code . --format sarif -o argus.sarif   # GitHub Security tab
```

Node/React projects:

```bash
npm install -D argus-codescan
npx argus-codescan scan all .
```

**MCP (any MCP-compatible IDE):**

```json
{
  "mcpServers": {
    "argus": { "command": "argus", "args": ["mcp"] }
  }
}
```

Repo: https://github.com/argus-code-scanning/argus-codescan-mcp  
Docs: https://github.com/argus-code-scanning/argus-codescan-mcp/blob/main/docs/features-roadmap.md

MIT licensed. Looking for contributors: add a malware/PII/language rule in YAML + a small test. Label: good first issue.

What would you want next: more malware rules, official GitHub Action, or PII/GDPR packs?

---

## Tips for posting

- Post ** weekday morning US time** (9–11am ET) for best visibility
- Submit the link first, then **immediately** add the body as a comment
- Reply to every comment in the first 2–3 hours
- Be honest about limitations (e.g. some tools need separate install; DAST needs a running app)
- Don't ask for stars directly — let the tool speak

---

## Follow-up replies (templates)

**"How is this different from Semgrep/Trivy alone?"**  
Argus doesn't replace them — it runs them (plus Bandit, Gitleaks, Checkov, etc.) in parallel, normalizes output, adds MCP/CLI, SARIF, policy file, baseline diff, and optional VS Code integration. One command instead of five.

**"Why MCP?"**  
So you can say in your IDE: "scan this repo for secrets and show only new findings vs main" without writing shell scripts. The scanner stays local; only the AI client needs a subscription if you use one.

**"Is it production-ready?"**  
Beta — core scans work; we're hardening CI publish, Docker image, and docs. Issues welcome on GitHub.
