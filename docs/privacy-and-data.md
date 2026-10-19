# Privacy and data handling

How Argus handles your code and scan data when you run the CLI, MCP server, VS Code extension, or CI workflows.

## Local-first by default

| Mode | Data leaves your machine? |
|------|---------------------------|
| `argus scan …` (CLI) | **No** — scans run locally; no Argus phone-home |
| `argus mcp` / MCP tools | **No** — JSON-RPC over stdio to your IDE only |
| VS Code extension (local MCP) | **No** — same as MCP |
| External scanners (Semgrep, Trivy, …) | **Your machine only** — you install and run them |

Argus does not require an Argus account or cloud subscription for local scanning.

## When data can leave your environment

| Feature | What is sent | Opt-in |
|---------|--------------|--------|
| **Cloud dashboard upload** | Aggregated scan JSON | Yes — only if `ARGUS_API_KEY` is set or `--upload` is used |
| **GitHub SARIF workflow** | SARIF file to GitHub Code Scanning | Yes — you enable the workflow in your repo |
| **AI / MCP clients** | Tool results shown to the model | Yes — your IDE sends MCP responses to the AI provider you chose |

See [AGENT-UPLOAD.md](AGENT-UPLOAD.md) for cloud upload env vars and behavior.

## Scan artifacts on disk

- CLI `-o report.json` writes files where you specify.
- Temp files may be created by subprocess scanners; see your OS temp directory.
- Planned: `--no-persist` and retention policy ([#60](https://github.com/argus-code-scanning/argus-codescan-mcp/issues/60)).

## Secrets and PII in reports

- Secret scanners may include **redacted** snippets in findings.
- Full code context can appear in JSON/Markdown/SARIF unless you enable redaction (planned [#53](https://github.com/argus-code-scanning/argus-codescan-mcp/issues/53)).
- Do not upload raw scan JSON to public tickets or shared AI chats if findings contain sensitive snippets.

## Environment variables affecting egress

| Variable | Effect |
|----------|--------|
| `ARGUS_API_KEY` | Enables post-scan upload to cloud dashboard when set |
| `ARGUS_API_URL` | Cloud API base URL (default localhost for dev) |
| `ARGUS_UPLOAD_SCRIPT` | Optional custom upload hook |
| `ARGUS_UPLOAD_REDACT` | `1` (default) redacts emails, SSNs and card numbers in uploads; `0` disables. Git remote credentials are always stripped. See [AGENT-UPLOAD.md](AGENT-UPLOAD.md#data-handling) |

Unset `ARGUS_API_KEY` to guarantee no cloud upload from MCP or CLI.

## Subprocessors and third parties

Local scans invoke **open-source CLI tools** you install (Semgrep, Trivy, Gitleaks, etc.). Those tools run on your hardware under their own licenses and network policies. Argus orchestrates them; it does not proxy your source code through Argus-operated servers during a normal local scan.

## GDPR / roles (high level)

- **Local use:** You are typically the **controller** of the code and findings; Argus software acts as a **tool** on your machine.
- **Cloud dashboard (if used):** Review the dashboard provider’s DPA for processor/controller roles and retention.

This document is informational, not legal advice.

## Related

- [SECURITY.md](../SECURITY.md) — reporting vulnerabilities
- [architecture.md](architecture.md) — MCP and data flow
- [features roadmap](features-roadmap.md) — planned data policy and PII features
