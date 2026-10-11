# GitHub Release v0.2.1 — copy/paste

Use at: https://github.com/argus-code-scanning/argus-codescan-mcp/releases/new

- **Tag:** `v0.2.1` (create from `main`)
- **Title:** `v0.2.1 — Malware / backdoor / crypto-miner heuristics`

---

## Release notes (paste below)

### Argus v0.2.1 — Malware heuristics + contributor launch

**Argus** is a free, MIT-licensed security scanner: 20+ open-source tools behind one CLI and one MCP server for any IDE.

### What's new

#### Malware / threat heuristics
- CLI: `argus scan malware .`
- MCP: `scan_malware`
- Included in `argus scan all` / MCP `scan_all`
- Built-in rules for crypto miners (XMRig, stratum), reverse shells, PowerShell download cradles, BAT/CMD droppers, web shells, persistence, and LOLBin abuse
- File discovery for `.bat`, `.cmd`, `.ps1`, `.vbs`, `.hta`
- Static heuristics only — not antivirus

```bash
pip install -U argus-scan argus-languages
argus scan malware .
```

#### Packages
| Package | Version |
|---------|---------|
| `argus-scan` (PyPI) | 0.2.1 |
| `argus-languages` (PyPI) | 0.1.4 |
| `argus-codescan` (npm) | 0.5.1 |

Note: malware scanning is in the **Python** packages. npm remains the Node/React SCA/SAST helper; use `pip install argus-scan` for malware/ML/SARIF/MCP.

#### Docs / launch
- Privacy & data handling doc
- Viral / contributor playbook (`docs/launch/viral-contributors.md`)
- Updated Show HN copy

### Contribute

Most new checks are YAML under `packages/languages/.../bundled_rules/`.

Browse **good first issues**:  
https://github.com/argus-code-scanning/argus-codescan-mcp/labels/good%20first%20issue

### Install

```bash
pip install -U argus-scan
argus scan all . --fail-on high
argus mcp   # for Cursor / VS Code / Claude Desktop / JetBrains
```

### Links

- Repo: https://github.com/argus-code-scanning/argus-codescan-mcp
- Features roadmap: https://github.com/argus-code-scanning/argus-codescan-mcp/blob/main/docs/features-roadmap.md
- Show HN draft: `docs/launch/show-hn.md`

MIT licensed. Feedback and PRs welcome.

---

## After publishing the GitHub Release

1. Confirm PyPI wheels for 0.2.1 / 0.1.4 (or publish manually with twine)
2. npm 0.5.1 already on registry (do not republish same version)
3. Post Show HN using `docs/launch/show-hn.md`
4. Point website feature card at malware scan + contribute CTA
