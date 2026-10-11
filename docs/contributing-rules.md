# Add a YAML security rule in 5 minutes

Most Argus built-in checks are plain YAML under `argus-languages`. You do not need to change the Python MCP server to add a pattern rule.

## Where rules live

```
packages/languages/src/argus_languages/bundled_rules/
  malware.yaml      # miners, reverse shells, droppers
  ml.yaml           # AI/ML unsafe loads, LLM keys
  database.yaml     # DB / ORM issues
  common.yaml       # shared patterns
  …
```

Register a **new** file name in `packages/languages/src/argus_languages/rules_loader.py` inside `RULE_FILES` if you create a new pack. Existing packs (like `malware.yaml`) are already registered.

## Rule fields

```yaml
- id: malware-example-rule          # unique, kebab-case
  title: Short human-readable title
  severity: critical                # critical | high | medium | low | info
  pattern: 'regex here'             # Python regex, one line of source at a time
  flags: [i]                        # optional: i = ignore case, m = multiline
  languages: [shell, python]        # optional: limit to languages; omit = all
```

### Tips

- Patterns run **per line** (not whole-file). Keep regex line-oriented.
- Prefer specific strings (hostnames, API shapes) over vague keywords.
- Say in the title when false positives are likely (e.g. legitimate `curl | bash` installers).

## Example (from malware pack)

```yaml
- id: malware-mining-pool-hosts
  title: Known crypto mining pool hostname
  severity: critical
  pattern: 'hashvault\.pro|xmrpool\.eu|c3pool\.com'
  flags: [i]
```

## Add a test

Create or extend a file under `packages/languages/tests/`:

```python
from pathlib import Path

from argus_languages.rules_loader import load_rules_from_files
from argus_languages.scanner import scan_path


def test_mining_pool_hosts(tmp_path: Path):
    f = tmp_path / "pool.sh"
    f.write_text('url = "https://xmrpool.eu:3333"\n')
    result = scan_path(f, rules=load_rules_from_files(("malware.yaml",)))
    assert "malware-mining-pool-hosts" in {x.rule_id for x in result.findings}
```

Use a file extension the scanner knows (`.sh`, `.py`, `.ps1`, `.bat`, `.php`, …).

## Run tests locally

```bash
cd packages/python
python3 -m venv .venv && source .venv/bin/activate
pip install -e ../languages -e ".[dev]"

pytest ../languages/tests/test_malware_rules.py -q
# or all language tests:
pytest ../languages/tests -q
```

## Try the rule with the CLI

```bash
argus scan malware /path/to/sample
# or full built-in code rules:
argus scan code /path/to/sample
```

## Open a PR

1. Fork / branch from `main` (or `dev` if the repo asks)
2. Add the YAML rule + test
3. Open a PR describing the rule id and why it matters
4. Link a related issue (`Fixes #66`) when applicable

Good first issues:  
https://github.com/argus-code-scanning/argus-codescan-mcp/labels/good%20first%20issue

See also: [CONTRIBUTING.md](../CONTRIBUTING.md) · [architecture.md](architecture.md)
