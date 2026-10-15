# Example: Pre-commit Hook with Argus Review

This example demonstrates a Git pre-commit hook that runs `argus review --staged` before every commit, blocking commits that introduce high-severity issues.

## Prerequisites

- Argus installed (`pip install argus-scan`)
- Git initialized in your project

## Related

Supersedes and replaces the secrets-only approach in [#42](https://github.com/argus-code-scanning/argus-codescan-mcp/issues/42). This example runs a full local review (`argus review --staged`), which includes secrets, SAST, and malware checks in a single pass.

## Installation

### Option 1 — Using the `pre-commit` Framework (Recommended)

If you use the [pre-commit](https://pre-commit.com/) framework, add the following to your project's `.pre-commit-config.yaml`:

```yaml
repos:
  - repo: https://github.com/argus-code-scanning/argus-codescan-mcp
    rev: main  # Pin to a tag or commit SHA in production
    hooks:
      - id: argus-review
```

Then run:

```bash
pip install pre-commit argus-scan
pre-commit install
```

### Option 2 — Manual Git Hook

1. Create the hook file in your project:

   ```bash
   touch .git/hooks/pre-commit
   ```

2. Copy the contents of `pre-commit.sh` into `.git/hooks/pre-commit`, and make it executable:

   ```bash
   cp pre-commit.sh .git/hooks/pre-commit
   chmod +x .git/hooks/pre-commit
   ```

## How It Works

- Runs `argus review . --staged --fail-on high`
- Reviews only staged files (`git add`)
- Exits with a non-zero status if high-severity issues are found
- Blocks the commit when issues are detected

## Bypassing the Hook

If you need to commit despite a warning:

```bash
git commit --no-verify
```

## Customization

Change `--fail-on high` to `--fail-on medium` or `--fail-on low` for stricter enforcement.
