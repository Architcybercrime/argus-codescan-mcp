# Example: Pre-commit Hook with Argus Review

This example demonstrates a Git pre-commit hook that runs `argus review --staged` before every commit, blocking commits that introduce high-severity issues.

## Prerequisites

- Argus installed (`pip install argus-scan`)
- Git initialized in your project

## Installation

1. Create the hook file in your project:

   ```bash
   touch .git/hooks/pre-commit
   ```

2. Copy the example hook into your project's Git hooks directory and make it executable:

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
