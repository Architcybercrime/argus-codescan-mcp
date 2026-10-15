#!/bin/sh
#
# Argus Pre-commit Hook Example
# Blocks commit if high-severity issues are found in staged files.

echo "Running Argus security review on staged files..."

argus review . --staged --fail-on high

if [ $? -ne 0 ]; then
    echo "❌ Argus review found issues. Please fix them before committing."
    echo "   (Bypass with 'git commit --no-verify')"
    exit 1
fi

echo "✅ Argus review passed. Proceeding with commit."
exit 0
