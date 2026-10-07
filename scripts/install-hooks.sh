#!/usr/bin/env bash
# Install the ALHacking repository guards (git hooks) in the current clone.
#
#   bash scripts/install-hooks.sh
#
# This sets core.hooksPath to the repository's hooks/ directory (a local git
# setting, not committed). The hook blocks commits that stage a potential
# secret; see SECRETS_POLICY.md (PL) / SECRETS_POLICY.en.md (EN).
set -euo pipefail

root=$(git rev-parse --show-toplevel)
cd "$root"

chmod +x hooks/* 2>/dev/null || true
git config core.hooksPath hooks

echo "installed: core.hooksPath -> hooks/"
echo "hook:      hooks/pre-commit (mask_secrets --git-staged --fail-on high)"

if command -v python3 >/dev/null 2>&1; then
    python3 tools/secrets/mask_secrets.py --version
    echo "self-check:"
    python3 tools/secrets/mask_secrets.py . --format text >/dev/null && echo "  repository scan: clean"
else
    echo "warning: python3 not found - the hook will skip scanning until it is installed." >&2
fi

echo "run the policy test-suite with: python3 tools/secrets/tests/test_mask_secrets.py"
