#!/usr/bin/env bash
# Prints `ref=<rivemu ref>` for GitHub Actions: the explicit input if given,
# otherwise the rivemu branch with the same name as this branch if it exists
# (so paired PRs are tested together), otherwise main.
set -euo pipefail
explicit=${1:-}
branch=${2:-}
if [ -n "$explicit" ]; then
    echo "ref=$explicit"
elif [ -n "$branch" ] && git ls-remote --exit-code --heads \
    https://github.com/kmehltretter82/rivemu.git "$branch" >/dev/null 2>&1; then
    echo "ref=$branch"
else
    echo "ref=main"
fi
