#!/usr/bin/env bash
# Runs every concrete RISU suite against QEMU (per-instruction checking) and
# against Sail, keeping one log per run. Exits non-zero if any run fails.
#
# Usage: scripts/ci-differential.sh <log-dir> [blocks] [insns]
set -uo pipefail
log_dir=$1
blocks=${2:-16}
insns=${3:-32}
repo_root=$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)
bin=${RIVEMU_LOCKSTEP_BIN:-"$repo_root/target/release/rivemu-lockstep"}
if [ ! -x "$bin" ]; then
    cargo build --release --manifest-path "$repo_root/Cargo.toml"
fi
suites="alu control fence-i mul bitmanip crypto float fp-edges mem csr privileged sv39 sv48 pmp cfi atomics compressed vector"
mkdir -p "$log_dir"
failed=0
for reference in qemu sail; do
    for suite in $suites; do
        extra=()
        [ "$reference" = qemu ] && extra=(--step-check)
        log="$log_dir/$reference-$suite.log"
        if "$bin" risu --reference "$reference" --suite "$suite" --blocks "$blocks" \
            --insns "$insns" --seed 0x1000 "${extra[@]}" > "$log" 2>&1; then
            echo "ok   $reference $suite: $(tail -n 1 "$log")"
        else
            failed=$((failed + 1))
            echo "FAIL $reference $suite: $(tail -n 1 "$log")"
        fi
    done
done
echo "failed=$failed"
[ "$failed" -eq 0 ]
