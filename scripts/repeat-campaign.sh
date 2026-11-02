#!/usr/bin/env bash
# Runs the same rivemu-lockstep command repeatedly and records every run.
#
# Usage: scripts/repeat-campaign.sh <runs> <log-dir> -- <rivemu-lockstep args...>
# Example (the multi-worker Sail startup stress test):
#   scripts/repeat-campaign.sh 20 /tmp/sail-stress -- \
#     campaign --reference sail --suite alu --workers 6 --blocks 300 --insns 16
#
# Each run's complete output is kept as <log-dir>/run<N>.log. A summary line
# per run (exit status, wall time, last output line) goes to
# <log-dir>/summary.txt and stdout. Exits non-zero if any run failed.
set -uo pipefail

if [ "$#" -lt 4 ] || [ "$3" != "--" ]; then
    echo "usage: $0 <runs> <log-dir> -- <rivemu-lockstep args...>" >&2
    exit 2
fi
runs=$1
log_dir=$2
shift 3

repo_root=$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)
bin=${RIVEMU_LOCKSTEP_BIN:-"$repo_root/target/release/rivemu-lockstep"}
mkdir -p "$log_dir"
: > "$log_dir/summary.txt"
failed=0
for i in $(seq 1 "$runs"); do
    start=$(date +%s.%N)
    "$bin" "$@" > "$log_dir/run$i.log" 2>&1
    status=$?
    end=$(date +%s.%N)
    wall=$(awk -v s="$start" -v e="$end" 'BEGIN { printf "%.2f", e - s }')
    [ "$status" -eq 0 ] || failed=$((failed + 1))
    line="run$i exit=$status wall=${wall}s $(tail -n 1 "$log_dir/run$i.log")"
    echo "$line" | tee -a "$log_dir/summary.txt"
done
echo "runs=$runs failed=$failed" | tee -a "$log_dir/summary.txt"
[ "$failed" -eq 0 ]
