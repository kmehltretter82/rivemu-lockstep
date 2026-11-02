#!/usr/bin/env bash
# Per-suite campaigns recorded on 2026-11-02 (Linux x86_64, 4 vCPUs).
# rivemu: branch claude/trusting-bell-xvhb0r; QEMU 11.1.3; Sail 0.16 + debug-v1.
set -u
D=$(cd "$(dirname "$0")" && pwd)
BIN=${RIVEMU_LOCKSTEP_BIN:-target/release/rivemu-lockstep}
SUITES="alu control fence-i mul bitmanip crypto float fp-edges mem csr privileged sv39 sv48 pmp cfi atomics compressed vector"
for s in $SUITES; do
    "$BIN" campaign --reference qemu --suite "$s" --workers 2 --blocks 512 --insns 32 \
        --seed 0x20000 --step-check > "$D/qemu-$s.log" 2>&1
    echo "qemu $s exit=$? $(tail -n 1 "$D/qemu-$s.log")"
done
for s in $SUITES; do
    "$BIN" campaign --reference sail --suite "$s" --workers 2 --blocks 384 --insns 32 \
        --seed 0x20000 > "$D/sail-$s.log" 2>&1
    echo "sail $s exit=$? $(tail -n 1 "$D/sail-$s.log")"
done
