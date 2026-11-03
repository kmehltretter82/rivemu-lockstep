#!/usr/bin/env bash
# Builds the rivemu_trace QEMU plugin (qemu-plugin/rivemu_trace.c) for
# `rivemu-lockstep boot-trace`.
#
# Usage: scripts/build-qemu-plugin.sh [<qemu-system-riscv64>]
# The plugin header comes from the QEMU installation (<prefix>/include/
# qemu-plugin.h next to <prefix>/bin/qemu-system-riscv64); set
# QEMU_PLUGIN_INCLUDE to override. Output: target/qemu-plugin/librivemu_trace.so
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
QEMU="${1:-$(command -v qemu-system-riscv64)}"
INCLUDE="${QEMU_PLUGIN_INCLUDE:-$(cd "$(dirname "$(readlink -f "$QEMU")")/../include" && pwd)}"
[[ -f "$INCLUDE/qemu-plugin.h" ]] || {
    echo "error: $INCLUDE/qemu-plugin.h not found (set QEMU_PLUGIN_INCLUDE)" >&2
    exit 1
}
mkdir -p "$ROOT/target/qemu-plugin"
cc -O2 -shared -fPIC -Wall -Wextra -Wno-unused-parameter -Werror \
    -I"$INCLUDE" $(pkg-config --cflags glib-2.0) \
    "$ROOT/qemu-plugin/rivemu_trace.c" -o "$ROOT/target/qemu-plugin/librivemu_trace.so"
echo "$ROOT/target/qemu-plugin/librivemu_trace.so"
