#!/usr/bin/env bash
# Syncs local ../qemu_rust and rivemu-lockstep workspaces to one or more GCE worker VMs
# and builds patched sail-riscv-0.16-debug-v1 + release binaries on each worker.
#
# Usage:
#   ./scripts/sync-gce-workers.sh [user@]ip1 [user@]ip2 [user@]ip3
set -euo pipefail

if [ "$#" -lt 1 ]; then
  echo "usage: $0 [user@]host1 [[user@]host2 ...]" >&2
  exit 2
fi

script_dir=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
lockstep_root=$(CDPATH= cd -- "$script_dir/.." && pwd)
rivemu_root=$(CDPATH= cd -- "$lockstep_root/../qemu_rust" && pwd)

for host in "$@"; do
  echo "=== Syncing workspace to $host ==="
  ssh -o StrictHostKeyChecking=accept-new "$host" "mkdir -p ~/work/qemu_rust ~/work/rivemu-lockstep ~/work/third_party"

  rsync -az --delete \
    --exclude 'target/' \
    --exclude '.git/' \
    --exclude 'linux-ab-results/' \
    --exclude 'images/debian/' \
    --exclude 'images/linux-test/' \
    "$rivemu_root/" "$host:~/work/qemu_rust/"

  rsync -az --delete \
    --exclude 'target/' \
    --exclude '.git/' \
    "$lockstep_root/" "$host:~/work/rivemu-lockstep/"

  echo "=== Building Sail debug-v1 & release binaries on $host ==="
  ssh "$host" 'bash -lc "
    set -euo pipefail
    source \$HOME/.cargo/env
    eval \"\$(opam env)\"
    if [ ! -x \$HOME/work/third_party/sail-riscv-0.16-debug-v1/bin/sail_riscv_sim ]; then
      SAIL_BUILD_JOBS=\$(nproc) sh \$HOME/work/rivemu-lockstep/scripts/build-sail-debug-v1.sh \$HOME/work/third_party/sail-riscv-0.16-debug-v1
    fi
    cargo +1.85.0 build --release --manifest-path \$HOME/work/qemu_rust/Cargo.toml --workspace
    cargo +1.85.0 build --release --manifest-path \$HOME/work/rivemu-lockstep/Cargo.toml
    echo \"READY on \$(hostname) (\$(uname -m))\"
  "'
done
