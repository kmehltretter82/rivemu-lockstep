#!/usr/bin/env bash
# Bootstrap a fresh Ubuntu 24.04 LTS GCE VM (x86_64 or aarch64) for:
#   1. Continuous rivemu-lockstep differential fuzzing (Sail + QEMU vs. Rivemu)
#   2. Linux kernel A/B reproducer builds & riscv-tests / riscv-arch-test
#   3. Cross-platform (x86_64 + aarch64) build & interpreter benchmarking
set -euo pipefail

export DEBIAN_FRONTEND=noninteractive
sudo apt-get update -y
sudo apt-get install -y \
  build-essential \
  cmake \
  ninja-build \
  pkg-config \
  git \
  curl \
  wget \
  rsync \
  tmux \
  htop \
  jq \
  bc \
  bison \
  flex \
  cpio \
  zstd \
  xz-utils \
  patch \
  libgmp-dev \
  zlib1g-dev \
  libglib2.0-dev \
  libpixman-1-dev \
  libslirp-dev \
  libssl-dev \
  libelf-dev \
  dwarves \
  device-tree-compiler \
  qemu-system-misc \
  gcc-riscv64-linux-gnu \
  g++-riscv64-linux-gnu \
  binutils-riscv64-linux-gnu \
  gcc-riscv64-unknown-elf \
  picolibc-riscv64-unknown-elf \
  python3 \
  python3-pip \
  python3-venv \
  opam \
  z3 \
  libdigest-sha-perl

# Install Rust 1.85.0 toolchain + RISC-V bare-metal & musl targets for current user.
if [ ! -x "$HOME/.cargo/bin/rustup" ]; then
  curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh -s -- -y --default-toolchain 1.85.0
fi
# shellcheck disable=SC1091
source "$HOME/.cargo/env"
rustup toolchain install 1.85.0
rustup default 1.85.0
rustup target add --toolchain 1.85.0 riscv64gc-unknown-none-elf riscv64gc-unknown-linux-musl

# Install Sail 0.20.3 via opam for building patched sail-riscv-0.16-debug-v1.
if [ ! -d "$HOME/.opam" ]; then
  opam init --disable-sandboxing -y -a
fi
eval "$(opam env)"
if ! command -v sail >/dev/null 2>&1 || ! sail --version | grep -q '^Sail 0.20.3'; then
  opam install -y sail.0.20.3
fi

mkdir -p "$HOME/work/qemu_rust" "$HOME/work/rivemu-lockstep" "$HOME/work/third_party"

echo "=== GCE Worker Bootstrap Complete ($(uname -m)) ==="
rustc +1.85.0 --version
qemu-system-riscv64 --version | head -n 1
riscv64-linux-gnu-gcc --version | head -n 1
sail --version
