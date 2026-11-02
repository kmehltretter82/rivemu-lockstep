#!/usr/bin/env bash
# Builds the reference simulators that rivemu-lockstep compares against, on
# Ubuntu 24.04 (x86_64):
#   - qemu-system-riscv64 v11.1.3 (riscv64-softmmu only), from source.
#     Ubuntu's qemu-system-misc is 8.2, which lacks CPU properties the
#     lockstep QEMU target enables (for example ssdbltrp, smmpm, x-svukte).
#   - Sail compiler 0.20.3 (official prebuilt release, SHA-256 verified).
#   - sail-riscv 0.16 with patches/sail-riscv-0.16-debug-v1.patch, via
#     scripts/build-sail-debug-v1.sh.
#
# Usage: scripts/setup-toolchain.sh [THIRD_PARTY_DIR]
# THIRD_PARTY_DIR defaults to ../third_party, where the lockstep binary and
# tests look for Sail. QEMU is installed to THIRD_PARTY_DIR/qemu-11.1.3/bin;
# put it on PATH or set RIVEMU_LOCKSTEP_QEMU. Already-built tools are reused.
# Set SKIP_APT=1 when the build dependencies are already installed.
# Takes roughly 35-40 minutes on 4 cores when nothing is cached.
set -euo pipefail

repo_root=$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)
third_party=${1:-"$repo_root/../third_party"}
mkdir -p "$third_party"
third_party=$(CDPATH= cd -- "$third_party" && pwd)
jobs=${JOBS:-$(nproc)}

qemu_tag=v11.1.3
qemu_prefix="$third_party/qemu-11.1.3"
sail_url=https://github.com/rems-project/sail/releases/download/0.20.3-binary/sail-Linux-x86_64.tar.gz
sail_sha256=8d7cd75624ece407d7001ad32905a13ae111d5cc1a055404f21510e113207e3f
sail_dir="$third_party/sail-0.20.3"
sim="$third_party/sail-riscv-0.16-debug-v1/bin/sail_riscv_sim"

if [ "$(uname -s)-$(uname -m)" != "Linux-x86_64" ]; then
  echo "setup-toolchain.sh supports Linux x86_64; see README.md for other hosts" >&2
  exit 2
fi

if [ "${SKIP_APT:-}" != 1 ]; then
  sudo_cmd=
  [ "$(id -u)" -eq 0 ] || sudo_cmd=sudo
  $sudo_cmd env DEBIAN_FRONTEND=noninteractive apt-get update -qq
  $sudo_cmd env DEBIAN_FRONTEND=noninteractive apt-get install -y -qq \
    build-essential git curl ca-certificates xz-utils patch cmake pkg-config \
    ninja-build meson flex bison python3-venv python3-tomli \
    libglib2.0-dev libpixman-1-dev libslirp-dev libfdt-dev zlib1g-dev \
    libgmp-dev z3
fi

if [ ! -x "$qemu_prefix/bin/qemu-system-riscv64" ]; then
  src="$third_party/src/qemu-11.1.3"
  rm -rf "$src"
  # git rather than download.qemu.org, which some sandboxes block.
  git clone -q --depth 1 --branch "$qemu_tag" https://gitlab.com/qemu-project/qemu.git "$src"
  mkdir -p "$src/build"
  (
    cd "$src/build"
    ../configure --prefix="$qemu_prefix" --target-list=riscv64-softmmu \
      --disable-docs --disable-werror --disable-sdl --disable-gtk --disable-opengl \
      --disable-vnc --disable-spice --disable-curses --enable-slirp --enable-fdt=system
    ninja -j"$jobs"
    ninja install
  )
  rm -rf "$src"
fi

if [ ! -x "$sail_dir/bin/sail" ]; then
  tarball="$third_party/sail-Linux-x86_64.tar.gz"
  curl -fsSL --retry 2 -o "$tarball" "$sail_url"
  echo "$sail_sha256  $tarball" | sha256sum -c -
  mkdir -p "$sail_dir"
  tar -xzf "$tarball" -C "$sail_dir" --strip-components=1
  rm -f "$tarball"
fi

if [ ! -x "$sim" ]; then
  PATH="$sail_dir/bin:$PATH" SAIL_BUILD_JOBS=${SAIL_BUILD_JOBS:-2} \
    sh "$repo_root/scripts/build-sail-debug-v1.sh" "$(dirname "$(dirname "$sim")")"
fi

"$qemu_prefix/bin/qemu-system-riscv64" --version | head -n 1
"$sim" --version
echo "QEMU: $qemu_prefix/bin/qemu-system-riscv64"
echo "Sail: $sim"
