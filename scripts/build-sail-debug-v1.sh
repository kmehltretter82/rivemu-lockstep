#!/bin/sh

set -eu

script_dir=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
repo_root=$(CDPATH= cd -- "$script_dir/.." && pwd)
patch_file="$repo_root/patches/sail-riscv-0.16-debug-v1.patch"
output_dir=${1:-"$repo_root/../third_party/sail-riscv-0.16-debug-v1"}
build_jobs=${SAIL_BUILD_JOBS:-2}
source_url=https://github.com/riscv/sail-riscv/archive/refs/tags/0.16.tar.gz
source_sha256=73a617fae97429f0659f7dedac4dada86ea6f27183146698ef70804b23b4203e

case "$build_jobs" in
  ''|*[!0-9]*)
    echo "SAIL_BUILD_JOBS must be a positive integer" >&2
    exit 2
    ;;
  0)
    echo "SAIL_BUILD_JOBS must be greater than zero" >&2
    exit 2
    ;;
esac

for tool in sail cmake curl shasum tar patch; do
  if ! command -v "$tool" >/dev/null 2>&1; then
    echo "missing required tool: $tool" >&2
    exit 2
  fi
done

case "$(sail --version)" in
  'Sail 0.20.3'*) ;;
  *)
    echo "Sail 0.20.3 is required to reproduce the validated build" >&2
    exit 2
    ;;
esac

build_root=$(mktemp -d "${TMPDIR:-/tmp}/sail-riscv-debug-v1.XXXXXX")
cleanup() {
  rm -rf "$build_root"
}
trap cleanup EXIT HUP INT TERM

archive="$build_root/sail-riscv-0.16.tar.gz"
source_dir="$build_root/source"
build_dir="$build_root/build"

curl -L --fail --retry 2 -o "$archive" "$source_url"
actual_sha256=$(shasum -a 256 "$archive" | awk '{print $1}')
if [ "$actual_sha256" != "$source_sha256" ]; then
  echo "Sail source checksum mismatch: got $actual_sha256" >&2
  exit 1
fi

mkdir -p "$source_dir"
tar -xzf "$archive" --strip-components=1 -C "$source_dir"
patch -d "$source_dir" -p1 < "$patch_file"

cmake -S "$source_dir" -B "$build_dir" \
  -DCMAKE_BUILD_TYPE=RelWithDebInfo \
  -DENABLE_RISCV_TESTS=FALSE \
  -DDOWNLOAD_GMP=FALSE
cmake --build "$build_dir" --target sail_riscv_sim --parallel "$build_jobs"

mkdir -p "$output_dir/bin"
cp "$build_dir/c_emulator/sail_riscv_sim" "$output_dir/bin/sail_riscv_sim"

echo "Built $output_dir/bin/sail_riscv_sim"
"$output_dir/bin/sail_riscv_sim" --version
shasum -a 256 "$output_dir/bin/sail_riscv_sim"
