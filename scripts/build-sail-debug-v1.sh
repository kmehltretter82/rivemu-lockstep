#!/bin/sh

set -eu

script_dir=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
repo_root=$(CDPATH= cd -- "$script_dir/.." && pwd)
patch_file="$repo_root/patches/sail-riscv-0.16-debug-v1.patch"
output_dir=${1:-"$repo_root/../third_party/sail-riscv-0.16-debug-v1"}
build_jobs=${SAIL_BUILD_JOBS:-2}
source_url=https://github.com/riscv/sail-riscv/archive/refs/tags/0.16.tar.gz
source_sha256=73a617fae97429f0659f7dedac4dada86ea6f27183146698ef70804b23b4203e
# Commit of tag 0.16, used when the archive cannot be downloaded (some
# sandboxed networks allow git but not GitHub archive downloads).
source_git=https://github.com/riscv/sail-riscv.git
source_commit=e5acebb04ff573e93203596486b831a5974117c3
# sail-riscv's CMake fetches jsoncons as a GitHub archive; same fallback.
jsoncons_url=https://github.com/danielaparker/jsoncons/archive/refs/tags/v1.8.1.tar.gz
jsoncons_git=https://github.com/danielaparker/jsoncons.git
jsoncons_commit=d35782026b6208d7c0ed80f5a8165a7a3b868e2f

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

sha256_of() {
  if command -v sha256sum >/dev/null 2>&1; then
    sha256sum "$1" | awk '{print $1}'
  else
    shasum -a 256 "$1" | awk '{print $1}'
  fi
}

# clone_verified <url> <tag> <commit> <dir>
clone_verified() {
  git clone -q --depth 1 --branch "$2" "$1" "$4"
  actual=$(git -C "$4" rev-parse HEAD)
  if [ "$actual" != "$3" ]; then
    echo "$1 tag $2 is $actual, expected $3" >&2
    exit 1
  fi
}

if ! command -v sha256sum >/dev/null 2>&1 && ! command -v shasum >/dev/null 2>&1; then
  echo "missing required tool: sha256sum or shasum" >&2
  exit 2
fi
for tool in sail cmake curl git tar patch; do
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

if curl -L --fail --retry 2 -o "$archive" "$source_url"; then
  actual_sha256=$(sha256_of "$archive")
  if [ "$actual_sha256" != "$source_sha256" ]; then
    echo "Sail source checksum mismatch: got $actual_sha256" >&2
    exit 1
  fi
  mkdir -p "$source_dir"
  tar -xzf "$archive" --strip-components=1 -C "$source_dir"
else
  echo "Source archive download failed; cloning tag 0.16 and verifying its commit" >&2
  clone_verified "$source_git" 0.16 "$source_commit" "$source_dir"
fi
patch -d "$source_dir" -p1 < "$patch_file"

jsoncons_args=
if ! curl -L --fail --retry 2 -o /dev/null "$jsoncons_url"; then
  echo "jsoncons archive download failed; cloning v1.8.1 and verifying its commit" >&2
  clone_verified "$jsoncons_git" v1.8.1 "$jsoncons_commit" "$build_root/jsoncons"
  jsoncons_args="-DFETCHCONTENT_SOURCE_DIR_JSONCONS=$build_root/jsoncons"
fi

# shellcheck disable=SC2086 # jsoncons_args is empty or a single word
cmake -S "$source_dir" -B "$build_dir" \
  -DCMAKE_BUILD_TYPE=RelWithDebInfo \
  -DENABLE_RISCV_TESTS=FALSE \
  -DDOWNLOAD_GMP=FALSE $jsoncons_args
cmake --build "$build_dir" --target sail_riscv_sim --parallel "$build_jobs"

mkdir -p "$output_dir/bin"
cp "$build_dir/c_emulator/sail_riscv_sim" "$output_dir/bin/sail_riscv_sim"

echo "Built $output_dir/bin/sail_riscv_sim"
"$output_dir/bin/sail_riscv_sim" --version
sha256_of "$output_dir/bin/sail_riscv_sim"
