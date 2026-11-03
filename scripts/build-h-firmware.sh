#!/usr/bin/env bash
# Builds firmware/h_test.S into target/firmware/h_test.bin (a flat image
# for 0x8000_0000), the H-extension test for `boot-trace --hypervisor`.
# Needs a RISC-V GNU toolchain: CROSS defaults to riscv64-linux-gnu-.
set -euo pipefail
root=$(cd "$(dirname "$0")/.." && pwd)
cross=${CROSS:-riscv64-linux-gnu-}
out="$root/target/firmware"
mkdir -p "$out"
"${cross}gcc" -march=rv64imach_zicsr_zifencei -mabi=lp64 -mcmodel=medany \
    -nostdlib -nostartfiles -static -Wl,-Ttext=0x80000000 -Wl,--no-relax -Wl,--build-id=none \
    -o "$out/h_test.elf" "$root/firmware/h_test.S"
"${cross}objcopy" -O binary -j .text "$out/h_test.elf" "$out/h_test.bin"
# With the checks that QEMU 11.1.3 fails (section S), for rivemu...
"${cross}gcc" -DSPEC -march=rv64imach_zicsr_zifencei -mabi=lp64 -mcmodel=medany \
    -nostdlib -nostartfiles -static -Wl,-Ttext=0x80000000 -Wl,--no-relax -Wl,--build-id=none \
    -o "$out/h_test_spec.elf" "$root/firmware/h_test.S"
"${cross}objcopy" -O binary -j .text "$out/h_test_spec.elf" "$out/h_test_spec.bin"
# ...and for the Sail model (console and exit through HTIF).
"${cross}gcc" -DSAIL -DSPEC -march=rv64imach_zicsr_zifencei -mabi=lp64 -mcmodel=medany \
    -nostdlib -nostartfiles -static -Wl,-Ttext=0x80000000 -Wl,--no-relax -Wl,--build-id=none -Wl,-N \
    -o "$out/h_test_sail.elf" "$root/firmware/h_test.S"
echo "$out/h_test.bin"
