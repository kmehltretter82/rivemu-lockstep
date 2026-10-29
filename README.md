# rivemu-lockstep

`rivemu-lockstep` differentially tests the pure-Rust [rivemu](https://github.com/kmehltretter82/rivemu) RISC-V emulator against `qemu-system-riscv64`. It runs deterministic RISU-style instruction blocks or steps firmware and a kernel through both emulators, compares architectural state, and reports the first divergent instruction.

## Prerequisites

- Rust 1.85 or newer.
- A sibling `../qemu_rust` rivemu checkout. The current `Cargo.toml` uses path dependencies from that directory.
- `qemu-system-riscv64` with TCG and the GDB stub. QEMU master is preferred when investigating possible QEMU bugs.

The CLI uses `/opt/homebrew/bin/qemu-system-riscv64` when present and otherwise searches `PATH`. Pass `--qemu <PATH>` to select a particular build explicitly.

## Build

```sh
cargo +1.85.0 build --release
```

## RISU differential tests

Run a bounded integer campaign against a QEMU master build:

```sh
target/release/rivemu-lockstep risu \
  --suite alu \
  --blocks 16 \
  --insns 32 \
  --seed 0x1000 \
  --qemu ../qemu/build-d7314928-arm-plain/qemu-system-riscv64
```

Available suites are:

- `alu`: RV64 integer arithmetic and logical operations.
- `mul`: RV64 multiply, divide, and remainder operations.
- `bitmanip`: Zba, Zbb, Zbc, and Zbs operations.
- `float`: F/D arithmetic, conversions, NaN boxing, rounding, and flags.
- `mem`: sandboxed loads, stores, atomics, LR/SC, and cache-block zeroing.
- `csr`: CSR WARL behavior and synchronous trap recovery.
- `all`: a deterministic mix of all suites.

By default, each generated block is compared at its final checkpoint and any mismatch is replayed one instruction at a time. Add `--step-check` to compare state (and scratch RAM for memory suites) after every instruction, which also catches transient differences that are overwritten before the final checkpoint. This mode is slower because QEMU is controlled over GDB.

Use `--check-csrs` when privileged CSR and trap state are part of the result. `--strict` enables rivemu's strict alignment and Svade behavior; it can intentionally differ from QEMU's default behavior.

## Early firmware CPU smoke test

The `boot` mode compares the early M-mode instruction stream of an OpenSBI image. An optional kernel is staged in memory so the boot layout and DTB match, but this mode intentionally stops with an error before paging, lower-privilege execution, enabled interrupts, or `wfi`. Rivemu does not yet expose a device-aware translated single-step API, so this is not a full operating-system lockstep run.

With the sibling workspace test images:

```sh
target/release/rivemu-lockstep boot \
  --bios ../qemu_rust/images/linux-test/fw_dynamic.bin \
  --kernel ../qemu_rust/images/linux-test/Image \
  --steps 100 \
  --qemu ../qemu/build-d7314928-arm-plain/qemu-system-riscv64
```

Start with a small step count because QEMU is controlled over its GDB remote protocol. Add `--check-csrs` for a short privileged-state comparison after the basic smoke test passes.
