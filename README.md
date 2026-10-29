# rivemu-lockstep

`rivemu-lockstep` differentially tests the pure-Rust [rivemu](https://github.com/kmehltretter82/rivemu) RISC-V emulator against the RISC-V International [Sail reference model](https://github.com/riscv/sail-riscv) or `qemu-system-riscv64`. It runs deterministic RISU-style instruction blocks through both implementations and reports the first divergence. Sail is checked after every instruction; QEMU supports either block checkpoints with automatic replay or per-instruction checking.

## Prerequisites

- Rust 1.85 or newer.
- A sibling `../qemu_rust` rivemu checkout. The current `Cargo.toml` uses path dependencies from that directory.
- Sail RISC-V 0.16 (`sail_riscv_sim`). The official macOS ARM64 release works without modification for normal register and memory comparison.
- Optional: `qemu-system-riscv64` with TCG and the GDB stub. QEMU master is preferred for manually replaying the same seed as an independent third implementation and is required by `boot` mode.

The CLI first looks for the patched workspace copy at `../third_party/sail-riscv-0.16-debug-v1/bin/sail_riscv_sim`, then the official copy at `../third_party/sail-riscv-0.16/bin/sail_riscv_sim`, then `PATH`. Pass `--sail <PATH>` to select another build. For QEMU, it uses `/opt/homebrew/bin/qemu-system-riscv64` when present and otherwise searches `PATH`.

## Build

```sh
cargo +1.85.0 build --release
```

## RISU differential tests

Sail is the default reference. Run a bounded integer campaign with:

```sh
target/release/rivemu-lockstep risu \
  --suite alu \
  --blocks 16 \
  --insns 32 \
  --seed 0x1000
```

Each Sail block gets a fresh model process and is checked instruction by instruction, avoiding hidden reservation or CSR state leaking between cases. Select QEMU explicitly when replaying the same deterministic seeds against a third implementation:

```sh
target/release/rivemu-lockstep risu \
  --reference qemu \
  --suite alu \
  --blocks 16 \
  --insns 32 \
  --seed 0x1000 \
  --step-check \
  --qemu ../qemu/build-d7314928-arm-plain/qemu-system-riscv64
```

Available suites are:

- `alu`: RV64 integer arithmetic and logical operations.
- `control`: AUIPC, JAL/JALR, all six branch conditions, and bounded loops.
- `fence-i`: guest self-modifying code and instruction-cache synchronization.
- `mul`: RV64 multiply, divide, and remainder operations.
- `bitmanip`: Zba, Zbb, Zbc, and Zbs operations.
- `float`: F/D arithmetic, conversions, NaN boxing, rounding, and flags.
- `mem`: sandboxed loads, stores, atomics, LR/SC, and cache-block zeroing.
- `csr`: portable CSR values and synchronous trap recovery. Implementation-defined WLRL/WARL values are deliberately excluded from exact comparison.
- `all`: a deterministic mix of all suites.

Sail always uses per-instruction comparison, including scratch RAM for memory suites. QEMU defaults to block checkpoints with one-instruction replay on a mismatch; add `--step-check` to catch transient differences that are overwritten before the final checkpoint.

Stock Sail 0.16 does not expose privileged CSRs through GDB, so `--check-csrs` is rejected for that binary. The optional [`sail-riscv-debug-v1`](docs/sail-riscv-debug-v1.md) endpoint patch adds explicit privileged-register access and is auto-detected; normal CSR instructions and trap-visible register effects work with stock Sail. Architecturally variable trap-value CSRs are captured but excluded from exact equality. `--strict` enables rivemu's strict alignment and Svade behavior; it can intentionally differ from another model's defaults.

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
