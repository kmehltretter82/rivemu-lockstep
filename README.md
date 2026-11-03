# rivemu-lockstep

`rivemu-lockstep` differentially tests the pure-Rust [rivemu](https://github.com/kmehltretter82/rivemu) RISC-V emulator against the RISC-V International [Sail reference model](https://github.com/riscv/sail-riscv) or `qemu-system-riscv64`. It runs deterministic RISU-style instruction blocks through both implementations and reports the first divergence. Sail is checked after every instruction; QEMU supports either block checkpoints with automatic replay or per-instruction checking.

## Prerequisites

- Rust 1.85 or newer.
- A sibling `../qemu_rust` rivemu checkout. The current `Cargo.toml` uses path dependencies from that directory.
- Sail RISC-V 0.16 (`sail_riscv_sim`). The official macOS ARM64 release works without modification for normal register and memory comparison; privileged suites need the [debug-v1 patch](docs/sail-riscv-debug-v1.md).
- `qemu-system-riscv64` with TCG and the GDB stub. The QEMU CPU model enables recent extensions (for example `ssdbltrp`, `smmpm`, `x-svukte`), so QEMU 11 or newer is required; Ubuntu 24.04's `qemu-system-misc` (8.2) cannot run the suites. `boot` mode always needs QEMU.

On Ubuntu 24.04 x86_64, `scripts/setup-toolchain.sh` builds QEMU 11.1.3 (riscv64-softmmu only) and the patched Sail into `../third_party` (about 35-40 minutes on 4 cores; already-built tools are reused). CI uses the same script.

Tool lookup:

- Sail: `--sail <PATH>`, then `$RIVEMU_LOCKSTEP_SAIL`, then `../third_party/sail-riscv-0.16-debug-v1/bin/sail_riscv_sim`, then `../third_party/sail-riscv-0.16/bin/sail_riscv_sim`, then `PATH`.
- QEMU: `--qemu <PATH>`, then `$RIVEMU_LOCKSTEP_QEMU`, then `PATH`.

Tests that need QEMU or Sail print a `skipping ...` line when the tool is missing. Set `RIVEMU_LOCKSTEP_REQUIRE_QEMU=1` and `RIVEMU_LOCKSTEP_REQUIRE_SAIL=1` to make a missing tool a failure, as CI does. `RIVEMU_LOCKSTEP_STRESS=1` enables `tests/spawn_stress.rs`, which starts 240 QEMU and 240 Sail targets from six threads to check reference-model startup under contention.

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
  --qemu ../third_party/qemu-11.1.3/bin/qemu-system-riscv64
```

Available suites are:

- `alu`: RV64 integer arithmetic and logical operations.
- `control`: AUIPC, JAL/JALR, all six branch conditions, and bounded loops.
- `fence-i`: guest self-modifying code and instruction-cache synchronization.
- `mul`: RV64 multiply, divide, and remainder operations.
- `bitmanip`: `Zba`, `Zbb`, `Zbc`, `Zbs`, and `Zicond` operations.
- `crypto` (aliases `zk`, `zkn`, `zbkb`, `zknd`, `zkne`, `zknh`): scalar cryptography extensions (`Zbkb` `pack`/`packh`/`packw`/`brev8`, `Zbkc` `clmul`/`clmulh`, `Zbkx` `xperm4`/`xperm8`, `Zknd`/`Zkne` `aes64es`/`aes64esm`/`aes64ds`/`aes64dsm`/`aes64im`/`aes64ks1i`/`aes64ks2`, `Zknh` `sha256*`/`sha512*`, `Zksed` `sm4ed`/`sm4ks`, and `Zksh` `sm3p0`/`sm3p1`).
- `float`: `F`/`D`, `Zfh`/`Zfhmin`/`Zfbfmin` (`f16` and `bf16`), and `Zfa` arithmetic, conversions, NaN boxing, rounding, and flags.
- `fp-edges` (aliases `fpedges` and `float-edges`): directed static/dynamic rounding, NaN-boxing and signed-zero behavior, fused operations, conversions, `Zfh`/`Zfbfmin`, `Zfa` (`fli`, `fminm`, `fmaxm`, `fround`, `froundnx`, `fcvtmod.w.d`, `fleq`, `fltq`), and isolated/sticky exception flags. Per-instruction checking is enabled automatically because later cases deliberately overwrite destinations and flags.
- `mem`: sandboxed loads, stores, atomics (`RV64A`, `Zacas`, `Zabha`), `LR`/`SC`, and `Zicbom`/`Zicbop`/`Zicboz` cache-block operations.
- `csr`: portable CSR values (`Smstateen` `mstateen0..3`/`sstateen0..3`, `Ssqosid` `srmcfg`, `mscratch`/`sscratch`, read-only CSR traps) and synchronous trap recovery. Implementation-defined WLRL/WARL values are deliberately excluded from exact comparison.
- `privileged` (aliases `priv` and `lower-priv`): directed S/U-mode execution, explicit `MRET`/`SRET` transitions, machine and delegated supervisor exception entry/recovery, `Zkr` (`seed` CSR gated by `mseccfg.SSEED`/`USEED`), `Ssdbltrp`/`Smdbltrp` double-trap (`SDT`/`MDT` auto-clearing `SIE`/`MIE` and `mcause = 16` double-trap escalation), and privilege-sensitive CSR/system instructions, including `TVM` and `TSR` trap controls. Privileged-state comparison is enabled automatically and requires the patched Sail debug-v1 endpoint.
- `sv39` (aliases `paging` and `vm`): three-level 4 KiB and 2 MiB superpage Sv39 mappings with translated S/U instruction fetches, loads, and stores; M-mode `MPRV=1` data translation; supervisor/user PTE permissions; `SUM`; `MXR`; misaligned superpage, reserved-PTE, non-canonical VA, and delegated instruction/load/store page-fault recovery; and guest leaf-PTE replacements synchronized by global, address-selective, ASID-selective, and address+ASID `SFENCE.VMA`.
- `sv48`: four-level `Sv48` (`satp.MODE = 9`) and five-level `Sv57` (`satp.MODE = 10`) translation, 512 GiB / 1 GiB / 2 MiB superpages, `Svnapot` 64 KiB contiguous PTEs (`pte.N`), `Svpbmt` (`PBMT` attributes and reserved `PBMT=3` faults), `Svrsw60t59b` (software-reserved PTE bits `[60:59]`), and `Svinval` (`sinval.vma`, `sfence.w.inval`, `sfence.inval.ir`).
- `pmp`: 16-entry Physical Memory Protection (`OFF`, `TOR`, `NA4`, `NAPOT`), lowest-index priority precedence, `L`-bit M-mode enforcement, boundary-straddling accesses, and `Zicbom`/`Zicboz` PMP access faults, plus `Smepmp` (`mseccfg`) lockstep verification.
- `cfi` (aliases `zicfiss`, `zicfilp`, `pmm`, `svukte`): RVA23 Control-Flow Integrity (`Zicfiss` shadow-stack PTEs, `sspush`/`c.sspush`, `sspopchk`/`c.sspopchk`, `ssrdp`, `ssamoswap.{w,d}`, `SW_CHECK` `tval=3`; `Zicfilp` landing pads `lpad`, `SW_CHECK` `tval=2`, `MPELP`/`SPELP`), Pointer Masking (`Ssnpm`/`Smnpm`/`Smmpm` `PMLEN=7/16`), `Svukte` (`senvcfg.UKTE`), and `Sdtrig` (`tdata1` `mcontrol6` + `mcontext` 13-bit WARL).
- `atomics` (aliases `atomic`, `rv64a`, and `lrsc`): directed RV64A, `Zacas` (`amocas.{w,d,q}`), and `Zabha` (`amo*.{b,h}`) AMO and `LR`/`SC` semantics, including ordering-bit encodings, operand aliases, failure paths, and word-result sign extension.
- `compressed` (aliases `rvc` and `c`): legal sequential RV64C (`Zca`, `Zcb`, `Zcd`) operations plus aligned scratch-backed `C.LW`/`C.LD`/`C.SW`/`C.SD`/`C.FLD`/`C.FSD` and `Zcb` byte/halfword loads, stores, and bit extensions.
- `vector` (aliases `rvv` and `v`): RISC-V Vector 1.0 (`V`, `VLEN = 256`, `ELEN = 64`) configuration (`vsetvli`, `vsetivli`, `vsetvl`, `vlenb`, `vl`, `vtype`, `vill`), unit-stride/strided/whole-register/mask loads and stores, integer ALU/saturating/averaging/narrowing/widening/mul/div/MAC, reductions, masks/permutations (`vcpop.m`, `vfirst.m`, `vmsbf.m`, `vmsof.m`, `vmsif.m`, `viota.m`, `vid.v`, `vslide*`, `vrgather`, `vcompress.vm`), and vector floating-point (`vfadd`, `vfsub`, `vfmul`, `vfdiv`, `vfsqrt`, `vfmin`, `vfmax`, `vfsgnj*`, `vfmacc`, `vfcvt*`, `vfclass`, `vmflt`, `vfredusum`, `vfredmax`), comparing all 256-bit vector register outputs in scratch RAM.
- `all`: a deterministic mix of integer, control-flow, `fence.i`, multiply/divide, bitmanip, scalar crypto, floating-point, sandboxed memory, CSR, and atomic suites.

Multi-worker continuous fuzzing across all 18 concrete suites with automatic 1-instruction bisection and Rust regression test emission (`--emit-repro`) is available via `campaign`:

```sh
target/release/rivemu-lockstep campaign \
  --reference sail \
  --workers 4 \
  --blocks 64 \
  --insns 32 \
  --emit-repro repro_test.rs
```

Sail always uses per-instruction comparison, including scratch RAM for memory suites. QEMU defaults to block checkpoints with one-instruction replay on a mismatch; add `--step-check` to catch transient differences that are overwritten before the final checkpoint.

Stock Sail 0.16 does not expose privileged CSRs or writable privilege state through GDB, so privileged-state checking and the lower-privilege suites require the patched endpoint. The optional [`sail-riscv-debug-v1`](docs/sail-riscv-debug-v1.md) patch adds explicit privileged-register access and is auto-detected; normal CSR instructions and trap-visible register effects work with stock Sail. Architecturally variable trap-value CSRs are captured but excluded from generic equality; the Sv39 handler separately folds exact load/store page-fault values into its signature. `--strict` enables rivemu's strict alignment, Svade, and PMP behavior; it can intentionally differ from another model's defaults.

## Firmware & kernel boot lockstep (`boot` v3)

The `boot` mode steps an OpenSBI or bare-metal firmware image (and optional staged kernel) instruction-by-instruction across M/S/U privilege transitions, `Sv39`/`Sv48`/`Sv57` virtual-memory translation, device MMIO (`UART`, `CLINT` `mtime`, `RTC`, `PLIC`), and both non-trapping and trapping (`TW=1`) `WFI` instructions.

With the sibling workspace test images:

```sh
target/release/rivemu-lockstep boot \
  --bios ../qemu_rust/images/linux-test/fw_dynamic.bin \
  --kernel ../qemu_rust/images/linux-test/Image \
  --steps 100 \
  --check-csrs \
  --qemu ../third_party/qemu-11.1.3/bin/qemu-system-riscv64
```

Start with a small step count because QEMU is controlled over its GDB remote protocol. Add `--check-csrs` for a short privileged-state comparison after the basic smoke test passes.

Boot mode starts QEMU from rivemu's reset state, so QEMU must be configured
to match rivemu, and implementation-defined values must be copied:

- **Configuration:** the QEMU CPU model (`QEMU_CPU_PMP`) enables V
  (VLEN 256), 16 PMP entries with Smepmp, Sscofpmf/Smcntrpmf with
  hpmcounter3..31, and 4 triggers.
- **Copied once:** before the first step, rivemu's `menvcfg`, `senvcfg` and
  `stimecmp` reset values are written into QEMU.
- **Copied after each read:** results of `csrr` from `cycle`, `time`,
  `instret`, `mcycle`, `minstret`, `tinfo` and `seed` are copied from QEMU
  to rivemu.

With OpenSBI v1.7 and Linux 6.12, `--steps 30000000 --check-csrs` runs with
zero divergences (about 4,700 steps/s).
`docs/evidence/2026-11-02-boot-lockstep/README.md` lists every divergence
found on the way and its fix. Two of them were rivemu bugs.

`boot` mode masks interrupts on both sides (QEMU's GDB single step does not
deliver them, and rivemu does not tick its devices), so Linux eventually
waits forever for a timer tick. `boot-trace` covers a whole boot instead.

## Trace-driven boot lockstep to the shell prompt (`boot-trace`)

`boot-trace` runs QEMU at full TCG speed with the `rivemu_trace` plugin
(`qemu-plugin/rivemu_trace.c`), which streams the PC of every instruction,
the previous instruction's destination register, every trap with the trap
CSRs, and all integer registers every 2^16 instructions. rivemu steps the
same instructions in-process and checks each one
(`src/lockstep/trace.rs`):

- results and control flow must match for every instruction;
- traps must go to the same target with the same privilege (with V),
  `mstatus` (compared bits), `mcause`/`mepc`/`mtval`, `scause`/`sepc`/
  `stval`, `satp`, `hstatus`, `htval` and `mtval2`;
- QEMU is the reference for device timing: when it takes an interrupt,
  rivemu takes the same one at the same instruction, and results that rivemu
  flags with `Hart::nondeterministic_read` (MMIO loads; counter, `time`,
  `seed`, `tinfo`, `mip`/`sip` CSR reads) are taken from QEMU;
- one implementation choice is accepted explicitly: QEMU keeps
  `mstatus.UXL` writable (RV32 user mode), rivemu fixes it at 64 bits, so a
  `sstatus`/`mstatus` read may differ only in `UXL`/`SXL` and the `FS`/`VS`/
  `SD` dirty bits (Linux's `compat_mode_detect` does this once).

QEMU gets rivemu's device tree with `-dtb` and the initrd through
`-device loader` at rivemu's address, so both see identical memory, and the
plugin writes rivemu's `menvcfg`, `senvcfg` and `stimecmp` reset values into
QEMU at the firmware entry.

```sh
scripts/build-qemu-plugin.sh ../third_party/qemu-11.1.3/bin/qemu-system-riscv64
target/release/rivemu-lockstep boot-trace \
  --qemu ../third_party/qemu-11.1.3/bin/qemu-system-riscv64 \
  --bios ../qemu_rust/images/linux-test/fw_dynamic.bin \
  --kernel ../qemu_rust/images/linux-src/Image \
  --initrd ../qemu_rust/images/linux-src/rootfs.cpio \
  --append console=ttyS0 --until-console '~ # '
```

With OpenSBI v1.7, Linux 6.12 and the BusyBox initramfs
(`../qemu_rust/scripts/build-linux-test-from-source.sh`), three runs reached
the shell prompt with zero divergences: 358.6 M to 362.8 M instructions,
12,129 to 13,077 interrupts mirrored, in 66 to 81 s each. An injected rivemu
bug (`sraiw` shifting by `imm & 15`) diverges after 18.2 M instructions with
the exact register. Logs: `docs/evidence/2026-11-03-boot-trace/`. The CI job
`boot-trace` runs the same boot.

### H extension (`--hypervisor`)

`--hypervisor` turns on H on both sides (QEMU `h=true`, rivemu
`hypervisor`). `firmware/h_test.S` (`scripts/build-h-firmware.sh`) is a
self-checking test of the H extension with 160 checks: CSRs, VS/VU-mode,
virtual-instruction exceptions, delegation, two-stage translation and
guest-page faults, HLV/HSV, VS-level interrupts and `sret` between modes.

```sh
scripts/build-h-firmware.sh
target/release/rivemu-lockstep boot-trace --hypervisor \
  --qemu ../third_party/qemu-11.1.3/bin/qemu-system-riscv64 \
  --bios target/firmware/h_test.bin --until-console 'H-TEST PASS'
```

It passes on QEMU alone, on rivemu alone and in lockstep (43,107
instructions, 61 exceptions, 4 interrupts mirrored, zero divergences), and
OpenSBI + Linux with H on both sides reaches the shell prompt with zero
divergences (364.9 M instructions). QEMU 11.1.3 differs from the privileged
spec in ten places around H, among them that `mstatus.MPV` is not writable
and how it sets `mstatus.GVA`. The default build avoids them and the
lockstep does not compare `mstatus.GVA` (it reports how often QEMU's
differed). Built with `-DSPEC`, the firmware adds 19 checks for those
places; the Sail model 0.16 and rivemu pass all of them, QEMU fails 11.
Details and logs: `docs/evidence/2026-11-03-h-extension/`. The CI job
`boot-trace` runs the firmware on QEMU alone and on Sail, the spec build on
rivemu, and both H lockstep runs.

Limitations: rivemu runs through `Hart::step` (the reference interpreter
path), not the block cache and inline fast paths that `run` uses; those are
covered by rivemu's block-versus-step equivalence tests, riscv-arch-test and
the Linux end-to-end tests. Only hart 0 is traced (`-smp 1`), and
floating-point registers are compared only through the integer results
they feed into.
