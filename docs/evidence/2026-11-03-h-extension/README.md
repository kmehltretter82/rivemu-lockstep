# H extension: QEMU 11.1.3 lockstep and the Sail model (2026-11-03)

rivemu implements the H extension behind `-cpu rv64,h=on` (rivemu
`crates/rivemu-cpu-riscv/src/hyp.rs`, two-stage translation in `mmu.rs`).
This directory holds the runs that check it against QEMU 11.1.3
(`-cpu rv64,...,h=true`) and the Sail RISC-V model 0.16 (the patched debug
build of `scripts/build-sail-debug-v1.sh`, default configuration, which
implements H v1.0), all built from source.

## Test firmware

`firmware/h_test.S` (built by `scripts/build-h-firmware.sh`; SHA-256 of the
images in `firmware.sha256`) is a self-checking bare-metal program. M-mode
drives each test: it enters HS, U, VS or VU, the test traps back, and the
registers the M, HS and VS handlers saved are checked. The default build
(`h_test.bin`, 160 checks) covers:

- the H CSRs from M-mode: `misa.H`, forced `mideleg` bits, the writable bits
  of `hedeleg`, `hideleg`, `medeleg` (with H), `hstatus`, `hvip`/`hip`/`hie`,
  `vsepc`, `vsatp`/`hgatp` (modes, VMID), `htimedelta`, `vsie` without
  delegation;
- VS-mode with both stages Bare: the VS copies of `sscratch`/`sstatus`, the
  HS copies left alone; virtual-instruction exceptions for `hstatus`,
  `vsstatus`, `hfence.vvma`, `hlv`, and with `VTVM`/`VTW`/`VTSR` for `satp`,
  `sfence.vma`, `wfi`, `sret`; illegal instruction for M CSRs; VU-mode `sstatus`
  and `wfi`; `ecall` from VU to M, HS (`SPV`, `SPVP`, `sepc`) and VS
  (`hedeleg`); `hcounteren`/`scounteren` for `time`; `htimedelta`; an illegal
  instruction delegated to HS (`stval`, `SPV`, `SPVP`, `GVA` = 0, `htval` = 0)
  and to VS;
- two-stage translation (Sv39 over Sv39x4, gigapages and a three-level
  G-stage): loads, a G-stage read-only page (load passes, store raises a
  store guest-page fault with `mtval` = GVA, `mtval2` = GPA >> 2, `GVA`,
  `MPV`), unmapped GPAs (load guest-page faults), a VS-stage page fault to M,
  HS (`GVA` = 1, `htval` = 0) and VS, a G-stage fault on the VS-stage walk of
  a fetch (`mtval2` = the PTE's GPA >> 2), `vsatp` changed from VS-mode;
- `hlv.d`/`hlv.w`/`hlvx.hu`/`hsv.d` from HS-mode with `SPVP` = 1 and 0 (a
  supervisor page as VU faults; delegated to HS with `GVA` = 1, `SPV` = 0),
  from U-mode with and without `hstatus.HU`; `hfence.*` in HS-mode and with
  `mstatus.TVM`; `hgatp` with `TVM`;
- M-mode loads and stores with `MPRV` and `MPV` = 1;
- interrupts: `hvip.VSSIP` taken in VS-mode (`scause` 1, `sepc`, `SPIE`), not
  with `vsstatus.SIE` = 0, always in VU-mode; undelegated (`hideleg` = 0) it
  is an HS interrupt with code 2 taken with V = 1; the VS timer from
  `vstimecmp` (`henvcfg.STCE`, code 5); `sie` from VS-mode is `vsie`;
- `sret` from HS into VS (clearing `SPV`), from VS into VU, from HS into U.

`-DSPEC` adds 19 checks (section S) where QEMU 11.1.3 differs from the
privileged spec (list below): `h_test_spec.bin` for rivemu and QEMU,
`h_test_sail.elf` (console and exit through HTIF) for Sail.

## Results

| Run | Log | Result |
|---|---|---|
| Sail 0.16, spec build | `sail-h_test_spec.log` | `H-TEST PASS` |
| rivemu alone, default and spec builds | `rivemu-alone-h_test.log`, `rivemu-alone-h_test_spec.log` | `H-TEST PASS` both |
| QEMU alone, default build | `qemu-alone-h_test.log` | `H-TEST PASS` |
| QEMU alone, spec build | `qemu-alone-h_test_spec.log` | fails 11 of the 19 spec-only checks: the deviations below |
| Trace lockstep, default build | `lockstep-h-firmware.log` | 43,107 instructions, 61 exceptions, 4 interrupts mirrored, **0 divergences** |
| Trace lockstep, OpenSBI v1.7 + Linux 6.12 + BusyBox with H on both sides | `lockstep-linux-h-on.log` | 364,904,448 instructions to `~ # `, **0 divergences** |
| The same with H off (regression) | `lockstep-linux-h-off.log` | 364,904,448 instructions to `~ # `, **0 divergences** |

The trace lockstep compares every instruction's destination register and
PC and, after every trap, the privilege level with V, `mstatus` (with
`MPV`), `mcause`, `mepc`, `mtval`, `scause`, `sepc`, `stval`, `satp`,
`hstatus`, `htval` and `mtval2`. The instruction count varies between runs
because the UART polling loops follow QEMU's device timing.

`mutations.log`: two injected rivemu bugs, each caught at the first trap it
affects (`htval`/`mtval2` without the shift by 2; VS interrupts not
renumbered for VS-mode).

## rivemu bugs found on the way

- `sret` from HS-mode into V = 1 took the return address from `sepc` after
  swapping in the VS copy, so it returned to `vsepc`. The firmware's first
  VS-mode test failed on rivemu alone; fixed.
- A write to `hgatp` with an unsupported MODE was ignored, as for `satp`.
  The H spec says it is not: the fields stay WARL, so VMID and PPN are
  written and only MODE keeps its value. Found by the Sail run; fixed.
- `vsatp`, `vsscratch` and the other `vs*` CSRs, read or written by a
  debugger while V = 1, went to the inactive copy (found by a unit test of
  the two-stage `debug_translate`); fixed.
- rivemu-lockstep: a divergence in the post-trap CSR comparison only ended
  the inner loop, so the run went on and later divergences overwrote the
  first one; fixed. The plugin required the H CSRs to exist; they are
  optional now (the H-off Linux run above uses the new plugin).

## Where QEMU 11.1.3 differs from the privileged spec

The default build avoids these, rivemu follows the spec, and the Sail model
agrees with rivemu in every case the spec build checks (1 to 9). Sources are
QEMU 11.1.3 `target/riscv/tcg/`.

1. `mstatus.MPV` and `GVA` are not writable: `write_mstatus` (`csr.c`) has
   neither in its mask, so `mret` cannot enter VS or VU unless a trap set MPV
   (spec checks 0x201 to 0x203).
2. `mstatus.GVA` on traps into M-mode (`riscv_cpu_do_interrupt`,
   `cpu_helper.c`): set whenever V = 1 and the trap value is nonzero, also
   for the instruction bits of an illegal or virtual instruction (0x205);
   not set for HLV/HSV or MPRV-with-MPV faults taken with V = 0, and never
   cleared (the spec build's 0x207 and 0x20a pass on QEMU only because an
   earlier trap left GVA set). The lockstep does not compare GVA in
   `mstatus` (`MSTATUS_COMPARE_MASK`) and takes QEMU's value for `mstatus`
   reads that differ only in GVA (42 in the firmware run, 0 in the Linux
   runs).
3. `hstatus.GVA` is written (with 0) on traps into VS-mode (0x20d).
4. Every `hstatus` bit is writable, the reserved ones included (0x20e).
5. `vsepc[0]` is not cleared (0x20f).
6. `hgatp` bits 59:58 are writable and `PPN[1:0]` are not zeroed (0x210).
7. A write to `hgatp` with an unsupported MODE is ignored entirely
   (`legalize_xatp`) (0x211).
8. A VS-mode `sie` read is masked with `mideleg`'s S-level bits
   (`rmw_sie64`) (0x212).
9. `hvip` reads include other pending interrupts (`rmw_hvip64` with
   `hideleg` = `hvien` = 0 reads all of `mip`) (0x213: STIP).
10. The guest physical fault address stays until the next TLB fill, so a
    later trap that is not a guest-page fault can report it in
    `htval`/`mtval2` (not checked by the firmware; its M handler flushes the
    TLB).

Two differences are implementation choices, not deviations: QEMU lets
`hideleg` delegate interrupts 16 and up (AIA local interrupts), and Sail's
default configuration lets `medeleg`/`hedeleg` delegate exception 19
(hardware error), which rivemu and QEMU do not raise. The firmware writes
only `hideleg` bits 15:0 and ignores bit 19.
