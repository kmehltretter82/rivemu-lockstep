# Boot lockstep: OpenSBI v1.7 + Linux 6.12 against QEMU 11.1.3 (2026-11-02)

Command for every run:

```sh
rivemu-lockstep boot --bios fw_dynamic.bin --kernel Image --steps 3000000 --check-csrs
```

Inputs:
- `fw_dynamic.bin`: OpenSBI v1.7 release, SHA-256 `4be29236…`, from rivemu
  `scripts/fetch-linux-test.sh`.
- `Image`: Linux v6.12, SHA-256 `3994b77e…`, from rivemu
  `scripts/build-linux-test-from-source.sh`.

Each log's first lines record the rivemu and rivemu-lockstep revisions.
Every run stopped at the first divergence. The next run fixed that
divergence and continued until the next one.

| Log | Matching steps | Divergence | Cause | Fix |
|---|---|---|---|---|
| `run1-misa-config-mismatch.log` | 475,009 | `misa` bit 21 (V) | Boot mode passed QEMU its own `-cpu` without V | lockstep `6e88e8c` |
| `run2-semihosting-ebreak.log` | 482,045 | `mcause` after OpenSBI's semihosting probe `ebreak` | rivemu always serviced semihosting | rivemu `7da4e37` (semihosting opt-in) |
| `run3-pmp-config-mismatch.log` | 1,587,711 | `csrw pmpcfg0` traps on QEMU | QEMU model without PMP | lockstep `5834b38` |
| `run4-hpmcounter-config-mismatch.log` | — | hpmcounter probe | QEMU model without Sscofpmf/Smcntrpmf and a different counter set | lockstep `78fc4b2` |
| `run5-menvcfg-harness-reset.log` | — | `menvcfg` read | `set_state` leaves implementation-defined envcfg reset values | lockstep `78fc4b2` |
| `run6-stimecmp-reset.log` | 1,589,018 | `stimecmp` read | Reset value UNSPECIFIED (QEMU 0, rivemu all-ones) | lockstep `78fc4b2` |
| `run7-mstateen-reset.log` | 1,589,034 | `mstateen0` read | **rivemu bug**: reset to its writable mask instead of 0 | rivemu `9b91323` |
| `run8-tinfo-trigger-types.log` | 1,919,953 | `tinfo` read | Implementation-defined trigger types and Sdtrig version | lockstep: copy QEMU's `tinfo` read result |
| `run9-tselect-trigger-count.log` | 1,920,046 | `tselect` read-back while probing | QEMU default 2 triggers, rivemu 4 | lockstep: QEMU `num-triggers=4` |
| `run10-pass-3M-steps.log` | **3,000,000** | none | | |
| `run11-marchid.log` (10M) | 6,678,554 | `marchid` read | Implementation-defined ID CSRs (QEMU's default `marchid` is 0x2a) | lockstep: QEMU `mvendorid=0,marchid=0,mimpid=0` |
| `run12-pass-10M-steps.log` | **10,000,000** | none (rivemu `5b8765a`, with its fast TLB and decode-cache changes) | | |
| `run13-pass-30M-steps.log` | **30,000,000** | none (rivemu `82f56c3`: also Zama16b, strict PMP and the inline fast path; lockstep `29e0e88`, which also compares fault `tval`s) | | |

Run 10 took 568.6 s on a loaded 4-vCPU container (about 5,300 steps/s); run 12, 10M steps, took 2,106.5 s; run 13, 30M steps, took 6,356.8 s.
