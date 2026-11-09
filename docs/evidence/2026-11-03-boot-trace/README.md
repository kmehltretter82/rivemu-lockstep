# Trace-driven boot lockstep to the shell prompt (2026-11-03)

`rivemu-lockstep boot-trace` (README, "Trace-driven boot lockstep") with
QEMU 11.1.3 and the `rivemu_trace` plugin, against rivemu `6cfb325`
(`Hart::nondeterministic_read`) on branch `claude/trusting-bell-xvhb0r`.

Inputs: OpenSBI v1.7 `fw_dynamic.bin` (pinned in rivemu's
`scripts/fetch-linux-test.sh`) and Linux 6.12 + BusyBox built by rivemu's
`scripts/build-linux-test-from-source.sh`; `--append console=ttyS0
--until-console '~ # '`, 256 MiB, one hart.

| Log | Instructions | Interrupts mirrored | Exceptions | Copied reads | Snapshots | Time | Result |
|---|---|---|---|---|---|---|---|
| `shell-prompt-run1.log` | 362,807,296 | 13,077 | 1,416 | 109,836 | 5,537 | 80.5 s | PASS, shell prompt |
| `shell-prompt-run2.log` | 358,612,992 | 12,465 | 1,411 | 105,220 | 5,473 | 72.5 s | PASS, shell prompt |
| `shell-prompt-run3.log` | 358,612,992 | 12,129 | 1,406 | 102,846 | 5,473 | 66.4 s | PASS, shell prompt |

QEMU runs in real time, so interrupt timing, and with it the instruction
count, differs from run to run. The run stops at the first 2^20-instruction
boundary after the prompt appears.

`mutation-sraiw.log`: with rivemu's `sraiw` changed to shift by `imm & 15`
(injected, then reverted), the run diverges after 18,201,763 instructions:
`x12: rivemu 0xfffffffffffffe7f, QEMU 0xffffffffffffffff`.

Divergences found while bringing the mode up, all in the harness:
1. `mstatus.SD` is derived on read in rivemu; the comparison now uses
   `MSTATUS_COMPARE_MASK` like the other modes.
2. A fetch page fault right after `csrw satp` (Linux's MMU switch) has no
   'I' record in QEMU; rivemu now steps once to take the same fault.
3. Linux's `compat_mode_detect` writes `sstatus.UXL` and reads it back:
   QEMU keeps UXL writable (RV32 user mode), rivemu does not. Both are
   legal (WARL); such reads are taken from QEMU and counted (1 per boot).
4. A snapshot taken right after `rdtime` saw QEMU's time value before the
   comparator had applied it; snapshots now follow the 'I' record.
