# Sail/QEMU startup "Connection reset by peer" (2026-11-02)

Host: Claude Code cloud container, Linux 6.18 x86_64, 4 vCPUs. Sail 0.16 with
the debug-v1 patch (built with Sail 0.20.3), QEMU 11.1.3 riscv64-softmmu.
Campaign command for every summary below:

```sh
rivemu-lockstep campaign --reference sail --suite alu --workers 6 --blocks 300 --insns 16
```

## Cause

`pick_free_port()` bound a probe `TcpListener` on `127.0.0.1:0`, read the
port, and dropped the listener. The caller started Sail on that port and
polled `connect()` until it succeeded.

1. **Inherited probe listener (main cause).** `Command::spawn` in another
   worker thread copies the whole fd table into the child. Close-on-exec
   only takes effect at `execve`, so a probe that this thread has already
   dropped can stay open in that child for a short time. A `connect()` in
   that window completes in the probe's backlog. When the child execs, the
   probe closes and the connection is reset. In `before-lockfree/inherited-probe.txt`,
   three failing runs show the client connecting about 0.35 ms after spawning
   Sail. A fresh Sail takes about 30 ms to listen. The port was picked only
   once, and that Sail had printed nothing yet.
2. **Two workers given the same port.** `before-lockfree/port-collision.txt`:
   both workers got port 41481. The second Sail failed with
   `bind: Address already in use`, and both clients connected to the first
   Sail. Sail accepts only one client. The other connection stayed in the
   backlog and was reset when that Sail exited.

`forkleak.rs` reproduces mechanism 1 with no Sail at all
(`forkleak-output.txt`). Without concurrent spawns, 0 of 20,000 connections
to a dropped probe succeed. With 4 threads running `Command::spawn`, 145
succeed and 142 are then reset.

The startup lock in 197993f hid both mechanisms. While one worker held a
probe, no other worker could be inside `Command::spawn`, and port selection
was serialized.

## Fix

- **Sail.** Ports come from a private range, 20000-29999. That is below the
  Linux (32768-60999) and macOS (49152-65535) ephemeral ranges, and the
  ports are reserved in-process until the Sail process is reaped. The process
  never opens a probe listener. The client connects only after its own Sail
  prints `Listening on port <N>` (stock and patched Sail both print it). Sail
  then holds the port, so no other listener can exist on it. If Sail exits
  with `Address already in use`, another port is tried.
- **QEMU.** The GDB stub is served on a Unix socket whose path is unique per
  process and spawn, so port selection is gone entirely.

## Results

| Version | Runs | Failed | Wall time per run |
|---|---|---|---|
| 197993f with the lock removed (`before-lockfree/summary.txt`) | 24 | 7 | 6.6-6.9 s |
| 197993f with the startup lock (`with-startup-lock/summary.txt`) | 8 | 0 | 9.7-10.5 s |
| This fix (`after-fix/summary.txt`, full logs `after-fix/run*.log`) | 25 | 0 | 5.7-6.4 s |

`tests/spawn_stress.rs` (`RIVEMU_LOCKSTEP_STRESS=1`) starts 240 QEMU and 240
Sail targets from 6 threads at once and checks that each answers a `g`
packet. Before the fix, 2 of 5 runs failed (`stress-before/`). In run 1,
the QEMU test failed with two resets, so QEMU had the same race. After the
fix, 10 of 10 runs passed, with 4,800 startups in total (`stress-after/`).
