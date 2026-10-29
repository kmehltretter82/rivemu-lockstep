# Sail RISC-V debug-v1 endpoint

Rivemu lockstep uses a small, versioned extension to the experimental GDB
endpoint in Sail RISC-V 0.16. The patch is pinned to upstream commit
`e5acebb04ff573e93203596486b831a5974117c3` and is stored in
`patches/sail-riscv-0.16-debug-v1.patch`.

The official 0.16 source archive has SHA-256
`73a617fae97429f0659f7dedac4dada86ea6f27183146698ef70804b23b4203e`.
The validated build uses Sail compiler 0.20.3.

## Why the patch exists

Stock Sail 0.16 already implements binary `X` memory writes, but not the hex
`M` form used by the lockstep client. Its `P` parser treats a target-endian
byte string as one numeric hex integer, byte-swapping every multi-byte register
write. A PC write also updates only `nextPC`; the next step replaces that value
before it becomes the current `PC`.

The patch:

- adds `M` memory writes while retaining `X`;
- decodes every `P` value as a little-endian RSP byte string;
- updates both `PC` and `nextPC` for debugger PC writes;
- exposes the current privilege and the trap/control CSR subset needed by the
  lockstep harness;
- preserves upstream register numbers 0-65, `target.xml`, and the `g` reply.

Clients detect the extension through `sail-riscv-debug-v1+` in `qSupported`.
The stable map is also available from
`qXfer:features:read:sail-riscv-debug.xml`.

## Stable p/P register map

| Decimal | RSP hex | Name | Width |
|---:|---:|---|---|
| 66 | 42 | priv | 8 bits |
| 67 | 43 | mtvec | XLEN |
| 68 | 44 | mstatus | XLEN |
| 69 | 45 | mepc | XLEN |
| 70 | 46 | mcause | XLEN |
| 71 | 47 | mtval | XLEN |
| 72 | 48 | sstatus | XLEN |
| 73 | 49 | sepc | XLEN |
| 74 | 4a | scause | XLEN |
| 75 | 4b | stval | XLEN |
| 76 | 4c | satp | XLEN |
| 77 | 4d | stvec | XLEN |
| 78 | 4e | mscratch | XLEN |
| 79 | 4f | sscratch | XLEN |
| 80 | 50 | medeleg | XLEN |
| 81 | 51 | mideleg | XLEN |
| 82 | 52 | senvcfg | XLEN |

`priv` uses the architectural encodings 0 (U), 1 (S), and 3 (M). CSR writes
use Sail's normal WARL/WLRL legalizers. Register values use target byte order,
so RV64 value `0x1122334455667788` is sent as `8877665544332211`.

## Rebuild

Install Sail 0.20.3, CMake, GMP, curl, and the standard patch/archive tools,
then run:

```sh
SAIL_BUILD_JOBS=2 sh scripts/build-sail-debug-v1.sh
```

The default destination is
`../third_party/sail-riscv-0.16-debug-v1/bin/sail_riscv_sim`. The script uses a
temporary source/build tree, verifies the source archive before extraction,
and removes only that temporary tree when it exits.

## Validation performed

The patched macOS arm64 simulator was compiled at two jobs, all generated RV32
and RV64 configurations passed the build's validation step, and a live RSP
probe verified:

- extension discovery and XML retrieval;
- `M` write followed by `m` read;
- little-endian GPR and FPR `P`/`p` round trips;
- privilege, `mtvec`, and `mscratch` `P`/`p` round trips;
- immediate PC write/read; and
- one step from the rewritten PC, including the expected PC and GPR result.
