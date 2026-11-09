# Differential suites against current rivemu (2026-11-09)

The previous campaign (`docs/evidence/2026-11-03-campaigns-superblocks/`)
ran against rivemu `23d425f`. Since then rivemu changed the interpreter
twice:

- `07fa5fe`: block instructions hold their register fields as a 32-value
  enum, so indexing the register file needs no mask;
- `64173c6`: each hart runs 50,000 instructions per turn instead of 10,000.

`scripts/ci-differential.sh` (all 18 suites, 16 blocks of 32 instructions,
seed 0x1000) against QEMU 11.1.3 with `--step-check` and against the Sail
model 0.16, with rivemu at `c5d2c64` (`64173c6` plus documentation; the
path dependencies in `Cargo.toml` point at that checkout), run locally:
**36/36 PASS**, `failed=0`, in 3 min 23 s (`summary.txt`, one log per run).
