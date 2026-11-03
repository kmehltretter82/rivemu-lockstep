# Differential suites against rivemu with superblocks (2026-11-03)

rivemu `21acfa8` changed the block interpreter (blocks go on past
conditional branches, a fetch table in the fast TLB) and, on the
single-step path these suites use, the order of `Op` and when the fetch
page cache is filled. `scripts/ci-differential.sh` (all 18 suites, 16
blocks of 32 instructions, seed 0x1000) against QEMU 11.1.3 with
`--step-check` and against the Sail model 0.16, with rivemu at `23d425f`
(the same code plus documentation), run locally: **36/36 PASS**
(`summary.txt`, one log per run).
