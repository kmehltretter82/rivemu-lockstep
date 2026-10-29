//! `RISU` block runner and automatic 1-instruction bisection engine.

use std::fmt;

use rivemu_cpu_riscv::decode;

use crate::risu::encode::build_trap_handler;
use crate::risu::seed::Rng;
use crate::risu::suite::{Suite, generate_block};
use crate::target::{QemuGdbTarget, RivemuTarget};
use crate::{ArchState, CosimTarget, FieldDiff, StopReason, TargetError};

/// Guest physical address where `RISU` instruction blocks are loaded.
pub const CODE_BASE: u64 = 0x8000_0000;
/// Guest physical address of the M-mode trap recovery handler (`mtvec`).
pub const TRAP_BASE: u64 = 0x8000_2000;
/// Guest physical address of the sandboxed 4 KiB scratch RAM buffer (`s0`).
pub const SCRATCH_BASE: u64 = 0x8001_0000;
/// Size of the seeded scratch buffer, including the end of unaligned accesses.
pub const SCRATCH_SEED_LEN: usize = 4096;

/// Detailed report produced when a `RISU` block diverges and is bisected to 1 instruction.
#[derive(Clone, Debug)]
pub struct BisectReport {
    /// Suite that generated the block.
    pub suite: Suite,
    /// Seed that generated the block.
    pub seed: u64,
    /// 0-based instruction step index where the divergence occurred.
    pub step_index: usize,
    /// PC of the diverging instruction.
    pub pc: u64,
    /// Raw 32-bit instruction encoding at `pc`.
    pub insn_word: u32,
    /// Decoded `rivemu` instruction structure.
    pub decoded: String,
    /// Architectural state immediately *before* the diverging instruction executed.
    pub pre_state: ArchState,
    /// Architectural state in `rivemu` immediately *after* the instruction.
    pub rivemu_post: ArchState,
    /// Architectural state in `QEMU` immediately *after* the instruction.
    pub qemu_post: ArchState,
    /// Register/CSR fields that differed.
    pub diffs: Vec<FieldDiff>,
}

impl fmt::Display for BisectReport {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        writeln!(
            f,
            "=== LOCKSTEP DIVERGENCE [suite={}, seed={:#018x}, step #{} @ pc={:#010x}] ===",
            self.suite.name(),
            self.seed,
            self.step_index,
            self.pc
        )?;
        writeln!(
            f,
            "  Instruction : {:#010x}   decoded = {}",
            self.insn_word, self.decoded
        )?;
        writeln!(
            f,
            "  Pre-fcsr    : {:#04x} (frm={}, fflags={:#04x})",
            self.pre_state.fcsr,
            (self.pre_state.fcsr >> 5) & 7,
            self.pre_state.fcsr & 0x1f
        )?;
        writeln!(f, "  Mismatched fields:")?;
        for d in &self.diffs {
            writeln!(f, "  {d}")?;
        }
        Ok(())
    }
}

/// Persistent `RISU` lockstep harness driving `RivemuTarget` and `QemuGdbTarget`.
pub struct RisuHarness<R = RivemuTarget, Q = QemuGdbTarget> {
    /// In-process `rivemu` target.
    pub rivemu: R,
    /// Persistent `qemu-system-riscv64` GDB target.
    pub qemu: Q,
    /// Whether to compare privileged CSRs at checkpoints.
    pub check_csrs: bool,
    /// Whether to compare architectural state and scratch RAM after every instruction.
    pub step_check: bool,
}

impl RisuHarness {
    /// Creates a new `RISU` lockstep harness and installs the trap handler at [`TRAP_BASE`].
    pub fn new(
        rivemu: RivemuTarget,
        mut qemu: QemuGdbTarget,
        check_csrs: bool,
    ) -> Result<Self, TargetError> {
        qemu.sync_csrs = check_csrs;
        Self::with_targets(rivemu, qemu, check_csrs)
    }
}

impl<R: CosimTarget, Q: CosimTarget> RisuHarness<R, Q> {
    fn with_targets(mut rivemu: R, mut qemu: Q, check_csrs: bool) -> Result<Self, TargetError> {
        let handler = build_trap_handler();
        rivemu.load_ram(TRAP_BASE, &handler)?;
        qemu.load_ram(TRAP_BASE, &handler)?;
        rivemu.set_trap_vector(TRAP_BASE)?;
        qemu.set_trap_vector(TRAP_BASE)?;
        Ok(Self {
            rivemu,
            qemu,
            check_csrs,
            step_check: false,
        })
    }

    /// Enables or disables comparison after every instruction instead of only at block boundaries.
    pub fn set_step_check(&mut self, enabled: bool) {
        self.step_check = enabled;
    }

    /// Runs a single seeded `RISU` block of `num_insns` instructions.
    /// Returns `Ok(None)` if `rivemu` and `QEMU` match, or `Ok(Some(BisectReport))` on divergence.
    pub fn run_seed(
        &mut self,
        suite: Suite,
        seed: u64,
        num_insns: usize,
    ) -> Result<Option<BisectReport>, TargetError> {
        if num_insns == 0 || num_insns >= ((TRAP_BASE - CODE_BASE) / 4) as usize {
            return Err(TargetError::Protocol(
                "instruction count must be nonzero and fit below the trap handler".into(),
            ));
        }
        let mut rng = Rng::new(seed);
        let init_state = rng.seed_state(CODE_BASE, SCRATCH_BASE);
        let insns = generate_block(&mut rng, suite, num_insns);
        let mut code_bytes = Vec::with_capacity(insns.len() * 4);
        for &w in &insns {
            code_bytes.extend_from_slice(&w.to_le_bytes());
        }
        if code_bytes.len() as u64 > TRAP_BASE - CODE_BASE {
            return Err(TargetError::Protocol(
                "generated block overlaps the trap handler".into(),
            ));
        }
        let end_pc = CODE_BASE + ((insns.len() - 1) * 4) as u64;

        let mut scratch = vec![0u8; SCRATCH_SEED_LEN];
        for chunk in scratch.chunks_exact_mut(8) {
            chunk.copy_from_slice(&rng.edge_u64().to_le_bytes());
        }

        // Load initial state and code into both targets.
        self.rivemu.load_ram(CODE_BASE, &code_bytes)?;
        self.qemu.load_ram(CODE_BASE, &code_bytes)?;
        if matches!(suite, Suite::SandboxMem | Suite::All) {
            self.rivemu.load_ram(SCRATCH_BASE, &scratch)?;
            self.qemu.load_ram(SCRATCH_BASE, &scratch)?;
        }
        self.rivemu.set_state(&init_state)?;
        self.qemu.set_state(&init_state)?;
        self.rivemu.set_trap_vector(TRAP_BASE)?;
        self.qemu.set_trap_vector(TRAP_BASE)?;

        let initial_diffs = self
            .rivemu
            .get_state()?
            .diff(&self.qemu.get_state()?, self.check_csrs);
        if !initial_diffs.is_empty() {
            return Err(TargetError::Protocol(format!(
                "targets differ before executing seed {seed:#x}: {}",
                initial_diffs[0]
            )));
        }
        if matches!(suite, Suite::SandboxMem | Suite::All) {
            verify_seeded_scratch(&mut self.rivemu, &mut self.qemu, &scratch)?;
        }

        let max_steps = (insns.len() as u64) * 16 + 64;
        if self.step_check {
            return self.run_step_checked(suite, seed, end_pc, max_steps as usize);
        }
        require_checkpoint("rivemu", end_pc, self.rivemu.run_until(end_pc, max_steps)?)?;
        require_checkpoint("QEMU", end_pc, self.qemu.run_until(end_pc, max_steps)?)?;

        let r_end = self.rivemu.get_state()?;
        let q_end = self.qemu.get_state()?;
        let mut diffs = r_end.diff(&q_end, self.check_csrs);
        if matches!(suite, Suite::SandboxMem | Suite::All) {
            diffs.extend(scratch_diffs(&mut self.rivemu, &mut self.qemu)?);
        }
        if diffs.is_empty() {
            return Ok(None);
        }

        // Block diverged! Rewind both targets and single-step bisect to the exact instruction.
        self.bisect_block(suite, seed, &init_state, &code_bytes, &scratch, end_pc)
    }

    fn bisect_block(
        &mut self,
        suite: Suite,
        seed: u64,
        init_state: &ArchState,
        code_bytes: &[u8],
        scratch: &[u8],
        end_pc: u64,
    ) -> Result<Option<BisectReport>, TargetError> {
        let max_steps = (code_bytes.len() / 4) * 16 + 64;
        self.rivemu.load_ram(CODE_BASE, code_bytes)?;
        self.qemu.load_ram(CODE_BASE, code_bytes)?;
        if matches!(suite, Suite::SandboxMem | Suite::All) {
            self.rivemu.load_ram(SCRATCH_BASE, scratch)?;
            self.qemu.load_ram(SCRATCH_BASE, scratch)?;
        }
        self.rivemu.set_state(init_state)?;
        self.qemu.set_state(init_state)?;
        self.rivemu.set_trap_vector(TRAP_BASE)?;
        self.qemu.set_trap_vector(TRAP_BASE)?;

        if matches!(suite, Suite::SandboxMem | Suite::All) {
            verify_seeded_scratch(&mut self.rivemu, &mut self.qemu, scratch)?;
        }
        let replay_diffs = self
            .rivemu
            .get_state()?
            .diff(&self.qemu.get_state()?, self.check_csrs);
        if !replay_diffs.is_empty() {
            return Err(TargetError::Protocol(format!(
                "targets differ before replaying seed {seed:#x}: {}",
                replay_diffs[0]
            )));
        }

        let mut pre_state = self.rivemu.get_state()?;
        for step_index in 0..max_steps {
            let pc = pre_state.pc;
            if pc == end_pc {
                break;
            }
            let mut word_bytes = [0u8; 4];
            self.rivemu.read_ram(pc, &mut word_bytes)?;
            let insn_word = u32::from_le_bytes(word_bytes);

            self.rivemu.step_one()?;
            self.qemu.step_one()?;

            let rivemu_post = self.rivemu.get_state()?;
            let qemu_post = self.qemu.get_state()?;
            let mut diffs = rivemu_post.diff(&qemu_post, self.check_csrs);
            if matches!(suite, Suite::SandboxMem | Suite::All) {
                diffs.extend(scratch_diffs(&mut self.rivemu, &mut self.qemu)?);
            }
            if !diffs.is_empty() {
                let decoded = format!("{:?}", decode::decode(insn_word));
                return Ok(Some(BisectReport {
                    suite,
                    seed,
                    step_index,
                    pc,
                    insn_word,
                    decoded,
                    pre_state,
                    rivemu_post,
                    qemu_post,
                    diffs,
                }));
            }
            pre_state = rivemu_post;
        }
        Err(TargetError::Protocol(format!(
            "checkpoint divergence for seed {seed:#x} could not be reproduced during replay"
        )))
    }

    fn run_step_checked(
        &mut self,
        suite: Suite,
        seed: u64,
        end_pc: u64,
        max_steps: usize,
    ) -> Result<Option<BisectReport>, TargetError> {
        for step_index in 0..max_steps {
            let pre_state = self.rivemu.get_state()?;
            if pre_state.pc == end_pc {
                return Ok(None);
            }

            let pc = pre_state.pc;
            let mut word_bytes = [0u8; 4];
            self.rivemu.read_ram(pc, &mut word_bytes)?;
            let insn_word = u32::from_le_bytes(word_bytes);

            self.rivemu.step_one()?;
            self.qemu.step_one()?;

            let rivemu_post = self.rivemu.get_state()?;
            let qemu_post = self.qemu.get_state()?;
            let mut diffs = rivemu_post.diff(&qemu_post, self.check_csrs);
            if matches!(suite, Suite::SandboxMem | Suite::All) {
                diffs.extend(scratch_diffs(&mut self.rivemu, &mut self.qemu)?);
            }
            if !diffs.is_empty() {
                return Ok(Some(BisectReport {
                    suite,
                    seed,
                    step_index,
                    pc,
                    insn_word,
                    decoded: format!("{:?}", decode::decode(insn_word)),
                    pre_state,
                    rivemu_post,
                    qemu_post,
                    diffs,
                }));
            }
        }

        let rivemu_pc = self.rivemu.get_state()?.pc;
        let qemu_pc = self.qemu.get_state()?.pc;
        if rivemu_pc == end_pc && qemu_pc == end_pc {
            return Ok(None);
        }

        Err(TargetError::Protocol(format!(
            "targets did not reach checkpoint {end_pc:#x} within {max_steps} steps for seed {seed:#x}"
        )))
    }
}

fn require_checkpoint(target: &str, pc: u64, reason: StopReason) -> Result<(), TargetError> {
    if reason != StopReason::Breakpoint {
        return Err(TargetError::Protocol(format!(
            "{target} did not reach checkpoint {pc:#x}: {reason:?}"
        )));
    }
    Ok(())
}

fn scratch_diffs<R: CosimTarget, Q: CosimTarget>(
    rivemu: &mut R,
    qemu: &mut Q,
) -> Result<Vec<FieldDiff>, TargetError> {
    let mut rv = vec![0; SCRATCH_SEED_LEN];
    let mut qv = vec![0; SCRATCH_SEED_LEN];
    rivemu.read_ram(SCRATCH_BASE, &mut rv)?;
    qemu.read_ram(SCRATCH_BASE, &mut qv)?;
    Ok(rv
        .iter()
        .zip(&qv)
        .enumerate()
        .filter(|(_, (r, q))| r != q)
        .map(|(offset, (&r, &q))| FieldDiff {
            name: format!("memory[{:#x}]", SCRATCH_BASE + offset as u64),
            rivemu: u64::from(r),
            qemu: u64::from(q),
        })
        .take(16)
        .collect())
}

fn verify_seeded_scratch<R: CosimTarget, Q: CosimTarget>(
    rivemu: &mut R,
    qemu: &mut Q,
    expected: &[u8],
) -> Result<(), TargetError> {
    let mut rv = vec![0; expected.len()];
    let mut qv = vec![0; expected.len()];
    rivemu.read_ram(SCRATCH_BASE, &mut rv)?;
    qemu.read_ram(SCRATCH_BASE, &mut qv)?;

    for (target, actual) in [("rivemu", rv.as_slice()), ("QEMU", qv.as_slice())] {
        if let Some(offset) = (0..expected.len()).find(|&i| actual[i] != expected[i]) {
            return Err(TargetError::Protocol(format!(
                "{target} scratch differs before execution at {:#x}: got {:#04x}, expected {:#04x}",
                SCRATCH_BASE + offset as u64,
                actual[offset],
                expected[offset]
            )));
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use std::collections::BTreeMap;

    use super::*;

    #[derive(Default)]
    struct MockTarget {
        state: ArchState,
        ram: BTreeMap<u64, u8>,
        trap_installed: bool,
        steps: usize,
        diverge_on_step: Option<usize>,
        corrupt_scratch: bool,
        fail_code_read: bool,
    }

    impl CosimTarget for MockTarget {
        fn load_ram(&mut self, gpa: u64, data: &[u8]) -> Result<(), TargetError> {
            for (offset, &byte) in data.iter().enumerate() {
                self.ram.insert(gpa + offset as u64, byte);
            }
            if self.corrupt_scratch && gpa == SCRATCH_BASE && !data.is_empty() {
                self.ram.insert(SCRATCH_BASE, data[0] ^ 1);
            }
            Ok(())
        }

        fn read_ram(&mut self, gpa: u64, buf: &mut [u8]) -> Result<(), TargetError> {
            if self.fail_code_read && (CODE_BASE..TRAP_BASE).contains(&gpa) {
                return Err(TargetError::Protocol("mock code read failure".into()));
            }
            for (offset, byte) in buf.iter_mut().enumerate() {
                *byte = self.ram.get(&(gpa + offset as u64)).copied().unwrap_or(0);
            }
            Ok(())
        }

        fn set_trap_vector(&mut self, _addr: u64) -> Result<(), TargetError> {
            self.trap_installed = true;
            Ok(())
        }

        fn set_state(&mut self, state: &ArchState) -> Result<(), TargetError> {
            self.state = state.clone();
            self.trap_installed = false;
            self.steps = 0;
            Ok(())
        }

        fn get_state(&mut self) -> Result<ArchState, TargetError> {
            Ok(self.state.clone())
        }

        fn step_one(&mut self) -> Result<(), TargetError> {
            if !self.trap_installed {
                return Err(TargetError::Protocol(
                    "trap vector was not reinstalled".into(),
                ));
            }
            self.state.pc += 4;
            if self.diverge_on_step == Some(self.steps) {
                self.state.x[1] ^= 1;
            }
            self.steps += 1;
            Ok(())
        }

        fn run_until(
            &mut self,
            target_pc: u64,
            _max_insns: u64,
        ) -> Result<StopReason, TargetError> {
            if !self.trap_installed {
                return Err(TargetError::Protocol(
                    "trap vector was not reinstalled".into(),
                ));
            }
            self.state.pc = target_pc;
            Ok(StopReason::Breakpoint)
        }
    }

    #[test]
    fn run_seed_reinstalls_trap_vector_after_state_reset() {
        let mut harness =
            RisuHarness::with_targets(MockTarget::default(), MockTarget::default(), false).unwrap();

        assert!(harness.run_seed(Suite::IntAlu, 1, 1).unwrap().is_none());
    }

    #[test]
    fn step_check_reports_a_transient_register_difference() {
        let qemu = MockTarget {
            diverge_on_step: Some(0),
            ..MockTarget::default()
        };
        let mut harness = RisuHarness::with_targets(MockTarget::default(), qemu, false).unwrap();
        harness.set_step_check(true);

        let report = harness
            .run_seed(Suite::IntAlu, 2, 1)
            .unwrap()
            .expect("the first instruction must diverge");
        assert_eq!(report.step_index, 0);
        assert!(report.diffs.iter().any(|diff| diff.name.starts_with("x1 ")));
    }

    #[test]
    fn run_seed_rejects_corrupt_initial_scratch_ram() {
        let qemu = MockTarget {
            corrupt_scratch: true,
            ..MockTarget::default()
        };
        let mut harness = RisuHarness::with_targets(MockTarget::default(), qemu, false).unwrap();

        let error = harness.run_seed(Suite::SandboxMem, 3, 1).unwrap_err();
        assert!(
            error
                .to_string()
                .contains("QEMU scratch differs before execution")
        );
    }

    #[test]
    fn step_check_propagates_instruction_fetch_errors() {
        let rivemu = MockTarget {
            fail_code_read: true,
            ..MockTarget::default()
        };
        let mut harness = RisuHarness::with_targets(rivemu, MockTarget::default(), false).unwrap();
        harness.set_step_check(true);

        let error = harness.run_seed(Suite::IntAlu, 4, 1).unwrap_err();
        assert!(error.to_string().contains("mock code read failure"));
    }
}
