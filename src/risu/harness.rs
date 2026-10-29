//! `RISU` block runner and automatic 1-instruction bisection engine.

use std::fmt;

use rivemu_cpu_riscv::decode;

use crate::risu::encode::{EBREAK, build_trap_handler};
use crate::risu::seed::Rng;
use crate::risu::suite::{Suite, generate_block, generate_compressed_block};
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

/// A fully materialized deterministic RISU case that can be replayed across references.
#[derive(Clone, Debug)]
pub struct RisuCase {
    /// Suite used to generate this case.
    suite: Suite,
    /// PRNG seed used to generate this case.
    seed: u64,
    /// Initial architectural state.
    init_state: ArchState,
    /// Encoded instruction block, including the final `EBREAK` checkpoint.
    code_bytes: Vec<u8>,
    /// Seeded scratch-memory contents.
    scratch: Vec<u8>,
    /// Address of the final `EBREAK` checkpoint.
    end_pc: u64,
    /// Maximum dynamic instruction attempts before the case is considered non-terminating.
    max_steps: usize,
}

impl RisuCase {
    /// Generates a deterministic case without executing either target.
    pub fn generate(suite: Suite, seed: u64, num_insns: usize) -> Result<Self, TargetError> {
        if num_insns == 0 {
            return Err(TargetError::Protocol(
                "instruction count must be nonzero and fit below the trap handler".into(),
            ));
        }
        let bytes_per_insn = if suite == Suite::Compressed { 2 } else { 4 };
        let minimum_code_len = num_insns
            .checked_mul(bytes_per_insn)
            .and_then(|len| len.checked_add(4))
            .ok_or_else(|| {
                TargetError::Protocol(
                    "instruction count must be nonzero and fit below the trap handler".into(),
                )
            })?;
        if minimum_code_len as u64 > TRAP_BASE - CODE_BASE {
            return Err(TargetError::Protocol(
                "instruction count must be nonzero and fit below the trap handler".into(),
            ));
        }

        let mut rng = Rng::new(seed);
        let init_state = rng.seed_state(CODE_BASE, SCRATCH_BASE);
        let (code_bytes, generated_insns) = if suite == Suite::Compressed {
            let insns = generate_compressed_block(&mut rng, num_insns);
            let mut bytes = Vec::with_capacity(insns.len() * 2 + 4);
            for &half in &insns {
                bytes.extend_from_slice(&half.to_le_bytes());
            }
            bytes.extend_from_slice(&EBREAK.to_le_bytes());
            (bytes, insns.len())
        } else {
            let insns = generate_block(&mut rng, suite, num_insns);
            let generated_insns = insns.len().checked_sub(1).ok_or_else(|| {
                TargetError::Protocol("generated block is missing its checkpoint".into())
            })?;
            let mut bytes = Vec::with_capacity(insns.len() * 4);
            for &word in &insns {
                bytes.extend_from_slice(&word.to_le_bytes());
            }
            (bytes, generated_insns)
        };
        if code_bytes.len() as u64 > TRAP_BASE - CODE_BASE {
            return Err(TargetError::Protocol(
                "generated block overlaps the trap handler".into(),
            ));
        }
        if code_bytes.len() < 4 || code_bytes[code_bytes.len() - 4..] != EBREAK.to_le_bytes() {
            return Err(TargetError::Protocol(
                "generated block is missing its final EBREAK checkpoint".into(),
            ));
        }

        let mut scratch = vec![0u8; SCRATCH_SEED_LEN];
        for chunk in scratch.chunks_exact_mut(8) {
            chunk.copy_from_slice(&rng.edge_u64().to_le_bytes());
        }

        let end_pc = CODE_BASE
            .checked_add((code_bytes.len() - 4) as u64)
            .ok_or_else(|| TargetError::Protocol("generated block address overflow".into()))?;
        let max_steps = generated_insns
            .checked_mul(16)
            .and_then(|steps| steps.checked_add(64))
            .ok_or_else(|| TargetError::Protocol("generated step limit overflow".into()))?;
        Ok(Self {
            suite,
            seed,
            init_state,
            code_bytes,
            scratch,
            end_pc,
            max_steps,
        })
    }

    /// Whether this case reads or writes the seeded scratch buffer.
    pub const fn uses_scratch(&self) -> bool {
        matches!(
            self.suite,
            Suite::SandboxMem | Suite::Atomics | Suite::Compressed | Suite::All
        )
    }

    /// Suite used to generate this case.
    pub const fn suite(&self) -> Suite {
        self.suite
    }

    /// PRNG seed used to generate this case.
    pub const fn seed(&self) -> u64 {
        self.seed
    }

    /// Initial architectural state.
    pub const fn init_state(&self) -> &ArchState {
        &self.init_state
    }

    /// Encoded instructions, including the final `EBREAK` checkpoint.
    pub fn code_bytes(&self) -> &[u8] {
        &self.code_bytes
    }

    /// Seeded scratch-memory contents.
    pub fn scratch(&self) -> &[u8] {
        &self.scratch
    }

    /// Address of the final `EBREAK` checkpoint.
    pub const fn end_pc(&self) -> u64 {
        self.end_pc
    }

    /// Dynamic instruction limit for this case.
    pub const fn max_steps(&self) -> usize {
        self.max_steps
    }
}

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
    /// Raw instruction encoding at `pc`, zero-extended to 32 bits.
    pub insn_word: u32,
    /// Encoded instruction length in bytes (2 or 4).
    pub insn_len: u8,
    /// Decoded `rivemu` instruction structure.
    pub decoded: String,
    /// Architectural state immediately *before* the diverging instruction executed.
    pub pre_state: ArchState,
    /// Human-readable candidate implementation name.
    pub candidate_name: &'static str,
    /// Human-readable reference implementation name.
    pub reference_name: &'static str,
    /// Candidate architectural state immediately *after* the instruction.
    pub candidate_post: ArchState,
    /// Reference architectural state immediately *after* the instruction.
    pub reference_post: ArchState,
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
        match self.insn_len {
            2 => writeln!(
                f,
                "  Instruction : {:#06x} (16-bit)   decoded = {}",
                self.insn_word, self.decoded
            )?,
            4 => writeln!(
                f,
                "  Instruction : {:#010x} (32-bit)   decoded = {}",
                self.insn_word, self.decoded
            )?,
            len => writeln!(
                f,
                "  Instruction : {:#010x} ({len}-byte)   decoded = {}",
                self.insn_word, self.decoded
            )?,
        }
        writeln!(
            f,
            "  Pre-fcsr    : {:#04x} (frm={}, fflags={:#04x})",
            self.pre_state.fcsr,
            (self.pre_state.fcsr >> 5) & 7,
            self.pre_state.fcsr & 0x1f
        )?;
        writeln!(f, "  Mismatched fields:")?;
        writeln!(
            f,
            "  Candidate/reference: {} / {}",
            self.candidate_name, self.reference_name
        )?;
        for d in &self.diffs {
            writeln!(f, "  {d}")?;
        }
        Ok(())
    }
}

#[derive(Clone, Copy, Debug)]
struct FetchedInsn {
    raw: u32,
    len: u8,
    decoded: decode::Insn,
}

fn fetch_and_decode<T: CosimTarget>(target: &mut T, pc: u64) -> Result<FetchedInsn, TargetError> {
    let mut low_bytes = [0u8; 2];
    target.read_ram(pc, &mut low_bytes)?;
    let low = u16::from_le_bytes(low_bytes);
    if low & 3 != 3 {
        return Ok(FetchedInsn {
            raw: u32::from(low),
            len: 2,
            decoded: decode::decode_compressed(low),
        });
    }

    let mut high_bytes = [0u8; 2];
    target.read_ram(pc + 2, &mut high_bytes)?;
    let raw = u32::from(low) | (u32::from(u16::from_le_bytes(high_bytes)) << 16);
    Ok(FetchedInsn {
        raw,
        len: 4,
        decoded: decode::decode(raw),
    })
}

/// Persistent `RISU` lockstep harness driving a candidate and reference target.
pub struct RisuHarness<C = RivemuTarget, R = QemuGdbTarget> {
    /// Implementation under test.
    pub candidate: C,
    /// Architectural reference implementation.
    pub reference: R,
    /// Whether to compare privileged CSRs at checkpoints.
    pub check_csrs: bool,
    /// Whether to compare architectural state and scratch RAM after every instruction.
    pub step_check: bool,
    case_started: bool,
}

impl RisuHarness {
    /// Creates a new `RISU` lockstep harness and installs the trap handler at [`TRAP_BASE`].
    pub fn new(
        candidate: RivemuTarget,
        mut reference: QemuGdbTarget,
        check_csrs: bool,
    ) -> Result<Self, TargetError> {
        reference.sync_csrs = check_csrs;
        Self::from_targets(candidate, reference, check_csrs)
    }
}

impl<C: CosimTarget, R: CosimTarget> RisuHarness<C, R> {
    /// Creates a harness from any candidate/reference pair and installs the trap handler.
    pub fn from_targets(
        mut candidate: C,
        mut reference: R,
        check_csrs: bool,
    ) -> Result<Self, TargetError> {
        if check_csrs && !candidate.supports_privileged_state() {
            return Err(TargetError::Protocol(format!(
                "{} does not expose complete privileged state",
                candidate.name()
            )));
        }
        if check_csrs && !reference.supports_privileged_state() {
            return Err(TargetError::Protocol(format!(
                "{} does not expose complete privileged state",
                reference.name()
            )));
        }
        let handler = build_trap_handler();
        candidate.load_ram(TRAP_BASE, &handler)?;
        reference.load_ram(TRAP_BASE, &handler)?;
        candidate.set_trap_vector(TRAP_BASE)?;
        reference.set_trap_vector(TRAP_BASE)?;
        Ok(Self {
            candidate,
            reference,
            check_csrs,
            step_check: false,
            case_started: false,
        })
    }

    /// Enables or disables comparison after every instruction instead of only at block boundaries.
    pub fn set_step_check(&mut self, enabled: bool) {
        self.step_check = enabled;
    }

    /// Generates and runs a single seeded `RISU` block of `num_insns` instructions.
    pub fn run_seed(
        &mut self,
        suite: Suite,
        seed: u64,
        num_insns: usize,
    ) -> Result<Option<BisectReport>, TargetError> {
        let case = RisuCase::generate(suite, seed, num_insns)?;
        self.run_case(&case)
    }

    /// Runs an already materialized case identically on candidate and reference.
    pub fn run_case(&mut self, case: &RisuCase) -> Result<Option<BisectReport>, TargetError> {
        if !self.step_check
            && (!self.candidate.supports_replay() || !self.reference.supports_replay())
        {
            return Err(TargetError::Protocol(format!(
                "block checkpoint mode requires replayable targets; use step-check for {} vs {}",
                self.candidate.name(),
                self.reference.name()
            )));
        }
        if self.case_started
            && (!self.candidate.supports_replay() || !self.reference.supports_replay())
        {
            return Err(TargetError::Protocol(format!(
                "{} vs {} requires fresh target processes for every case",
                self.candidate.name(),
                self.reference.name()
            )));
        }
        self.case_started = true;
        self.candidate.load_ram(CODE_BASE, &case.code_bytes)?;
        self.reference.load_ram(CODE_BASE, &case.code_bytes)?;
        if case.uses_scratch() {
            self.candidate.load_ram(SCRATCH_BASE, &case.scratch)?;
            self.reference.load_ram(SCRATCH_BASE, &case.scratch)?;
        }
        self.candidate.set_state(&case.init_state)?;
        self.reference.set_state(&case.init_state)?;
        self.candidate.set_trap_vector(TRAP_BASE)?;
        self.reference.set_trap_vector(TRAP_BASE)?;

        let initial_diffs = self
            .candidate
            .get_state()?
            .diff(&self.reference.get_state()?, self.check_csrs);
        if !initial_diffs.is_empty() {
            return Err(TargetError::Protocol(format!(
                "targets differ before executing seed {:#x}: {}",
                case.seed, initial_diffs[0]
            )));
        }
        if case.uses_scratch() {
            verify_seeded_scratch(&mut self.candidate, &mut self.reference, &case.scratch)?;
        }

        if self.step_check {
            return self.run_step_checked(case);
        }
        let candidate_name = self.candidate.name();
        let reference_name = self.reference.name();
        require_checkpoint(
            candidate_name,
            case.end_pc,
            self.candidate
                .run_until(case.end_pc, case.max_steps as u64)?,
        )?;
        require_checkpoint(
            reference_name,
            case.end_pc,
            self.reference
                .run_until(case.end_pc, case.max_steps as u64)?,
        )?;

        let candidate_end = self.candidate.get_state()?;
        let reference_end = self.reference.get_state()?;
        let mut diffs = candidate_end.diff(&reference_end, self.check_csrs);
        if case.uses_scratch() {
            diffs.extend(scratch_diffs(&mut self.candidate, &mut self.reference)?);
        }
        if diffs.is_empty() {
            return Ok(None);
        }

        self.bisect_block(case)
    }

    fn bisect_block(&mut self, case: &RisuCase) -> Result<Option<BisectReport>, TargetError> {
        self.candidate.load_ram(CODE_BASE, &case.code_bytes)?;
        self.reference.load_ram(CODE_BASE, &case.code_bytes)?;
        if case.uses_scratch() {
            self.candidate.load_ram(SCRATCH_BASE, &case.scratch)?;
            self.reference.load_ram(SCRATCH_BASE, &case.scratch)?;
        }
        self.candidate.set_state(&case.init_state)?;
        self.reference.set_state(&case.init_state)?;
        self.candidate.set_trap_vector(TRAP_BASE)?;
        self.reference.set_trap_vector(TRAP_BASE)?;

        if case.uses_scratch() {
            verify_seeded_scratch(&mut self.candidate, &mut self.reference, &case.scratch)?;
        }
        let replay_diffs = self
            .candidate
            .get_state()?
            .diff(&self.reference.get_state()?, self.check_csrs);
        if !replay_diffs.is_empty() {
            return Err(TargetError::Protocol(format!(
                "targets differ before replaying seed {:#x}: {}",
                case.seed, replay_diffs[0]
            )));
        }

        let mut pre_state = self.candidate.get_state()?;
        for step_index in 0..case.max_steps {
            let pc = pre_state.pc;
            if pc == case.end_pc {
                break;
            }
            let insn = fetch_and_decode(&mut self.candidate, pc)?;

            self.candidate.step_one()?;
            self.reference.step_one()?;

            let candidate_post = self.candidate.get_state()?;
            let reference_post = self.reference.get_state()?;
            let mut diffs = candidate_post.diff(&reference_post, self.check_csrs);
            if case.uses_scratch() {
                diffs.extend(scratch_diffs(&mut self.candidate, &mut self.reference)?);
            }
            if !diffs.is_empty() {
                return Ok(Some(BisectReport {
                    suite: case.suite,
                    seed: case.seed,
                    step_index,
                    pc,
                    insn_word: insn.raw,
                    insn_len: insn.len,
                    decoded: format!("{:?}", insn.decoded),
                    pre_state,
                    candidate_name: self.candidate.name(),
                    reference_name: self.reference.name(),
                    candidate_post,
                    reference_post,
                    diffs,
                }));
            }
            pre_state = candidate_post;
        }
        Err(TargetError::Protocol(format!(
            "checkpoint divergence for seed {:#x} could not be reproduced during replay",
            case.seed
        )))
    }

    fn run_step_checked(&mut self, case: &RisuCase) -> Result<Option<BisectReport>, TargetError> {
        for step_index in 0..case.max_steps {
            let pre_state = self.candidate.get_state()?;
            if pre_state.pc == case.end_pc {
                let reference_state = self.reference.get_state()?;
                let mut diffs = pre_state.diff(&reference_state, self.check_csrs);
                if case.uses_scratch() {
                    diffs.extend(scratch_diffs(&mut self.candidate, &mut self.reference)?);
                }
                if reference_state.pc != case.end_pc || !diffs.is_empty() {
                    return Err(TargetError::Protocol(format!(
                        "{} reached checkpoint {:#x} but {} did not match there",
                        self.candidate.name(),
                        case.end_pc,
                        self.reference.name()
                    )));
                }
                return Ok(None);
            }

            let pc = pre_state.pc;
            let insn = fetch_and_decode(&mut self.candidate, pc)?;

            self.candidate.step_one()?;
            self.reference.step_one()?;

            let candidate_post = self.candidate.get_state()?;
            let reference_post = self.reference.get_state()?;
            let mut diffs = candidate_post.diff(&reference_post, self.check_csrs);
            if case.uses_scratch() {
                diffs.extend(scratch_diffs(&mut self.candidate, &mut self.reference)?);
            }
            if !diffs.is_empty() {
                return Ok(Some(BisectReport {
                    suite: case.suite,
                    seed: case.seed,
                    step_index,
                    pc,
                    insn_word: insn.raw,
                    insn_len: insn.len,
                    decoded: format!("{:?}", insn.decoded),
                    pre_state,
                    candidate_name: self.candidate.name(),
                    reference_name: self.reference.name(),
                    candidate_post,
                    reference_post,
                    diffs,
                }));
            }
        }

        let candidate_pc = self.candidate.get_state()?.pc;
        let reference_pc = self.reference.get_state()?.pc;
        if candidate_pc == case.end_pc && reference_pc == case.end_pc {
            return Ok(None);
        }

        Err(TargetError::Protocol(format!(
            "targets did not reach checkpoint {:#x} within {} steps for seed {:#x}",
            case.end_pc, case.max_steps, case.seed
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

fn scratch_diffs<C: CosimTarget, R: CosimTarget>(
    candidate: &mut C,
    reference: &mut R,
) -> Result<Vec<FieldDiff>, TargetError> {
    let mut candidate_bytes = vec![0; SCRATCH_SEED_LEN];
    let mut reference_bytes = vec![0; SCRATCH_SEED_LEN];
    candidate.read_ram(SCRATCH_BASE, &mut candidate_bytes)?;
    reference.read_ram(SCRATCH_BASE, &mut reference_bytes)?;
    Ok(candidate_bytes
        .iter()
        .zip(&reference_bytes)
        .enumerate()
        .filter(|(_, (candidate, reference))| candidate != reference)
        .map(|(offset, (&candidate, &reference))| FieldDiff {
            name: format!("memory[{:#x}]", SCRATCH_BASE + offset as u64),
            candidate: u64::from(candidate),
            reference: u64::from(reference),
        })
        .take(16)
        .collect())
}

fn verify_seeded_scratch<C: CosimTarget, R: CosimTarget>(
    candidate: &mut C,
    reference: &mut R,
    expected: &[u8],
) -> Result<(), TargetError> {
    let candidate_name = candidate.name();
    let reference_name = reference.name();
    let mut candidate_bytes = vec![0; expected.len()];
    let mut reference_bytes = vec![0; expected.len()];
    candidate.read_ram(SCRATCH_BASE, &mut candidate_bytes)?;
    reference.read_ram(SCRATCH_BASE, &mut reference_bytes)?;

    for (target, actual) in [
        (candidate_name, candidate_bytes.as_slice()),
        (reference_name, reference_bytes.as_slice()),
    ] {
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

    use rivemu_cpu_riscv::decode::Op;

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
        non_replayable: bool,
    }

    impl CosimTarget for MockTarget {
        fn name(&self) -> &'static str {
            "mock"
        }

        fn supports_replay(&self) -> bool {
            !self.non_replayable
        }

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
            let low = u16::from_le_bytes([
                self.ram.get(&self.state.pc).copied().unwrap_or(0),
                self.ram.get(&(self.state.pc + 1)).copied().unwrap_or(0),
            ]);
            self.state.pc += if low & 3 == 3 { 4 } else { 2 };
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
            RisuHarness::from_targets(MockTarget::default(), MockTarget::default(), false).unwrap();

        assert!(harness.run_seed(Suite::IntAlu, 1, 1).unwrap().is_none());
    }

    #[test]
    fn generated_cases_are_exactly_reproducible() {
        let first = RisuCase::generate(Suite::All, 0x1234, 32).unwrap();
        let second = RisuCase::generate(Suite::All, 0x1234, 32).unwrap();

        assert_eq!(first.suite(), second.suite());
        assert_eq!(first.seed(), second.seed());
        assert_eq!(first.init_state(), second.init_state());
        assert_eq!(first.code_bytes(), second.code_bytes());
        assert_eq!(first.scratch(), second.scratch());
        assert_eq!(first.end_pc(), second.end_pc());
        assert_eq!(first.max_steps(), second.max_steps());
    }

    #[test]
    fn compressed_case_has_exact_checkpoint_layout() {
        let case = RisuCase::generate(Suite::Compressed, 0x1234, 17).unwrap();

        assert!(case.uses_scratch());
        assert_eq!(case.code_bytes().len(), 17 * 2 + 4);
        assert_eq!(case.end_pc(), CODE_BASE + 17 * 2);
        assert_eq!(case.max_steps(), 17 * 16 + 64);
        assert_eq!(&case.code_bytes()[17 * 2..], &EBREAK.to_le_bytes());
        for bytes in case.code_bytes()[..17 * 2].chunks_exact(2) {
            let raw = u16::from_le_bytes(bytes.try_into().unwrap());
            let insn = decode::decode_compressed(raw);
            assert_eq!(insn.len, 2);
            assert_ne!(insn.op, Op::Illegal);
        }
    }

    #[test]
    fn fetch_and_decode_handles_16_and_32_bit_instructions() {
        let mut target = MockTarget::default();
        target
            .load_ram(CODE_BASE, &[0x05, 0x45, 0x73, 0x00, 0x10, 0x00])
            .unwrap();

        let compressed = fetch_and_decode(&mut target, CODE_BASE).unwrap();
        assert_eq!((compressed.raw, compressed.len), (0x4505, 2));
        assert_eq!(compressed.decoded.op, Op::Addi);
        assert_eq!(compressed.decoded.len, 2);

        let full = fetch_and_decode(&mut target, CODE_BASE + 2).unwrap();
        assert_eq!((full.raw, full.len), (EBREAK, 4));
        assert_eq!(full.decoded.op, Op::Ebreak);
        assert_eq!(full.decoded.len, 4);
    }

    #[test]
    fn block_mode_rejects_non_replayable_references() {
        let reference = MockTarget {
            non_replayable: true,
            ..MockTarget::default()
        };
        let mut harness =
            RisuHarness::from_targets(MockTarget::default(), reference, false).unwrap();

        let error = harness.run_seed(Suite::IntAlu, 1, 1).unwrap_err();
        assert!(error.to_string().contains("use step-check"));
    }

    #[test]
    fn non_replayable_reference_accepts_only_one_step_checked_case() {
        let reference = MockTarget {
            non_replayable: true,
            ..MockTarget::default()
        };
        let mut harness =
            RisuHarness::from_targets(MockTarget::default(), reference, false).unwrap();
        harness.set_step_check(true);

        assert!(harness.run_seed(Suite::IntAlu, 1, 1).unwrap().is_none());
        let error = harness.run_seed(Suite::IntAlu, 2, 1).unwrap_err();
        assert!(error.to_string().contains("fresh target processes"));
    }

    #[test]
    fn step_check_reports_a_transient_register_difference() {
        let qemu = MockTarget {
            diverge_on_step: Some(0),
            ..MockTarget::default()
        };
        let mut harness = RisuHarness::from_targets(MockTarget::default(), qemu, false).unwrap();
        harness.set_step_check(true);

        let report = harness
            .run_seed(Suite::IntAlu, 2, 1)
            .unwrap()
            .expect("the first instruction must diverge");
        assert_eq!(report.step_index, 0);
        assert_eq!(report.insn_len, 4);
        assert!(report.to_string().contains("(32-bit)"));
        assert!(report.diffs.iter().any(|diff| diff.name.starts_with("x1 ")));
    }

    #[test]
    fn compressed_divergence_report_preserves_raw_width_metadata() {
        let reference = MockTarget {
            diverge_on_step: Some(0),
            ..MockTarget::default()
        };
        let mut harness =
            RisuHarness::from_targets(MockTarget::default(), reference, false).unwrap();
        harness.set_step_check(true);

        let report = harness
            .run_seed(Suite::Compressed, 0x4321, 1)
            .unwrap()
            .expect("the first compressed instruction must diverge");
        assert_eq!(report.insn_len, 2);
        assert!(report.insn_word <= u32::from(u16::MAX));
        assert_ne!(report.insn_word & 3, 3);
        let rendered = report.to_string();
        assert!(rendered.contains("(16-bit)"));
        assert!(rendered.contains(&format!("{:#06x}", report.insn_word)));
    }

    #[test]
    fn run_seed_rejects_corrupt_initial_scratch_ram() {
        let qemu = MockTarget {
            corrupt_scratch: true,
            ..MockTarget::default()
        };
        let mut harness = RisuHarness::from_targets(MockTarget::default(), qemu, false).unwrap();

        let error = harness.run_seed(Suite::SandboxMem, 3, 1).unwrap_err();
        assert!(
            error
                .to_string()
                .contains("mock scratch differs before execution")
        );
    }

    #[test]
    fn step_check_propagates_instruction_fetch_errors() {
        let rivemu = MockTarget {
            fail_code_read: true,
            ..MockTarget::default()
        };
        let mut harness = RisuHarness::from_targets(rivemu, MockTarget::default(), false).unwrap();
        harness.set_step_check(true);

        let error = harness.run_seed(Suite::IntAlu, 4, 1).unwrap_err();
        assert!(error.to_string().contains("mock code read failure"));
    }
}
