//! Directed and randomized Physical Memory Protection (`PMP`) lockstep cases (`Suite::Pmp`).

use crate::ArchState;
use crate::risu::encode::{EBREAK, i_type, s_type};
use crate::risu::harness::{CODE_BASE, SCRATCH_BASE};
use crate::risu::seed::Rng;

const CSR_MSTATUS: i32 = 0x300;
const CSR_MENVCFG: i32 = 0x30a;
const CSR_MEPC: i32 = 0x341;
const CSR_PMPCFG0: i32 = 0x3a0;
const CSR_PMPADDR0: i32 = 0x3b0;
const CSR_PMPADDR1: i32 = 0x3b1;
const CSR_PMPADDR2: i32 = 0x3b2;
const CSR_PMPADDR3: i32 = 0x3b3;
const CSR_MSECCFG: i32 = 0x747;

const MRET: u32 = 0x3020_0073;
const SFENCE_VMA_ALL: u32 = 0x1200_0073;

const MSTATUS_MPP_MASK: u64 = 3 << 11;
const MSTATUS_MPP_S: u64 = 1 << 11;
const MSTATUS_MPRV: u64 = 1 << 17;

const PMP_R: u64 = 1 << 0;
const PMP_W: u64 = 1 << 1;
const PMP_X: u64 = 1 << 2;
const PMP_TOR: u64 = 1 << 3;
const PMP_NA4: u64 = 2 << 3;
const PMP_NAPOT: u64 = 3 << 3;

const CATCH_ALL_PMPADDR: u64 = 0x003f_ffff_ffff_ffff;
const CATCH_ALL_PMPCFG: u64 = PMP_NAPOT | PMP_R | PMP_W | PMP_X;

const PROLOGUE_INSNS: u64 = 8;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Case {
    NapotReadOnly,
    Na4AndBoundaryStraddle,
    TorAndBoundaryStraddle,
    LowestEntryPrecedence,
    UnmatchedDefaultDeny,
    ZicboPmpPermissions,
    MprvSupervisorVsMachine,
    EmptyTorRange,
}

impl Case {
    const fn from_seed(seed: u64) -> Self {
        match seed & 7 {
            0 => Self::NapotReadOnly,
            1 => Self::Na4AndBoundaryStraddle,
            2 => Self::TorAndBoundaryStraddle,
            3 => Self::LowestEntryPrecedence,
            4 => Self::UnmatchedDefaultDeny,
            5 => Self::ZicboPmpPermissions,
            6 => Self::MprvSupervisorVsMachine,
            _ => Self::EmptyTorRange,
        }
    }
}

const fn napot_addr(base: u64, size: u64) -> u64 {
    debug_assert!(size >= 8 && size.is_power_of_two());
    (base >> 2) | ((size >> 3) - 1)
}

const fn pack_pmpcfg0(c0: u64, c1: u64, c2: u64, c3: u64) -> u64 {
    (c0 & 0xff) | ((c1 & 0xff) << 8) | ((c2 & 0xff) << 16) | ((c3 & 0xff) << 24)
}

/// Seeds initial M-mode state and PMP CSR values in `x20..x25` for a `Suite::Pmp` block.
pub fn configure_case(seed: u64, state: &mut ArchState) {
    let case = Case::from_seed(seed);
    let use_user_mode = (seed >> 3) & 1 != 0 && case != Case::ZicboPmpPermissions;

    state.prv = 3;
    state.pc = CODE_BASE;
    state.mepc = CODE_BASE + PROLOGUE_INSNS * 4;
    state.x[8] = SCRATCH_BASE;
    state.x[9] = SCRATCH_BASE + 64;
    state.x[10] = SCRATCH_BASE + 128;
    state.x[11] = SCRATCH_BASE + 256;
    state.x[25] = 0xd0; // menvcfg: CBZE | CBCFE | CBIE=01

    state.mstatus &= !(MSTATUS_MPP_MASK | MSTATUS_MPRV);
    if case == Case::MprvSupervisorVsMachine {
        state.mstatus |= MSTATUS_MPP_S | MSTATUS_MPRV;
        state.x[11] = (0x2au64 << 57) | (SCRATCH_BASE + 256);
        state.x[26] = 2u64 << 32; // mseccfg.PMM = PMLEN_7 (Smmpm)
    } else if !use_user_mode {
        state.mstatus |= MSTATUS_MPP_S;
    }

    let (addr0, addr1, addr2, addr3, cfg0) = match case {
        Case::NapotReadOnly => (
            napot_addr(SCRATCH_BASE, 64),
            0,
            0,
            CATCH_ALL_PMPADDR,
            pack_pmpcfg0(PMP_NAPOT | PMP_R, 0, 0, CATCH_ALL_PMPCFG),
        ),
        Case::Na4AndBoundaryStraddle => (
            (SCRATCH_BASE + 16) >> 2,
            (SCRATCH_BASE + 32) >> 2,
            0,
            CATCH_ALL_PMPADDR,
            pack_pmpcfg0(
                PMP_NA4,
                PMP_NA4 | PMP_R | PMP_W,
                0,
                CATCH_ALL_PMPCFG,
            ),
        ),
        Case::TorAndBoundaryStraddle => (
            (SCRATCH_BASE + 64) >> 2,
            (SCRATCH_BASE + 124) >> 2,
            0,
            CATCH_ALL_PMPADDR,
            pack_pmpcfg0(0, PMP_TOR | PMP_R, 0, CATCH_ALL_PMPCFG),
        ),
        Case::LowestEntryPrecedence => (
            napot_addr(SCRATCH_BASE, 64),
            napot_addr(SCRATCH_BASE, 256),
            napot_addr(SCRATCH_BASE, 1024),
            CATCH_ALL_PMPADDR,
            pack_pmpcfg0(
                PMP_NAPOT,
                PMP_NAPOT | PMP_R,
                PMP_NAPOT | PMP_R | PMP_W,
                CATCH_ALL_PMPCFG,
            ),
        ),
        Case::UnmatchedDefaultDeny => (
            // Cover CODE_BASE (0x8000_0000) and TRAP_BASE (0x8000_2000) with a 64 KiB
            // NAPOT region [0x8000_0000, 0x8001_0000), leaving SCRATCH_BASE unmatched.
            napot_addr(CODE_BASE, 65536),
            0,
            0,
            0,
            pack_pmpcfg0(PMP_NAPOT | PMP_R | PMP_W | PMP_X, 0, 0, 0),
        ),
        Case::ZicboPmpPermissions => (
            napot_addr(SCRATCH_BASE, 64),
            napot_addr(SCRATCH_BASE + 64, 64),
            napot_addr(SCRATCH_BASE + 128, 64),
            CATCH_ALL_PMPADDR,
            pack_pmpcfg0(
                PMP_NAPOT,
                PMP_NAPOT | PMP_R,
                PMP_NAPOT | PMP_R | PMP_W,
                CATCH_ALL_PMPCFG,
            ),
        ),
        Case::MprvSupervisorVsMachine => (
            napot_addr(SCRATCH_BASE, 64),
            0,
            0,
            CATCH_ALL_PMPADDR,
            pack_pmpcfg0(PMP_NAPOT | PMP_R, 0, 0, CATCH_ALL_PMPCFG),
        ),
        Case::EmptyTorRange => (
            (SCRATCH_BASE + 128) >> 2,
            (SCRATCH_BASE + 64) >> 2,
            napot_addr(SCRATCH_BASE, 64),
            CATCH_ALL_PMPADDR,
            pack_pmpcfg0(0, PMP_TOR, PMP_NAPOT | PMP_R, CATCH_ALL_PMPCFG),
        ),
    };

    state.x[20] = addr0;
    state.x[21] = addr1;
    state.x[22] = addr2;
    state.x[23] = addr3;
    state.x[24] = cfg0;
}

/// Generates a deterministic `Suite::Pmp` instruction block terminated by `EBREAK`.
pub fn generate_block(rng: &mut Rng, seed: u64, num_insns: usize) -> Vec<u32> {
    let case = Case::from_seed(seed);
    let mut out = Vec::with_capacity(num_insns + PROLOGUE_INSNS as usize + 1);

    // 8-instruction M-mode setup prologue:
    out.push(i_type(0x73, 0, 0b001, 20, CSR_PMPADDR0)); // csrw pmpaddr0, x20
    out.push(i_type(0x73, 0, 0b001, 21, CSR_PMPADDR1)); // csrw pmpaddr1, x21
    out.push(i_type(0x73, 0, 0b001, 22, CSR_PMPADDR2)); // csrw pmpaddr2, x22
    out.push(i_type(0x73, 0, 0b001, 23, CSR_PMPADDR3)); // csrw pmpaddr3, x23
    out.push(i_type(0x73, 0, 0b001, 24, CSR_PMPCFG0));  // csrw pmpcfg0, x24
    out.push(i_type(0x73, 0, 0b001, 25, CSR_MENVCFG));  // csrw menvcfg, x25
    out.push(SFENCE_VMA_ALL);
    if case == Case::MprvSupervisorVsMachine {
        out.push(i_type(0x73, 0, 0b001, 26, CSR_MSECCFG)); // csrw mseccfg, x26 (enable Smmpm in M-mode)
    } else {
        out.push(MRET); // drop to S-mode or U-mode at CODE_BASE + 32
    }

    for slot in 0..num_insns {
        let rd = 12 + (slot % 6) as u8;
        let rs2 = 5 + (slot % 3) as u8;
        let insn = match case {
            Case::NapotReadOnly => match slot % 4 {
                0 => i_type(0x03, rd, 0b011, 8, ((slot * 8) & 0x38) as i32), // ld in RO [0..64) -> ok
                1 => s_type(0x23, 0b011, 8, rs2, ((slot * 8) & 0x38) as i32), // sd in RO [0..64) -> mcause=7
                2 => s_type(0x23, 0b011, 8, rs2, 64 + ((slot * 8) & 0x38) as i32), // sd in RW [64..128) -> ok
                _ => i_type(0x03, rd, 0b011, 8, 64 + ((slot * 8) & 0x38) as i32), // ld in RW [64..128) -> ok
            },
            Case::Na4AndBoundaryStraddle => match slot % 6 {
                0 => i_type(0x03, rd, 0b010, 8, 16), // lw at NA4 no-access [16..20) -> mcause=5
                1 => s_type(0x23, 0b010, 8, rs2, 16), // sw at NA4 no-access [16..20) -> mcause=7
                2 => s_type(0x23, 0b010, 8, rs2, 32), // sw at NA4 RW [32..36) -> ok
                3 => i_type(0x03, rd, 0b010, 8, 32), // lw at NA4 RW [32..36) -> ok
                4 => i_type(0x03, rd, 0b011, 8, 32), // 8B ld at [32..40) straddling NA4 upper bound -> mcause=5
                _ => s_type(0x23, 0b011, 8, rs2, 32), // 8B sd at [32..40) straddling NA4 upper bound -> mcause=7
            },
            Case::TorAndBoundaryStraddle => match slot % 6 {
                0 => s_type(0x23, 0b011, 8, rs2, 56), // 8B sd below TOR [56..64) -> ok
                1 => i_type(0x03, rd, 0b011, 8, 64),  // 8B ld inside TOR RO [64..72) -> ok
                2 => s_type(0x23, 0b011, 8, rs2, 64), // 8B sd inside TOR RO [64..72) -> mcause=7
                3 => i_type(0x03, rd, 0b011, 8, 120), // 8B ld at [120..128) straddling TOR top 124 -> mcause=5
                4 => s_type(0x23, 0b011, 8, rs2, 120), // 8B sd at [120..128) straddling TOR top 124 -> mcause=7
                _ => s_type(0x23, 0b011, 8, rs2, 128), // 8B sd above TOR [128..136) -> ok
            },
            Case::LowestEntryPrecedence => match slot % 6 {
                0 => i_type(0x03, rd, 0b011, 8, 0),   // pmp0 (no-access): ld -> mcause=5
                1 => s_type(0x23, 0b011, 8, rs2, 8),  // pmp0 (no-access): sd -> mcause=7
                2 => i_type(0x03, rd, 0b011, 8, 64),  // pmp1 (RO): ld -> ok
                3 => s_type(0x23, 0b011, 8, rs2, 72), // pmp1 (RO): sd -> mcause=7
                4 => s_type(0x23, 0b011, 8, rs2, 256), // pmp2 (RW): sd -> ok
                _ => i_type(0x03, rd, 0b011, 8, 256), // pmp2 (RW): ld -> ok
            },
            Case::UnmatchedDefaultDeny => {
                let off = ((rng.next_u64() as i32) & 0x1f8).max(0);
                if slot & 1 == 0 {
                    i_type(0x03, rd, 0b011, 8, off) // unmatched S/U load -> mcause=5
                } else {
                    s_type(0x23, 0b011, 8, rs2, off) // unmatched S/U store -> mcause=7
                }
            }
            Case::ZicboPmpPermissions => match slot % 7 {
                0 => i_type(0x0f, 0, 0b010, 8, 4),  // cbo.zero 0(s0) on no-access pmp0 -> mcause=7
                1 => i_type(0x0f, 0, 0b010, 8, 1),  // cbo.clean 0(s0) on no-access pmp0 -> mcause=7
                2 => i_type(0x0f, 0, 0b010, 9, 1),  // cbo.clean 0(s1) on RO pmp1 -> ok
                3 => i_type(0x0f, 0, 0b010, 9, 2),  // cbo.flush 0(s1) on RO pmp1 -> ok
                4 => i_type(0x0f, 0, 0b010, 9, 4),  // cbo.zero 0(s1) on RO pmp1 -> mcause=7
                5 => i_type(0x0f, 0, 0b010, 10, 4), // cbo.zero 0(s2) on RW pmp2 -> ok
                _ => i_type(0x03, rd, 0b011, 10, 0), // ld from zeroed RW pmp2 -> 0
            },
            Case::MprvSupervisorVsMachine => match slot % 4 {
                0 => i_type(0x03, rd, 0b011, 8, 0),  // ld in RO pmp0 -> ok
                1 => s_type(0x23, 0b011, 8, rs2, 0), // 1st time: MPRV=1,MPP=S faults (mcause=7) & trap handler sets MPP=M; later times: MPP=M succeeds!
                2 => i_type(0x03, rd, 0b011, 8, 0),  // ld in pmp0 -> observes store when MPP=M
                _ => i_type(0x03, rd, 0b011, 11, 0), // ld via tagged x11 (Smmpm PMLEN=7 in M-mode -> SCRATCH_BASE+256)
            },
            Case::EmptyTorRange => match slot % 4 {
                0 => s_type(0x23, 0b011, 8, rs2, 64), // [64..128) is NOT matched by empty TOR pmp1 -> succeeds via pmp3!
                1 => i_type(0x03, rd, 0b011, 8, 64),  // ld at 64 -> succeeds via pmp3!
                2 => i_type(0x03, rd, 0b011, 8, 0),   // ld at 0 -> succeeds via RO pmp2
                _ => s_type(0x23, 0b011, 8, rs2, 0),  // sd at 0 -> faults via RO pmp2 (mcause=7)
            },
        };
        let _ = (CSR_MSTATUS, CSR_MEPC);
        out.push(insn);
    }

    out.push(EBREAK);
    out
}

#[cfg(test)]
mod tests {
    use crate::risu::encode::build_trap_handler;
    use crate::risu::harness::{RisuCase, TRAP_BASE};
    use crate::risu::suite::Suite;
    use crate::target::RivemuTarget;
    use crate::{CosimTarget, StopReason};

    use super::*;

    #[test]
    fn all_pmp_subcases_execute_to_checkpoint_on_rivemu() {
        let mut target = RivemuTarget::new_bare(false).unwrap();
        target.load_ram(TRAP_BASE, &build_trap_handler()).unwrap();

        for seed in 0x7000..0x7010 {
            let case = RisuCase::generate(Suite::Pmp, seed, 12).unwrap();
            target.load_ram(CODE_BASE, case.code_bytes()).unwrap();
            target.load_ram(SCRATCH_BASE, case.scratch()).unwrap();
            target.set_state(case.init_state()).unwrap();
            target.set_trap_vector(TRAP_BASE).unwrap();

            let reason = target
                .run_until(case.end_pc(), case.max_steps() as u64)
                .unwrap();
            assert_eq!(reason, StopReason::Breakpoint, "seed={seed:#x}");
            let end_state = target.get_state().unwrap();
            assert_eq!(end_state.pc, case.end_pc(), "seed={seed:#x}");
        }
    }
}

