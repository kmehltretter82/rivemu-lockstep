//! Directed and randomized RVA23 Control-Flow Integrity (`Zicfiss`, `Zicfilp`),
//! Pointer Masking (`Ssnpm`, `Smnpm`), and `Svukte` lockstep cases (`Suite::Cfi`).

use crate::ArchState;
use crate::risu::encode::{EBREAK, NOP, i_type, r_type, s_type, u_type};
use crate::risu::harness::{CODE_BASE, SCRATCH_BASE, SV39_TRAP_BASE, TRAP_BASE};
use crate::risu::seed::Rng;
use crate::risu::sv39::{
    ALT_PAGE_BASE, L0_PAGE_BASE, L1_PAGE_BASE, ROOT_PAGE_BASE, VM_SETUP_BASE, VM_SETUP_LEN,
};

const PAGE_SIZE: usize = 4096;
const PTE_V: u64 = 1 << 0;
const PTE_R: u64 = 1 << 1;
const PTE_W: u64 = 1 << 2;
const PTE_X: u64 = 1 << 3;
const PTE_U: u64 = 1 << 4;
const PTE_A: u64 = 1 << 6;
const PTE_D: u64 = 1 << 7;

const MSTATUS_MPP_MASK: u64 = 3 << 11;
const MSTATUS_MPP_SUPERVISOR: u64 = 1 << 11;
const MSTATUS_MPRV: u64 = 1 << 17;
const MSTATUS_SUM: u64 = 1 << 18;
const MSTATUS_MXR: u64 = 1 << 19;
const MSTATUS_SPELP: u64 = 1 << 23;
const MSTATUS_MPELP: u64 = 1 << 41;

const ENVCFG_LPE: u64 = 1 << 2;
const ENVCFG_SSE: u64 = 1 << 3;
const ENVCFG_UKTE: u64 = 1 << 8;
const ENVCFG_PMM_PMLEN_7: u64 = 2 << 32;
const ENVCFG_PMM_PMLEN_16: u64 = 3 << 32;
const ENVCFG_DTE: u64 = 1 << 59;
const ENVCFG_ADUE: u64 = 1 << 61;

const CSR_SSP: i32 = 0x011;
const CSR_SSTATUS: i32 = 0x100;
const CSR_SENVCFG: i32 = 0x10a;
const CSR_MENVCFG: i32 = 0x30a;
const CSR_TDATA1: i32 = 0x7a1;
const CSR_MCONTEXT: i32 = 0x7a8;

/// `Sdtrig` `mcontrol6` (`type = 6`) header (`0x6000_0000_0000_0000`).
const MCONTROL6_TYPE: u64 = 6u64 << 60;

const MRET: u32 = 0x3020_0073;
const SFENCE_VMA_ALL: u32 = 0x1200_0073;
const SSPUSH_X1: u32 = 0xce10_4073;
const SSPUSH_X5: u32 = 0xce50_4073;
const SSPOPCHK_X1: u32 = 0xcdc0_c073;
const SSPOPCHK_X5: u32 = 0xcdc2_c073;

const SATP_SV39: u64 = (8u64 << 60) | (ROOT_PAGE_BASE >> 12);

/// Virtual/physical base of the dedicated 4 KiB shadow-stack page (`R=0, W=1, X=0`).
pub const SS_PAGE_VA: u64 = ALT_PAGE_BASE;
/// Initial shadow-stack pointer in the middle of [`SS_PAGE_VA`].
pub const INITIAL_SSP: u64 = SS_PAGE_VA + 512;
/// Read-only virtual alias (`R=1, W=0, X=0`) mapped to [`SCRATCH_BASE`] for shadow-stack fault tests.
pub const RO_PAGE_VA: u64 = L0_PAGE_BASE + PAGE_SIZE as u64;
/// High negative Sv39 virtual alias (`vpn[2] = 0x1ff`) mapped to [`SCRATCH_BASE`] for `Svukte` tests.
pub const HIGH_UKTE_VA: u64 = 0xffff_ffc0_8001_0000;

/// Exceptions delegated to `SV39_TRAP_BASE` in `Suite::Cfi`:
/// `ILLEGAL_INSN` (2), `LOAD_ACCESS` (5), `STORE_ACCESS` (7),
/// `INSN_PAGE_FAULT` (12), `LOAD_PAGE_FAULT` (13), `STORE_PAGE_FAULT` (15), `SW_CHECK` (18).
const CFI_DELEGATION: u64 =
    (1 << 2) | (1 << 5) | (1 << 7) | (1 << 12) | (1 << 13) | (1 << 15) | (1 << 18);

const PROLOGUE_INSNS: u64 = 5;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Case {
    ZicfissPushPopSsrdp,
    ZicfissPopchkMismatchFault,
    ZicfissPagePermAndAmoswap,
    ZicfissDisabledMopNop,
    ZicfilpValidLandingPads,
    ZicfilpFaultAndSpelpRecovery,
    PointerMaskingPmlen7And16,
    SvukteUserKernelTableFault,
}

impl Case {
    const fn from_seed(seed: u64) -> Self {
        match seed & 7 {
            0 => Self::ZicfissPushPopSsrdp,
            1 => Self::ZicfissPopchkMismatchFault,
            2 => Self::ZicfissPagePermAndAmoswap,
            3 => Self::ZicfissDisabledMopNop,
            4 => Self::ZicfilpValidLandingPads,
            5 => Self::ZicfilpFaultAndSpelpRecovery,
            6 => Self::PointerMaskingPmlen7And16,
            _ => Self::SvukteUserKernelTableFault,
        }
    }

    const fn uses_user_mode(self, seed: u64) -> bool {
        match self {
            Self::SvukteUserKernelTableFault => true,
            Self::ZicfissPushPopSsrdp
            | Self::ZicfissPopchkMismatchFault
            | Self::ZicfilpValidLandingPads
            | Self::ZicfilpFaultAndSpelpRecovery
            | Self::PointerMaskingPmlen7And16 => (seed >> 3) & 1 != 0,
            Self::ZicfissPagePermAndAmoswap | Self::ZicfissDisabledMopNop => false,
        }
    }
}

const fn ssrdp(rd: u8) -> u32 {
    0xcdc0_4073 | ((rd as u32 & 0x1f) << 7)
}

const fn ssamoswap_w(rd: u8, rs2: u8, rs1: u8) -> u32 {
    r_type(0x2f, rd, 0b010, rs1, rs2, 0x09 << 2)
}

const fn ssamoswap_d(rd: u8, rs2: u8, rs1: u8) -> u32 {
    r_type(0x2f, rd, 0b011, rs1, rs2, 0x09 << 2)
}

const fn lpad(label20: u32) -> u32 {
    u_type(0x17, 0, label20)
}

/// Configures the initial architectural state and returns the Sv39 page-table setup image for `Suite::Cfi`.
pub fn configure_case(seed: u64, state: &mut ArchState) -> Vec<u8> {
    let case = Case::from_seed(seed);
    let user_mode = case.uses_user_mode(seed);

    state.prv = 3;
    state.pc = CODE_BASE;
    state.mepc = CODE_BASE + PROLOGUE_INSNS * 4;
    state.satp = SATP_SV39;
    state.stvec = SV39_TRAP_BASE;
    state.medeleg = CFI_DELEGATION;

    state.mstatus &= !(MSTATUS_MPP_MASK
        | MSTATUS_MPRV
        | MSTATUS_SUM
        | MSTATUS_MXR
        | MSTATUS_SPELP
        | MSTATUS_MPELP);
    state.sstatus &= !(MSTATUS_SUM | MSTATUS_MXR | MSTATUS_SPELP);
    if !user_mode {
        state.mstatus |= MSTATUS_MPP_SUPERVISOR;
    } else {
        state.mstatus |= MSTATUS_SUM;
        state.sstatus |= MSTATUS_SUM;
    }

    let pmm_bits = if (seed >> 4) & 1 != 0 {
        ENVCFG_PMM_PMLEN_16
    } else {
        ENVCFG_PMM_PMLEN_7
    };

    let (menvcfg, senvcfg) = match case {
        Case::ZicfissPushPopSsrdp
        | Case::ZicfissPopchkMismatchFault
        | Case::ZicfissPagePermAndAmoswap => (ENVCFG_ADUE | ENVCFG_SSE, ENVCFG_SSE),
        Case::ZicfissDisabledMopNop => (ENVCFG_ADUE | ENVCFG_DTE, 0),
        Case::ZicfilpValidLandingPads | Case::ZicfilpFaultAndSpelpRecovery => {
            state.mstatus |= MSTATUS_MPELP;
            (ENVCFG_ADUE | ENVCFG_LPE, ENVCFG_LPE)
        }
        Case::PointerMaskingPmlen7And16 => {
            (ENVCFG_ADUE | ENVCFG_SSE | pmm_bits, ENVCFG_SSE | pmm_bits)
        }
        Case::SvukteUserKernelTableFault => (ENVCFG_ADUE, ENVCFG_UKTE),
    };

    state.x[8] = SCRATCH_BASE;
    state.x[9] = SS_PAGE_VA + 256;
    state.x[20] = menvcfg;
    state.x[21] = senvcfg;
    state.x[22] = INITIAL_SSP;

    match case {
        Case::ZicfissPagePermAndAmoswap => {
            state.x[10] = RO_PAGE_VA;
        }
        Case::ZicfissDisabledMopNop => {
            state.x[21] = MCONTROL6_TYPE;
            state.x[22] = 0xffff_5a5a;
        }
        Case::PointerMaskingPmlen7And16 => {
            let tag_shift = if pmm_bits == ENVCFG_PMM_PMLEN_16 {
                48
            } else {
                57
            };
            let tag = 0x2au64 << tag_shift;
            state.x[10] = tag | SCRATCH_BASE;
            state.x[11] = tag | (SS_PAGE_VA + 256);
        }
        Case::SvukteUserKernelTableFault => {
            state.x[10] = HIGH_UKTE_VA;
        }
        _ => {}
    }

    build_setup_image(user_mode)
}

/// Generates a deterministic `Suite::Cfi` instruction block terminated by `EBREAK`.
pub fn generate_block(rng: &mut Rng, seed: u64, num_insns: usize) -> Vec<u32> {
    let case = Case::from_seed(seed);
    let mut out = Vec::with_capacity(num_insns + PROLOGUE_INSNS as usize + 8);

    // 5-instruction M-mode prologue:
    out.push(i_type(0x73, 0, 0b001, 20, CSR_MENVCFG)); // csrw menvcfg, x20
    if case == Case::ZicfissDisabledMopNop {
        out.push(i_type(0x73, 0, 0b001, 21, CSR_TDATA1)); // csrw tdata1, x21 (mcontrol6 type = 6)
        out.push(i_type(0x73, 0, 0b001, 22, CSR_MCONTEXT)); // csrw mcontext, x22 (0xffff_5a5a -> 0x1a5a)
        out.push(i_type(0x73, 19, 0b010, 0, CSR_MCONTEXT)); // csrr x19, mcontext (observe 13-bit WARL 0x1a5a)
    } else {
        out.push(i_type(0x73, 0, 0b001, 21, CSR_SENVCFG)); // csrw senvcfg, x21
        out.push(i_type(0x73, 0, 0b001, 22, CSR_SSP)); // csrw ssp, x22
        out.push(SFENCE_VMA_ALL);
    }
    out.push(MRET);

    if matches!(
        case,
        Case::ZicfilpValidLandingPads | Case::ZicfilpFaultAndSpelpRecovery
    ) {
        // Satisfy the initial MPELP -> ELP transition upon MRET.
        out.push(lpad(0));
    }

    while out.len() < num_insns + PROLOGUE_INSNS as usize {
        let _ = rng.next_u64();
        match case {
            Case::ZicfissPushPopSsrdp => {
                out.extend_from_slice(&[
                    i_type(0x13, 1, 0b000, 8, 0x111), // addi x1, x8, 0x111
                    i_type(0x13, 5, 0b000, 8, 0x222), // addi x5, x8, 0x222
                    SSPUSH_X1,                        // sspush x1
                    SSPUSH_X5,                        // sspush x5
                    ssrdp(12),                        // ssrdp x12
                    i_type(0x03, 13, 0b011, 12, 0),   // ld x13, 0(x12): read top of shadow stack
                    i_type(0x03, 14, 0b011, 12, 8),   // ld x14, 8(x12): read previous slot
                    SSPOPCHK_X5,                      // sspopchk x5
                    SSPOPCHK_X1,                      // sspopchk x1
                    ssrdp(15),                        // ssrdp x15 (back to INITIAL_SSP)
                ]);
            }
            Case::ZicfissPopchkMismatchFault => {
                out.extend_from_slice(&[
                    i_type(0x13, 1, 0b000, 8, 0x333), // addi x1, x8, 0x333
                    SSPUSH_X1,                        // sspush x1
                    i_type(0x13, 1, 0b000, 1, 1),     // addi x1, x1, 1 (corrupt link value)
                    SSPOPCHK_X1, // sspopchk x1 -> SW_CHECK (scause=18, stval=3)
                    i_type(0x13, 1, 0b000, 1, -1), // addi x1, x1, -1 (restore matching value)
                    SSPOPCHK_X1, // sspopchk x1 -> succeeds
                    ssrdp(12),   // ssrdp x12
                ]);
            }
            Case::ZicfissPagePermAndAmoswap => {
                out.extend_from_slice(&[
                    i_type(0x13, 12, 0b000, 0, 0x5a),  // li x12, 0x5a
                    s_type(0x23, 0b011, 9, 12, 0), // sd x12, 0(x9) on SS page -> STORE_ACCESS (7)
                    ssamoswap_d(13, 12, 9),        // ssamoswap.d x13, x12, (x9) on SS page -> ok
                    i_type(0x03, 14, 0b011, 9, 0), // ld x14, 0(x9) on SS page -> ok (0x5a)
                    i_type(0x13, 15, 0b000, 0, -0x25), // li x15, -0x25
                    ssamoswap_w(16, 15, 9),        // ssamoswap.w x16, x15, (x9) -> sign-ext old
                    ssamoswap_d(17, 12, 10), // ssamoswap.d on RO page (x10) -> STORE_PAGE_FAULT (15)
                ]);
            }
            Case::ZicfissDisabledMopNop => {
                out.extend_from_slice(&[
                    SSPUSH_X1,                                          // sspush x1 (NOP when SSE=0)
                    SSPOPCHK_X5,                    // sspopchk x5 (NOP when SSE=0)
                    ssrdp(12),                      // ssrdp x12 -> writes 0 when SSE=0
                    ssamoswap_d(13, 1, 9), // ssamoswap.d -> S-mode ILLEGAL_INSN (2) (sets SDT=1, SRET clears SDT=0)
                    u_type(0x37, 15, 0x01000), // lui x15, 0x1000 (0x0100_0000 = status::SDT)
                    i_type(0x13, 15, 0b110, 15, 2), // ori x15, x15, 2 (SDT | SIE)
                    r_type(0x73, 16, 0b010, 15, 0, CSR_SSTATUS as u32), // csrrs x16, sstatus, x15 (sets SDT=1, auto-clears SIE=0)
                    i_type(0x73, 17, 0b010, 0, CSR_SSTATUS), // csrr x17, sstatus (observe SDT=1, SIE=0)
                    i_type(0x73, 14, 0b010, 0, CSR_SSP), // csrr x14, ssp -> Ssdbltrp escalates to M-mode DOUBLE_TRAP (mcause=16)!
                    r_type(0x73, 18, 0b011, 15, 0, CSR_SSTATUS as u32), // csrrc x18, sstatus, x15 (observe SDT=1 after MRET to S-mode, clear SDT=0)
                ]);
            }
            Case::ZicfilpValidLandingPads => {
                // 1) Indirect jump via x16 (rs1 != x1, x5, x7) to matching lpad 0x55555:
                out.extend_from_slice(&[
                    u_type(0x37, 7, 0x55555),        // lui x7, 0x55555
                    u_type(0x17, 16, 0),             // auipc x16, 0
                    i_type(0x13, 16, 0b000, 16, 12), // addi x16, x16, 12
                    i_type(0x67, 0, 0b000, 16, 0),   // jalr x0, 0(x16) -> sets ELP = 1
                    lpad(0x55555),                   // lpad 0x55555 -> matches x7, clears ELP
                    // 2) Software-guarded return via x1 (rs1 = x1) does not set ELP:
                    u_type(0x17, 1, 0),             // auipc x1, 0
                    i_type(0x13, 1, 0b000, 1, 12),  // addi x1, x1, 12
                    i_type(0x67, 0, 0b000, 1, 0),   // jalr x0, 0(x1) -> ELP remains 0
                    i_type(0x13, 12, 0b000, 12, 7), // addi x12, x12, 7 (non-lpad target succeeds)
                ]);
            }
            Case::ZicfilpFaultAndSpelpRecovery => {
                // Indirect jump via x16 to mismatched lpad 0x77777 traps with SW_CHECK (scause=18, stval=2)
                // and saves SPELP=1; trap handler advances sepc by +4 and runs sret, restoring ELP=1
                // onto the universal `lpad 0` at sepc + 4.
                out.extend_from_slice(&[
                    u_type(0x37, 7, 0x55555),        // lui x7, 0x55555
                    u_type(0x17, 16, 0),             // auipc x16, 0
                    i_type(0x13, 16, 0b000, 16, 12), // addi x16, x16, 12
                    i_type(0x67, 0, 0b000, 16, 0),   // jalr x0, 0(x16) -> sets ELP = 1
                    lpad(0x77777),                   // lpad 0x77777 -> SW_CHECK (18, stval=2)
                    lpad(0),                         // lpad 0 -> satisfies restored SPELP -> ELP
                    // Indirect jump via x16 to non-lpad instruction (`nop`) also raises SW_CHECK:
                    u_type(0x17, 16, 0),             // auipc x16, 0
                    i_type(0x13, 16, 0b000, 16, 12), // addi x16, x16, 12
                    i_type(0x67, 0, 0b000, 16, 0),   // jalr x0, 0(x16) -> sets ELP = 1
                    NOP,                             // nop (not an lpad) -> SW_CHECK (18, stval=2)
                    lpad(0),                         // lpad 0 -> satisfies restored SPELP -> ELP
                ]);
            }
            Case::PointerMaskingPmlen7And16 => {
                out.extend_from_slice(&[
                    i_type(0x13, 12, 0b000, 0, 0x6b),  // li x12, 0x6b
                    s_type(0x23, 0b011, 10, 12, 0),    // sd x12, 0(x10) (masked -> SCRATCH_BASE)
                    i_type(0x03, 13, 0b011, 10, 0),    // ld x13, 0(x10) (masked -> SCRATCH_BASE)
                    i_type(0x03, 14, 0b011, 8, 0), // ld x14, 0(x8)  (untagged alias matches x13)
                    ssamoswap_d(15, 12, 11), // ssamoswap.d x15, x12, (x11) (masked -> SS_PAGE_VA+256)
                    i_type(0x03, 16, 0b011, 11, 0), // ld x16, 0(x11) (masked load from SS page)
                    i_type(0x13, 0, 0b110, 10, 0x000), // prefetch.i 0(x10)  (Zicbop)
                    i_type(0x13, 0, 0b110, 10, 0x021), // prefetch.r 32(x10) (Zicbop)
                    i_type(0x13, 0, 0b110, 10, 0x043), // prefetch.w 64(x10) (Zicbop)
                ]);
            }
            Case::SvukteUserKernelTableFault => {
                out.extend_from_slice(&[
                    i_type(0x13, 12, 0b000, 0, 0x4d), // li x12, 0x4d
                    s_type(0x23, 0b011, 8, 12, 0),    // sd x12, 0(x8)  (low U-mode VA succeeds)
                    i_type(0x03, 13, 0b011, 8, 0),    // ld x13, 0(x8)  (low U-mode VA succeeds)
                    i_type(0x03, 14, 0b011, 10, 0), // ld x14, 0(x10) (va[63]=1 -> LOAD_PAGE_FAULT 13)
                    s_type(0x23, 0b011, 10, 12, 0), // sd x12, 0(x10) (va[63]=1 -> STORE_PAGE_FAULT 15)
                ]);
            }
        }
    }

    out.push(EBREAK);
    out
}

fn build_setup_image(user_mode: bool) -> Vec<u8> {
    let mut image = vec![0u8; VM_SETUP_LEN];
    for (index, chunk) in image[..PAGE_SIZE].chunks_exact_mut(8).enumerate() {
        let val = 0xcf10_0000_0000_0000u64 | (index as u64);
        chunk.copy_from_slice(&val.to_le_bytes());
    }

    let u_bit = if user_mode { PTE_U } else { 0 };
    let code_flags = PTE_V | PTE_R | PTE_W | PTE_X | PTE_A | PTE_D | u_bit;
    let trap_flags = PTE_V | PTE_R | PTE_W | PTE_X | PTE_A | PTE_D;
    let data_flags = PTE_V | PTE_R | PTE_W | PTE_A | PTE_D | u_bit;
    let ro_flags = PTE_V | PTE_R | PTE_A | u_bit;
    // Zicfiss shadow-stack PTE encoding: V=1, R=0, W=1, X=0, A=1, D=1.
    let ss_flags = PTE_V | PTE_W | PTE_A | PTE_D | u_bit;

    // Root L2 entry for 0x8000_0000 (`vpn[2] = 2`) and high alias (`vpn[2] = 0x1ff`) -> L1_PAGE_BASE:
    write_pte(
        &mut image,
        ROOT_PAGE_BASE,
        vpn_index(CODE_BASE, 2),
        pointer_pte(L1_PAGE_BASE),
    );
    write_pte(
        &mut image,
        ROOT_PAGE_BASE,
        vpn_index(HIGH_UKTE_VA, 2),
        pointer_pte(L1_PAGE_BASE),
    );

    // L1 entry (`vpn[1] = 0`) -> L0_PAGE_BASE:
    write_pte(
        &mut image,
        L1_PAGE_BASE,
        vpn_index(CODE_BASE, 1),
        pointer_pte(L0_PAGE_BASE),
    );

    // L0 leaf entries:
    write_pte(
        &mut image,
        L0_PAGE_BASE,
        vpn_index(CODE_BASE, 0),
        leaf_pte(CODE_BASE, code_flags),
    );
    write_pte(
        &mut image,
        L0_PAGE_BASE,
        vpn_index(CODE_BASE + 0x1000, 0),
        leaf_pte(CODE_BASE + 0x1000, code_flags),
    );
    write_pte(
        &mut image,
        L0_PAGE_BASE,
        vpn_index(TRAP_BASE, 0),
        leaf_pte(TRAP_BASE, trap_flags),
    );
    write_pte(
        &mut image,
        L0_PAGE_BASE,
        vpn_index(SCRATCH_BASE, 0),
        leaf_pte(SCRATCH_BASE, data_flags),
    );
    write_pte(
        &mut image,
        L0_PAGE_BASE,
        vpn_index(SS_PAGE_VA, 0),
        leaf_pte(SS_PAGE_VA, ss_flags),
    );
    write_pte(
        &mut image,
        L0_PAGE_BASE,
        vpn_index(RO_PAGE_VA, 0),
        leaf_pte(SCRATCH_BASE, ro_flags),
    );
    for page_index in 1..4 {
        let pa = VM_SETUP_BASE + (page_index * PAGE_SIZE) as u64;
        write_pte(
            &mut image,
            L0_PAGE_BASE,
            vpn_index(pa, 0),
            leaf_pte(pa, data_flags),
        );
    }

    image
}

const fn vpn_index(va: u64, level: usize) -> usize {
    ((va >> (12 + level * 9)) & 0x1ff) as usize
}

const fn pointer_pte(next_table_pa: u64) -> u64 {
    ((next_table_pa >> 12) << 10) | PTE_V
}

const fn leaf_pte(page_pa: u64, flags: u64) -> u64 {
    ((page_pa >> 12) << 10) | flags
}

fn write_pte(image: &mut [u8], table_pa: u64, index: usize, pte: u64) {
    let offset = (table_pa - VM_SETUP_BASE) as usize + index * 8;
    image[offset..offset + 8].copy_from_slice(&pte.to_le_bytes());
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::CosimTarget;
    use crate::risu::encode::{build_supervisor_page_fault_handler, build_trap_handler};
    use crate::risu::{RisuCase, Suite};
    use crate::target::RivemuTarget;

    #[test]
    fn all_eight_cfi_cases_execute_to_checkpoint_on_rivemu() {
        let mut target = RivemuTarget::new_bare(true).unwrap();
        target.load_ram(TRAP_BASE, &build_trap_handler()).unwrap();
        target
            .load_ram(SV39_TRAP_BASE, &build_supervisor_page_fault_handler())
            .unwrap();
        target.set_trap_vector(TRAP_BASE).unwrap();

        for seed in 0..16 {
            let case = RisuCase::generate(Suite::Cfi, seed, 16).unwrap();
            target.load_ram(CODE_BASE, case.code_bytes()).unwrap();
            target.load_ram(SCRATCH_BASE, case.scratch()).unwrap();
            target.load_ram(VM_SETUP_BASE, case.vm_setup()).unwrap();
            target.set_state(case.init_state()).unwrap();
            target.set_trap_vector(TRAP_BASE).unwrap();

            let reason = target
                .run_until(case.end_pc(), case.max_steps() as u64)
                .unwrap();
            assert_eq!(
                reason,
                crate::StopReason::Breakpoint,
                "seed {seed:#x} did not reach checkpoint"
            );
        }
    }
}
