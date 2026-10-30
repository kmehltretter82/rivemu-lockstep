//! Deterministic Sv39 page tables and translated load/store blocks.

use crate::ArchState;
use crate::risu::encode::{EBREAK, NOP, i_type, r_type, s_type};
use crate::risu::harness::{CODE_BASE, SCRATCH_BASE, SV39_TRAP_BASE};
use crate::risu::seed::Rng;

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

/// Physical base of an alternate data page reserved for TLB-remap tests.
pub const ALT_PAGE_BASE: u64 = SCRATCH_BASE + PAGE_SIZE as u64;
/// Physical base of the Sv39 root page table.
pub const ROOT_PAGE_BASE: u64 = ALT_PAGE_BASE + PAGE_SIZE as u64;
/// Physical base of the Sv39 level-1 page table.
pub const L1_PAGE_BASE: u64 = ROOT_PAGE_BASE + PAGE_SIZE as u64;
/// Physical base of the Sv39 level-0 page table.
pub const L0_PAGE_BASE: u64 = L1_PAGE_BASE + PAGE_SIZE as u64;
/// Physical base of the Sv48 level-3 root page table.
pub const L3_PAGE_BASE: u64 = L0_PAGE_BASE + PAGE_SIZE as u64;
/// Base of the contiguous alternate-page and page-table setup image.
pub const VM_SETUP_BASE: u64 = ALT_PAGE_BASE;
/// Length of the contiguous Sv39 setup image.
pub const VM_SETUP_LEN: usize = PAGE_SIZE * 4;
/// Length of the contiguous Sv48 setup image (adds the level-3 root page table).
pub const SV48_VM_SETUP_LEN: usize = PAGE_SIZE * 5;
/// Guest virtual alias used for permission probes over the physical scratch page.
pub const PROBE_VA: u64 = VM_SETUP_BASE + VM_SETUP_LEN as u64;
/// Executable virtual alias immediately above `PROBE_VA` used for fetch-fault recovery.
pub const EXEC_ALIAS_VA: u64 = PROBE_VA + PAGE_SIZE as u64;
#[cfg(test)]
pub(crate) const INSN_FAULT_VA: u64 = EXEC_ALIAS_VA - 4;
/// Base of the 2 MiB level-1 superpage window (`vpn[2] = 2, vpn[1] = 1`).
pub const SUPERPAGE_BASE_VA: u64 = CODE_BASE + 0x0020_0000;
/// Superpage virtual alias whose `vpn[0]` selects `SCRATCH_BASE` inside `CODE_BASE..+2 MiB`.
pub const SUPERPAGE_PROBE_VA: u64 = SUPERPAGE_BASE_VA + (SCRATCH_BASE - CODE_BASE);
/// Virtual alias mapped to a reserved `R=0, W=1` level-0 PTE.
pub const RESERVED_RW_VA: u64 = EXEC_ALIAS_VA + PAGE_SIZE as u64;
/// Virtual alias mapped through a level-1 non-leaf PTE with reserved `PTE_U = 1`.
pub const NONLEAF_ADU_VA: u64 = CODE_BASE + 0x0040_0000;
/// Non-canonical Sv39 virtual address (`va[38] = 1`, `va[63:39] = 0`).
pub const NONCANONICAL_SV39_VA: u64 = 1u64 << 38;
/// High positive Sv48 virtual base (`vpn[3] = 1`, `512 GiB`).
pub const SV48_HIGH_BASE: u64 = 1u64 << 39;
/// Non-canonical Sv48 virtual address (`va[47] = 1`, `va[63:48] = 0`).
pub const NONCANONICAL_SV48_VA: u64 = 1u64 << 47;

const SATP_SV39: u64 = (8u64 << 60) | (ROOT_PAGE_BASE >> 12);
pub(crate) const SATP_SV48: u64 = (9u64 << 60) | (L3_PAGE_BASE >> 12);
pub(crate) const REMAP_ASID: u64 = 1;
pub(crate) const SATP_SV39_REMAP_ASID: u64 = SATP_SV39 | (REMAP_ASID << 44);
pub(crate) const SATP_SV48_REMAP_ASID: u64 = SATP_SV48 | (REMAP_ASID << 44);
const PAGE_FAULT_DELEGATION: u64 = (1 << 12) | (1 << 13) | (1 << 15);
const REMAP_FLAGS: u64 = PTE_V | PTE_R | PTE_W | PTE_A | PTE_D;

pub(crate) const OLD_SENTINEL: u64 = 0x5a5a_0000_0000_0000;
pub(crate) const ALT_SENTINEL: u64 = 0xa5a5_0000_0000_0000;
pub(crate) const PROBE_PTE_ADDR: u64 = L0_PAGE_BASE + vpn_index(PROBE_VA, 0) as u64 * 8;
#[cfg(test)]
pub(crate) const INITIAL_PROBE_PTE: u64 = leaf_pte(SCRATCH_BASE, REMAP_FLAGS);
pub(crate) const REPLACEMENT_PTE: u64 = leaf_pte(ALT_PAGE_BASE, REMAP_FLAGS);
pub(crate) const VALID_SUPERPAGE_PTE: u64 = leaf_pte(CODE_BASE, REMAP_FLAGS);
pub(crate) const MISALIGNED_SUPERPAGE_PTE: u64 = leaf_pte(SCRATCH_BASE, REMAP_FLAGS);
pub(crate) const RESERVED_RW_PTE: u64 = leaf_pte(SCRATCH_BASE, PTE_V | PTE_W | PTE_A | PTE_D);
pub(crate) const NONLEAF_ADU_PTE: u64 = pointer_pte(L0_PAGE_BASE) | PTE_U;
pub(crate) const USER_EXEC_PROBE_PTE: u64 = leaf_pte(
    SCRATCH_BASE,
    PTE_V | PTE_R | PTE_W | PTE_X | PTE_U | PTE_A | PTE_D,
);
pub(crate) const RET_INSN: u32 = i_type(0x67, 0, 0, 1, 0);

const REMAP_INSN_LEN: usize = 8;
const INSN_PAGE_FAULT_SEQUENCE: [u32; 6] = [
    i_type(0x67, 1, 0, 9, -4),      // jalr x1, x9, -4: fault at INSN_FAULT_VA (PTE_X = 0)
    i_type(0x03, 0, 0b011, 13, 0),  // ld x0, 0(x13): prewarm PTE-page translation
    s_type(0x23, 0b011, 13, 14, 0), // sd x14, 0(x13): rewrite PROBE_VA to U+X leaf PTE
    r_type(0x73, 0, 0, 8, 0, 0x09), // sfence.vma x8, x0
    i_type(0x03, 10, 0b011, 8, 0),  // ld x10, 0(x8): S-mode SUM=1 data load succeeds on U page
    i_type(0x67, 1, 0, 9, -4),      // jalr x1, x9, -4: fault at INSN_FAULT_VA (U page in S-mode)
];

const fn sfence_remap_sequence(rs1: u8, rs2: u8) -> [u32; REMAP_INSN_LEN] {
    [
        0x0003_3503,                        // ld x10, 0(x6): read the alternate sentinel
        0x0002_b003,                        // ld x0, 0(x5): prewarm the PTE-page translation
        0x0004_3483,                        // ld x9, 0(x8): warm the probe translation
        0x0330_000f,                        // fence rw, rw
        0x0072_b023,                        // sd x7, 0(x5): replace the probe leaf PTE
        r_type(0x73, 0, 0, rs1, rs2, 0x09), // sfence.vma rs1, rs2
        0x0004_3583,                        // ld x11, 0(x8): observe the replacement mapping
        0x00b5_4633,                        // xor x12, x10, x11: zero equality witness
    ]
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Case {
    Supervisor,
    User,
    SupervisorUserSumOff,
    SupervisorUserSumOn,
    SupervisorExecuteOnlyMxrOff,
    SupervisorExecuteOnlyMxrOn,
    UserSupervisorPage,
    SupervisorReadOnlyStore,
    GlobalSfenceRemap,
    AddressSfenceRemap,
    AsidSfenceRemap,
    AddressAsidSfenceRemap,
    Superpage2Mib,
    MisalignedSuperpageFault,
    InstructionPageFault,
    MachineMprvSv39,
}

impl Case {
    const fn from_seed(seed: u64) -> Self {
        match seed & 0xf {
            0 => Self::Supervisor,
            1 => Self::User,
            2 => Self::SupervisorUserSumOff,
            3 => Self::SupervisorUserSumOn,
            4 => Self::SupervisorExecuteOnlyMxrOff,
            5 => Self::SupervisorExecuteOnlyMxrOn,
            6 => Self::UserSupervisorPage,
            7 => Self::SupervisorReadOnlyStore,
            8 => Self::GlobalSfenceRemap,
            9 => Self::AddressSfenceRemap,
            10 => Self::AsidSfenceRemap,
            11 => Self::AddressAsidSfenceRemap,
            12 => Self::Superpage2Mib,
            13 => Self::MisalignedSuperpageFault,
            14 => Self::InstructionPageFault,
            _ => Self::MachineMprvSv39,
        }
    }

    const fn sfence_operands(self) -> Option<(u8, u8)> {
        match self {
            Self::GlobalSfenceRemap => Some((0, 0)),
            Self::AddressSfenceRemap => Some((8, 0)),
            Self::AsidSfenceRemap => Some((0, 13)),
            Self::AddressAsidSfenceRemap => Some((8, 13)),
            _ => None,
        }
    }

    const fn is_sfence_remap(self) -> bool {
        self.sfence_operands().is_some()
    }

    const fn uses_remap_asid(self) -> bool {
        matches!(self, Self::AsidSfenceRemap | Self::AddressAsidSfenceRemap)
    }

    const fn uses_superpage_probe(self) -> bool {
        matches!(self, Self::Superpage2Mib | Self::MisalignedSuperpageFault)
    }

    const fn initial_privilege(self) -> u8 {
        match self {
            Self::User | Self::UserSupervisorPage => 0,
            Self::MachineMprvSv39 => 3,
            _ => 1,
        }
    }

    const fn starts_in_user(self) -> bool {
        matches!(self, Self::User | Self::UserSupervisorPage)
    }

    const fn loads_only(self) -> bool {
        matches!(
            self,
            Self::SupervisorExecuteOnlyMxrOff | Self::SupervisorExecuteOnlyMxrOn
        )
    }

    const fn stores_only(self) -> bool {
        matches!(self, Self::SupervisorReadOnlyStore)
    }
}

/// Configures the initial architectural state and returns its physical Sv39 image.
pub fn configure_case(seed: u64, state: &mut ArchState) -> Vec<u8> {
    let case = Case::from_seed(seed);
    state.prv = case.initial_privilege();
    state.satp = if case.uses_remap_asid() {
        SATP_SV39_REMAP_ASID
    } else {
        SATP_SV39
    };
    state.stvec = SV39_TRAP_BASE;
    state.medeleg = PAGE_FAULT_DELEGATION;
    state.x[8] = if case.uses_superpage_probe() {
        SUPERPAGE_PROBE_VA
    } else {
        PROBE_VA
    };
    state.mstatus &= !(MSTATUS_MPP_MASK | MSTATUS_MPRV | MSTATUS_SUM | MSTATUS_MXR);
    state.sstatus &= !(MSTATUS_SUM | MSTATUS_MXR);
    // The identity scratch mapping is used only for debugger observation. U
    // cases make it a U page; keep SUM set so the same mapping remains readable
    // while a fault has temporarily entered the S-mode recovery handler.
    if matches!(
        case,
        Case::SupervisorUserSumOn | Case::InstructionPageFault
    ) || case.starts_in_user()
    {
        state.mstatus |= MSTATUS_SUM;
        state.sstatus |= MSTATUS_SUM;
    }
    if case == Case::SupervisorExecuteOnlyMxrOn {
        state.mstatus |= MSTATUS_MXR;
        state.sstatus |= MSTATUS_MXR;
    }
    if case == Case::MachineMprvSv39 {
        state.mstatus |= MSTATUS_MPRV | MSTATUS_MPP_SUPERVISOR;
    }
    if case.is_sfence_remap() {
        state.x[5] = PROBE_PTE_ADDR;
        state.x[6] = ALT_PAGE_BASE;
        state.x[7] = REPLACEMENT_PTE;
        if case.uses_remap_asid() {
            state.x[13] = REMAP_ASID;
        }
    }
    if case == Case::MisalignedSuperpageFault {
        state.x[9] = RESERVED_RW_VA;
        state.x[10] = NONLEAF_ADU_VA;
        state.x[11] = NONCANONICAL_SV39_VA;
    }
    if case == Case::InstructionPageFault {
        state.x[9] = EXEC_ALIAS_VA;
        state.x[13] = PROBE_PTE_ADDR;
        state.x[14] = USER_EXEC_PROBE_PTE;
    }

    build_setup_image(case)
}

/// Configures the initial architectural state and returns its physical 4-level Sv48 image.
pub fn configure_sv48_case(seed: u64, state: &mut ArchState) -> Vec<u8> {
    let case = Case::from_seed(seed);
    let mut image = configure_case(seed, state);
    image.resize(SV48_VM_SETUP_LEN, 0);
    put_pte(
        &mut image,
        L3_PAGE_BASE,
        vpn_index(CODE_BASE, 3),
        pointer_pte(ROOT_PAGE_BASE),
    );
    put_pte(
        &mut image,
        L3_PAGE_BASE,
        vpn_index(SV48_HIGH_BASE, 3),
        pointer_pte(ROOT_PAGE_BASE),
    );
    state.satp = if case.uses_remap_asid() {
        SATP_SV48_REMAP_ASID
    } else {
        SATP_SV48
    };
    state.x[8] |= SV48_HIGH_BASE;
    if case == Case::MisalignedSuperpageFault {
        state.x[9] |= SV48_HIGH_BASE;
        state.x[10] |= SV48_HIGH_BASE;
        state.x[11] = NONCANONICAL_SV48_VA;
    }
    if case == Case::InstructionPageFault {
        state.x[9] |= SV48_HIGH_BASE;
    }
    image
}

/// Fixes the remap case's old-page sentinel so a stale translation is observable.
pub(crate) fn configure_scratch(seed: u64, scratch: &mut [u8]) {
    if Case::from_seed(seed).is_sfence_remap() {
        scratch[..8].copy_from_slice(&OLD_SENTINEL.to_le_bytes());
    }
}

/// Generates an exact-length translated-memory block followed by `EBREAK`.
pub fn generate_block(rng: &mut Rng, seed: u64, num_insns: usize) -> Vec<u32> {
    let case = Case::from_seed(seed);
    if let Some((rs1, rs2)) = case.sfence_operands() {
        let sequence = sfence_remap_sequence(rs1, rs2);
        let mut out = Vec::with_capacity(num_insns + 1);
        if num_insns >= sequence.len() {
            out.extend_from_slice(&sequence);
        }
        out.resize(num_insns, NOP);
        out.push(EBREAK);
        return out;
    }
    if case == Case::InstructionPageFault {
        let mut out = Vec::with_capacity(num_insns + 1);
        if num_insns >= INSN_PAGE_FAULT_SEQUENCE.len() {
            out.extend_from_slice(&INSN_PAGE_FAULT_SEQUENCE);
        }
        out.resize(num_insns, NOP);
        out.push(EBREAK);
        return out;
    }
    let mut out = Vec::with_capacity(num_insns + 1);
    while out.len() < num_insns {
        let slot = out.len();
        let offset = ((rng.next_u64() % 256) * 8) as i32;
        let base_reg = if case == Case::MisalignedSuperpageFault {
            8 + ((slot >> 2) & 3) as u8
        } else {
            8
        };
        let word = if case.loads_only() {
            let funct3 = if slot & 1 == 0 { 0b011 } else { 0b010 }; // LD / LW
            i_type(0x03, rng.pick_gpr(), funct3, base_reg, offset)
        } else if case.stores_only() {
            let funct3 = if slot & 1 == 0 { 0b011 } else { 0b010 }; // SD / SW
            s_type(0x23, funct3, base_reg, rng.pick_gpr(), offset)
        } else {
            match slot & 3 {
                0 => i_type(0x03, rng.pick_gpr(), 0b011, base_reg, offset), // LD
                1 => s_type(0x23, 0b011, base_reg, rng.pick_gpr(), offset), // SD
                2 => i_type(0x03, rng.pick_gpr(), 0b010, base_reg, offset), // LW
                _ => s_type(0x23, 0b010, base_reg, rng.pick_gpr(), offset), // SW
            }
        };
        out.push(word);
    }
    out.push(EBREAK);
    out
}

fn build_setup_image(case: Case) -> Vec<u8> {
    let mut image = vec![0u8; VM_SETUP_LEN];
    for (index, chunk) in image[..PAGE_SIZE].chunks_exact_mut(8).enumerate() {
        let sentinel = ALT_SENTINEL ^ index as u64;
        chunk.copy_from_slice(&sentinel.to_le_bytes());
    }
    if case == Case::InstructionPageFault {
        image[..4].copy_from_slice(&RET_INSN.to_le_bytes());
    }

    put_pte(
        &mut image,
        ROOT_PAGE_BASE,
        vpn_index(CODE_BASE, 2),
        pointer_pte(L1_PAGE_BASE),
    );
    put_pte(
        &mut image,
        L1_PAGE_BASE,
        vpn_index(CODE_BASE, 1),
        pointer_pte(L0_PAGE_BASE),
    );
    if case == Case::Superpage2Mib {
        put_pte(
            &mut image,
            L1_PAGE_BASE,
            vpn_index(SUPERPAGE_PROBE_VA, 1),
            VALID_SUPERPAGE_PTE,
        );
    } else if case == Case::MisalignedSuperpageFault {
        put_pte(
            &mut image,
            L1_PAGE_BASE,
            vpn_index(SUPERPAGE_PROBE_VA, 1),
            MISALIGNED_SUPERPAGE_PTE,
        );
        put_pte(
            &mut image,
            L1_PAGE_BASE,
            vpn_index(NONLEAF_ADU_VA, 1),
            NONLEAF_ADU_PTE,
        );
        put_pte(
            &mut image,
            L0_PAGE_BASE,
            vpn_index(RESERVED_RW_VA, 0),
            RESERVED_RW_PTE,
        );
    }

    let mut code_flags = if case == Case::MachineMprvSv39 {
        // Leave CODE_BASE non-executable in the page table so M-mode with
        // MPRV=1 must fetch untranslated while translating data accesses.
        PTE_V | PTE_R | PTE_A | PTE_D
    } else {
        PTE_V | PTE_R | PTE_X | PTE_A | PTE_D
    };
    if case.starts_in_user() {
        code_flags |= PTE_U;
    }
    let scratch_flags = match case {
        Case::User | Case::SupervisorUserSumOff | Case::SupervisorUserSumOn => {
            PTE_V | PTE_R | PTE_W | PTE_U | PTE_A | PTE_D
        }
        Case::SupervisorExecuteOnlyMxrOff | Case::SupervisorExecuteOnlyMxrOn => {
            PTE_V | PTE_X | PTE_A | PTE_D
        }
        Case::SupervisorReadOnlyStore => PTE_V | PTE_R | PTE_A | PTE_D,
        Case::GlobalSfenceRemap
        | Case::AddressSfenceRemap
        | Case::AsidSfenceRemap
        | Case::AddressAsidSfenceRemap => REMAP_FLAGS,
        _ => PTE_V | PTE_R | PTE_W | PTE_A | PTE_D,
    };

    for address in [CODE_BASE, CODE_BASE + PAGE_SIZE as u64] {
        put_leaf(&mut image, address, code_flags);
    }
    put_leaf(
        &mut image,
        CODE_BASE + 2 * PAGE_SIZE as u64,
        PTE_V | PTE_R | PTE_X | PTE_A | PTE_D,
    );
    put_leaf(
        &mut image,
        CODE_BASE + 3 * PAGE_SIZE as u64,
        PTE_V | PTE_R | PTE_X | PTE_A | PTE_D,
    );
    let identity_scratch_flags =
        PTE_V | PTE_R | PTE_W | PTE_A | PTE_D | if case.starts_in_user() { PTE_U } else { 0 };
    put_leaf(&mut image, SCRATCH_BASE, identity_scratch_flags);
    put_mapping(&mut image, PROBE_VA, SCRATCH_BASE, scratch_flags);
    if case == Case::InstructionPageFault {
        put_mapping(
            &mut image,
            EXEC_ALIAS_VA,
            ALT_PAGE_BASE,
            PTE_V | PTE_R | PTE_X | PTE_A | PTE_D,
        );
    }
    for address in [ALT_PAGE_BASE, ROOT_PAGE_BASE, L1_PAGE_BASE, L0_PAGE_BASE] {
        put_leaf(&mut image, address, PTE_V | PTE_R | PTE_W | PTE_A | PTE_D);
    }
    image
}

const fn vpn_index(address: u64, level: u32) -> usize {
    ((address >> (12 + 9 * level)) & 0x1ff) as usize
}

const fn pointer_pte(next_table: u64) -> u64 {
    ((next_table >> 12) << 10) | PTE_V
}

const fn leaf_pte(address: u64, flags: u64) -> u64 {
    ((address >> 12) << 10) | flags
}

fn put_leaf(image: &mut [u8], address: u64, flags: u64) {
    put_mapping(image, address, address, flags);
}

fn put_mapping(image: &mut [u8], virtual_address: u64, physical_address: u64, flags: u64) {
    put_pte(
        image,
        L0_PAGE_BASE,
        vpn_index(virtual_address, 0),
        leaf_pte(physical_address, flags),
    );
}

fn put_pte(image: &mut [u8], table: u64, index: usize, value: u64) {
    let offset = (table - VM_SETUP_BASE) as usize + index * 8;
    image[offset..offset + 8].copy_from_slice(&value.to_le_bytes());
}

#[cfg(test)]
mod tests {
    use rivemu_cpu_riscv::decode::{self, Op};

    use super::*;

    fn read_pte(image: &[u8], table: u64, address: u64, level: u32) -> u64 {
        let offset = (table - VM_SETUP_BASE) as usize + vpn_index(address, level) * 8;
        u64::from_le_bytes(image[offset..offset + 8].try_into().unwrap())
    }

    #[test]
    fn setup_image_has_exact_three_level_identity_mappings() {
        let mut state = ArchState::default();
        let image = configure_case(0, &mut state);

        assert_eq!(image.len(), VM_SETUP_LEN);
        assert_eq!(VM_SETUP_BASE + VM_SETUP_LEN as u64, PROBE_VA);
        assert_eq!(VM_SETUP_BASE, SCRATCH_BASE + PAGE_SIZE as u64);
        assert_eq!(state.satp, SATP_SV39);
        assert_eq!(
            read_pte(&image, ROOT_PAGE_BASE, CODE_BASE, 2),
            pointer_pte(L1_PAGE_BASE)
        );
        assert_eq!(
            read_pte(&image, L1_PAGE_BASE, CODE_BASE, 1),
            pointer_pte(L0_PAGE_BASE)
        );
        for address in [
            CODE_BASE,
            CODE_BASE + PAGE_SIZE as u64,
            CODE_BASE + 2 * PAGE_SIZE as u64,
            CODE_BASE + 3 * PAGE_SIZE as u64,
            SCRATCH_BASE,
            ALT_PAGE_BASE,
            ROOT_PAGE_BASE,
            L1_PAGE_BASE,
            L0_PAGE_BASE,
        ] {
            let pte = read_pte(&image, L0_PAGE_BASE, address, 0);
            assert_eq!(((pte >> 10) << 12) & !0xfff, address);
            assert_eq!(pte & (PTE_V | PTE_A | PTE_D), PTE_V | PTE_A | PTE_D);
        }
        let probe = read_pte(&image, L0_PAGE_BASE, PROBE_VA, 0);
        assert_eq!(((probe >> 10) << 12) & !0xfff, SCRATCH_BASE);
    }

    #[test]
    fn eight_seeds_cover_privilege_sum_mxr_and_fetch_permissions() {
        for seed in 0..8 {
            let mut state = ArchState::default();
            let image = configure_case(seed, &mut state);
            let code = read_pte(&image, L0_PAGE_BASE, CODE_BASE, 0);
            let scratch = read_pte(&image, L0_PAGE_BASE, PROBE_VA, 0);

            assert_eq!(state.prv, if matches!(seed, 1 | 6) { 0 } else { 1 });
            assert_eq!(state.stvec, SV39_TRAP_BASE);
            assert_eq!(state.medeleg, PAGE_FAULT_DELEGATION);
            assert_eq!(state.mstatus & MSTATUS_SUM != 0, matches!(seed, 1 | 3 | 6));
            assert_eq!(state.sstatus & MSTATUS_SUM != 0, matches!(seed, 1 | 3 | 6));
            assert_eq!(state.mstatus & MSTATUS_MXR != 0, seed == 5);
            assert_eq!(state.sstatus & MSTATUS_MXR != 0, seed == 5);
            assert_eq!(code & PTE_U != 0, matches!(seed, 1 | 6));
            assert_ne!(code & PTE_X, 0);
            assert_eq!(scratch & PTE_U != 0, matches!(seed, 1..=3));
            assert_eq!(
                scratch & PTE_R == 0 && scratch & PTE_X != 0,
                matches!(seed, 4 | 5)
            );
            assert_eq!(scratch & PTE_W == 0 && scratch & PTE_R != 0, seed == 7);
        }
    }

    #[test]
    fn sfence_remap_cases_have_exact_remap_state_asid_and_sentinels() {
        for (seed, expected_satp, uses_asid) in [
            (0x5008, SATP_SV39, false),
            (0x5009, SATP_SV39, false),
            (0x500a, SATP_SV39_REMAP_ASID, true),
            (0x500b, SATP_SV39_REMAP_ASID, true),
        ] {
            let mut state = ArchState::default();
            let image = configure_case(seed, &mut state);

            assert_eq!(PROBE_PTE_ADDR, 0x8001_40a8);
            assert_eq!(INITIAL_PROBE_PTE, 0x2000_40c7);
            assert_eq!(REPLACEMENT_PTE, 0x2000_44c7);
            assert_eq!(state.prv, 1);
            assert_eq!(state.satp, expected_satp);
            assert_eq!(state.x[5], PROBE_PTE_ADDR);
            assert_eq!(state.x[6], ALT_PAGE_BASE);
            assert_eq!(state.x[7], REPLACEMENT_PTE);
            assert_eq!(state.x[8], PROBE_VA);
            assert_eq!(state.x[13], if uses_asid { REMAP_ASID } else { 0 });
            assert_eq!(
                read_pte(&image, L0_PAGE_BASE, PROBE_VA, 0),
                INITIAL_PROBE_PTE
            );
            assert_eq!(
                u64::from_le_bytes(image[..8].try_into().unwrap()),
                ALT_SENTINEL
            );

            let mut scratch = vec![0xff; 16];
            configure_scratch(seed, &mut scratch);
            assert_eq!(
                u64::from_le_bytes(scratch[..8].try_into().unwrap()),
                OLD_SENTINEL
            );
            assert_eq!(&scratch[8..], &[0xff; 8]);
        }
    }

    #[test]
    fn sfence_remap_blocks_are_exact_and_never_emit_a_partial_remap() {
        for (seed, rs1, rs2, expected_sfence) in [
            (0x5008, 0, 0, 0x1200_0073),
            (0x5009, 8, 0, 0x1204_0073),
            (0x500a, 0, 13, 0x12d0_0073),
            (0x500b, 8, 13, 0x12d4_0073),
        ] {
            let expected = sfence_remap_sequence(rs1, rs2);
            assert_eq!(expected[5], expected_sfence);
            let decoded = decode::decode(expected[5]);
            assert_eq!(decoded.op, Op::SfenceVma);
            assert_eq!(decoded.rs1, rs1);
            assert_eq!(decoded.rs2, rs2);

            let mut rng = Rng::new(seed);
            let exact = generate_block(&mut rng, seed, REMAP_INSN_LEN);
            assert_eq!(&exact[..REMAP_INSN_LEN], &expected);
            assert_eq!(exact.last(), Some(&EBREAK));

            let padded = generate_block(&mut rng, seed, REMAP_INSN_LEN + 4);
            assert_eq!(&padded[..REMAP_INSN_LEN], &expected);
            assert!(
                padded[REMAP_INSN_LEN..padded.len() - 1]
                    .iter()
                    .all(|&word| word == NOP)
            );
            assert_eq!(padded.last(), Some(&EBREAK));

            let short = generate_block(&mut rng, seed, REMAP_INSN_LEN - 1);
            assert!(short[..short.len() - 1].iter().all(|&word| word == NOP));
            assert_eq!(short.last(), Some(&EBREAK));
        }
    }

    #[test]
    fn superpage_and_mprv_cases_configure_level1_leaves_and_machine_translation() {
        let mut superpage_state = ArchState::default();
        let superpage_image = configure_case(0x500c, &mut superpage_state);
        assert_eq!(superpage_state.prv, 1);
        assert_eq!(superpage_state.x[8], SUPERPAGE_PROBE_VA);
        assert_eq!(
            read_pte(&superpage_image, L1_PAGE_BASE, SUPERPAGE_PROBE_VA, 1),
            VALID_SUPERPAGE_PTE
        );

        let mut misaligned_state = ArchState::default();
        let misaligned_image = configure_case(0x500d, &mut misaligned_state);
        assert_eq!(misaligned_state.prv, 1);
        assert_eq!(misaligned_state.x[8], SUPERPAGE_PROBE_VA);
        assert_eq!(misaligned_state.x[9], RESERVED_RW_VA);
        assert_eq!(misaligned_state.x[10], NONLEAF_ADU_VA);
        assert_eq!(misaligned_state.x[11], NONCANONICAL_SV39_VA);
        assert_eq!(
            read_pte(&misaligned_image, L1_PAGE_BASE, SUPERPAGE_PROBE_VA, 1),
            MISALIGNED_SUPERPAGE_PTE
        );
        assert_eq!(
            read_pte(&misaligned_image, L1_PAGE_BASE, NONLEAF_ADU_VA, 1),
            NONLEAF_ADU_PTE
        );
        assert_eq!(
            read_pte(&misaligned_image, L0_PAGE_BASE, RESERVED_RW_VA, 0),
            RESERVED_RW_PTE
        );
        assert_ne!((MISALIGNED_SUPERPAGE_PTE >> 10) & 0x1ff, 0);

        let mut mprv_state = ArchState::default();
        let mprv_image = configure_case(0x500f, &mut mprv_state);
        assert_eq!(mprv_state.prv, 3);
        assert_eq!(mprv_state.x[8], PROBE_VA);
        assert_ne!(mprv_state.mstatus & MSTATUS_MPRV, 0);
        assert_eq!(mprv_state.mstatus & MSTATUS_MPP_MASK, MSTATUS_MPP_SUPERVISOR);
        assert_eq!(read_pte(&mprv_image, L0_PAGE_BASE, CODE_BASE, 0) & PTE_X, 0);
    }

    #[test]
    fn instruction_page_fault_case_installs_executable_alias_and_exact_sequence() {
        let mut state = ArchState::default();
        let image = configure_case(0x500e, &mut state);

        assert_eq!(state.prv, 1);
        assert_ne!(state.mstatus & MSTATUS_SUM, 0);
        assert_ne!(state.sstatus & MSTATUS_SUM, 0);
        assert_eq!(state.x[8], PROBE_VA);
        assert_eq!(state.x[9], EXEC_ALIAS_VA);
        assert_eq!(state.x[13], PROBE_PTE_ADDR);
        assert_eq!(state.x[14], USER_EXEC_PROBE_PTE);
        assert_eq!(
            u32::from_le_bytes(image[..4].try_into().unwrap()),
            RET_INSN
        );
        assert_eq!(
            read_pte(&image, L0_PAGE_BASE, PROBE_VA, 0),
            INITIAL_PROBE_PTE
        );
        assert_eq!(
            read_pte(&image, L0_PAGE_BASE, EXEC_ALIAS_VA, 0),
            leaf_pte(ALT_PAGE_BASE, PTE_V | PTE_R | PTE_X | PTE_A | PTE_D)
        );

        let mut rng = Rng::new(0x500e);
        let exact = generate_block(&mut rng, 0x500e, INSN_PAGE_FAULT_SEQUENCE.len());
        assert_eq!(
            &exact[..INSN_PAGE_FAULT_SEQUENCE.len()],
            &INSN_PAGE_FAULT_SEQUENCE
        );
        assert_eq!(exact.last(), Some(&EBREAK));

        let short = generate_block(&mut rng, 0x500e, INSN_PAGE_FAULT_SEQUENCE.len() - 1);
        assert!(short[..short.len() - 1].iter().all(|&word| word == NOP));
        assert_eq!(short.last(), Some(&EBREAK));
    }

    #[test]
    fn generated_blocks_use_only_expected_32_bit_operations() {
        for seed in 0..8 {
            let mut rng = Rng::new(seed);
            let words = generate_block(&mut rng, seed, 32);
            assert_eq!(words.len(), 33);
            assert_eq!(*words.last().unwrap(), EBREAK);
            for &word in &words[..32] {
                let insn = decode::decode(word);
                assert_eq!(insn.len, 4);
                let expected = if matches!(seed, 4 | 5) {
                    matches!(insn.op, Op::Ld | Op::Lw)
                } else if seed == 7 {
                    matches!(insn.op, Op::Sd | Op::Sw)
                } else {
                    matches!(insn.op, Op::Ld | Op::Sd | Op::Lw | Op::Sw)
                };
                assert!(expected, "seed {seed} generated {:?}", insn.op);
            }
        }
    }

    #[test]
    fn sv48_setup_image_installs_level3_root_and_high_virtual_aliases() {
        let mut state = ArchState::default();
        let image = configure_sv48_case(0x6000, &mut state);
        assert_eq!(image.len(), SV48_VM_SETUP_LEN);
        assert_eq!(state.satp, SATP_SV48);
        assert_eq!(state.x[8], SV48_HIGH_BASE | PROBE_VA);
        assert_eq!(
            read_pte(&image, L3_PAGE_BASE, CODE_BASE, 3),
            pointer_pte(ROOT_PAGE_BASE)
        );
        assert_eq!(
            read_pte(&image, L3_PAGE_BASE, SV48_HIGH_BASE, 3),
            pointer_pte(ROOT_PAGE_BASE)
        );

        let mut misaligned = ArchState::default();
        let _ = configure_sv48_case(0x600d, &mut misaligned);
        assert_eq!(misaligned.x[8], SV48_HIGH_BASE | SUPERPAGE_PROBE_VA);
        assert_eq!(misaligned.x[9], SV48_HIGH_BASE | RESERVED_RW_VA);
        assert_eq!(misaligned.x[10], SV48_HIGH_BASE | NONLEAF_ADU_VA);
        assert_eq!(misaligned.x[11], NONCANONICAL_SV48_VA);
    }
}
