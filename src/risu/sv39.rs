//! Deterministic Sv39 page tables and translated load/store blocks.

use crate::ArchState;
use crate::risu::encode::{EBREAK, NOP, i_type, s_type};
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
/// Base of the contiguous alternate-page and page-table setup image.
pub const VM_SETUP_BASE: u64 = ALT_PAGE_BASE;
/// Length of the contiguous Sv39 setup image.
pub const VM_SETUP_LEN: usize = PAGE_SIZE * 4;
/// Guest virtual alias used for permission probes over the physical scratch page.
pub const PROBE_VA: u64 = VM_SETUP_BASE + VM_SETUP_LEN as u64;

const SATP_SV39: u64 = (8u64 << 60) | (ROOT_PAGE_BASE >> 12);
const PAGE_FAULT_DELEGATION: u64 = (1 << 12) | (1 << 13) | (1 << 15);
const REMAP_FLAGS: u64 = PTE_V | PTE_R | PTE_W | PTE_A | PTE_D;

pub(crate) const OLD_SENTINEL: u64 = 0x5a5a_0000_0000_0000;
pub(crate) const ALT_SENTINEL: u64 = 0xa5a5_0000_0000_0000;
pub(crate) const PROBE_PTE_ADDR: u64 = L0_PAGE_BASE + vpn_index(PROBE_VA, 0) as u64 * 8;
#[cfg(test)]
pub(crate) const INITIAL_PROBE_PTE: u64 = leaf_pte(SCRATCH_BASE, REMAP_FLAGS);
pub(crate) const REPLACEMENT_PTE: u64 = leaf_pte(ALT_PAGE_BASE, REMAP_FLAGS);

const GLOBAL_SFENCE_REMAP: [u32; 8] = [
    0x0003_3503, // ld x10, 0(x6): read the alternate sentinel
    0x0002_b003, // ld x0, 0(x5): prewarm the PTE-page translation
    0x0004_3483, // ld x9, 0(x8): warm the probe translation
    0x0330_000f, // fence rw, rw
    0x0072_b023, // sd x7, 0(x5): replace the probe leaf PTE
    0x1200_0073, // sfence.vma x0, x0
    0x0004_3583, // ld x11, 0(x8): observe the replacement mapping
    0x00b5_4633, // xor x12, x10, x11: zero equality witness
];

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
}

impl Case {
    const fn from_seed(seed: u64) -> Self {
        if seed & 0xf == 8 {
            return Self::GlobalSfenceRemap;
        }
        match seed & 7 {
            0 => Self::Supervisor,
            1 => Self::User,
            2 => Self::SupervisorUserSumOff,
            3 => Self::SupervisorUserSumOn,
            4 => Self::SupervisorExecuteOnlyMxrOff,
            5 => Self::SupervisorExecuteOnlyMxrOn,
            6 => Self::UserSupervisorPage,
            _ => Self::SupervisorReadOnlyStore,
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
    state.prv = if case.starts_in_user() { 0 } else { 1 };
    state.satp = SATP_SV39;
    state.stvec = SV39_TRAP_BASE;
    state.medeleg = PAGE_FAULT_DELEGATION;
    state.x[8] = PROBE_VA;
    state.mstatus &= !(MSTATUS_SUM | MSTATUS_MXR);
    state.sstatus &= !(MSTATUS_SUM | MSTATUS_MXR);
    // The identity scratch mapping is used only for debugger observation. U
    // cases make it a U page; keep SUM set so the same mapping remains readable
    // while a fault has temporarily entered the S-mode recovery handler.
    if case == Case::SupervisorUserSumOn || case.starts_in_user() {
        state.mstatus |= MSTATUS_SUM;
        state.sstatus |= MSTATUS_SUM;
    }
    if case == Case::SupervisorExecuteOnlyMxrOn {
        state.mstatus |= MSTATUS_MXR;
        state.sstatus |= MSTATUS_MXR;
    }
    if case == Case::GlobalSfenceRemap {
        state.x[5] = PROBE_PTE_ADDR;
        state.x[6] = ALT_PAGE_BASE;
        state.x[7] = REPLACEMENT_PTE;
    }

    build_setup_image(case)
}

/// Fixes the remap case's old-page sentinel so a stale translation is observable.
pub(crate) fn configure_scratch(seed: u64, scratch: &mut [u8]) {
    if Case::from_seed(seed) == Case::GlobalSfenceRemap {
        scratch[..8].copy_from_slice(&OLD_SENTINEL.to_le_bytes());
    }
}

/// Generates an exact-length translated-memory block followed by `EBREAK`.
pub fn generate_block(rng: &mut Rng, seed: u64, num_insns: usize) -> Vec<u32> {
    let case = Case::from_seed(seed);
    if case == Case::GlobalSfenceRemap {
        let mut out = Vec::with_capacity(num_insns + 1);
        if num_insns >= GLOBAL_SFENCE_REMAP.len() {
            out.extend_from_slice(&GLOBAL_SFENCE_REMAP);
        }
        out.resize(num_insns, NOP);
        out.push(EBREAK);
        return out;
    }
    let mut out = Vec::with_capacity(num_insns + 1);
    while out.len() < num_insns {
        let slot = out.len();
        let offset = ((rng.next_u64() % 256) * 8) as i32;
        let word = if case.loads_only() {
            let funct3 = if slot & 1 == 0 { 0b011 } else { 0b010 }; // LD / LW
            i_type(0x03, rng.pick_gpr(), funct3, 8, offset)
        } else if case.stores_only() {
            let funct3 = if slot & 1 == 0 { 0b011 } else { 0b010 }; // SD / SW
            s_type(0x23, funct3, 8, rng.pick_gpr(), offset)
        } else {
            match slot & 3 {
                0 => i_type(0x03, rng.pick_gpr(), 0b011, 8, offset), // LD
                1 => s_type(0x23, 0b011, 8, rng.pick_gpr(), offset), // SD
                2 => i_type(0x03, rng.pick_gpr(), 0b010, 8, offset), // LW
                _ => s_type(0x23, 0b010, 8, rng.pick_gpr(), offset), // SW
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

    let mut code_flags = PTE_V | PTE_R | PTE_X | PTE_A | PTE_D;
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
        Case::GlobalSfenceRemap => REMAP_FLAGS,
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
            assert_eq!(scratch & PTE_U != 0, matches!(seed, 1 | 2 | 3));
            assert_eq!(
                scratch & PTE_R == 0 && scratch & PTE_X != 0,
                matches!(seed, 4 | 5)
            );
            assert_eq!(scratch & PTE_W == 0 && scratch & PTE_R != 0, seed == 7);
        }
    }

    #[test]
    fn global_sfence_case_has_exact_remap_state_and_sentinels() {
        let mut state = ArchState::default();
        let image = configure_case(0x5008, &mut state);

        assert_eq!(PROBE_PTE_ADDR, 0x8001_40a8);
        assert_eq!(INITIAL_PROBE_PTE, 0x2000_40c7);
        assert_eq!(REPLACEMENT_PTE, 0x2000_44c7);
        assert_eq!(state.prv, 1);
        assert_eq!(state.x[5], PROBE_PTE_ADDR);
        assert_eq!(state.x[6], ALT_PAGE_BASE);
        assert_eq!(state.x[7], REPLACEMENT_PTE);
        assert_eq!(state.x[8], PROBE_VA);
        assert_eq!(
            read_pte(&image, L0_PAGE_BASE, PROBE_VA, 0),
            INITIAL_PROBE_PTE
        );
        assert_eq!(
            u64::from_le_bytes(image[..8].try_into().unwrap()),
            ALT_SENTINEL
        );

        let mut scratch = vec![0xff; 16];
        configure_scratch(0x5008, &mut scratch);
        assert_eq!(
            u64::from_le_bytes(scratch[..8].try_into().unwrap()),
            OLD_SENTINEL
        );
        assert_eq!(&scratch[8..], &[0xff; 8]);
    }

    #[test]
    fn global_sfence_block_is_exact_and_never_emits_a_partial_remap() {
        let mut rng = Rng::new(0x5008);
        let exact = generate_block(&mut rng, 0x5008, GLOBAL_SFENCE_REMAP.len());
        assert_eq!(&exact[..GLOBAL_SFENCE_REMAP.len()], &GLOBAL_SFENCE_REMAP);
        assert_eq!(exact.last(), Some(&EBREAK));

        let padded = generate_block(&mut rng, 0x5008, GLOBAL_SFENCE_REMAP.len() + 4);
        assert_eq!(&padded[..GLOBAL_SFENCE_REMAP.len()], &GLOBAL_SFENCE_REMAP);
        assert!(
            padded[GLOBAL_SFENCE_REMAP.len()..padded.len() - 1]
                .iter()
                .all(|&word| word == NOP)
        );
        assert_eq!(padded.last(), Some(&EBREAK));

        let short = generate_block(&mut rng, 0x5008, GLOBAL_SFENCE_REMAP.len() - 1);
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
}
