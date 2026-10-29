//! Deterministic floating-point instruction/state integration edge cases.

use crate::ArchState;
use crate::risu::encode::{i_type, r_type, r4_type};

pub(crate) const CASE_COUNT: usize = 30;

const F64_POS_ZERO: u8 = 0;
const F64_NEG_ZERO: u8 = 1;
const F64_TWO: u8 = 2;
const F64_THREE: u8 = 3;
const F64_FOUR: u8 = 4;
const F64_ONE_PLUS_ULP: u8 = 5;
const F64_ONE_PLUS_TWO_ULP: u8 = 6;
const F64_ONE: u8 = 7;
const F64_HALF_ULP_AT_ONE: u8 = 8;
const F64_MAX_FINITE: u8 = 12;
const F64_MIN_SUBNORMAL: u8 = 14;
const F64_HALF: u8 = 15;
const F64_NEG_ONE: u8 = 16;
const F32_POS_ZERO: u8 = 17;
const F32_NEG_ZERO: u8 = 18;
const F32_IMPROPER_SNAN: u8 = 19;
const F32_TWO31: u8 = 20;
const F32_ONE: u8 = 21;
const FD: u8 = 28;

const GPR_CLASS_RESULT: u8 = 9;
const GPR_COMPARE_RESULT: u8 = 10;
const GPR_MOVE_RESULT: u8 = 11;
const GPR_CONVERT_RESULT: u8 = 12;
const GPR_SENTINEL: u64 = 0x5a5a_a5a5_dead_beef;

const FCSR: i32 = 0x003;
const FFLAGS: i32 = 0x001;
const FRM: i32 = 0x002;

/// Replaces the random floating-point seed with operands shared by every case.
pub(crate) fn configure_initial_state(state: &mut ArchState) {
    for (offset, register) in [
        GPR_CLASS_RESULT,
        GPR_COMPARE_RESULT,
        GPR_MOVE_RESULT,
        GPR_CONVERT_RESULT,
    ]
    .into_iter()
    .enumerate()
    {
        state.x[usize::from(register)] = GPR_SENTINEL.rotate_left((offset * 11) as u32);
    }
    state.f = [0xffff_ffff_0000_0000; 32];
    state.f[F64_POS_ZERO as usize] = 0x0000_0000_0000_0000;
    state.f[F64_NEG_ZERO as usize] = 0x8000_0000_0000_0000;
    state.f[F64_TWO as usize] = 0x4000_0000_0000_0000;
    state.f[F64_THREE as usize] = 0x4008_0000_0000_0000;
    state.f[F64_FOUR as usize] = 0x4010_0000_0000_0000;
    state.f[F64_ONE_PLUS_ULP as usize] = 0x3ff0_0000_0000_0001;
    state.f[F64_ONE_PLUS_TWO_ULP as usize] = 0x3ff0_0000_0000_0002;
    state.f[F64_ONE as usize] = 0x3ff0_0000_0000_0000;
    state.f[F64_HALF_ULP_AT_ONE as usize] = 0x3ca0_0000_0000_0000;
    state.f[F64_MAX_FINITE as usize] = 0x7fef_ffff_ffff_ffff;
    state.f[F64_MIN_SUBNORMAL as usize] = 0x0000_0000_0000_0001;
    state.f[F64_HALF as usize] = 0x3fe0_0000_0000_0000;
    state.f[F64_NEG_ONE as usize] = 0xbff0_0000_0000_0000;
    state.f[F32_POS_ZERO as usize] = 0xffff_ffff_0000_0000;
    state.f[F32_NEG_ZERO as usize] = 0xffff_ffff_8000_0000;
    // The upper word deliberately violates NaN boxing.  Keeping bit 31 set in
    // the raw single-precision payload also checks FMV.X.W's XLEN sign extension.
    state.f[F32_IMPROPER_SNAN as usize] = 0x0000_0000_ff80_0001;
    state.f[F32_TWO31 as usize] = 0xffff_ffff_4f00_0000;
    state.f[F32_ONE as usize] = 0xffff_ffff_3f80_0000;
    state.f[FD as usize] = 0x5a5a_a5a5_dead_beef;
    state.fcsr = 0;
    // Make the suite independent of the random seed's FS state.
    state.mstatus |= 3 << 13;
}

#[inline]
fn csrwi(csr: i32, value: u8) -> u32 {
    i_type(0x73, 0, 0b101, value, csr)
}

#[inline]
fn clear_fcsr(out: &mut Vec<u32>) {
    out.push(csrwi(FCSR, 0));
}

#[inline]
fn set_frm_and_clear_flags(out: &mut Vec<u32>, frm: u8) {
    out.push(csrwi(FRM, frm));
    out.push(csrwi(FFLAGS, 0));
}

#[inline]
fn fp(funct7: u32, rd: u8, rm: u32, rs1: u8, rs2: u8) -> u32 {
    r_type(0x53, rd, rm, rs1, rs2, funct7)
}

#[inline]
fn fadd_d(rd: u8, rm: u32, rs1: u8, rs2: u8) -> u32 {
    fp(0x01, rd, rm, rs1, rs2)
}

#[inline]
fn fmul_d(rd: u8, rm: u32, rs1: u8, rs2: u8) -> u32 {
    fp(0x09, rd, rm, rs1, rs2)
}

#[inline]
fn fdiv_d(rd: u8, rm: u32, rs1: u8, rs2: u8) -> u32 {
    fp(0x0d, rd, rm, rs1, rs2)
}

/// Appends one complete case. Every case restores the relevant `fcsr` fields,
/// so cycling can begin at any selector without depending on a predecessor.
pub(crate) fn generate_case(selector: usize, out: &mut Vec<u32>) {
    debug_assert!(selector < CASE_COUNT);
    match selector {
        // Static rounding of the exact halfway sum 1.0 + 2^-53.
        0..=4 => {
            clear_fcsr(out);
            out.push(fadd_d(FD, selector as u32, F64_ONE, F64_HALF_ULP_AT_ONE));
        }
        // An improperly NaN-boxed single acts as canonical qNaN for arithmetic
        // consumers, while FMV.X.W transfers the raw low word.
        5 => {
            clear_fcsr(out);
            out.push(fp(0x70, GPR_CLASS_RESULT, 0b001, F32_IMPROPER_SNAN, 0)); // fclass.s
        }
        6 => {
            clear_fcsr(out);
            out.push(fp(
                0x50,
                GPR_COMPARE_RESULT,
                0b010,
                F32_IMPROPER_SNAN,
                F32_POS_ZERO,
            )); // feq.s
        }
        7 => {
            clear_fcsr(out);
            out.push(fp(0x14, FD, 0b000, F32_IMPROPER_SNAN, F32_ONE)); // fmin.s
        }
        8 => {
            clear_fcsr(out);
            out.push(fp(0x70, GPR_MOVE_RESULT, 0b000, F32_IMPROPER_SNAN, 0)); // fmv.x.w
        }
        // Signed-zero min/max is independent of operand order.
        9..=12 => {
            clear_fcsr(out);
            let offset = selector - 9;
            let max = offset >= 2;
            let reverse = offset & 1 != 0;
            let (a, b) = if reverse {
                (F32_NEG_ZERO, F32_POS_ZERO)
            } else {
                (F32_POS_ZERO, F32_NEG_ZERO)
            };
            out.push(fp(0x14, FD, u32::from(max), a, b));
        }
        // RV64 FCVT.WU sign-extends its 32-bit result to XLEN.
        13 => {
            clear_fcsr(out);
            out.push(fp(0x60, GPR_CONVERT_RESULT, 0, F32_TWO31, 1));
        }
        // All four fused multiply-add opcode sign mappings: 2 * 3 +/- 4.
        14..=17 => {
            clear_fcsr(out);
            let opcode = [0x43, 0x47, 0x4b, 0x4f][selector - 14];
            out.push(r4_type(opcode, FD, 0, F64_TWO, F64_THREE, F64_FOUR, 1));
        }
        // (1 + 2^-52)^2 - (1 + 2^-51) = 2^-104, requiring one fused rounding.
        18 => {
            clear_fcsr(out);
            out.push(r4_type(
                0x47,
                FD,
                0,
                F64_ONE_PLUS_ULP,
                F64_ONE_PLUS_ULP,
                F64_ONE_PLUS_TWO_ULP,
                1,
            ));
        }
        // Isolated IEEE exception flags.
        19 => {
            clear_fcsr(out);
            out.push(fdiv_d(FD, 0, F64_ONE, F64_POS_ZERO)); // DZ
        }
        20 => {
            clear_fcsr(out);
            out.push(fp(0x2d, FD, 0, F64_NEG_ONE, 0)); // sqrt(-1): NV
        }
        21 => {
            clear_fcsr(out);
            out.push(fmul_d(FD, 0, F64_MAX_FINITE, F64_TWO)); // OF | NX
        }
        22 => {
            clear_fcsr(out);
            out.push(fmul_d(FD, 0, F64_MIN_SUBNORMAL, F64_HALF)); // UF | NX
        }
        23 => {
            clear_fcsr(out);
            out.push(fdiv_d(FD, 0, F64_ONE, F64_POS_ZERO)); // DZ
            out.push(fp(0x2d, FD, 0, F64_NEG_ONE, 0)); // then accrue NV
        }
        // Dynamic rounding of the exact halfway sum 1.0 + 2^-53.
        24..=28 => {
            let frm = (selector - 24) as u8;
            set_frm_and_clear_flags(out, frm);
            out.push(fadd_d(FD, 7, F64_ONE, F64_HALF_ULP_AT_ONE));
        }
        // A computational single-precision consumer must replace an improperly
        // NaN-boxed operand with the canonical NaN before doing arithmetic.
        29 => {
            clear_fcsr(out);
            out.push(fp(0x00, FD, 0, F32_IMPROPER_SNAN, F32_ONE)); // fadd.s
        }
        _ => unreachable!("floating-point edge selector outside the case matrix"),
    }
}

#[cfg(test)]
mod tests {
    use rivemu_cpu_riscv::decode::{self, Op};

    use super::*;

    fn case_words(selector: usize) -> Vec<u32> {
        let mut words = Vec::new();
        generate_case(selector, &mut words);
        words
    }

    fn assert_csrwi(raw: u32, csr: i32, value: u32) {
        assert_eq!(raw & 0x7f, 0x73);
        assert_eq!((raw >> 7) & 0x1f, 0);
        assert_eq!((raw >> 12) & 7, 0b101);
        assert_eq!((raw >> 15) & 0x1f, value);
        assert_eq!((raw >> 20) & 0xfff, csr as u32);
    }

    #[test]
    fn initial_state_contains_exact_directed_operands() {
        let mut state = ArchState::default();
        state.x[8] = 0x8001_0000;
        state.x[27] = 0x2712_2712_2712_2712;
        configure_initial_state(&mut state);

        let expected_fprs = [
            (F64_POS_ZERO, 0x0000_0000_0000_0000),
            (F64_NEG_ZERO, 0x8000_0000_0000_0000),
            (F64_TWO, 0x4000_0000_0000_0000),
            (F64_THREE, 0x4008_0000_0000_0000),
            (F64_FOUR, 0x4010_0000_0000_0000),
            (F64_ONE_PLUS_ULP, 0x3ff0_0000_0000_0001),
            (F64_ONE_PLUS_TWO_ULP, 0x3ff0_0000_0000_0002),
            (F64_ONE, 0x3ff0_0000_0000_0000),
            (F64_HALF_ULP_AT_ONE, 0x3ca0_0000_0000_0000),
            (F64_MAX_FINITE, 0x7fef_ffff_ffff_ffff),
            (F64_MIN_SUBNORMAL, 0x0000_0000_0000_0001),
            (F64_HALF, 0x3fe0_0000_0000_0000),
            (F64_NEG_ONE, 0xbff0_0000_0000_0000),
            (F32_POS_ZERO, 0xffff_ffff_0000_0000),
            (F32_NEG_ZERO, 0xffff_ffff_8000_0000),
            (F32_IMPROPER_SNAN, 0x0000_0000_ff80_0001),
            (F32_TWO31, 0xffff_ffff_4f00_0000),
            (F32_ONE, 0xffff_ffff_3f80_0000),
            (FD, 0x5a5a_a5a5_dead_beef),
        ];
        for (register, expected) in expected_fprs {
            assert_eq!(state.f[register as usize], expected, "f{register}");
        }

        assert_eq!(state.x[usize::from(GPR_CLASS_RESULT)], GPR_SENTINEL);
        assert_eq!(
            state.x[usize::from(GPR_COMPARE_RESULT)],
            GPR_SENTINEL.rotate_left(11)
        );
        assert_eq!(
            state.x[usize::from(GPR_MOVE_RESULT)],
            GPR_SENTINEL.rotate_left(22)
        );
        assert_eq!(
            state.x[usize::from(GPR_CONVERT_RESULT)],
            GPR_SENTINEL.rotate_left(33)
        );
        assert_eq!(state.x[8], 0x8001_0000);
        assert_eq!(state.x[27], 0x2712_2712_2712_2712);
        assert_eq!(state.fcsr, 0);
        assert_ne!(state.mstatus & (3 << 13), 0);
    }

    #[test]
    fn every_case_is_legal_at_decode_and_preserves_reserved_gprs() {
        for selector in 0..CASE_COUNT {
            let mut words = Vec::new();
            generate_case(selector, &mut words);
            assert!(!words.is_empty(), "selector {selector}");
            for raw in words {
                let insn = decode::decode(raw);
                assert_ne!(insn.op, Op::Illegal, "selector {selector}, raw {raw:#x}");
                if matches!(insn.op, Op::Fclass | Op::Feq | Op::FmvXF | Op::FcvtIntF) {
                    assert!(!matches!(insn.rd, 8 | 27));
                }
            }
        }
    }

    #[test]
    fn static_rounding_matrix_has_clean_flags_and_sentinel_destination() {
        for (selector, rm) in (0..=4).zip(0..=4) {
            let words = case_words(selector);
            assert_eq!(words.len(), 2);
            assert_csrwi(words[0], FCSR, 0);
            assert_eq!((words[1] >> 7) & 0x1f, u32::from(FD));
            assert_eq!((words[1] >> 12) & 7, rm);
        }
    }

    #[test]
    fn boxing_signed_zero_and_word_conversion_matrix_is_complete() {
        for (selector, rd, funct7, funct3, rs1, rs2) in [
            (5, GPR_CLASS_RESULT, 0x70, 1, F32_IMPROPER_SNAN, 0),
            (
                6,
                GPR_COMPARE_RESULT,
                0x50,
                2,
                F32_IMPROPER_SNAN,
                F32_POS_ZERO,
            ),
            (7, FD, 0x14, 0, F32_IMPROPER_SNAN, F32_ONE),
            (8, GPR_MOVE_RESULT, 0x70, 0, F32_IMPROPER_SNAN, 0),
            (29, FD, 0x00, 0, F32_IMPROPER_SNAN, F32_ONE),
        ] {
            let words = case_words(selector);
            assert_csrwi(words[0], FCSR, 0);
            let raw = words[1];
            assert_eq!((raw >> 7) & 0x1f, u32::from(rd));
            assert_eq!((raw >> 12) & 7, funct3);
            assert_eq!((raw >> 15) & 0x1f, u32::from(rs1));
            assert_eq!((raw >> 20) & 0x1f, u32::from(rs2));
            assert_eq!(raw >> 25, funct7);
        }

        for (selector, funct3, rs1, rs2) in [
            (9, 0, F32_POS_ZERO, F32_NEG_ZERO),
            (10, 0, F32_NEG_ZERO, F32_POS_ZERO),
            (11, 1, F32_POS_ZERO, F32_NEG_ZERO),
            (12, 1, F32_NEG_ZERO, F32_POS_ZERO),
        ] {
            let raw = case_words(selector)[1];
            assert_eq!((raw >> 12) & 7, funct3);
            assert_eq!((raw >> 15) & 0x1f, u32::from(rs1));
            assert_eq!((raw >> 20) & 0x1f, u32::from(rs2));
            assert_eq!(raw >> 25, 0x14);
        }

        let convert = case_words(13);
        assert_csrwi(convert[0], FCSR, 0);
        assert_eq!((convert[1] >> 7) & 0x1f, u32::from(GPR_CONVERT_RESULT));
        assert_eq!((convert[1] >> 15) & 0x1f, u32::from(F32_TWO31));
        assert_eq!((convert[1] >> 20) & 0x1f, 1); // FCVT.WU.S
        assert_eq!(convert[1] >> 25, 0x60);
    }

    #[test]
    fn fused_opcode_and_exact_fused_case_matrix_is_complete() {
        for (selector, opcode) in (14..=17).zip([0x43, 0x47, 0x4b, 0x4f]) {
            let words = case_words(selector);
            assert_csrwi(words[0], FCSR, 0);
            let raw = words[1];
            assert_eq!(raw & 0x7f, opcode);
            assert_eq!((raw >> 7) & 0x1f, u32::from(FD));
            assert_eq!((raw >> 15) & 0x1f, u32::from(F64_TWO));
            assert_eq!((raw >> 20) & 0x1f, u32::from(F64_THREE));
            assert_eq!((raw >> 25) & 3, 1); // double precision
            assert_eq!((raw >> 27) & 0x1f, u32::from(F64_FOUR));
        }

        let fused = case_words(18);
        let raw = fused[1];
        assert_eq!(raw & 0x7f, 0x47); // FMSUB.D
        assert_eq!((raw >> 15) & 0x1f, u32::from(F64_ONE_PLUS_ULP));
        assert_eq!((raw >> 20) & 0x1f, u32::from(F64_ONE_PLUS_ULP));
        assert_eq!((raw >> 27) & 0x1f, u32::from(F64_ONE_PLUS_TWO_ULP));
    }

    #[test]
    fn exception_flag_and_dynamic_rounding_matrices_are_complete() {
        for (selector, funct7, rs1, rs2) in [
            (19, 0x0d, F64_ONE, F64_POS_ZERO),
            (20, 0x2d, F64_NEG_ONE, F64_POS_ZERO),
            (21, 0x09, F64_MAX_FINITE, F64_TWO),
            (22, 0x09, F64_MIN_SUBNORMAL, F64_HALF),
        ] {
            let words = case_words(selector);
            assert_eq!(words.len(), 2);
            assert_csrwi(words[0], FCSR, 0);
            assert_eq!(words[1] >> 25, funct7);
            assert_eq!((words[1] >> 15) & 0x1f, u32::from(rs1));
            assert_eq!((words[1] >> 20) & 0x1f, u32::from(rs2));
        }

        let sticky = case_words(23);
        assert_eq!(sticky.len(), 3);
        assert_csrwi(sticky[0], FCSR, 0);
        assert_eq!(sticky[1] >> 25, 0x0d); // DZ
        assert_eq!(sticky[2] >> 25, 0x2d); // accrue NV

        for selector in 24..=28 {
            let words = case_words(selector);
            assert_eq!(words.len(), 3);
            assert_csrwi(words[0], FRM, (selector - 24) as u32);
            assert_csrwi(words[1], FFLAGS, 0);
            assert_eq!((words[2] >> 12) & 7, 7);
            assert_eq!((words[2] >> 15) & 0x1f, u32::from(F64_ONE));
            assert_eq!((words[0] >> 15) & 0x1f, (selector - 24) as u32);
            assert_eq!((words[2] >> 20) & 0x1f, u32::from(F64_HALF_ULP_AT_ONE));
        }
    }
}
