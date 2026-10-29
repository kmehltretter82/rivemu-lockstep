//! RISC-V 32-bit and 16-bit instruction encoders for `RISU` block generation.

/// Encodes a standard R-type instruction (`opcode`, `rd`, `funct3`, `rs1`, `rs2`, `funct7`).
#[inline]
pub const fn r_type(opcode: u32, rd: u8, funct3: u32, rs1: u8, rs2: u8, funct7: u32) -> u32 {
    (opcode & 0x7f)
        | ((rd as u32 & 0x1f) << 7)
        | ((funct3 & 0x7) << 12)
        | ((rs1 as u32 & 0x1f) << 15)
        | ((rs2 as u32 & 0x1f) << 20)
        | ((funct7 & 0x7f) << 25)
}

/// Encodes a floating-point R4-type instruction (`fmadd`, `fmsub`, `fnmsub`, `fnmadd`).
#[inline]
pub const fn r4_type(opcode: u32, rd: u8, rm: u32, rs1: u8, rs2: u8, rs3: u8, fmt: u32) -> u32 {
    (opcode & 0x7f)
        | ((rd as u32 & 0x1f) << 7)
        | ((rm & 0x7) << 12)
        | ((rs1 as u32 & 0x1f) << 15)
        | ((rs2 as u32 & 0x1f) << 20)
        | ((fmt & 0x3) << 25)
        | ((rs3 as u32 & 0x1f) << 27)
}

/// Encodes a standard I-type instruction (`opcode`, `rd`, `funct3`, `rs1`, `imm12`).
#[inline]
pub const fn i_type(opcode: u32, rd: u8, funct3: u32, rs1: u8, imm12: i32) -> u32 {
    (opcode & 0x7f)
        | ((rd as u32 & 0x1f) << 7)
        | ((funct3 & 0x7) << 12)
        | ((rs1 as u32 & 0x1f) << 15)
        | (((imm12 as u32) & 0xfff) << 20)
}

/// Encodes a standard S-type instruction (`opcode`, `funct3`, `rs1`, `rs2`, `imm12`).
#[inline]
pub const fn s_type(opcode: u32, funct3: u32, rs1: u8, rs2: u8, imm12: i32) -> u32 {
    let u = (imm12 as u32) & 0xfff;
    (opcode & 0x7f)
        | ((u & 0x1f) << 7)
        | ((funct3 & 0x7) << 12)
        | ((rs1 as u32 & 0x1f) << 15)
        | ((rs2 as u32 & 0x1f) << 20)
        | ((u >> 5) << 25)
}

/// Encodes a standard B-type branch instruction.
///
/// `imm13` is the signed byte offset from the branch PC; bit 0 is ignored by
/// the encoding and callers must supply an aligned offset.
#[inline]
pub const fn b_type(opcode: u32, funct3: u32, rs1: u8, rs2: u8, imm13: i32) -> u32 {
    let u = (imm13 as u32) & 0x1fff;
    (opcode & 0x7f)
        | (((u >> 11) & 0x1) << 7)
        | (((u >> 1) & 0xf) << 8)
        | ((funct3 & 0x7) << 12)
        | ((rs1 as u32 & 0x1f) << 15)
        | ((rs2 as u32 & 0x1f) << 20)
        | (((u >> 5) & 0x3f) << 25)
        | (((u >> 12) & 0x1) << 31)
}

/// Encodes a standard J-type `jal` instruction.
///
/// `imm21` is the signed byte offset from the instruction PC; bit 0 is ignored
/// by the encoding and callers must supply an aligned offset.
#[inline]
pub const fn j_type(opcode: u32, rd: u8, imm21: i32) -> u32 {
    let u = (imm21 as u32) & 0x1f_ffff;
    (opcode & 0x7f)
        | ((rd as u32 & 0x1f) << 7)
        | (((u >> 12) & 0xff) << 12)
        | (((u >> 11) & 0x1) << 20)
        | (((u >> 1) & 0x3ff) << 21)
        | (((u >> 20) & 0x1) << 31)
}

/// Encodes a standard U-type instruction (`lui`, `auipc`).
#[inline]
pub const fn u_type(opcode: u32, rd: u8, imm20: u32) -> u32 {
    (opcode & 0x7f) | ((rd as u32 & 0x1f) << 7) | ((imm20 & 0xfffff) << 12)
}

/// `ebreak` instruction (`0x0010_0073`), used as the end-of-block sentinel.
pub const EBREAK: u32 = 0x0010_0073;
/// `nop` instruction (`addi x0, x0, 0`).
pub const NOP: u32 = 0x0000_0013;

/// Builds a deterministic M-mode trap handler that:
/// 1. Mixes `mcause` and `mepc` into signature register `s11` (`x27`) using `t1` (`x6`).
/// 2. Advances `mepc` by `+4` (all generated trapping instructions are 32-bit) and executes `mret`.
///
/// `mtval` is deliberately excluded: for an illegal-instruction exception, a
/// conforming implementation may report either zero or instruction bits.
pub fn build_trap_handler() -> Vec<u8> {
    build_recovery_handler(0x342, 0x341, 0x3020_0073)
}

/// Builds the corresponding S-mode recovery handler using `scause`, `sepc`,
/// and `sret`. It is installed at the privileged suite's `stvec` address.
pub fn build_supervisor_trap_handler() -> Vec<u8> {
    build_recovery_handler(0x142, 0x141, 0x1020_0073)
}

fn build_recovery_handler(cause_csr: i32, epc_csr: i32, return_insn: u32) -> Vec<u8> {
    let insns: &[u32] = &[
        // csrr t1, {m,s}cause
        i_type(0x73, 6, 0b010, 0, cause_csr),
        // slli s11, s11, 7
        i_type(0x13, 27, 0b001, 27, 7),
        // xor s11, s11, t1
        r_type(0x33, 27, 0b100, 27, 6, 0x00),
        // csrr t1, {m,s}epc
        i_type(0x73, 6, 0b010, 0, epc_csr),
        // xor s11, s11, t1
        r_type(0x33, 27, 0b100, 27, 6, 0x00),
        // addi t1, t1, 4 (all generated trap-suite instructions are 32-bit)
        i_type(0x13, 6, 0b000, 6, 4),
        // csrw {m,s}epc, t1
        i_type(0x73, 0, 0b001, 6, epc_csr),
        // mret or sret
        return_insn,
    ];
    let mut bytes = Vec::with_capacity(insns.len() * 4);
    for &w in insns {
        bytes.extend_from_slice(&w.to_le_bytes());
    }
    bytes
}

#[cfg(test)]
mod tests {
    use super::*;

    fn decode_b_imm(word: u32) -> i32 {
        let bits = (((word >> 31) & 1) << 12)
            | (((word >> 7) & 1) << 11)
            | (((word >> 25) & 0x3f) << 5)
            | (((word >> 8) & 0xf) << 1);
        ((bits << 19) as i32) >> 19
    }

    fn decode_j_imm(word: u32) -> i32 {
        let bits = (((word >> 31) & 1) << 20)
            | (((word >> 12) & 0xff) << 12)
            | (((word >> 20) & 1) << 11)
            | (((word >> 21) & 0x3ff) << 1);
        ((bits << 11) as i32) >> 11
    }

    #[test]
    fn branch_encoder_places_positive_and_negative_immediates() {
        assert_eq!(b_type(0x63, 0, 0, 0, 8), 0x0000_0463);
        for immediate in [-4096, -4, 2, 8, 4094] {
            let word = b_type(0x63, 0b111, 5, 6, immediate);
            assert_eq!(decode_b_imm(word), immediate);
            assert_eq!((word >> 12) & 7, 0b111);
            assert_eq!((word >> 15) & 0x1f, 5);
            assert_eq!((word >> 20) & 0x1f, 6);
        }
    }

    #[test]
    fn jump_encoder_places_positive_and_negative_immediates() {
        assert_eq!(j_type(0x6f, 1, 8), 0x0080_00ef);
        for immediate in [-1_048_576, -4, 2, 8, 1_048_574] {
            let word = j_type(0x6f, 31, immediate);
            assert_eq!(decode_j_imm(word), immediate);
            assert_eq!((word >> 7) & 0x1f, 31);
        }
    }

    #[test]
    fn recovery_handlers_use_the_matching_privilege_csrs_and_return() {
        let words = |bytes: Vec<u8>| {
            bytes
                .chunks_exact(4)
                .map(|chunk| u32::from_le_bytes(chunk.try_into().unwrap()))
                .collect::<Vec<_>>()
        };

        let machine = words(build_trap_handler());
        assert_eq!(machine.len(), 8);
        assert_eq!((machine[0] >> 20) & 0xfff, 0x342);
        assert_eq!((machine[3] >> 20) & 0xfff, 0x341);
        assert_eq!((machine[6] >> 20) & 0xfff, 0x341);
        assert_eq!(machine[7], 0x3020_0073);

        let supervisor = words(build_supervisor_trap_handler());
        assert_eq!(supervisor.len(), 8);
        assert_eq!((supervisor[0] >> 20) & 0xfff, 0x142);
        assert_eq!((supervisor[3] >> 20) & 0xfff, 0x141);
        assert_eq!((supervisor[6] >> 20) & 0xfff, 0x141);
        assert_eq!(supervisor[7], 0x1020_0073);
    }
}
