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

/// Encodes a standard U-type instruction (`lui`, `auipc`).
#[inline]
pub const fn u_type(opcode: u32, rd: u8, imm20: u32) -> u32 {
    (opcode & 0x7f) | ((rd as u32 & 0x1f) << 7) | ((imm20 & 0xfffff) << 12)
}

/// `ebreak` instruction (`0x0010_0073`), used as the end-of-block sentinel.
pub const EBREAK: u32 = 0x0010_0073;
/// `nop` instruction (`addi x0, x0, 0`).
pub const NOP: u32 = 0x0000_0013;

/// Builds a deterministic M-mode trap handler (for `mtvec = 0x8000_2000`) that:
/// 1. Mixes `mcause` and `mepc` into signature register `s11` (`x27`) using `t1` (`x6`).
/// 2. Advances `mepc` by `+4` (all generated trapping instructions are 32-bit) and executes `mret`.
///
/// `mtval` is deliberately excluded: for an illegal-instruction exception, a
/// conforming implementation may report either zero or instruction bits.
pub fn build_trap_handler() -> Vec<u8> {
    let insns: &[u32] = &[
        // csrr t1, mcause (0x342)
        i_type(0x73, 6, 0b010, 0, 0x342),
        // slli s11, s11, 7
        i_type(0x13, 27, 0b001, 27, 7),
        // xor s11, s11, t1
        r_type(0x33, 27, 0b100, 27, 6, 0x00),
        // csrr t1, mepc (0x341)
        i_type(0x73, 6, 0b010, 0, 0x341),
        // xor s11, s11, t1
        r_type(0x33, 27, 0b100, 27, 6, 0x00),
        // addi t1, t1, 4 (all generated trap-suite instructions are 32-bit)
        i_type(0x13, 6, 0b000, 6, 4),
        // csrw mepc, t1
        i_type(0x73, 0, 0b001, 6, 0x341),
        // mret (0x3020_0073)
        0x3020_0073,
    ];
    let mut bytes = Vec::with_capacity(insns.len() * 4);
    for &w in insns {
        bytes.extend_from_slice(&w.to_le_bytes());
    }
    bytes
}
