//! Constrained-random instruction generators for each `RISU` verification suite.

use crate::risu::encode::{EBREAK, b_type, i_type, j_type, r_type, r4_type, s_type, u_type};
use crate::risu::seed::Rng;

/// Available `RISU` instruction fuzzing suites.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Suite {
    /// RV64I base integer ALU and immediate operations.
    IntAlu,
    /// RV64I branches, jumps, link semantics, and PC-relative address formation.
    ControlFlow,
    /// RV64M 64-bit and 32-bit multiply, divide, and remainder operations.
    MulDiv,
    /// `Zba`, `Zbb`, `Zbc`, and `Zbs` bit-manipulation extensions.
    Bitmanip,
    /// IEEE-754 single (`F`) and double (`D`) floating-point arithmetic, conversions, and `fflags`.
    Float,
    /// Sandboxed memory loads, stores, AMOs (`RV64A`), and `Zicbom`/`Zicboz` cache-block ops.
    SandboxMem,
    /// CSR WARL reads/writes and trap-handler recovery (`mtvec` signature checks).
    CsrTrap,
    /// Combined mix of all suites above.
    All,
}

impl Suite {
    /// Parses a suite name from the CLI.
    pub fn parse(s: &str) -> Option<Self> {
        match s.to_ascii_lowercase().as_str() {
            "alu" | "int" | "intalu" => Some(Self::IntAlu),
            "control" | "control-flow" | "branch" => Some(Self::ControlFlow),
            "mul" | "muldiv" | "m" => Some(Self::MulDiv),
            "bitmanip" | "zb" | "b" => Some(Self::Bitmanip),
            "float" | "fp" | "fd" => Some(Self::Float),
            "mem" | "amo" | "sandboxmem" => Some(Self::SandboxMem),
            "csr" | "trap" | "csrtrap" => Some(Self::CsrTrap),
            "all" => Some(Self::All),
            _ => None,
        }
    }

    /// Human-readable suite name.
    pub const fn name(self) -> &'static str {
        match self {
            Self::IntAlu => "int-alu",
            Self::ControlFlow => "control-flow",
            Self::MulDiv => "mul-div",
            Self::Bitmanip => "bitmanip",
            Self::Float => "float-fd",
            Self::SandboxMem => "sandbox-mem-amo",
            Self::CsrTrap => "csr-trap",
            Self::All => "all",
        }
    }
}

/// Generates a block of `num_insns` instructions for `suite`, terminated by `EBREAK`.
pub fn generate_block(rng: &mut Rng, suite: Suite, num_insns: usize) -> Vec<u32> {
    let mut out = Vec::with_capacity(num_insns + 4);
    while out.len() < num_insns {
        let active = match suite {
            Suite::All => match rng.next_u64() % 7 {
                0 => Suite::IntAlu,
                1 => Suite::ControlFlow,
                2 => Suite::MulDiv,
                3 => Suite::Bitmanip,
                4 => Suite::Float,
                5 => Suite::SandboxMem,
                _ => Suite::CsrTrap,
            },
            other => other,
        };
        match active {
            Suite::IntAlu => out.push(gen_int_alu(rng)),
            Suite::ControlFlow => gen_control_flow(rng, &mut out),
            Suite::MulDiv => out.push(gen_mul_div(rng)),
            Suite::Bitmanip => out.push(gen_bitmanip(rng)),
            Suite::Float => out.push(gen_float(rng)),
            Suite::SandboxMem => gen_sandbox_mem(rng, &mut out),
            Suite::CsrTrap => out.push(gen_csr_trap(rng)),
            Suite::All => unreachable!(),
        }
    }
    out.push(EBREAK);
    out
}

fn gen_int_alu(rng: &mut Rng) -> u32 {
    let rd = rng.pick_gpr();
    let rs1 = rng.pick_src_gpr();
    let rs2 = rng.pick_src_gpr();
    let imm12 = (rng.edge_u64() & 0xfff) as i32;
    let shamt6 = (rng.next_u64() & 63) as i32;
    let shamt5 = (rng.next_u64() & 31) as i32;

    match rng.next_u64() % 29 {
        0 => r_type(0x33, rd, 0b000, rs1, rs2, 0x00),  // add
        1 => r_type(0x33, rd, 0b000, rs1, rs2, 0x20),  // sub
        2 => r_type(0x33, rd, 0b001, rs1, rs2, 0x00),  // sll
        3 => r_type(0x33, rd, 0b010, rs1, rs2, 0x00),  // slt
        4 => r_type(0x33, rd, 0b011, rs1, rs2, 0x00),  // sltu
        5 => r_type(0x33, rd, 0b100, rs1, rs2, 0x00),  // xor
        6 => r_type(0x33, rd, 0b101, rs1, rs2, 0x00),  // srl
        7 => r_type(0x33, rd, 0b101, rs1, rs2, 0x20),  // sra
        8 => r_type(0x33, rd, 0b110, rs1, rs2, 0x00),  // or
        9 => r_type(0x33, rd, 0b111, rs1, rs2, 0x00),  // and
        10 => r_type(0x3b, rd, 0b000, rs1, rs2, 0x00), // addw
        11 => r_type(0x3b, rd, 0b000, rs1, rs2, 0x20), // subw
        12 => r_type(0x3b, rd, 0b001, rs1, rs2, 0x00), // sllw
        13 => r_type(0x3b, rd, 0b101, rs1, rs2, 0x00), // srlw
        14 => r_type(0x3b, rd, 0b101, rs1, rs2, 0x20), // sraw
        15 => i_type(0x13, rd, 0b000, rs1, imm12),     // addi
        16 => i_type(0x13, rd, 0b010, rs1, imm12),     // slti
        17 => i_type(0x13, rd, 0b011, rs1, imm12),     // sltiu
        18 => i_type(0x13, rd, 0b100, rs1, imm12),     // xori
        19 => i_type(0x13, rd, 0b110, rs1, imm12),     // ori
        20 => i_type(0x13, rd, 0b111, rs1, imm12),     // andi
        21 => i_type(0x13, rd, 0b001, rs1, shamt6),    // slli
        22 => i_type(0x13, rd, 0b101, rs1, shamt6),    // srli
        23 => i_type(0x13, rd, 0b101, rs1, 0x400 | shamt6), // srai
        24 => i_type(0x1b, rd, 0b000, rs1, imm12),     // addiw
        25 => i_type(0x1b, rd, 0b001, rs1, shamt5),    // slliw
        26 => i_type(0x1b, rd, 0b101, rs1, shamt5),    // srliw
        27 => i_type(0x1b, rd, 0b101, rs1, 0x400 | shamt5), // sraiw
        _ => u_type(0x37, rd, (rng.edge_u64() & 0xfffff) as u32), // lui
    }
}

fn gen_control_flow(rng: &mut Rng, out: &mut Vec<u32>) {
    match rng.next_u64() % 10 {
        branch @ 0..=5 => {
            const BRANCH_FUNCT3: [u32; 6] = [0b000, 0b001, 0b100, 0b101, 0b110, 0b111];
            let taken = (rng.next_u64() & 1) != 0;
            let marker_rd = rng.pick_gpr();
            gen_conditional_branch(out, BRANCH_FUNCT3[branch as usize], taken, marker_rd);
        }
        6 => {
            let rd = if (rng.next_u64() & 3) == 0 {
                0
            } else {
                rng.pick_gpr()
            };
            let marker_rd = rng.pick_gpr();
            gen_jal_skip(out, rd, marker_rd);
        }
        7 => {
            // Exercise both normal link registers and rd == rs1 aliasing.
            let rd = match rng.next_u64() & 3 {
                0 => 0,
                1 => 5,
                _ => rng.pick_gpr(),
            };
            let marker_rd = rng.pick_gpr();
            gen_jalr_skip(out, rd, marker_rd);
        }
        8 => {
            let rd = rng.pick_gpr();
            out.push(u_type(0x17, rd, (rng.edge_u64() & 0x000f_ffff) as u32));
        }
        _ => gen_bounded_loop(out, ((rng.next_u64() & 3) + 1) as i32),
    }
}

fn gen_conditional_branch(out: &mut Vec<u32>, funct3: u32, taken: bool, marker_rd: u8) {
    // t0/t1 are reserved by the generator as control-flow and trap scratch.
    // Set operands explicitly so every branch form is generated in both taken
    // and not-taken configurations independent of the seeded register state.
    let (lhs, rhs) = branch_operands(funct3, taken);
    out.push(i_type(0x13, 5, 0b000, 0, lhs));
    out.push(i_type(0x13, 6, 0b000, 0, rhs));
    // A taken branch skips exactly one 32-bit marker and reconverges at the
    // first instruction appended by the next snippet (or the final EBREAK).
    out.push(b_type(0x63, funct3, 5, 6, 8));
    out.push(i_type(0x13, marker_rd, 0b000, marker_rd, 1));
}

const fn branch_operands(funct3: u32, taken: bool) -> (i32, i32) {
    match (funct3, taken) {
        (0b000, true) | (0b001, false) => (1, 1), // beq / bne
        (0b000, false) | (0b001, true) => (1, 2),
        (0b100, true) | (0b101, false) => (-1, 1), // blt / bge
        (0b100, false) | (0b101, true) => (1, -1),
        (0b110, true) | (0b111, false) => (1, 2), // bltu / bgeu
        (0b110, false) | (0b111, true) => (2, 1),
        _ => (0, 0),
    }
}

fn gen_jal_skip(out: &mut Vec<u32>, rd: u8, marker_rd: u8) {
    out.push(j_type(0x6f, rd, 8));
    out.push(i_type(0x13, marker_rd, 0b000, marker_rd, 1));
}

fn gen_jalr_skip(out: &mut Vec<u32>, rd: u8, marker_rd: u8) {
    // AUIPC yields this snippet's PC. Adding 17 produces an odd address one
    // byte beyond the desired target; JALR must clear bit 0 and land at +16.
    out.push(u_type(0x17, 5, 0));
    out.push(i_type(0x13, 5, 0b000, 5, 17));
    out.push(i_type(0x67, rd, 0b000, 5, 0));
    out.push(i_type(0x13, marker_rd, 0b000, marker_rd, 1));
}

fn gen_bounded_loop(out: &mut Vec<u32>, iterations: i32) {
    debug_assert!((1..=4).contains(&iterations));
    out.push(i_type(0x13, 5, 0b000, 0, iterations));
    out.push(i_type(0x13, 5, 0b000, 5, -1));
    out.push(b_type(0x63, 0b001, 5, 0, -4));
}

fn gen_mul_div(rng: &mut Rng) -> u32 {
    let rd = rng.pick_gpr();
    let rs1 = rng.pick_src_gpr();
    let rs2 = rng.pick_src_gpr();
    match rng.next_u64() % 13 {
        0 => r_type(0x33, rd, 0b000, rs1, rs2, 0x01),  // mul
        1 => r_type(0x33, rd, 0b001, rs1, rs2, 0x01),  // mulh
        2 => r_type(0x33, rd, 0b010, rs1, rs2, 0x01),  // mulhsu
        3 => r_type(0x33, rd, 0b011, rs1, rs2, 0x01),  // mulhu
        4 => r_type(0x33, rd, 0b100, rs1, rs2, 0x01),  // div
        5 => r_type(0x33, rd, 0b101, rs1, rs2, 0x01),  // divu
        6 => r_type(0x33, rd, 0b110, rs1, rs2, 0x01),  // rem
        7 => r_type(0x33, rd, 0b111, rs1, rs2, 0x01),  // remu
        8 => r_type(0x3b, rd, 0b000, rs1, rs2, 0x01),  // mulw
        9 => r_type(0x3b, rd, 0b100, rs1, rs2, 0x01),  // divw
        10 => r_type(0x3b, rd, 0b101, rs1, rs2, 0x01), // divuw
        11 => r_type(0x3b, rd, 0b110, rs1, rs2, 0x01), // remw
        _ => r_type(0x3b, rd, 0b111, rs1, rs2, 0x01),  // remuw
    }
}

fn gen_bitmanip(rng: &mut Rng) -> u32 {
    let rd = rng.pick_gpr();
    let rs1 = rng.pick_src_gpr();
    let rs2 = rng.pick_src_gpr();
    let shamt6 = (rng.next_u64() & 63) as i32;
    let shamt5 = (rng.next_u64() & 31) as i32;

    match rng.next_u64() % 43 {
        // Zba
        0 => r_type(0x3b, rd, 0b000, rs1, rs2, 0x04), // add.uw
        1 => r_type(0x33, rd, 0b010, rs1, rs2, 0x10), // sh1add
        2 => r_type(0x33, rd, 0b100, rs1, rs2, 0x10), // sh2add
        3 => r_type(0x33, rd, 0b110, rs1, rs2, 0x10), // sh3add
        4 => r_type(0x3b, rd, 0b010, rs1, rs2, 0x10), // sh1add.uw
        5 => r_type(0x3b, rd, 0b100, rs1, rs2, 0x10), // sh2add.uw
        6 => r_type(0x3b, rd, 0b110, rs1, rs2, 0x10), // sh3add.uw
        7 => i_type(0x1b, rd, 0b001, rs1, 0x080 | shamt6), // slli.uw
        // Zbb
        8 => r_type(0x33, rd, 0b111, rs1, rs2, 0x20), // andn
        9 => r_type(0x33, rd, 0b110, rs1, rs2, 0x20), // orn
        10 => r_type(0x33, rd, 0b100, rs1, rs2, 0x20), // xnor
        11 => i_type(0x13, rd, 0b001, rs1, 0x600),    // clz
        12 => i_type(0x13, rd, 0b001, rs1, 0x601),    // ctz
        13 => i_type(0x13, rd, 0b001, rs1, 0x602),    // cpop
        14 => i_type(0x1b, rd, 0b001, rs1, 0x600),    // clzw
        15 => i_type(0x1b, rd, 0b001, rs1, 0x601),    // ctzw
        16 => i_type(0x1b, rd, 0b001, rs1, 0x602),    // cpopw
        17 => r_type(0x33, rd, 0b110, rs1, rs2, 0x05), // max
        18 => r_type(0x33, rd, 0b111, rs1, rs2, 0x05), // maxu
        19 => r_type(0x33, rd, 0b100, rs1, rs2, 0x05), // min
        20 => r_type(0x33, rd, 0b101, rs1, rs2, 0x05), // minu
        21 => i_type(0x13, rd, 0b001, rs1, 0x604),    // sext.b
        22 => i_type(0x13, rd, 0b001, rs1, 0x605),    // sext.h
        23 => r_type(0x3b, rd, 0b100, rs1, 0, 0x04),  // zext.h (RV64)
        24 => r_type(0x33, rd, 0b001, rs1, rs2, 0x30), // rol
        25 => r_type(0x3b, rd, 0b001, rs1, rs2, 0x30), // rolw
        26 => r_type(0x33, rd, 0b101, rs1, rs2, 0x30), // ror
        27 => r_type(0x3b, rd, 0b101, rs1, rs2, 0x30), // rorw
        28 => i_type(0x13, rd, 0b101, rs1, 0x600 | shamt6), // rori
        29 => i_type(0x1b, rd, 0b101, rs1, 0x600 | shamt5), // roriw
        30 => i_type(0x13, rd, 0b101, rs1, 0x287),    // orc.b
        31 => i_type(0x13, rd, 0b101, rs1, 0x6b8),    // rev8 (RV64)
        // Zbc
        32 => r_type(0x33, rd, 0b001, rs1, rs2, 0x05), // clmul
        33 => r_type(0x33, rd, 0b011, rs1, rs2, 0x05), // clmulh
        34 => r_type(0x33, rd, 0b010, rs1, rs2, 0x05), // clmulr
        // Zbs
        35 => r_type(0x33, rd, 0b001, rs1, rs2, 0x24), // bclr
        36 => i_type(0x13, rd, 0b001, rs1, 0x480 | shamt6), // bclri
        37 => r_type(0x33, rd, 0b101, rs1, rs2, 0x24), // bext
        38 => i_type(0x13, rd, 0b101, rs1, 0x480 | shamt6), // bexti
        39 => r_type(0x33, rd, 0b001, rs1, rs2, 0x34), // binv
        40 => i_type(0x13, rd, 0b001, rs1, 0x680 | shamt6), // binvi
        41 => r_type(0x33, rd, 0b001, rs1, rs2, 0x14), // bset
        _ => i_type(0x13, rd, 0b001, rs1, 0x280 | shamt6), // bseti
    }
}

fn gen_float(rng: &mut Rng) -> u32 {
    let fd = rng.pick_fpr();
    let fs1 = rng.pick_fpr();
    let fs2 = rng.pick_fpr();
    let fs3 = rng.pick_fpr();
    let rd = rng.pick_gpr();
    let rs1 = rng.pick_src_gpr();
    // Valid static rounding modes: 0..=4, or 7 (DYN), plus occasional invalid rm (5, 6) to test trap behavior.
    const RMS: [u32; 8] = [0, 1, 2, 3, 4, 7, 5, 6];
    let rm = if (rng.next_u64() & 0xf) == 0 {
        RMS[rng.index(RMS.len())]
    } else {
        RMS[rng.index(6)]
    };
    // fmt: 0 = .s (single), 1 = .d (double)
    let is_double = (rng.next_u64() & 1) != 0;
    let f7_fmt = if is_double { 1u32 } else { 0u32 };

    match rng.next_u64() % 30 {
        0 => r_type(0x53, fd, rm, fs1, fs2, f7_fmt), // fadd.s/d
        1 => r_type(0x53, fd, rm, fs1, fs2, 0x04 | f7_fmt), // fsub.s/d
        2 => r_type(0x53, fd, rm, fs1, fs2, 0x08 | f7_fmt), // fmul.s/d
        3 => r_type(0x53, fd, rm, fs1, fs2, 0x0c | f7_fmt), // fdiv.s/d
        4 => r_type(0x53, fd, rm, fs1, 0, 0x2c | f7_fmt), // fsqrt.s/d
        5 => r_type(0x53, fd, 0b000, fs1, fs2, 0x10 | f7_fmt), // fsgnj.s/d
        6 => r_type(0x53, fd, 0b001, fs1, fs2, 0x10 | f7_fmt), // fsgnjn.s/d
        7 => r_type(0x53, fd, 0b010, fs1, fs2, 0x10 | f7_fmt), // fsgnjx.s/d
        8 => r_type(0x53, fd, 0b000, fs1, fs2, 0x14 | f7_fmt), // fmin.s/d
        9 => r_type(0x53, fd, 0b001, fs1, fs2, 0x14 | f7_fmt), // fmax.s/d
        10 => r_type(0x53, rd, 0b010, fs1, fs2, 0x50 | f7_fmt), // feq.s/d
        11 => r_type(0x53, rd, 0b001, fs1, fs2, 0x50 | f7_fmt), // flt.s/d
        12 => r_type(0x53, rd, 0b000, fs1, fs2, 0x50 | f7_fmt), // fle.s/d
        13 => r_type(0x53, rd, 0b001, fs1, 0, 0x70 | f7_fmt), // fclass.s/d
        14 => r_type(0x53, rd, rm, fs1, 0, 0x60 | f7_fmt), // fcvt.w.s/d
        15 => r_type(0x53, rd, rm, fs1, 1, 0x60 | f7_fmt), // fcvt.wu.s/d
        16 => r_type(0x53, rd, rm, fs1, 2, 0x60 | f7_fmt), // fcvt.l.s/d
        17 => r_type(0x53, rd, rm, fs1, 3, 0x60 | f7_fmt), // fcvt.lu.s/d
        18 => r_type(0x53, fd, rm, rs1, 0, 0x68 | f7_fmt), // fcvt.s/d.w
        19 => r_type(0x53, fd, rm, rs1, 1, 0x68 | f7_fmt), // fcvt.s/d.wu
        20 => r_type(0x53, fd, rm, rs1, 2, 0x68 | f7_fmt), // fcvt.s/d.l
        21 => r_type(0x53, fd, rm, rs1, 3, 0x68 | f7_fmt), // fcvt.s/d.lu
        22 => r_type(0x53, fd, rm, fs1, 1, 0x20),    // fcvt.s.d
        23 => r_type(0x53, fd, rm, fs1, 0, 0x21),    // fcvt.d.s
        24 => r_type(0x53, rd, 0b000, fs1, 0, 0x70 | f7_fmt), // fmv.x.w / fmv.x.d
        25 => r_type(0x53, fd, 0b000, rs1, 0, 0x78 | f7_fmt), // fmv.w.x / fmv.d.x
        26 => r4_type(0x43, fd, rm, fs1, fs2, fs3, f7_fmt), // fmadd.s/d
        27 => r4_type(0x47, fd, rm, fs1, fs2, fs3, f7_fmt), // fmsub.s/d
        28 => r4_type(0x4b, fd, rm, fs1, fs2, fs3, f7_fmt), // fnmsub.s/d
        _ => r4_type(0x4f, fd, rm, fs1, fs2, fs3, f7_fmt), // fnmadd.s/d
    }
}

fn gen_sandbox_mem(rng: &mut Rng, out: &mut Vec<u32>) {
    // s0 (x8) holds 0x8001_0000 (4 KiB scratch buffer).
    // Compute an 8-byte aligned address in t0 (x5):
    //   andi t0, rs_rand, 0x7f8
    //   add  t0, t0, s0
    let rs_idx = rng.pick_src_gpr();
    out.push(i_type(0x13, 5, 0b111, rs_idx, 0x7f8));
    out.push(r_type(0x33, 5, 0b000, 5, 8, 0x00));

    let rd = rng.pick_gpr();
    let rs2 = rng.pick_src_gpr();
    let fd = rng.pick_fpr();
    let fs2 = rng.pick_fpr();
    // Occasional unaligned byte offset (0..7) for regular loads/stores
    let unaligned_off = if (rng.next_u64() & 3) == 0 {
        (rng.next_u64() & 7) as i32
    } else {
        0
    };

    let insn = match rng.next_u64() % 38 {
        0 => i_type(0x03, rd, 0b000, 5, unaligned_off), // lb rd, off(t0)
        1 => i_type(0x03, rd, 0b001, 5, unaligned_off), // lh rd, off(t0)
        2 => i_type(0x03, rd, 0b010, 5, unaligned_off), // lw rd, off(t0)
        3 => i_type(0x03, rd, 0b011, 5, unaligned_off), // ld rd, off(t0)
        4 => i_type(0x03, rd, 0b100, 5, unaligned_off), // lbu rd, off(t0)
        5 => i_type(0x03, rd, 0b101, 5, unaligned_off), // lhu rd, off(t0)
        6 => i_type(0x03, rd, 0b110, 5, unaligned_off), // lwu rd, off(t0)
        7 => s_type(0x23, 0b000, 5, rs2, unaligned_off), // sb rs2, off(t0)
        8 => s_type(0x23, 0b001, 5, rs2, unaligned_off), // sh rs2, off(t0)
        9 => s_type(0x23, 0b010, 5, rs2, unaligned_off), // sw rs2, off(t0)
        10 => s_type(0x23, 0b011, 5, rs2, unaligned_off), // sd rs2, off(t0)
        11 => i_type(0x07, fd, 0b010, 5, unaligned_off), // flw fd, off(t0)
        12 => i_type(0x07, fd, 0b011, 5, unaligned_off), // fld fd, off(t0)
        13 => s_type(0x27, 0b010, 5, fs2, unaligned_off), // fsw fs2, off(t0)
        14 => s_type(0x27, 0b011, 5, fs2, unaligned_off), // fsd fs2, off(t0)
        // RV64A AMOs (32-bit .w and 64-bit .d)
        15 => r_type(0x2f, rd, 0b010, 5, rs2, 0b000_0100), // amoswap.w
        16 => r_type(0x2f, rd, 0b011, 5, rs2, 0b000_0100), // amoswap.d
        17 => r_type(0x2f, rd, 0b010, 5, rs2, 0b000_0000), // amoadd.w
        18 => r_type(0x2f, rd, 0b011, 5, rs2, 0b000_0000), // amoadd.d
        19 => r_type(0x2f, rd, 0b010, 5, rs2, 0b001_0000), // amoxor.w
        20 => r_type(0x2f, rd, 0b011, 5, rs2, 0b001_0000), // amoxor.d
        21 => r_type(0x2f, rd, 0b010, 5, rs2, 0b011_0000), // amoand.w
        22 => r_type(0x2f, rd, 0b011, 5, rs2, 0b011_0000), // amoand.d
        23 => r_type(0x2f, rd, 0b010, 5, rs2, 0b010_0000), // amoor.w
        24 => r_type(0x2f, rd, 0b011, 5, rs2, 0b010_0000), // amoor.d
        25 => r_type(0x2f, rd, 0b010, 5, rs2, 0b100_0000), // amomin.w
        26 => r_type(0x2f, rd, 0b011, 5, rs2, 0b100_0000), // amomin.d
        27 => r_type(0x2f, rd, 0b010, 5, rs2, 0b101_0000), // amomax.w
        28 => r_type(0x2f, rd, 0b011, 5, rs2, 0b101_0000), // amomax.d
        29 => r_type(0x2f, rd, 0b010, 5, rs2, 0b110_0000), // amominu.w
        30 => r_type(0x2f, rd, 0b011, 5, rs2, 0b110_0000), // amominu.d
        31 => r_type(0x2f, rd, 0b010, 5, rs2, 0b111_0000), // amomaxu.w
        32 => r_type(0x2f, rd, 0b011, 5, rs2, 0b111_0000), // amomaxu.d
        33 => {
            // Paired lr.w + sc.w on 0(t0)
            let rd2 = rng.pick_gpr();
            out.push(r_type(0x2f, rd, 0b010, 5, 0, 0b000_1000));
            r_type(0x2f, rd2, 0b010, 5, rs2, 0b000_1100)
        }
        34 => r_type(0x2f, rd, 0b010, 5, rs2, 0b000_1100), // standalone sc.w (must fail with 1)
        35 => {
            // Paired lr.d + sc.d on 0(t0)
            let rd2 = rng.pick_gpr();
            out.push(r_type(0x2f, rd, 0b011, 5, 0, 0b000_1000));
            r_type(0x2f, rd2, 0b011, 5, rs2, 0b000_1100)
        }
        36 => r_type(0x2f, rd, 0b011, 5, rs2, 0b000_1100), // standalone sc.d (must fail with 1)
        _ => i_type(0x0f, 0, 0b010, 5, 0x004),             // cbo.zero 0(t0)
    };
    out.push(insn);
}

fn gen_csr_trap(rng: &mut Rng) -> u32 {
    let rd = rng.pick_gpr();
    let rs1 = rng.pick_src_gpr();
    match rng.next_u64() % 18 {
        // Safe CSR reads/writes. Keep WLRL/WARL values portable across
        // implementations so exact-value differential comparison is meaningful.
        0 => i_type(0x73, rd, 0b001, rs1, 0x340), // csrrw rd, mscratch, rs1
        1 => i_type(0x73, rd, 0b010, rs1, 0x340), // csrrs rd, mscratch, rs1
        2 => i_type(0x73, rd, 0b011, rs1, 0x340), // csrrc rd, mscratch, rs1
        3 => i_type(0x73, rd, 0b001, rs1, 0x140), // csrrw rd, sscratch, rs1
        4 => i_type(0x73, rd, 0b001, rs1, 0x001), // csrrw rd, fflags, rs1
        5 => i_type(0x73, rd, 0b101, 0, 0x002),   // csrrwi rd, frm, RNE
        6 => i_type(0x73, rd, 0b101, 0, 0x003),   // csrrwi rd, fcsr, 0
        // mvendorid, marchid, mimpid, and misa are deliberately excluded: their
        // values legitimately differ between rivemu and QEMU. mhartid is safe for -smp 1.
        7 => i_type(0x73, rd, 0b010, 0, 0xf14), // csrr rd, mhartid
        8 => i_type(0x73, rd, 0b101, 2, 0x142), // csrrwi rd, scause, illegal-insn
        9 => i_type(0x73, rd, 0b010, rs1, 0x001), // csrrs rd, fflags, rs1
        10 => i_type(0x73, rd, 0b101, 0, 0x143), // csrrwi rd, stval, 0
        11 => i_type(0x73, rd, 0b010, rs1, 0x140), // csrrs rd, sscratch, rs1
        12 => i_type(0x73, rd, 0b101, 0, 0x341), // csrrwi rd, mepc, 0
        13 => i_type(0x73, rd, 0b101, 0, 0x141), // csrrwi rd, sepc, 0
        14 => i_type(0x73, rd, 0b101, 0, 0x105), // csrrwi rd, stvec, direct@0
        15 => i_type(0x73, rd, 0b101, 0, 0x180), // csrrwi rd, satp, bare
        // Synchronous traps caught by our M-mode handler at mtvec = 0x8000_2000:
        16 => 0x0000_0073, // ecall (from M-mode -> mcause = 11, mtval = 0)
        _ => 0x0000_7003,  // illegal 32-bit instruction (LOAD with reserved funct3 = 0b111)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn decode_i_imm(word: u32) -> i32 {
        (word as i32) >> 20
    }

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

    fn branch_is_taken(funct3: u32, lhs: i64, rhs: i64) -> bool {
        match funct3 {
            0b000 => lhs == rhs,
            0b001 => lhs != rhs,
            0b100 => lhs < rhs,
            0b101 => lhs >= rhs,
            0b110 => (lhs as u64) < (rhs as u64),
            0b111 => (lhs as u64) >= (rhs as u64),
            _ => panic!("invalid branch funct3"),
        }
    }

    #[test]
    fn control_flow_suite_names_parse() {
        assert_eq!(Suite::parse("control"), Some(Suite::ControlFlow));
        assert_eq!(Suite::parse("control-flow"), Some(Suite::ControlFlow));
        assert_eq!(Suite::parse("branch"), Some(Suite::ControlFlow));
        assert_eq!(Suite::ControlFlow.name(), "control-flow");
    }

    #[test]
    fn conditional_snippets_cover_every_branch_both_ways() {
        for funct3 in [0b000, 0b001, 0b100, 0b101, 0b110, 0b111] {
            for expected_taken in [false, true] {
                let mut words = Vec::new();
                gen_conditional_branch(&mut words, funct3, expected_taken, 7);

                assert_eq!(words.len(), 4);
                assert_eq!(words[2] & 0x7f, 0x63);
                assert_eq!((words[2] >> 12) & 7, funct3);
                assert_eq!((words[2] >> 15) & 0x1f, 5);
                assert_eq!((words[2] >> 20) & 0x1f, 6);
                assert_eq!(decode_b_imm(words[2]), 8);

                let lhs = i64::from(decode_i_imm(words[0]));
                let rhs = i64::from(decode_i_imm(words[1]));
                assert_eq!(branch_is_taken(funct3, lhs, rhs), expected_taken);
            }
        }
    }

    #[test]
    fn jump_snippets_skip_one_slot_and_test_jalr_bit_zero() {
        let mut jal = Vec::new();
        gen_jal_skip(&mut jal, 1, 7);
        assert_eq!(jal.len(), 2);
        assert_eq!(jal[0] & 0x7f, 0x6f);
        assert_eq!((jal[0] >> 7) & 0x1f, 1);
        assert_eq!(decode_j_imm(jal[0]), 8);

        let mut jalr = Vec::new();
        gen_jalr_skip(&mut jalr, 5, 7);
        assert_eq!(jalr.len(), 4);
        assert_eq!(jalr[0] & 0x7f, 0x17);
        assert_eq!((jalr[0] >> 7) & 0x1f, 5);
        assert_eq!(decode_i_imm(jalr[1]), 17);
        assert_eq!(jalr[2] & 0x7f, 0x67);
        assert_eq!((jalr[2] >> 7) & 0x1f, 5);
        assert_eq!((jalr[2] >> 15) & 0x1f, 5);
        let snippet_pc = 0x8000_0100u64;
        assert_eq!((snippet_pc + 17) & !1, snippet_pc + 16);
    }

    #[test]
    fn bounded_loop_has_a_small_backward_target() {
        let mut words = Vec::new();
        gen_bounded_loop(&mut words, 4);
        assert_eq!(words.len(), 3);
        assert_eq!(decode_i_imm(words[0]), 4);
        assert_eq!(decode_i_imm(words[1]), -1);
        assert_eq!((words[2] >> 12) & 7, 0b001);
        assert_eq!(decode_b_imm(words[2]), -4);
    }

    #[test]
    fn generated_control_flow_targets_remain_inside_the_block() {
        for seed in 1..=64 {
            let mut rng = Rng::new(seed);
            let words = generate_block(&mut rng, Suite::ControlFlow, 64);
            assert_eq!(words.last(), Some(&EBREAK));

            for (index, &word) in words.iter().enumerate() {
                let opcode = word & 0x7f;
                let immediate = match opcode {
                    0x63 => Some(decode_b_imm(word)),
                    0x6f => Some(decode_j_imm(word)),
                    _ => None,
                };
                if let Some(immediate) = immediate {
                    let target = index as i64 * 4 + i64::from(immediate);
                    assert_eq!(target & 3, 0);
                    assert!((0..words.len() as i64 * 4).contains(&target));
                }
                if opcode == 0x67 {
                    assert!(index >= 2);
                    assert!(index + 2 < words.len());
                }
            }
        }
    }
}
