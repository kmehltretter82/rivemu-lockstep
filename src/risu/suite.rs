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
    /// Self-modifying code with `FENCE.I` instruction-cache synchronization.
    FenceI,
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
    /// Directed RV64A AMO and LR/SC semantics over sandboxed scratch memory.
    Atomics,
    /// Legal, sequential RV64C integer and scratch-memory operations.
    Compressed,
    /// Original mixed suites, excluding specialized [`Self::Atomics`] and [`Self::Compressed`].
    All,
}

impl Suite {
    /// Parses a suite name from the CLI.
    pub fn parse(s: &str) -> Option<Self> {
        match s.to_ascii_lowercase().as_str() {
            "alu" | "int" | "intalu" => Some(Self::IntAlu),
            "control" | "control-flow" | "branch" => Some(Self::ControlFlow),
            "fencei" | "fence-i" | "smc" => Some(Self::FenceI),
            "mul" | "muldiv" | "m" => Some(Self::MulDiv),
            "bitmanip" | "zb" | "b" => Some(Self::Bitmanip),
            "float" | "fp" | "fd" => Some(Self::Float),
            "mem" | "amo" | "sandboxmem" => Some(Self::SandboxMem),
            "csr" | "trap" | "csrtrap" => Some(Self::CsrTrap),
            "atomic" | "atomics" | "rv64a" | "lrsc" => Some(Self::Atomics),
            "compressed" | "rvc" | "c" => Some(Self::Compressed),
            "all" => Some(Self::All),
            _ => None,
        }
    }

    /// Human-readable suite name.
    pub const fn name(self) -> &'static str {
        match self {
            Self::IntAlu => "int-alu",
            Self::ControlFlow => "control-flow",
            Self::FenceI => "fence-i-smc",
            Self::MulDiv => "mul-div",
            Self::Bitmanip => "bitmanip",
            Self::Float => "float-fd",
            Self::SandboxMem => "sandbox-mem-amo",
            Self::CsrTrap => "csr-trap",
            Self::Atomics => "rv64a-directed",
            Self::Compressed => "rv64c",
            Self::All => "all",
        }
    }
}

/// Generates a block of `num_insns` instructions for `suite`, terminated by `EBREAK`.
pub fn generate_block(rng: &mut Rng, suite: Suite, num_insns: usize) -> Vec<u32> {
    let mut out = Vec::with_capacity(num_insns + 4);
    let mut atomic_slot = 0usize;
    let mut atomic_selector = if suite == Suite::Atomics {
        rng.index(ATOMIC_CASES)
    } else {
        0
    };
    while out.len() < num_insns {
        let active = match suite {
            Suite::All => match rng.next_u64() % 8 {
                0 => Suite::IntAlu,
                1 => Suite::ControlFlow,
                2 => Suite::FenceI,
                3 => Suite::MulDiv,
                4 => Suite::Bitmanip,
                5 => Suite::Float,
                6 => Suite::SandboxMem,
                _ => Suite::CsrTrap,
            },
            other => other,
        };
        match active {
            Suite::IntAlu => out.push(gen_int_alu(rng)),
            Suite::ControlFlow => gen_control_flow(rng, &mut out),
            Suite::FenceI => gen_fence_i(&mut out),
            Suite::MulDiv => out.push(gen_mul_div(rng)),
            Suite::Bitmanip => out.push(gen_bitmanip(rng)),
            Suite::Float => out.push(gen_float(rng)),
            Suite::SandboxMem => gen_sandbox_mem(rng, &mut out),
            Suite::CsrTrap => gen_csr_trap(rng, &mut out),
            Suite::Atomics => {
                gen_atomic_case(atomic_selector, atomic_slot, &mut out);
                atomic_slot += 1;
                atomic_selector = (atomic_selector + 1) % ATOMIC_CASES;
            }
            Suite::Compressed => {
                unreachable!("compressed instructions use generate_compressed_block")
            }
            Suite::All => unreachable!(),
        }
    }
    out.push(EBREAK);
    out
}

/// Generates exactly `num_insns` legal, sequential RV64C instructions.
///
/// Unlike [`generate_block`], this does not append the 32-bit `EBREAK`
/// checkpoint because its return type deliberately contains only 16-bit
/// instructions. The case materializer appends that checkpoint after byte
/// serialization.
pub fn generate_compressed_block(rng: &mut Rng, num_insns: usize) -> Vec<u16> {
    let mut out = Vec::with_capacity(num_insns);
    while out.len() < num_insns {
        let insn = match rng.next_u64() % 24 {
            // Give C.ADDI and its architecturally defined hints extra weight.
            0 => encode_ci(0b000, 0, 0),                 // C.NOP
            1 => encode_ci(0b000, 0, nonzero_imm6(rng)), // C.ADDI hint
            2..=4 => encode_ci(0b000, compressed_rd(rng), random_imm6(rng)),
            5 => encode_ci(0b001, compressed_rd(rng), random_imm6(rng)), // C.ADDIW
            6 => encode_ci(0b010, compressed_rd(rng), random_imm6(rng)), // C.LI
            7 => {
                let mut rd = compressed_rd(rng);
                while rd == 2 {
                    rd = compressed_rd(rng);
                }
                encode_ci(0b011, rd, nonzero_imm6(rng)) // C.LUI
            }
            8 => encode_cb_imm(0b00, compact_dest(rng), random_imm6(rng)), // C.SRLI
            9 => encode_cb_imm(0b01, compact_dest(rng), random_imm6(rng)), // C.SRAI
            10 => encode_cb_imm(0b10, compact_dest(rng), random_imm6(rng)), // C.ANDI
            11 => encode_ca(0, 0b00, compact_dest(rng), compact_src(rng)), // C.SUB
            12 => encode_ca(0, 0b01, compact_dest(rng), compact_src(rng)), // C.XOR
            13 => encode_ca(0, 0b10, compact_dest(rng), compact_src(rng)), // C.OR
            14 => encode_ca(0, 0b11, compact_dest(rng), compact_src(rng)), // C.AND
            15 => encode_ca(1, 0b00, compact_dest(rng), compact_src(rng)), // C.SUBW
            16 => encode_ca(1, 0b01, compact_dest(rng), compact_src(rng)), // C.ADDW
            17 => encode_ci_shift(compressed_rd(rng), random_imm6(rng)),   // C.SLLI
            18 => encode_cr(0, compressed_rd(rng), nonzero_reg(rng)),      // C.MV
            19 => encode_cr(1, compressed_rd(rng), nonzero_reg(rng)),      // C.ADD
            20 => encode_compact_mem(0b010, compact_dest(rng), word_offset(rng)), // C.LW
            21 => encode_compact_mem(0b011, compact_dest(rng), double_offset(rng)), // C.LD
            22 => encode_compact_mem(0b110, compact_dest(rng), word_offset(rng)), // C.SW
            _ => encode_compact_mem(0b111, compact_dest(rng), double_offset(rng)), // C.SD
        };
        out.push(insn);
    }
    out
}

fn random_imm6(rng: &mut Rng) -> u8 {
    (rng.next_u64() & 0x3f) as u8
}

fn nonzero_imm6(rng: &mut Rng) -> u8 {
    let imm = random_imm6(rng);
    if imm == 0 { 1 } else { imm }
}

fn compressed_rd(rng: &mut Rng) -> u8 {
    // `pick_gpr` excludes x8, which must retain SCRATCH_BASE throughout the block.
    rng.pick_gpr()
}

fn compact_dest(rng: &mut Rng) -> u8 {
    // Compact register index 1..=7 maps to x9..=x15, never the x8 scratch base.
    1 + (rng.next_u64() % 7) as u8
}

fn compact_src(rng: &mut Rng) -> u8 {
    (rng.next_u64() & 7) as u8
}

fn nonzero_reg(rng: &mut Rng) -> u8 {
    1 + (rng.next_u64() % 31) as u8
}

fn word_offset(rng: &mut Rng) -> u16 {
    ((rng.next_u64() % 32) * 4) as u16
}

fn double_offset(rng: &mut Rng) -> u16 {
    ((rng.next_u64() % 32) * 8) as u16
}

fn encode_ci(funct3: u16, rd: u8, imm6: u8) -> u16 {
    debug_assert!(funct3 < 8 && rd < 32 && imm6 < 64);
    (funct3 << 13)
        | (u16::from(imm6 >> 5) << 12)
        | (u16::from(rd) << 7)
        | (u16::from(imm6 & 0x1f) << 2)
        | 0b01
}

fn encode_cb_imm(selector: u16, rd_prime: u8, imm6: u8) -> u16 {
    debug_assert!(selector < 3 && rd_prime < 8 && imm6 < 64);
    (0b100 << 13)
        | (u16::from(imm6 >> 5) << 12)
        | (selector << 10)
        | (u16::from(rd_prime) << 7)
        | (u16::from(imm6 & 0x1f) << 2)
        | 0b01
}

fn encode_ca(high_bit: u16, funct2: u16, rd_prime: u8, rs2_prime: u8) -> u16 {
    debug_assert!(high_bit < 2 && funct2 < 4 && rd_prime < 8 && rs2_prime < 8);
    (0b100 << 13)
        | (high_bit << 12)
        | (0b11 << 10)
        | (u16::from(rd_prime) << 7)
        | (funct2 << 5)
        | (u16::from(rs2_prime) << 2)
        | 0b01
}

fn encode_ci_shift(rd: u8, shamt: u8) -> u16 {
    debug_assert!(rd < 32 && shamt < 64);
    (u16::from(shamt >> 5) << 12) | (u16::from(rd) << 7) | (u16::from(shamt & 0x1f) << 2) | 0b10
}

fn encode_cr(high_bit: u16, rd: u8, rs2: u8) -> u16 {
    debug_assert!(high_bit < 2 && rd < 32 && rs2 > 0 && rs2 < 32);
    (0b100 << 13) | (high_bit << 12) | (u16::from(rd) << 7) | (u16::from(rs2) << 2) | 0b10
}

fn encode_compact_mem(funct3: u16, reg_prime: u8, offset: u16) -> u16 {
    debug_assert!(matches!(funct3, 0b010 | 0b011 | 0b110 | 0b111));
    debug_assert!(reg_prime > 0 && reg_prime < 8);
    let offset_bits = if funct3 == 0b010 || funct3 == 0b110 {
        debug_assert!(offset <= 124 && offset % 4 == 0);
        (((offset >> 3) & 0x7) << 10) | (((offset >> 2) & 1) << 6) | (((offset >> 6) & 1) << 5)
    } else {
        debug_assert!(offset <= 248 && offset % 8 == 0);
        (((offset >> 3) & 0x7) << 10) | (((offset >> 6) & 0x3) << 5)
    };
    (funct3 << 13) | offset_bits | (u16::from(reg_prime) << 2)
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

/// Appends a self-modifying sequence that warms an instruction-cache entry,
/// overwrites it through a guest store, executes `FENCE.I`, then re-enters it.
/// The replacement changes `a0` from 1 to 2, making stale execution observable.
fn gen_fence_i(out: &mut Vec<u32>) {
    const SMC_SNIPPET: [u32; 11] = [
        0x0000_0297, // auipc t0, 0
        0x0242_8293, // addi  t0, t0, 36 (address of patch slot)
        0x01c0_00ef, // jal   ra, +28 (execute original slot)
        0x0020_0337, // lui   t1, 0x200
        0x5133_0313, // addi  t1, t1, 0x513 => addi a0, zero, 2
        0x0062_a023, // sw    t1, 0(t0)
        0x0000_100f, // fence.i
        0x0080_00ef, // jal   ra, +8 (execute replacement slot)
        0x00c0_006f, // jal   zero, +12 (continue after snippet)
        0x0010_0513, // patch slot: addi a0, zero, 1
        0x0000_8067, // jalr  zero, 0(ra)
    ];
    out.extend_from_slice(&SMC_SNIPPET);
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

const ATOMIC_AMO_FUNCTS: [u32; 9] = [
    0x00, // amoadd
    0x01, // amoswap
    0x04, // amoxor
    0x08, // amoor
    0x0c, // amoand
    0x10, // amomin
    0x14, // amomax
    0x18, // amominu
    0x1c, // amomaxu
];
const ATOMIC_AMO_CASES: usize = ATOMIC_AMO_FUNCTS.len() * 2 * 4;
const ATOMIC_CASES: usize = ATOMIC_AMO_CASES + 12;

fn atomic_insn(funct5: u32, aqrl: u32, dbl: bool, rd: u8, rs1: u8, rs2: u8) -> u32 {
    debug_assert!(funct5 < 32 && aqrl < 4);
    r_type(
        0x2f,
        rd,
        if dbl { 0b011 } else { 0b010 },
        rs1,
        rs2,
        (funct5 << 2) | aqrl,
    )
}

fn atomic_slot_offset(slot: usize, dbl: bool) -> i32 {
    // Keep each of the first 256 snippets in its own 8-byte scratch slot. Word
    // atomics deliberately use the upper word, exercising 4-byte-but-not-8-byte
    // alignment while leaving the lower word as an adjacent sentinel.
    let base = ((slot % 256) * 8) as i32;
    if dbl { base } else { base + 4 }
}

fn gen_atomic_setup(out: &mut Vec<u32>, slot: usize, dbl: bool) {
    let offset = atomic_slot_offset(slot, dbl);
    out.push(i_type(0x13, 5, 0b000, 8, offset)); // addi t0, s0, offset
    if dbl {
        // t1 = INT64_MIN, t2 = INT64_MAX. These distinguish signed and
        // unsigned min/max and provide an edge-valued old result.
        out.push(i_type(0x13, 6, 0b000, 0, 1));
        out.push(i_type(0x13, 6, 0b001, 6, 63));
        out.push(i_type(0x13, 7, 0b000, 0, -1));
        out.push(i_type(0x13, 7, 0b101, 7, 1));
        out.push(s_type(0x23, 0b011, 5, 6, 0)); // sd t1, 0(t0)
    } else {
        // t1[31:0] = INT32_MIN, t2[31:0] = INT32_MAX. The old AMO.W/LR.W
        // result must be sign-extended, while only the addressed word changes.
        out.push(u_type(0x37, 6, 0x80000));
        out.push(u_type(0x37, 7, 0x80000));
        out.push(i_type(0x13, 7, 0b000, 7, -1));
        out.push(s_type(0x23, 0b010, 5, 7, -4)); // adjacent sentinel
        out.push(s_type(0x23, 0b010, 5, 6, 0)); // sw t1, 0(t0)
    }
}

fn gen_atomic_case(selector: usize, slot: usize, out: &mut Vec<u32>) {
    debug_assert!(selector < ATOMIC_CASES);
    if selector < ATOMIC_AMO_CASES {
        let funct5 = ATOMIC_AMO_FUNCTS[selector / 8];
        let dbl = (selector / 4) & 1 != 0;
        let aqrl = (selector & 3) as u32;
        gen_atomic_setup(out, slot, dbl);
        out.push(atomic_insn(funct5, aqrl, dbl, 9, 5, 7));
        return;
    }

    match selector - ATOMIC_AMO_CASES {
        0 => {
            // rd=x0: discard the old value without suppressing the memory update.
            gen_atomic_setup(out, slot, false);
            out.push(atomic_insn(0x01, 0b11, false, 0, 5, 7));
        }
        1 => {
            // rs2=x0: the zero source participates normally in the RMW.
            gen_atomic_setup(out, slot, false);
            out.push(atomic_insn(0x01, 0b10, false, 9, 5, 0));
        }
        2 => {
            // rd=rs2: the source must be captured before the old value is written.
            gen_atomic_setup(out, slot, false);
            out.push(atomic_insn(0x00, 0b01, false, 7, 5, 7));
        }
        3 => {
            // rd=rs1: the effective address must be captured before rd changes.
            gen_atomic_setup(out, slot, true);
            out.push(atomic_insn(0x04, 0b11, true, 5, 5, 7));
        }
        4 => {
            // rs2=rs1: store the address value itself into the selected word.
            gen_atomic_setup(out, slot, true);
            out.push(atomic_insn(0x01, 0, true, 9, 5, 5));
        }
        5 => {
            // Adjacent LR.W/SC.W: normal success path with acquire/release bits.
            gen_atomic_setup(out, slot, false);
            out.push(atomic_insn(0x02, 0b10, false, 9, 5, 0));
            out.push(atomic_insn(0x03, 0b01, false, 10, 5, 7));
        }
        6 => {
            // Adjacent LR.D/SC.D with both ordering bits set.
            gen_atomic_setup(out, slot, true);
            out.push(atomic_insn(0x02, 0b11, true, 9, 5, 0));
            out.push(atomic_insn(0x03, 0b11, true, 10, 5, 7));
        }
        7 => {
            // LR rd=x0 must still establish a reservation used by the SC.
            gen_atomic_setup(out, slot, false);
            out.push(atomic_insn(0x02, 0b01, false, 0, 5, 0));
            out.push(atomic_insn(0x03, 0b10, false, 10, 5, 7));
        }
        8 => {
            // SC rd=x0 must still update memory and consume the reservation.
            gen_atomic_setup(out, slot, false);
            out.push(atomic_insn(0x02, 0, false, 9, 5, 0));
            out.push(atomic_insn(0x03, 0b11, false, 0, 5, 7));
            out.push(i_type(0x03, 10, 0b010, 5, 0)); // lw a0, 0(t0)
        }
        9 => {
            // Every SC consumes the reservation; a second SC must fail.
            gen_atomic_setup(out, slot, true);
            out.push(atomic_insn(0x02, 0b10, true, 9, 5, 0));
            out.push(atomic_insn(0x03, 0b01, true, 10, 5, 7));
            out.push(atomic_insn(0x03, 0, true, 11, 5, 6));
        }
        10 => {
            // A mapped SC without a preceding LR must fail and leave RAM intact.
            gen_atomic_setup(out, slot, false);
            out.push(atomic_insn(0x03, 0, false, 9, 5, 7));
        }
        _ => {
            // SC rd=rs1: the effective address must be captured before the
            // success status overwrites the address register.
            gen_atomic_setup(out, slot, true);
            out.push(atomic_insn(0x02, 0b10, true, 9, 5, 0));
            out.push(atomic_insn(0x03, 0b01, true, 5, 5, 7));
        }
    }
}

fn gen_csr_trap(rng: &mut Rng, out: &mut Vec<u32>) {
    match rng.next_u64() % 23 {
        0 => gen_csr_alias_set(out),
        1 => gen_csr_alias_clear(out),
        2 => gen_csr_immediate_forms(out),
        3 => gen_csr_write_suppression(out),
        4 => gen_read_only_csr_traps(out),
        selector => gen_csr_single(rng, selector - 5, out),
    }
}

fn gen_csr_alias_set(out: &mut Vec<u32>) {
    out.extend([
        i_type(0x13, 28, 0b000, 0, 0x105),
        i_type(0x13, 29, 0b000, 0, 0x050),
        i_type(0x73, 0, 0b001, 28, 0x340),  // csrw  mscratch, x28
        i_type(0x73, 29, 0b010, 29, 0x340), // csrrs x29, mscratch, x29
        i_type(0x73, 30, 0b010, 0, 0x340),  // csrr  x30, mscratch
    ]);
}

fn gen_csr_alias_clear(out: &mut Vec<u32>) {
    out.extend([
        i_type(0x13, 28, 0b000, 0, 0x155),
        i_type(0x13, 29, 0b000, 0, 0x050),
        i_type(0x73, 0, 0b001, 28, 0x140),  // csrw  sscratch, x28
        i_type(0x73, 29, 0b011, 29, 0x140), // csrrc x29, sscratch, x29
        i_type(0x73, 30, 0b010, 0, 0x140),  // csrr  x30, sscratch
    ]);
}

fn gen_csr_immediate_forms(out: &mut Vec<u32>) {
    out.extend([
        i_type(0x73, 31, 0b101, 0x1b, 0x340), // csrrwi x31, mscratch, 0x1b
        i_type(0x73, 31, 0b110, 0x04, 0x340), // csrrsi x31, mscratch, 0x04
        i_type(0x73, 31, 0b111, 0x03, 0x340), // csrrci x31, mscratch, 0x03
        i_type(0x73, 31, 0b110, 0, 0x340),    // csrrsi x31, mscratch, 0
        i_type(0x73, 30, 0b111, 0, 0x340),    // csrrci x30, mscratch, 0
        i_type(0x73, 29, 0b010, 0, 0x340),    // csrr   x29, mscratch
    ]);
}

fn gen_csr_write_suppression(out: &mut Vec<u32>) {
    out.extend([
        i_type(0x13, 28, 0b000, 0, 0x155),
        i_type(0x13, 29, 0b000, 0, 0x002),
        i_type(0x73, 0, 0b001, 28, 0x140), // csrw  sscratch, x28
        i_type(0x73, 0, 0b010, 0, 0x140),  // csrrs x0, sscratch, x0
        i_type(0x73, 0, 0b011, 0, 0x140),  // csrrc x0, sscratch, x0
        i_type(0x73, 0, 0b010, 29, 0x140), // csrrs x0, sscratch, x29
        i_type(0x73, 30, 0b010, 0, 0x140), // csrr  x30, sscratch
        i_type(0x73, 0, 0b011, 29, 0x140), // csrrc x0, sscratch, x29
        i_type(0x73, 31, 0b010, 0, 0x140), // csrr  x31, sscratch
    ]);
}

fn gen_read_only_csr_traps(out: &mut Vec<u32>) {
    out.extend([
        i_type(0x73, 28, 0b010, 0, 0xf14), // csrrs  x28, mhartid, x0
        i_type(0x73, 29, 0b011, 0, 0xf14), // csrrc  x29, mhartid, x0
        i_type(0x73, 30, 0b110, 0, 0xf14), // csrrsi x30, mhartid, 0
        i_type(0x73, 31, 0b111, 0, 0xf14), // csrrci x31, mhartid, 0
        i_type(0x13, 31, 0b000, 0, 0x05a),
        i_type(0x73, 31, 0b001, 0, 0xf14), // csrrw  x31, mhartid, x0: illegal
        i_type(0x13, 31, 0b000, 0, 0x05a),
        i_type(0x73, 31, 0b101, 0, 0xf14), // csrrwi x31, mhartid, 0: illegal
    ]);
}

fn gen_csr_single(rng: &mut Rng, selector: u64, out: &mut Vec<u32>) {
    let rd = rng.pick_gpr();
    let rs1 = rng.pick_src_gpr();
    let (insn, readback_csr) = match selector {
        // Safe CSR reads/writes. Keep WLRL/WARL values portable across
        // implementations so exact-value differential comparison is meaningful.
        0 => (i_type(0x73, rd, 0b001, rs1, 0x340), Some(0x340)),
        1 => (i_type(0x73, rd, 0b010, rs1, 0x340), Some(0x340)),
        2 => (i_type(0x73, rd, 0b011, rs1, 0x340), Some(0x340)),
        3 => (i_type(0x73, rd, 0b001, rs1, 0x140), Some(0x140)),
        4 => (i_type(0x73, rd, 0b001, rs1, 0x001), None),
        5 => (i_type(0x73, rd, 0b101, 0, 0x002), None),
        6 => (i_type(0x73, rd, 0b101, 0, 0x003), None),
        // mvendorid, marchid, mimpid, and misa are deliberately excluded: their
        // values legitimately differ between rivemu and QEMU. mhartid is safe for -smp 1.
        7 => (i_type(0x73, rd, 0b010, 0, 0xf14), None),
        8 => (i_type(0x73, rd, 0b101, 2, 0x142), None),
        9 => (i_type(0x73, rd, 0b010, rs1, 0x001), None),
        10 => (i_type(0x73, rd, 0b101, 0, 0x143), None),
        11 => (i_type(0x73, rd, 0b010, rs1, 0x140), Some(0x140)),
        12 => (i_type(0x73, rd, 0b101, 0, 0x341), None),
        13 => (i_type(0x73, rd, 0b101, 0, 0x141), None),
        14 => (i_type(0x73, rd, 0b101, 0, 0x105), None),
        15 => (i_type(0x73, rd, 0b101, 0, 0x180), None),
        // Synchronous traps caught by our M-mode handler at mtvec = 0x8000_2000:
        16 => (0x0000_0073, None), // ecall (from M-mode -> mcause = 11)
        _ => (0x0000_7003, None),  // illegal 32-bit instruction
    };
    out.push(insn);
    if let Some(csr) = readback_csr {
        out.push(i_type(0x73, 31, 0b010, 0, csr));
    }
}

#[cfg(test)]
mod tests {
    use rivemu_cpu_riscv::decode::{self, Op};

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
    fn fence_i_suite_names_parse() {
        assert_eq!(Suite::parse("fencei"), Some(Suite::FenceI));
        assert_eq!(Suite::parse("fence-i"), Some(Suite::FenceI));
        assert_eq!(Suite::parse("smc"), Some(Suite::FenceI));
        assert_eq!(Suite::FenceI.name(), "fence-i-smc");
    }

    #[test]
    fn compressed_suite_names_parse() {
        assert_eq!(Suite::parse("compressed"), Some(Suite::Compressed));
        assert_eq!(Suite::parse("rvc"), Some(Suite::Compressed));
        assert_eq!(Suite::parse("c"), Some(Suite::Compressed));
        assert_eq!(Suite::Compressed.name(), "rv64c");
    }

    #[test]
    fn atomics_suite_names_parse() {
        assert_eq!(Suite::parse("atomic"), Some(Suite::Atomics));
        assert_eq!(Suite::parse("atomics"), Some(Suite::Atomics));
        assert_eq!(Suite::parse("rv64a"), Some(Suite::Atomics));
        assert_eq!(Suite::parse("lrsc"), Some(Suite::Atomics));
        assert_eq!(Suite::Atomics.name(), "rv64a-directed");
    }

    #[test]
    fn atomic_matrix_covers_every_amo_width_and_ordering_encoding() {
        let mut seen = [[[false; 4]; 2]; ATOMIC_AMO_FUNCTS.len()];

        for selector in 0..ATOMIC_AMO_CASES {
            let mut words = Vec::new();
            gen_atomic_case(selector, selector, &mut words);

            let funct_index = selector / 8;
            let dbl_index = (selector / 4) & 1;
            let aqrl = selector & 3;
            let raw = *words.last().unwrap();
            let insn = decode::decode(raw);
            assert_eq!(insn.op, Op::Amo, "selector {selector}");
            assert_eq!(
                usize::from(insn.funct),
                ATOMIC_AMO_FUNCTS[funct_index] as usize
            );
            assert_eq!(usize::from(insn.dbl), dbl_index);
            assert_eq!(((raw >> 25) & 3) as usize, aqrl);
            assert_eq!((insn.rd, insn.rs1, insn.rs2), (9, 5, 7));

            let address = decode::decode(words[0]);
            assert_eq!(address.op, Op::Addi);
            assert_eq!((address.rd, address.rs1), (5, 8));
            assert_eq!(address.imm, atomic_slot_offset(selector, insn.dbl));
            assert_eq!(address.imm.rem_euclid(8), if insn.dbl { 0 } else { 4 });

            let initial_store = decode::decode(words[words.len() - 2]);
            assert_eq!(initial_store.op, if insn.dbl { Op::Sd } else { Op::Sw });
            assert_eq!((initial_store.rs1, initial_store.rs2), (5, 6));
            assert_eq!(initial_store.imm, 0);

            seen[funct_index][dbl_index][aqrl] = true;
        }

        assert!(seen.into_iter().flatten().flatten().all(|covered| covered));
    }

    #[test]
    fn atomic_directed_cases_cover_aliases_and_lrsc() {
        for directed in 0..12 {
            let selector = ATOMIC_AMO_CASES + directed;
            let mut words = Vec::new();
            gen_atomic_case(selector, directed, &mut words);
            let atomics: Vec<_> = words
                .iter()
                .copied()
                .map(decode::decode)
                .filter(|insn| matches!(insn.op, Op::Amo | Op::Lr | Op::Sc))
                .collect();
            assert!(!atomics.is_empty(), "directed selector {directed}");
            assert!(atomics.iter().all(|insn| insn.rs1 == 5));
            assert!(atomics.iter().all(|insn| insn.op != Op::Illegal));

            for word in words.iter().copied().map(decode::decode) {
                if matches!(
                    word.op,
                    Op::Addi
                        | Op::Slli
                        | Op::Srli
                        | Op::Lui
                        | Op::Lw
                        | Op::Ld
                        | Op::Lr
                        | Op::Sc
                        | Op::Amo
                ) {
                    assert!(!matches!(word.rd, 8 | 27));
                }
            }

            match directed {
                0 => assert_eq!(atomics[0].rd, 0),
                1 => assert_eq!(atomics[0].rs2, 0),
                2 => assert_eq!((atomics[0].rd, atomics[0].rs2), (7, 7)),
                3 => assert_eq!((atomics[0].rd, atomics[0].rs1), (5, 5)),
                4 => assert_eq!((atomics[0].rs1, atomics[0].rs2), (5, 5)),
                5 | 6 => assert!(
                    matches!(atomics.as_slice(), [lr, sc] if lr.op == Op::Lr && sc.op == Op::Sc)
                ),
                7 => {
                    assert_eq!(atomics[0].op, Op::Lr);
                    assert_eq!(atomics[0].rd, 0);
                    assert_eq!(atomics[1].op, Op::Sc);
                }
                8 => {
                    assert_eq!(atomics[0].op, Op::Lr);
                    assert_eq!(atomics[1].op, Op::Sc);
                    assert_eq!(atomics[1].rd, 0);
                    assert_eq!(decode::decode(*words.last().unwrap()).op, Op::Lw);
                }
                9 => assert!(matches!(atomics.as_slice(), [lr, first, second]
                        if lr.op == Op::Lr && first.op == Op::Sc && second.op == Op::Sc)),
                10 => assert_eq!(atomics[0].op, Op::Sc),
                _ => {
                    assert!(matches!(atomics.as_slice(), [lr, sc]
                            if lr.op == Op::Lr && sc.op == Op::Sc));
                    assert_eq!((atomics[1].rd, atomics[1].rs1), (5, 5));
                }
            }
        }
    }

    #[test]
    fn atomic_generator_cycles_through_full_amo_matrix() {
        let mut seen = [[[false; 4]; 2]; ATOMIC_AMO_FUNCTS.len()];

        let mut rng = Rng::new(1);
        for raw in generate_block(&mut rng, Suite::Atomics, 1024) {
            let insn = decode::decode(raw);
            if insn.op != Op::Amo {
                continue;
            }
            let Some(funct_index) = ATOMIC_AMO_FUNCTS
                .iter()
                .position(|&funct| funct == u32::from(insn.funct))
            else {
                panic!("unexpected AMO function {:#x}", insn.funct);
            };
            let dbl_index = usize::from(insn.dbl);
            let aqrl = ((raw >> 25) & 3) as usize;
            seen[funct_index][dbl_index][aqrl] = true;
        }

        assert!(seen.into_iter().flatten().flatten().all(|covered| covered));
    }

    #[test]
    fn compressed_generator_is_exact_legal_and_scratch_safe() {
        const SCRATCH_LEN: i32 = 4096;

        for seed in 1..=128 {
            let mut rng = Rng::new(seed);
            let halfwords = generate_compressed_block(&mut rng, 128);
            assert_eq!(halfwords.len(), 128);

            for raw in halfwords {
                assert_ne!(raw & 3, 3, "seed {seed:#x}, raw {raw:#06x}");
                let insn = decode::decode_compressed(raw);
                assert_ne!(insn.op, Op::Illegal, "seed {seed:#x}, raw {raw:#06x}");
                assert_eq!(insn.len, 2, "seed {seed:#x}, raw {raw:#06x}");
                assert_eq!(insn.raw, u32::from(raw));
                assert!(
                    matches!(
                        insn.op,
                        Op::Addi
                            | Op::Addiw
                            | Op::Lui
                            | Op::Srli
                            | Op::Srai
                            | Op::Andi
                            | Op::Sub
                            | Op::Xor
                            | Op::Or
                            | Op::And
                            | Op::Subw
                            | Op::Addw
                            | Op::Slli
                            | Op::Add
                            | Op::Lw
                            | Op::Ld
                            | Op::Sw
                            | Op::Sd
                    ),
                    "unexpected operation for seed {seed:#x}, raw {raw:#06x}: {insn:?}"
                );

                match insn.op {
                    Op::Lw | Op::Ld => {
                        let width = if insn.op == Op::Lw { 4 } else { 8 };
                        assert_eq!(insn.rs1, 8);
                        assert!((9..=15).contains(&insn.rd));
                        assert!(insn.imm >= 0 && insn.imm + width <= SCRATCH_LEN);
                        assert_eq!(insn.imm % width, 0);
                    }
                    Op::Sw | Op::Sd => {
                        let width = if insn.op == Op::Sw { 4 } else { 8 };
                        assert_eq!(insn.rs1, 8);
                        assert!((9..=15).contains(&insn.rs2));
                        assert!(insn.imm >= 0 && insn.imm + width <= SCRATCH_LEN);
                        assert_eq!(insn.imm % width, 0);
                    }
                    Op::Lui => {
                        assert_ne!(insn.rd, 2);
                        assert_ne!(insn.rd, 8);
                        assert_ne!(insn.imm, 0);
                    }
                    _ => assert_ne!(
                        insn.rd, 8,
                        "x8 scratch base clobber for seed {seed:#x}, raw {raw:#06x}: {insn:?}"
                    ),
                }
            }
        }
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
    fn fence_i_snippet_warms_patches_and_reenters_one_slot() {
        let mut words = Vec::new();
        gen_fence_i(&mut words);
        assert_eq!(words.len(), 11);

        let base = 0x8000_0100u64;
        assert_eq!(words[0], 0x0000_0297); // auipc t0, 0
        assert_eq!(decode_i_imm(words[1]), 36);
        assert_eq!(
            base + u64::try_from(decode_i_imm(words[1])).unwrap(),
            base + 36
        );

        assert_eq!(base + 8 + decode_j_imm(words[2]) as u64, base + 36);
        assert_eq!(base + 28 + decode_j_imm(words[7]) as u64, base + 36);
        assert_eq!(base + 32 + decode_j_imm(words[8]) as u64, base + 44);

        let replacement =
            (words[3] & 0xffff_f000).wrapping_add(u32::try_from(decode_i_imm(words[4])).unwrap());
        assert_eq!(replacement, 0x0020_0513); // addi a0, zero, 2
        assert_eq!(words[9], 0x0010_0513); // original: addi a0, zero, 1

        assert_eq!(words[5] & 0x7f, 0x23); // sw t1, 0(t0)
        assert_eq!((words[5] >> 15) & 0x1f, 5);
        assert_eq!((words[5] >> 20) & 0x1f, 6);
        assert_eq!(words[6], 0x0000_100f); // fence.i
        assert_eq!(words[10], 0x0000_8067); // jalr zero, 0(ra)
    }

    #[test]
    fn repeated_fence_i_snippets_end_at_the_checkpoint() {
        let mut rng = Rng::new(1);
        let words = generate_block(&mut rng, Suite::FenceI, 12);
        assert_eq!(words.len(), 23);
        assert_eq!(&words[..11], &words[11..22]);
        assert_eq!(words[22], EBREAK);
    }

    fn simulate_scratch_csr(words: &[u32], expected_csr: u16) -> ([u64; 32], u64) {
        let mut regs = [0u64; 32];
        let mut csr = 0u64;
        for &word in words {
            match word & 0x7f {
                0x13 => {
                    let rd = ((word >> 7) & 0x1f) as usize;
                    let rs1 = ((word >> 15) & 0x1f) as usize;
                    if rd != 0 {
                        regs[rd] = regs[rs1].wrapping_add_signed(i64::from(decode_i_imm(word)));
                    }
                }
                0x73 => {
                    assert_eq!((word >> 20) as u16, expected_csr);
                    let rd = ((word >> 7) & 0x1f) as usize;
                    let funct3 = (word >> 12) & 7;
                    let rs1_or_zimm = ((word >> 15) & 0x1f) as usize;
                    let source = if funct3 >= 0b101 {
                        rs1_or_zimm as u64
                    } else {
                        regs[rs1_or_zimm]
                    };
                    let old = csr;
                    match funct3 {
                        0b001 | 0b101 => csr = source,
                        0b010 | 0b110 if source != 0 => csr |= source,
                        0b011 | 0b111 if source != 0 => csr &= !source,
                        0b010 | 0b011 | 0b110 | 0b111 => {}
                        _ => panic!("unexpected CSR funct3 {funct3:#x}"),
                    }
                    if rd != 0 {
                        regs[rd] = old;
                    }
                }
                opcode => panic!("unexpected opcode {opcode:#x}"),
            }
            regs[0] = 0;
        }
        (regs, csr)
    }

    #[test]
    fn csr_alias_templates_use_original_source_values() {
        let mut set_words = Vec::new();
        gen_csr_alias_set(&mut set_words);
        let (set_regs, set_csr) = simulate_scratch_csr(&set_words, 0x340);
        assert_eq!(set_words.len(), 5);
        assert_eq!(set_regs[29], 0x105);
        assert_eq!(set_regs[30], 0x155);
        assert_eq!(set_csr, 0x155);

        let mut clear_words = Vec::new();
        gen_csr_alias_clear(&mut clear_words);
        let (clear_regs, clear_csr) = simulate_scratch_csr(&clear_words, 0x140);
        assert_eq!(clear_words.len(), 5);
        assert_eq!(clear_regs[29], 0x155);
        assert_eq!(clear_regs[30], 0x105);
        assert_eq!(clear_csr, 0x105);
    }

    #[test]
    fn csr_immediate_and_suppression_templates_expose_final_values() {
        let mut immediate_words = Vec::new();
        gen_csr_immediate_forms(&mut immediate_words);
        let (immediate_regs, immediate_csr) = simulate_scratch_csr(&immediate_words, 0x340);
        assert_eq!(immediate_words.len(), 6);
        assert_eq!(immediate_regs[29], 0x1c);
        assert_eq!(immediate_regs[30], 0x1c);
        assert_eq!(immediate_regs[31], 0x1c);
        assert_eq!(immediate_csr, 0x1c);

        let mut suppression_words = Vec::new();
        gen_csr_write_suppression(&mut suppression_words);
        let (suppression_regs, suppression_csr) = simulate_scratch_csr(&suppression_words, 0x140);
        assert_eq!(suppression_words.len(), 9);
        assert_eq!(suppression_regs[30], 0x157);
        assert_eq!(suppression_regs[31], 0x155);
        assert_eq!(suppression_csr, 0x155);
    }

    #[test]
    fn read_only_csr_template_has_legal_reads_and_illegal_writes() {
        let mut words = Vec::new();
        gen_read_only_csr_traps(&mut words);
        assert_eq!(words.len(), 8);
        for (index, expected_funct3) in [0b010, 0b011, 0b110, 0b111].into_iter().enumerate() {
            assert_eq!((words[index] >> 20) & 0xfff, 0xf14);
            assert_eq!((words[index] >> 12) & 7, expected_funct3);
            assert_eq!((words[index] >> 15) & 0x1f, 0);
        }
        assert_eq!(decode_i_imm(words[4]), 0x5a);
        assert_eq!((words[5] >> 20) & 0xfff, 0xf14);
        assert_eq!((words[5] >> 12) & 7, 0b001);
        assert_eq!(decode_i_imm(words[6]), 0x5a);
        assert_eq!((words[7] >> 20) & 0xfff, 0xf14);
        assert_eq!((words[7] >> 12) & 7, 0b101);
    }

    #[test]
    fn random_scratch_mutations_append_a_gpr_readback() {
        for selector in [0, 1, 2, 3, 11] {
            let mut rng = Rng::new(selector + 1);
            let mut words = Vec::new();
            gen_csr_single(&mut rng, selector, &mut words);
            assert_eq!(words.len(), 2);
            assert_eq!((words[1] >> 7) & 0x1f, 31);
            assert_eq!((words[1] >> 12) & 7, 0b010);
            assert_eq!((words[1] >> 15) & 0x1f, 0);
            assert_eq!((words[1] >> 20) & 0xfff, (words[0] >> 20) & 0xfff);
        }
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
