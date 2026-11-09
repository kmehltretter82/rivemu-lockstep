//! Directed and constrained-random `RVV 1.0` (`V`, `VLEN = 256`, `ELEN = 64`) suite (`Suite::Vector`).
//!
//! Exercises vector configuration (`vsetvli`, `vsetivli`, `vsetvl`, `vlenb`, `vl`, `vtype`, `vill`),
//! vector loads and stores (unit-stride, strided, whole-register, and mask loads/stores),
//! vector integer ALU, fixed-point saturating/averaging/narrowing, integer multiply/divide/MAC,
//! widening/extension, reductions, masks/permutations (`vcpop.m`, `vfirst.m`, `vmsbf.m`, `vmsof.m`,
//! `vmsif.m`, `viota.m`, `vid.v`, `vslideup`, `vslidedown`, `vslide1up`, `vslide1down`, `vrgather`,
//! `vcompress.vm`), and vector floating-point (`vfadd`, `vfsub`, `vfmul`, `vfdiv`, `vfsqrt`,
//! `vfmin`, `vfmax`, `vfsgnj*`, `vfmacc`, `vfcvt*`, `vfclass`, `vmfeq`, `vmflt`, `vfredusum`,
//! `vfredmax`, `vfmv.f.s`, `vfmv.s.f`).

use crate::ArchState;
use crate::risu::encode::{EBREAK, i_type, u_type};
use crate::risu::seed::Rng;

const fn csrrw(csr: u16, rd: u8, rs1: u8) -> u32 {
    i_type(0x73, rd, 0b001, rs1, csr as i32)
}

const fn csrrs(csr: u16, rd: u8, rs1: u8) -> u32 {
    i_type(0x73, rd, 0b010, rs1, csr as i32)
}

const fn vsetivli(rd: u8, uimm5: u8, zimm10: u16) -> u32 {
    (0b11 << 30)
        | (((zimm10 as u32) & 0x3ff) << 20)
        | (((uimm5 as u32) & 0x1f) << 15)
        | (0b111 << 12)
        | (((rd as u32) & 0x1f) << 7)
        | 0x57
}

const fn vsetvl(rd: u8, rs1: u8, rs2: u8) -> u32 {
    (0b1000000 << 25)
        | (((rs2 as u32) & 0x1f) << 20)
        | (((rs1 as u32) & 0x1f) << 15)
        | (0b111 << 12)
        | (((rd as u32) & 0x1f) << 7)
        | 0x57
}

const fn vop(funct6: u8, vm: u8, vs2: u8, rs1: u8, f3: u8, vd: u8) -> u32 {
    (((funct6 as u32) & 0x3f) << 26)
        | (((vm as u32) & 1) << 25)
        | (((vs2 as u32) & 0x1f) << 20)
        | (((rs1 as u32) & 0x1f) << 15)
        | (((f3 as u32) & 0x7) << 12)
        | (((vd as u32) & 0x1f) << 7)
        | 0x57
}

const fn vload_unit(width: u8, vm: u8, lumop: u8, rs1: u8, nf: u8, vd: u8) -> u32 {
    (((nf as u32) & 0x7) << 29)
        | (((vm as u32) & 1) << 25)
        | (((lumop as u32) & 0x1f) << 20)
        | (((rs1 as u32) & 0x1f) << 15)
        | (((width as u32) & 0x7) << 12)
        | (((vd as u32) & 0x1f) << 7)
        | 0x07
}

const fn vload_strided(width: u8, vm: u8, rs2: u8, rs1: u8, vd: u8) -> u32 {
    (0b10 << 26)
        | (((vm as u32) & 1) << 25)
        | (((rs2 as u32) & 0x1f) << 20)
        | (((rs1 as u32) & 0x1f) << 15)
        | (((width as u32) & 0x7) << 12)
        | (((vd as u32) & 0x1f) << 7)
        | 0x07
}

const fn vstore_unit(width: u8, vm: u8, sumop: u8, rs1: u8, nf: u8, vs3: u8) -> u32 {
    (((nf as u32) & 0x7) << 29)
        | (((vm as u32) & 1) << 25)
        | (((sumop as u32) & 0x1f) << 20)
        | (((rs1 as u32) & 0x1f) << 15)
        | (((width as u32) & 0x7) << 12)
        | (((vs3 as u32) & 0x1f) << 7)
        | 0x27
}

const fn vstore_strided(width: u8, vm: u8, rs2: u8, rs1: u8, vs3: u8) -> u32 {
    (0b10 << 26)
        | (((vm as u32) & 1) << 25)
        | (((rs2 as u32) & 0x1f) << 20)
        | (((rs1 as u32) & 0x1f) << 15)
        | (((width as u32) & 0x7) << 12)
        | (((vs3 as u32) & 0x1f) << 7)
        | 0x27
}

/// Configures the initial architectural state for `Suite::Vector`.
pub(crate) fn configure_case(_seed: u64, _state: &mut ArchState) {}

/// Generates a deterministic RVV 1.0 instruction block terminated by `EBREAK`.
pub(crate) fn generate_block(rng: &mut Rng, seed: u64, _num_insns: usize) -> Vec<u32> {
    let mut out = Vec::with_capacity(48);

    // Common preamble: enable mstatus.VS = Dirty (0x600), clear vcsr/vstart,
    // and load v0..v31 (1024 bytes) from SCRATCH_BASE (s0 = x8).
    out.push(i_type(0x13, 5, 0b000, 0, 0x600)); // addi t0, zero, 0x600 (mstatus.VS = Dirty)
    out.push(csrrs(0x300, 0, 5)); // csrs mstatus, t0
    out.push(csrrw(0x00f, 0, 0)); // csrw vcsr, zero
    out.push(csrrw(0x008, 0, 0)); // csrw vstart, zero
    out.push(vload_unit(0b111, 1, 0x08, 8, 7, 0)); // vl8re64.v v0, (s0)
    out.push(i_type(0x13, 5, 0b000, 8, 256)); // addi t0, s0, 256
    out.push(vload_unit(0b111, 1, 0x08, 5, 7, 8)); // vl8re64.v v8, (t0)
    // Initialize v16..v31 as well: a persistent reference process (QEMU)
    // would otherwise carry them over from the previous block.
    out.push(i_type(0x13, 5, 0b000, 8, 512)); // addi t0, s0, 512
    out.push(vload_unit(0b111, 1, 0x08, 5, 7, 16)); // vl8re64.v v16, (t0)
    out.push(i_type(0x13, 5, 0b000, 8, 768)); // addi t0, s0, 768
    out.push(vload_unit(0b111, 1, 0x08, 5, 7, 24)); // vl8re64.v v24, (t0)

    match seed & 7 {
        0 => {
            // Sub-mode 0: Vector configuration (vsetivli, vsetvl, vlenb, vl, vtype, vill)
            // and unit-stride, strided, whole-register, and mask loads/stores.
            out.push(csrrs(0xc22, 10, 0)); // csrr a0, vlenb (32)
            out.push(vsetivli(11, 4, 0x018)); // vsetivli a1, 4, e64, m1, tu, mu
            out.push(csrrs(0xc20, 12, 0)); // csrr a2, vl
            out.push(csrrs(0xc21, 13, 0)); // csrr a3, vtype
            out.push(vload_unit(0b111, 1, 0x00, 8, 0, 2)); // vle64.v v2, (s0)
            out.push(i_type(0x13, 6, 0b000, 8, 32)); // addi t1, s0, 32
            out.push(vload_unit(0b111, 1, 0x00, 6, 0, 4)); // vle64.v v4, (t1)
            out.push(vop(0x00, 1, 2, 4, 0, 6)); // vadd.vv v6, v2, v4
            out.push(i_type(0x13, 7, 0b000, 8, 512)); // addi t2, s0, 512
            out.push(vstore_unit(0b111, 1, 0x00, 7, 0, 6)); // vse64.v v6, (t2)
            out.push(i_type(0x13, 28, 0b000, 0, 16)); // addi t3, zero, 16
            out.push(vload_strided(0b111, 1, 28, 8, 8)); // vlse64.v v8, (s0), t3
            out.push(i_type(0x13, 29, 0b000, 8, 576)); // addi t4, s0, 576
            out.push(vstore_strided(0b111, 1, 28, 29, 8)); // vsse64.v v8, (t4), t3
            out.push(vload_unit(0b000, 1, 0x0b, 8, 0, 0)); // vlm.v v0, (s0)
            out.push(i_type(0x13, 30, 0b000, 8, 640)); // addi t5, s0, 640
            out.push(vstore_unit(0b000, 1, 0x0b, 30, 0, 0)); // vsm.v v0, (t5)
            // Test vsetvl with reserved vtype bits -> sets vill = 1 (bit 63), vl = 0:
            out.push(u_type(0x37, 5, 1)); // lui t0, 1 (0x1000)
            out.push(vsetvl(14, 11, 5)); // vsetvl a4, a1, t0
            out.push(csrrs(0xc21, 15, 0)); // csrr a5, vtype
            out.push(csrrs(0xc20, 16, 0)); // csrr a6, vl
            // Restore valid vtype (e32, m1, vl=8) and execute whole-register move vmv1r.v:
            out.push(vsetivli(11, 8, 0x010)); // vsetivli a1, 8, e32, m1, tu, mu
            out.push(vop(0x27, 1, 6, 0, 3, 10)); // vmv1r.v v10, v6
        }
        1 => {
            // Sub-mode 1: Integer ALU, fixed-point saturating/averaging/narrowing,
            // multiply/divide/MAC, and widening/extension.
            out.push(vsetivli(10, 8, 0x010)); // vsetivli a0, 8, e32, m1, tu, mu
            out.push(vload_unit(0b110, 1, 0x00, 8, 0, 2)); // vle32.v v2, (s0)
            out.push(i_type(0x13, 5, 0b000, 8, 32)); // addi t0, s0, 32
            out.push(vload_unit(0b110, 1, 0x00, 5, 0, 4)); // vle32.v v4, (t0)
            out.push(vop(0x00, 1, 2, 4, 0, 6)); // vadd.vv v6, v2, v4
            out.push(vop(0x02, 1, 6, 4, 0, 8)); // vsub.vv v8, v6, v4
            out.push(vop(0x04, 1, 2, 4, 0, 6)); // vminu.vv v6, v2, v4
            out.push(vop(0x07, 1, 2, 4, 0, 8)); // vmax.vv v8, v2, v4
            out.push(vop(0x09, 1, 6, 8, 0, 6)); // vand.vv v6, v6, v8
            out.push(vop(0x0a, 1, 2, 4, 0, 8)); // vor.vv v8, v2, v4
            out.push(vop(0x0b, 1, 6, 5, 3, 6)); // vxor.vi v6, v6, 5
            out.push(vop(0x25, 1, 2, 3, 3, 8)); // vsll.vi v8, v2, 3
            out.push(vop(0x28, 1, 4, 2, 3, 6)); // vsrl.vi v6, v4, 2
            out.push(vop(0x29, 1, 4, 2, 3, 8)); // vsra.vi v8, v4, 2
            // Saturating and averaging operations:
            out.push(vop(0x20, 1, 2, 4, 0, 6)); // vsaddu.vv v6, v2, v4
            out.push(vop(0x21, 1, 2, 4, 0, 8)); // vsadd.vv v8, v2, v4
            out.push(vop(0x08, 1, 6, 4, 2, 6)); // vaaddu.vv v6, v6, v4
            out.push(vop(0x09, 1, 8, 4, 2, 8)); // vaadd.vv v8, v8, v4
            out.push(csrrs(0x00f, 11, 0)); // csrr a1, vcsr
            out.push(csrrs(0x009, 12, 0)); // csrr a2, vxsat
            // Multiply, divide, remainder, MAC:
            out.push(vop(0x25, 1, 2, 4, 2, 10)); // vmul.vv v10, v2, v4
            out.push(vop(0x24, 1, 2, 4, 2, 12)); // vmulhu.vv v12, v2, v4
            out.push(vop(0x20, 1, 2, 4, 2, 14)); // vdivu.vv v14, v2, v4
            out.push(vop(0x2d, 1, 2, 4, 2, 10)); // vmacc.vv v10, v4, v2
            // Widening (SEW=16 -> 32) and narrowing (SEW=32 -> 16):
            out.push(vsetivli(10, 8, 0x008)); // vsetivli a0, 8, e16, m1, tu, mu
            out.push(vop(0x30, 1, 2, 4, 2, 12)); // vwaddu.vv v12, v2, v4
            out.push(vop(0x2c, 1, 12, 3, 3, 6)); // vnsrl.wi v6, v12, 3
            out.push(vop(0x2e, 1, 12, 2, 3, 8)); // vnclipu.wi v8, v12, 2
            out.push(vsetivli(10, 8, 0x010)); // vsetivli a0, 8, e32, m1, tu, mu
            out.push(vop(0x12, 1, 6, 6, 2, 12)); // vzext.vf2 v12, v6
            out.push(vop(0x12, 1, 8, 7, 2, 14)); // vsext.vf2 v14, v8
        }
        2 => {
            // Sub-mode 2: Reductions, integer compares, mask logical/bit ops
            // (vcpop.m, vfirst.m, vmsbf.m, vmsof.m, vmsif.m, viota.m, vid.v),
            // and permutations (vslideup, vslidedown, vslide1up, vslide1down, vrgather, vcompress.vm).
            out.push(vsetivli(10, 8, 0x010)); // vsetivli a0, 8, e32, m1, tu, mu
            out.push(vload_unit(0b110, 1, 0x00, 8, 0, 2)); // vle32.v v2, (s0)
            out.push(i_type(0x13, 5, 0b000, 8, 32)); // addi t0, s0, 32
            out.push(vload_unit(0b110, 1, 0x00, 5, 0, 4)); // vle32.v v4, (t0)
            out.push(vop(0x00, 1, 2, 4, 2, 6)); // vredsum.vs v6, v2, v4
            out.push(vop(0x06, 1, 2, 4, 2, 8)); // vredmaxu.vs v8, v2, v4
            out.push(vop(0x05, 1, 2, 4, 2, 10)); // vredmin.vs v10, v2, v4
            out.push(vop(0x03, 1, 2, 4, 2, 12)); // vredxor.vs v12, v2, v4
            out.push(vop(0x10, 1, 6, 0, 2, 11)); // vmv.x.s a1, v6
            out.push(vop(0x10, 1, 8, 0, 2, 12)); // vmv.x.s a2, v8
            out.push(vop(0x10, 1, 10, 0, 2, 13)); // vmv.x.s a3, v10
            out.push(vop(0x10, 1, 12, 0, 2, 14)); // vmv.x.s a4, v12
            // Compares & mask operations:
            out.push(vop(0x1a, 1, 2, 4, 0, 0)); // vmsltu.vv v0, v2, v4
            out.push(vop(0x19, 1, 2, 0, 3, 6)); // vmsne.vi v6, v2, 0
            out.push(vop(0x19, 1, 0, 6, 2, 0)); // vmand.mm v0, v0, v6
            out.push(vop(0x10, 1, 0, 16, 2, 15)); // vcpop.m a5, v0
            out.push(vop(0x10, 1, 0, 17, 2, 16)); // vfirst.m a6, v0
            out.push(vop(0x14, 1, 0, 1, 2, 8)); // vmsbf.m v8, v0
            out.push(vop(0x14, 1, 0, 2, 2, 10)); // vmsof.m v10, v0
            out.push(vop(0x14, 1, 0, 3, 2, 12)); // vmsif.m v12, v0
            out.push(vop(0x14, 1, 0, 16, 2, 6)); // viota.m v6, v0
            out.push(vop(0x14, 1, 0, 17, 2, 8)); // vid.v v8
            // Permutations:
            out.push(vop(0x0e, 1, 2, 2, 3, 10)); // vslideup.vi v10, v2, 2
            out.push(vop(0x0f, 1, 4, 2, 3, 12)); // vslidedown.vi v12, v4, 2
            out.push(i_type(0x13, 6, 0b000, 0, 99)); // addi t1, zero, 99
            out.push(vop(0x0e, 1, 2, 6, 6, 6)); // vslide1up.vx v6, v2, t1
            out.push(vop(0x0f, 1, 4, 6, 6, 8)); // vslide1down.vx v8, v4, t1
            out.push(vop(0x14, 1, 0, 17, 2, 4)); // vid.v v4 ([0..7])
            out.push(vop(0x03, 1, 4, 7, 3, 4)); // vrsub.vi v4, v4, 7 ([7..0])
            out.push(vop(0x0c, 1, 2, 4, 0, 10)); // vrgather.vv v10, v2, v4
            out.push(vop(0x17, 1, 2, 0, 2, 14)); // vcompress.vm v14, v2, v0
        }
        4 => random_alu(rng, &mut out),
        5 => random_segments(rng, &mut out),
        6 => random_indexed(rng, &mut out),
        7 => reserved_encodings(rng, &mut out),
        _ => {
            // Sub-mode 3: Vector floating-point (SEW=64, LMUL=1, vl=4).
            // Construct exact positive finite FP64 vectors via vid.v + integer shifts + vfcvt.f.x.v
            // so all operations (including vfdiv and vfsqrt) are 100% deterministic across models.
            out.push(csrrw(0x003, 0, 0)); // csrw fcsr, zero
            out.push(vsetivli(10, 4, 0x018)); // vsetivli a0, 4, e64, m1, tu, mu
            out.push(vop(0x14, 1, 0, 17, 2, 2)); // vid.v v2 ([0, 1, 2, 3])
            out.push(vop(0x00, 1, 2, 1, 3, 2)); // vadd.vi v2, v2, 1 ([1, 2, 3, 4])
            out.push(vop(0x25, 1, 2, 2, 0, 4)); // vsll.vv v4, v2, v2 ([2, 8, 24, 64])
            out.push(vop(0x12, 1, 2, 3, 1, 2)); // vfcvt.f.x.v v2, v2 ([1.0, 2.0, 3.0, 4.0])
            out.push(vop(0x12, 1, 4, 3, 1, 4)); // vfcvt.f.x.v v4, v4 ([2.0, 8.0, 24.0, 64.0])
            out.push(vop(0x00, 1, 2, 4, 1, 6)); // vfadd.vv v6, v2, v4
            out.push(vop(0x02, 1, 4, 2, 1, 8)); // vfsub.vv v8, v4, v2
            out.push(vop(0x24, 1, 2, 4, 1, 10)); // vfmul.vv v10, v2, v4
            out.push(vop(0x20, 1, 4, 2, 1, 12)); // vfdiv.vv v12, v4, v2
            out.push(vop(0x13, 1, 2, 0, 1, 14)); // vfsqrt.v v14, v2
            out.push(vop(0x04, 1, 6, 10, 1, 6)); // vfmin.vv v6, v6, v10
            out.push(vop(0x06, 1, 8, 12, 1, 8)); // vfmax.vv v8, v8, v12
            out.push(vop(0x09, 1, 2, 4, 1, 10)); // vfsgnjn.vv v10, v2, v4
            out.push(vop(0x0a, 1, 2, 4, 1, 12)); // vfsgnjx.vv v12, v2, v4
            out.push(vop(0x28, 1, 4, 2, 1, 6)); // vfmacc.vv v6, v2, v4
            out.push(vop(0x13, 1, 6, 16, 1, 8)); // vfclass.v v8, v6
            out.push(vop(0x1b, 1, 2, 4, 1, 0)); // vmflt.vv v0, v2, v4
            out.push(vop(0x10, 1, 0, 16, 2, 11)); // vcpop.m a1, v0
            out.push(vop(0x01, 1, 6, 2, 1, 10)); // vfredusum.vs v10, v6, v2
            out.push(vop(0x07, 1, 6, 2, 1, 12)); // vfredmax.vs v12, v6, v2
            out.push(vop(0x10, 1, 10, 0, 1, 10)); // vfmv.f.s fa0, v10
            out.push(vop(0x10, 1, 12, 0, 1, 11)); // vfmv.f.s fa1, v12
            out.push(vop(0x12, 1, 6, 1, 1, 14)); // vfcvt.x.f.v v14, v6
        }
    }

    // Common epilogue: store v0..v31 (1024 bytes) to SCRATCH_BASE + 1024..2048 so scratch-RAM
    // comparison verifies all 32 256-bit vector registers bit-for-bit.
    out.push(i_type(0x13, 5, 0b000, 8, 1024)); // addi t0, s0, 1024
    out.push(vstore_unit(0b000, 1, 0x08, 5, 7, 0)); // vs8r.v v0, (t0)
    out.push(i_type(0x13, 5, 0b000, 8, 1280)); // addi t0, s0, 1280
    out.push(vstore_unit(0b000, 1, 0x08, 5, 7, 8)); // vs8r.v v8, (t0)
    out.push(i_type(0x13, 5, 0b000, 8, 1536)); // addi t0, s0, 1536
    out.push(vstore_unit(0b000, 1, 0x08, 5, 7, 16)); // vs8r.v v16, (t0)
    out.push(i_type(0x13, 5, 0b000, 8, 1792)); // addi t0, s0, 1792
    out.push(vstore_unit(0b000, 1, 0x08, 5, 7, 24)); // vs8r.v v24, (t0)
    // vl, vtype and vstart are not part of ArchState; fold them into GPRs.
    out.push(csrrs(0xc20, 28, 0)); // csrr t3, vl
    out.push(csrrs(0xc21, 29, 0)); // csrr t4, vtype
    out.push(csrrs(0x008, 30, 0)); // csrr t5, vstart
    out.push(EBREAK);
    out
}

// ---------------------------------------------------------------------------
// Constrained-random sub-modes 4-7.
//
// Memory layout inside the 4 KiB scratch window (s0 = SCRATCH_BASE):
//   0..1024     seed data read by loads (and v0..v15 at entry)
//   1024..2048  epilogue dump of v0..v31
//   2048..4096  store targets of sub-modes 5 and 6
// Registers: s0 = scratch base, s11 = trap signature (trap handler), t1 is
// clobbered by the trap handler. x18..x26 carry random seeded values.

const STORE_BASE: i32 = 2048;
const STORE_LEN: usize = 2048;
const LOAD_LEN: usize = 1024;

const fn vsetvli(rd: u8, rs1: u8, zimm11: u16) -> u32 {
    (((zimm11 as u32) & 0x7ff) << 20)
        | (((rs1 as u32) & 0x1f) << 15)
        | (0b111 << 12)
        | (((rd as u32) & 0x1f) << 7)
        | 0x57
}

/// Vector load/store with all fields: `opcode` 0x07 (load) or 0x27 (store).
#[allow(clippy::too_many_arguments)]
const fn vmem(opcode: u32, nf: u8, mop: u8, vm: u8, rs2: u8, rs1: u8, width: u8, vd: u8) -> u32 {
    ((((nf - 1) as u32) & 0x7) << 29)
        | (((mop as u32) & 0x3) << 26)
        | (((vm as u32) & 1) << 25)
        | (((rs2 as u32) & 0x1f) << 20)
        | (((rs1 as u32) & 0x1f) << 15)
        | (((width as u32) & 0x7) << 12)
        | (((vd as u32) & 0x1f) << 7)
        | opcode
}

/// `li rd, value` for values that fit in 12 bits.
fn li(out: &mut Vec<u32>, rd: u8, value: i32) {
    debug_assert!((-2048..2048).contains(&value));
    out.push(i_type(0x13, rd, 0b000, 0, value));
}

/// Memory-operation width field for an element width of `bytes`.
const fn width_field(bytes: usize) -> u8 {
    match bytes {
        1 => 0b000,
        2 => 0b101,
        4 => 0b110,
        _ => 0b111,
    }
}

/// A random legal vector configuration.
#[derive(Clone, Copy)]
struct Config {
    sew_bytes: usize,
    lmul_pow: i32,
    vl: usize,
}

impl Config {
    fn group(self) -> usize {
        if self.lmul_pow <= 0 {
            1
        } else {
            1 << self.lmul_pow
        }
    }

    fn vlmax(self) -> usize {
        let bits = 256usize;
        if self.lmul_pow >= 0 {
            (bits << self.lmul_pow) / (self.sew_bytes * 8)
        } else {
            (bits >> -self.lmul_pow) / (self.sew_bytes * 8)
        }
    }
}

/// Emits `vsetvli` for a random legal SEW/LMUL (`lmul_pow` in `lmul_range`),
/// a random AVL and random tail/mask policies, and returns the configuration.
fn random_vsetvli(rng: &mut Rng, out: &mut Vec<u32>, lmul_range: (i32, i32)) -> Config {
    loop {
        let sew_pow = rng.index(4) as i32;
        let lmul_pow = lmul_range.0 + rng.index((lmul_range.1 - lmul_range.0 + 1) as usize) as i32;
        // SEW <= LMUL * ELEN (ELEN = 64): fractional LMUL limits SEW.
        if lmul_pow < 0 && sew_pow > 3 + lmul_pow {
            continue;
        }
        let vlmul = if lmul_pow >= 0 {
            lmul_pow
        } else {
            8 + lmul_pow
        } as u16;
        let vta = rng.index(2) as u16;
        let vma = rng.index(2) as u16;
        let zimm = vlmul | ((sew_pow as u16) << 3) | (vta << 6) | (vma << 7);
        let mut cfg = Config {
            sew_bytes: 1 << sew_pow,
            lmul_pow,
            vl: 0,
        };
        let vlmax = cfg.vlmax();
        // AVL beyond VLMAX is legal and clamps to VLMAX.
        let avl = 1 + rng.index(vlmax + 2);
        cfg.vl = avl.min(vlmax);
        li(out, 11, avl as i32);
        out.push(vsetvli(10, 11, zimm));
        return cfg;
    }
}

/// A random register-group base aligned to `group` registers in v1..v31,
/// avoiding `avoid` (inclusive start, exclusive end) ranges.
fn pick_group(rng: &mut Rng, group: usize, count: usize, avoid: &[(usize, usize)]) -> u8 {
    loop {
        let base = group * rng.index(32 / group);
        let end = base + group * count;
        if base == 0 || end > 32 {
            continue;
        }
        if avoid.iter().all(|&(a, b)| end <= a || base >= b) {
            return base as u8;
        }
    }
}

/// Sets v0 from a compare so that masked operations see a mixed mask.
fn random_mask(rng: &mut Rng, out: &mut Vec<u32>, cfg: Config) {
    let src = pick_group(rng, cfg.group(), 1, &[]);
    let rs1 = 18 + rng.index(9) as u8;
    // vmsltu.vx v0, src, rs1 (writes a mask register; v0 is allowed)
    out.push(vop(0x1a, 1, src, rs1, 0b100, 0));
}

/// Sub-mode 4: random single-width integer arithmetic at random vtype.
fn random_alu(rng: &mut Rng, out: &mut Vec<u32>) {
    // (funct6, f3 forms): f3 0 = OPIVV, 4 = OPIVX, 3 = OPIVI, 2 = OPMVV, 6 = OPMVX.
    const OPS: &[(u8, &[u8])] = &[
        (0x00, &[0, 4, 3]), // vadd
        (0x02, &[0, 4]),    // vsub
        (0x03, &[4, 3]),    // vrsub
        (0x04, &[0, 4]),    // vminu
        (0x05, &[0, 4]),    // vmin
        (0x06, &[0, 4]),    // vmaxu
        (0x07, &[0, 4]),    // vmax
        (0x09, &[0, 4, 3]), // vand
        (0x0a, &[0, 4, 3]), // vor
        (0x0b, &[0, 4, 3]), // vxor
        (0x25, &[0, 4, 3]), // vsll
        (0x28, &[0, 4, 3]), // vsrl
        (0x29, &[0, 4, 3]), // vsra
        (0x20, &[0, 4, 3]), // vsaddu
        (0x21, &[0, 4, 3]), // vsadd
        (0x22, &[0, 4]),    // vssubu
        (0x23, &[0, 4]),    // vssub
        (0x2a, &[0, 4, 3]), // vssrl
        (0x2b, &[0, 4, 3]), // vssra
    ];
    const MOPS: &[(u8, &[u8])] = &[
        (0x08, &[2, 6]), // vaaddu
        (0x09, &[2, 6]), // vaadd
        (0x0a, &[2, 6]), // vasubu
        (0x0b, &[2, 6]), // vasub
        (0x20, &[2, 6]), // vdivu
        (0x21, &[2, 6]), // vdiv
        (0x22, &[2, 6]), // vremu
        (0x23, &[2, 6]), // vrem
        (0x24, &[2, 6]), // vmulhu
        (0x25, &[2, 6]), // vmul
        (0x26, &[2, 6]), // vmulhsu
        (0x27, &[2, 6]), // vmulh
        (0x29, &[2, 6]), // vmadd
        (0x2b, &[2, 6]), // vnmsub
        (0x2d, &[2, 6]), // vmacc
        (0x2f, &[2, 6]), // vnmsac
    ];
    // Random fixed-point rounding mode.
    li(out, 5, rng.index(4) as i32);
    out.push(csrrw(0x00a, 0, 5)); // csrw vxrm, t0
    for _ in 0..3 {
        let cfg = random_vsetvli(rng, out, (-3, 3));
        random_mask(rng, out, cfg);
        for _ in 0..6 {
            let (funct6, forms) = if rng.index(2) == 0 {
                OPS[rng.index(OPS.len())]
            } else {
                MOPS[rng.index(MOPS.len())]
            };
            let f3 = forms[rng.index(forms.len())];
            let vm = rng.index(2) as u8;
            let g = cfg.group();
            let vd = pick_group(rng, g, 1, &[]);
            let vs2 = pick_group(rng, g, 1, &[]);
            let rs1 = match f3 {
                0 | 2 => pick_group(rng, g, 1, &[]),
                3 => rng.index(32) as u8,
                _ => 18 + rng.index(9) as u8,
            };
            out.push(vop(funct6, vm, vs2, rs1, f3, vd));
        }
        // vmerge.vvm (vm = 0) and vmv.v.v (vm = 1, vs2 = 0)
        let g = cfg.group();
        let vd = pick_group(rng, g, 1, &[]);
        out.push(vop(
            0x17,
            0,
            pick_group(rng, g, 1, &[]),
            pick_group(rng, g, 1, &[]),
            0,
            vd,
        ));
        out.push(vop(
            0x17,
            1,
            0,
            pick_group(rng, g, 1, &[]),
            0,
            pick_group(rng, g, 1, &[]),
        ));
    }
    out.push(csrrs(0x009, 12, 0)); // csrr a2, vxsat
}

/// Sub-mode 5: segment, strided and fault-only-first loads and stores.
fn random_segments(rng: &mut Rng, out: &mut Vec<u32>) {
    for _ in 0..4 {
        let cfg = random_vsetvli(rng, out, (-3, 3));
        random_mask(rng, out, cfg);
        // Pick EEW so that EMUL = EEW / SEW * LMUL stays within [1/8, 8].
        let (eew_bytes, emul_pow) = loop {
            let eew_pow = rng.index(4) as i32;
            let emul = eew_pow - cfg.sew_bytes.trailing_zeros() as i32 + cfg.lmul_pow;
            if (-3..=3).contains(&emul) {
                break (1usize << eew_pow, emul);
            }
        };
        let fields = if emul_pow <= 0 { 1 } else { 1usize << emul_pow };
        let max_nf = (8 / fields).min(8);
        let nf = 1 + rng.index(max_nf);
        let vm = rng.index(2) as u8;
        let vd = pick_group(rng, fields, nf, &[]);
        let width = width_field(eew_bytes);
        let seg_bytes = nf * eew_bytes;
        // Unit-stride segment load and store.
        let load_off = rng.index(LOAD_LEN - cfg.vl * seg_bytes + 1) & !(eew_bytes - 1);
        li(out, 12, load_off as i32);
        out.push(r_add(12, 8, 12)); // a2 = s0 + offset
        out.push(vmem(0x07, nf as u8, 0, vm, 0, 12, width, vd));
        let store_off = rng.index(STORE_LEN - cfg.vl * seg_bytes + 1) & !(eew_bytes - 1);
        li(out, 13, store_off as i32);
        addr_s0(out, 14, STORE_BASE);
        out.push(r_add(13, 14, 13)); // a3 = s0 + 2048 + offset
        out.push(vmem(0x27, nf as u8, 0, vm, 0, 13, width, vd));
        // Strided segment load/store with a stride that keeps the access in range.
        let max_stride = if cfg.vl > 1 {
            (LOAD_LEN - seg_bytes) / (cfg.vl - 1)
        } else {
            seg_bytes
        };
        let stride = (seg_bytes + rng.index(max_stride.saturating_sub(seg_bytes) + 1))
            .min(max_stride)
            .max(eew_bytes)
            & !(eew_bytes - 1);
        li(out, 15, stride.min(2047) as i32);
        let vd2 = pick_group(rng, fields, nf, &[]);
        out.push(addi_s0(12, 0));
        out.push(vmem(0x07, nf as u8, 0b10, vm, 15, 12, width, vd2));
        let store_stride_max = if cfg.vl > 1 {
            (STORE_LEN - seg_bytes) / (cfg.vl - 1)
        } else {
            seg_bytes
        };
        li(
            out,
            15,
            stride.min(store_stride_max).max(eew_bytes).min(2047) as i32 & !(eew_bytes as i32 - 1),
        );
        addr_s0(out, 13, STORE_BASE);
        out.push(vmem(0x27, nf as u8, 0b10, vm, 15, 13, width, vd2));
        // Fault-only-first unit-stride load (nf = 1) that does not fault, and a
        // unit-stride load resumed from a nonzero vstart.
        {
            let vd3 = pick_group(rng, fields, 1, &[]);
            out.push(addi_s0(
                12,
                (rng.index(LOAD_LEN - cfg.vl * eew_bytes + 1) & !(eew_bytes - 1)) as i32,
            ));
            out.push(vmem(0x07, 1, 0, vm, 0x10, 12, width, vd3));
            out.push(csrrs(0xc20, 16, 0)); // csrr a6, vl
            li(out, 5, rng.index(cfg.vl.max(1)) as i32);
            out.push(csrrw(0x008, 0, 5)); // csrw vstart, t0
            out.push(vmem(0x07, 1, 0, vm, 0, 12, width, vd3));
        }
    }
}

/// Sub-mode 6: unordered and ordered indexed loads and stores.
fn random_indexed(rng: &mut Rng, out: &mut Vec<u32>) {
    for _ in 0..4 {
        let data = random_vsetvli(rng, out, (-3, 2));
        let sew_pow = data.sew_bytes.trailing_zeros() as i32;
        // Index EEW with EMUL_index = EEW_index / SEW * LMUL in [1/8, 8].
        let (idx_bytes, idx_pow) = loop {
            let eew_pow = rng.index(4) as i32;
            let emul = eew_pow - sew_pow + data.lmul_pow;
            if (-3..=3).contains(&emul) {
                break (1usize << eew_pow, emul);
            }
        };
        let idx_group = if idx_pow <= 0 { 1 } else { 1usize << idx_pow };
        let data_group = data.group();
        // Build indices with the same VLMAX: switch to SEW = index EEW and
        // LMUL = EMUL_index, then vid.v * data width + small offset.
        let vidx = pick_group(rng, idx_group, 1, &[]);
        let idx_vlmul = if idx_pow >= 0 { idx_pow } else { 8 + idx_pow } as u16;
        let idx_zimm = idx_vlmul | ((idx_bytes.trailing_zeros() as u16) << 3);
        out.push(vsetvli(0, 0, idx_zimm)); // keep vl (VLMAX ratio unchanged)
        out.push(vop(0x14, 1, 0, 17, 2, vidx)); // vid.v vidx
        // Byte offsets must fit the index EEW: EEW8 indices stay below 256.
        let scale = data.sew_bytes.trailing_zeros() as u8;
        out.push(vop(0x25, 1, vidx, scale, 3, vidx)); // vsll.vi vidx, vidx, log2(SEW bytes)
        let extra = (rng.index(16) as i32) * data.sew_bytes as i32;
        let max_bytes: i32 = if idx_bytes == 1 { 255 } else { 1023 };
        let span = (data.vl as i32) * data.sew_bytes as i32;
        let extra = extra.min((max_bytes - span).max(0)) & !(data.sew_bytes as i32 - 1);
        li(out, 17, extra);
        out.push(vop(0x00, 1, vidx, 17, 4, vidx)); // vadd.vx vidx, vidx, a7
        // Back to the data configuration (same VLMAX, vl unchanged).
        let data_vlmul = if data.lmul_pow >= 0 {
            data.lmul_pow
        } else {
            8 + data.lmul_pow
        } as u16;
        out.push(vsetvli(0, 0, data_vlmul | ((sew_pow as u16) << 3)));
        let avoid = [(vidx as usize, vidx as usize + idx_group)];
        let vd = pick_group(rng, data_group, 1, &avoid);
        let ordered = rng.index(2) as u8; // mop 0b01 unordered, 0b11 ordered
        let width = width_field(idx_bytes);
        out.push(addi_s0(12, 0));
        out.push(vmem(0x07, 1, 0b01 | (ordered << 1), 1, vidx, 12, width, vd));
        addr_s0(out, 13, STORE_BASE);
        out.push(vmem(0x27, 1, 0b01 | (ordered << 1), 1, vidx, 13, width, vd));
    }
}

/// Sub-mode 7: encodings RVV 1.0 reserves and both Sail and QEMU reject.
/// Each must trap with an illegal-instruction exception; the trap handler
/// records the cause. Reserved encodings that QEMU accepts (a masked store
/// whose data group is v0, `vsetvli x0, x0` changing SEW/LMUL) are covered
/// by rivemu's directed tests against the Sail rules instead.
fn reserved_encodings(rng: &mut Rng, out: &mut Vec<u32>) {
    /// Legal `vsetvli x0, a1, zimm` with AVL = 4.
    fn set_vtype(out: &mut Vec<u32>, zimm: u16) {
        li(out, 11, 4);
        out.push(vsetvli(0, 11, zimm));
    }
    let candidates: [fn(&mut Rng, &mut Vec<u32>); 5] = [
        // vd not aligned to LMUL for single-width arithmetic.
        |rng, out| {
            set_vtype(out, 0x01 | (2 << 3)); // e32, m2
            let vd = 1 + 2 * rng.index(15) as u8;
            out.push(vop(0x00, 1, 2, 4, 0, vd)); // vadd.vv vd(odd), v2, v4
        },
        // Masked arithmetic writing v0.
        |_, out| {
            set_vtype(out, 2 << 3); // e32, m1
            out.push(vop(0x00, 0, 2, 4, 0, 0)); // vadd.vv v0, v2, v4, v0.t
        },
        // Segment load with nf * EMUL > 8.
        |_, out| {
            set_vtype(out, 0x02 | (2 << 3)); // e32, m4
            out.push(addi_s0(12, 0));
            out.push(vmem(0x07, 3, 0, 1, 0, 12, 0b110, 8)); // vlseg3e32.v v8 (12 regs)
        },
        // Segment fields past v31.
        |_, out| {
            set_vtype(out, 2 << 3); // e32, m1
            out.push(addi_s0(12, 0));
            out.push(vmem(0x07, 4, 0, 1, 0, 12, 0b110, 30)); // vlseg4e32.v v30
        },
        // Unit-stride load whose data group is not EMUL-aligned.
        |_, out| {
            set_vtype(out, 0x01 | (2 << 3)); // e32, m2
            out.push(addi_s0(12, 0));
            out.push(vmem(0x07, 1, 0, 1, 0, 12, 0b110, 3)); // vle32.v v3
        },
    ];
    for _ in 0..6 {
        candidates[rng.index(candidates.len())](rng, out);
    }
    // Restore a valid configuration for the epilogue.
    set_vtype(out, 2 << 3);
}

/// `addi rd, s0, imm` for a 12-bit `imm`.
const fn addi_s0(rd: u8, imm: i32) -> u32 {
    i_type(0x13, rd, 0b000, 8, imm)
}

/// `rd = s0 + offset` for offsets up to 4094, split across two `addi`s when
/// the offset does not fit a 12-bit immediate.
fn addr_s0(out: &mut Vec<u32>, rd: u8, offset: i32) {
    if offset < 2048 {
        out.push(addi_s0(rd, offset));
    } else {
        out.push(addi_s0(rd, 2047));
        out.push(i_type(0x13, rd, 0b000, rd, offset - 2047));
    }
}

/// `add rd, rs1, rs2`.
const fn r_add(rd: u8, rs1: u8, rs2: u8) -> u32 {
    crate::risu::encode::r_type(0x33, rd, 0b000, rs1, rs2, 0)
}

#[cfg(test)]
mod tests {
    use crate::risu::{RisuCase, RisuHarness, Suite};
    use crate::target::RivemuTarget;

    #[test]
    fn all_vector_submodes_execute_to_checkpoint_on_rivemu() {
        for seed in 0..64u64 {
            let case = RisuCase::generate(Suite::Vector, seed, 32).unwrap();
            let cand = RivemuTarget::new_bare(true).unwrap();
            let refr = RivemuTarget::new_bare(true).unwrap();
            let mut harness = RisuHarness::from_targets(cand, refr, true).unwrap();
            harness.set_step_check(true);
            let res = harness.run_case(&case).unwrap();
            assert!(res.is_none(), "vector seed {seed} diverged: {res:?}");
        }
    }
}
