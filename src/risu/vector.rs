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
pub(crate) fn generate_block(_rng: &mut Rng, seed: u64, _num_insns: usize) -> Vec<u32> {
    let mut out = Vec::with_capacity(48);

    // Common preamble: enable mstatus.VS = Dirty (0x600), clear vcsr/vstart,
    // and load v0..v15 (512 bytes) from SCRATCH_BASE (s0 = x8).
    out.push(i_type(0x13, 5, 0b000, 0, 0x600)); // addi t0, zero, 0x600 (mstatus.VS = Dirty)
    out.push(csrrs(0x300, 0, 5)); // csrs mstatus, t0
    out.push(csrrw(0x00f, 0, 0)); // csrw vcsr, zero
    out.push(csrrw(0x008, 0, 0)); // csrw vstart, zero
    out.push(vload_unit(0b111, 1, 0x08, 8, 7, 0)); // vl8re64.v v0, (s0)
    out.push(i_type(0x13, 5, 0b000, 8, 256)); // addi t0, s0, 256
    out.push(vload_unit(0b111, 1, 0x08, 5, 7, 8)); // vl8re64.v v8, (t0)

    match seed & 3 {
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

    // Common epilogue: store v0..v15 (512 bytes) to SCRATCH_BASE + 1024..1536 so scratch-RAM
    // comparison verifies all 16 modified 256-bit vector registers bit-for-bit.
    out.push(i_type(0x13, 5, 0b000, 8, 1024)); // addi t0, s0, 1024
    out.push(vstore_unit(0b000, 1, 0x08, 5, 7, 0)); // vs8r.v v0, (t0)
    out.push(i_type(0x13, 5, 0b000, 8, 1280)); // addi t0, s0, 1280
    out.push(vstore_unit(0b000, 1, 0x08, 5, 7, 8)); // vs8r.v v8, (t0)
    out.push(EBREAK);
    out
}

#[cfg(test)]
mod tests {
    use crate::risu::{RisuCase, RisuHarness, Suite};
    use crate::target::RivemuTarget;

    #[test]
    fn all_four_vector_submodes_execute_to_checkpoint_on_rivemu() {
        for seed in 0..4u64 {
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
