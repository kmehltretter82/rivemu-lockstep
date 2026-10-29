//! Deterministic PRNG and edge-case operand generators for `RISU` fuzzing.

use crate::ArchState;

/// Fast, deterministic 64-bit Xorshift* PRNG.
#[derive(Clone, Copy, Debug)]
pub struct Rng(u64);

impl Rng {
    /// Creates a new PRNG from a 64-bit seed (avoiding the zero state).
    pub const fn new(seed: u64) -> Self {
        Self(if seed == 0 {
            0x9e37_79b9_7f4a_7c15
        } else {
            seed
        })
    }

    /// Returns the next 64-bit pseudo-random number.
    #[inline]
    pub fn next_u64(&mut self) -> u64 {
        let mut x = self.0;
        x ^= x >> 12;
        x ^= x << 25;
        x ^= x >> 27;
        self.0 = x;
        x.wrapping_mul(0x2545_f491_4f6c_dd1d)
    }

    /// Returns a uniform index in `0..len`.
    #[inline]
    pub fn index(&mut self, len: usize) -> usize {
        (self.next_u64() as usize) % len
    }

    /// Picks a register in `1..=31`, excluding reserved registers (`s0 = x8` scratch base,
    /// `t0 = x5` address scratch, `t1 = x6` trap scratch, `s11 = x27` trap signature).
    pub fn pick_gpr(&mut self) -> u8 {
        const POOL: &[u8] = &[
            1, 2, 3, 4, 7, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20, 21, 22, 23, 24, 25, 26,
            28, 29, 30, 31,
        ];
        POOL[self.index(POOL.len())]
    }

    /// Picks any GPR in `0..=31` as a source operand (including `x0`).
    pub fn pick_src_gpr(&mut self) -> u8 {
        if (self.next_u64() & 0xf) == 0 {
            0
        } else {
            self.pick_gpr()
        }
    }

    /// Picks any floating-point register `f0..f31`.
    pub fn pick_fpr(&mut self) -> u8 {
        (self.next_u64() & 31) as u8
    }

    /// Generates an edge-case-weighted 64-bit integer value.
    pub fn edge_u64(&mut self) -> u64 {
        const EDGES: &[u64] = &[
            0x0000_0000_0000_0000,
            0x0000_0000_0000_0001,
            0x0000_0000_0000_0002,
            0xffff_ffff_ffff_ffff, // -1
            0xffff_ffff_ffff_fffe, // -2
            0x0000_0000_7fff_ffff, // i32::MAX zero-extended
            0x0000_0000_8000_0000, // u32 sign bit zero-extended
            0x0000_0000_ffff_ffff, // u32::MAX zero-extended
            0xffff_ffff_7fff_ffff, // i32::MAX with upper ones
            0xffff_ffff_8000_0000, // i32::MIN sign-extended
            0x7fff_ffff_ffff_ffff, // i64::MAX
            0x8000_0000_0000_0000, // i64::MIN
            0x8000_0000_0000_0001,
            0x5555_5555_5555_5555,
            0xaaaa_aaaa_aaaa_aaaa,
            0x0102_0304_0506_0708,
            0x8040_2010_0804_0201,
            0x00ff_00ff_00ff_00ff,
        ];
        match self.next_u64() % 4 {
            0 | 1 => EDGES[self.index(EDGES.len())],
            2 => {
                let bit = (self.next_u64() & 63) as u32;
                if (self.next_u64() & 1) == 0 {
                    1u64 << bit
                } else {
                    !(1u64 << bit)
                }
            }
            _ => self.next_u64(),
        }
    }

    /// Generates an edge-case-weighted 64-bit FPR bit pattern (covering both `f64` and NaN-boxed `f32`).
    pub fn edge_f64_bits(&mut self) -> u64 {
        const FP_EDGES: &[u64] = &[
            // Double-precision (f64) edge cases:
            0x0000_0000_0000_0000, // +0.0 (f64) / unboxed +0.0 (f32)
            0x8000_0000_0000_0000, // -0.0 (f64)
            0x0000_0000_0000_0001, // smallest positive f64 subnormal
            0x000f_ffff_ffff_ffff, // largest positive f64 subnormal
            0x8000_0000_0000_0001, // smallest negative f64 subnormal
            0x0010_0000_0000_0000, // smallest positive f64 normal
            0x3ff0_0000_0000_0000, // +1.0 (f64)
            0xbff0_0000_0000_0000, // -1.0 (f64)
            0x4000_0000_0000_0000, // +2.0 (f64)
            0x4330_0000_0000_0000, // 2^52 (f64 integer boundary)
            0x43e0_0000_0000_0000, // 2^63 (i64 conversion boundary)
            0xc3e0_0000_0000_0000, // -2^63 (i64::MIN conversion boundary)
            0x7fef_ffff_ffff_ffff, // max finite f64
            0x7ff0_0000_0000_0000, // +Inf (f64)
            0xfff0_0000_0000_0000, // -Inf (f64)
            0x7ff8_0000_0000_0000, // canonical qNaN (f64)
            0xfff8_0000_0000_0001, // negative qNaN with payload (f64)
            0x7ff0_0000_0000_0001, // signaling sNaN (f64)
            0xfff0_0000_0000_0001, // negative sNaN (f64)
            // Single-precision (f32) properly NaN-boxed (`0xffff_ffff_xxxx_xxxx`):
            0xffff_ffff_0000_0000, // +0.0 (f32)
            0xffff_ffff_8000_0000, // -0.0 (f32)
            0xffff_ffff_0000_0001, // smallest positive f32 subnormal
            0xffff_ffff_007f_ffff, // largest positive f32 subnormal
            0xffff_ffff_0080_0000, // smallest positive f32 normal
            0xffff_ffff_3f80_0000, // +1.0 (f32)
            0xffff_ffff_bf80_0000, // -1.0 (f32)
            0xffff_ffff_4f00_0000, // 2^31 (i32 conversion boundary)
            0xffff_ffff_cf00_0000, // -2^31 (i32::MIN conversion boundary)
            0xffff_ffff_7f7f_ffff, // max finite f32
            0xffff_ffff_7f80_0000, // +Inf (f32)
            0xffff_ffff_ff80_0000, // -Inf (f32)
            0xffff_ffff_7fc0_0000, // canonical qNaN (f32)
            0xffff_ffff_7f80_0001, // signaling sNaN (f32)
            // Improperly NaN-boxed f32 (upper 32 bits != 0xffff_ffff -> must unbox as canonical qNaN):
            0x0000_0000_3f80_0000,
            0xdead_beef_3f80_0000,
            0x7fff_ffff_7f80_0001,
        ];
        if (self.next_u64() % 4) != 0 {
            FP_EDGES[self.index(FP_EDGES.len())]
        } else if (self.next_u64() & 1) == 0 {
            0xffff_ffff_0000_0000 | (self.next_u64() & 0xffff_ffff)
        } else {
            self.next_u64()
        }
    }

    /// Generates an initial [`ArchState`] seeded with edge-case GPR and FPR values.
    pub fn seed_state(&mut self, start_pc: u64, scratch_base: u64) -> ArchState {
        let mut state = ArchState {
            pc: start_pc,
            prv: 3,
            ..ArchState::default()
        };
        for i in 1..32 {
            state.x[i] = self.edge_u64();
        }
        // Reserve s0 (x8) for the 4 KiB scratch RAM base and s11 (x27) for trap signature accumulation.
        state.x[8] = scratch_base;
        state.x[27] = 0;
        for i in 0..32 {
            state.f[i] = self.edge_f64_bits();
        }
        // Valid dynamic rounding modes are 0..=4 (RNE, RTZ, RDN, RUP, RMM).
        let frm = (self.next_u64() % 5) as u32;
        let fflags = (self.next_u64() & 0x1f) as u32;
        state.fcsr = (frm << 5) | fflags;
        state
    }
}
