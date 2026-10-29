//! Core architectural state, diff engine, and target traits for `rivemu-lockstep`.

#![forbid(unsafe_code)]

pub mod lockstep;
pub mod risu;
pub mod target;

use std::fmt;
use thiserror::Error;

/// Standard RISC-V integer ABI register names (`x0`..`x31`).
pub const XREG_NAMES: [&str; 32] = [
    "zero", "ra", "sp", "gp", "tp", "t0", "t1", "t2", "s0", "s1", "a0", "a1", "a2", "a3", "a4",
    "a5", "a6", "a7", "s2", "s3", "s4", "s5", "s6", "s7", "s8", "s9", "s10", "s11", "t3", "t4",
    "t5", "t6",
];

/// Standard RISC-V floating-point ABI register names (`f0`..`f31`).
pub const FREG_NAMES: [&str; 32] = [
    "ft0", "ft1", "ft2", "ft3", "ft4", "ft5", "ft6", "ft7", "fs0", "fs1", "fa0", "fa1", "fa2",
    "fa3", "fa4", "fa5", "fa6", "fa7", "fs2", "fs3", "fs4", "fs5", "fs6", "fs7", "fs8", "fs9",
    "fs10", "fs11", "ft8", "ft9", "ft10", "ft11",
];

/// Complete architectural state compared at every lockstep checkpoint.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ArchState {
    /// Program counter.
    pub pc: u64,
    /// Privilege mode (`0` = U, `1` = S, `3` = M).
    pub prv: u8,
    /// General-purpose registers (`x0..x31`).
    pub x: [u64; 32],
    /// Floating-point registers (`f0..f31`, raw 64-bit NaN-boxed representation).
    pub f: [u64; 32],
    /// Floating-point control and status register (`frm << 5 | fflags`).
    pub fcsr: u32,
    /// Machine status register (`mstatus`).
    pub mstatus: u64,
    /// Machine exception program counter (`mepc`).
    pub mepc: u64,
    /// Machine trap cause (`mcause`).
    pub mcause: u64,
    /// Machine trap value (`mtval`).
    pub mtval: u64,
    /// Supervisor status register (`sstatus`).
    pub sstatus: u64,
    /// Supervisor exception program counter (`sepc`).
    pub sepc: u64,
    /// Supervisor trap cause (`scause`).
    pub scause: u64,
    /// Supervisor trap value (`stval`).
    pub stval: u64,
    /// Supervisor address translation and protection (`satp`).
    pub satp: u64,
}

impl Default for ArchState {
    fn default() -> Self {
        Self {
            pc: 0x8000_0000,
            prv: 3, // M-mode
            x: [0; 32],
            f: [0xffff_ffff_0000_0000; 32],
            fcsr: 0,
            // M-mode with FS = Dirty (3 << 13), UXL=2, SXL=2
            mstatus: 0x0000_000a_0000_6000,
            mepc: 0,
            mcause: 0,
            mtval: 0,
            sstatus: 0x0000_0002_0000_6000,
            sepc: 0,
            scause: 0,
            stval: 0,
            satp: 0,
        }
    }
}

/// Mask of `mstatus` bits compared in lockstep (excludes `SD` bit 63 if FS state encoding differs,
/// or compares architectural bits `SIE`, `MIE`, `SPIE`, `MPIE`, `SPP`, `MPP`, `SUM`, `MXR`, `TVM`, `TW`, `TSR`).
pub const MSTATUS_COMPARE_MASK: u64 = 0x0000_0000_007e_19aa;

impl ArchState {
    /// Compares two architectural states (`self` = `rivemu`, `other` = `QEMU`), returning all differences.
    pub fn diff(&self, other: &Self, check_csrs: bool) -> Vec<FieldDiff> {
        let mut out = Vec::new();
        if self.pc != other.pc {
            out.push(FieldDiff {
                name: "pc".into(),
                rivemu: self.pc,
                qemu: other.pc,
            });
        }
        if check_csrs && self.prv != other.prv {
            out.push(FieldDiff {
                name: "priv".into(),
                rivemu: u64::from(self.prv),
                qemu: u64::from(other.prv),
            });
        }
        for (i, name) in XREG_NAMES.iter().enumerate().skip(1) {
            if self.x[i] != other.x[i] {
                out.push(FieldDiff {
                    name: format!("x{i:<2} ({name})"),
                    rivemu: self.x[i],
                    qemu: other.x[i],
                });
            }
        }
        for (i, name) in FREG_NAMES.iter().enumerate() {
            if self.f[i] != other.f[i] {
                out.push(FieldDiff {
                    name: format!("f{i:<2} ({name})"),
                    rivemu: self.f[i],
                    qemu: other.f[i],
                });
            }
        }
        if (self.fcsr & 0xff) != (other.fcsr & 0xff) {
            out.push(FieldDiff {
                name: "fcsr".into(),
                rivemu: u64::from(self.fcsr & 0xff),
                qemu: u64::from(other.fcsr & 0xff),
            });
        }
        if check_csrs {
            let rm = self.mstatus & MSTATUS_COMPARE_MASK;
            let qm = other.mstatus & MSTATUS_COMPARE_MASK;
            if rm != qm {
                out.push(FieldDiff {
                    name: "mstatus(masked)".into(),
                    rivemu: self.mstatus,
                    qemu: other.mstatus,
                });
            }
            for (name, rv, qv) in [
                ("mepc", self.mepc, other.mepc),
                ("mcause", self.mcause, other.mcause),
                ("mtval", self.mtval, other.mtval),
                ("sepc", self.sepc, other.sepc),
                ("scause", self.scause, other.scause),
                ("stval", self.stval, other.stval),
                ("satp", self.satp, other.satp),
            ] {
                if rv != qv {
                    out.push(FieldDiff {
                        name: name.into(),
                        rivemu: rv,
                        qemu: qv,
                    });
                }
            }
        }
        out
    }
}

/// A single register or CSR mismatch between `rivemu` and `QEMU`.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct FieldDiff {
    /// Register or CSR name.
    pub name: String,
    /// Value observed in `rivemu`.
    pub rivemu: u64,
    /// Value observed in `QEMU`.
    pub qemu: u64,
}

impl fmt::Display for FieldDiff {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "  {:<16} rivemu = {:#018x}   qemu = {:#018x}   (xor = {:#018x})",
            self.name,
            self.rivemu,
            self.qemu,
            self.rivemu ^ self.qemu
        )
    }
}

/// Reason a target stopped during [`CosimTarget::run_until`].
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum StopReason {
    /// Reached the target breakpoint address (`ebreak` or hardware breakpoint).
    Breakpoint,
    /// Single step completed.
    Step,
    /// Instruction limit reached before hitting breakpoint.
    LimitReached,
}

/// Error returned by a [`CosimTarget`].
#[derive(Debug, Error)]
pub enum TargetError {
    /// I/O or GDB socket error.
    #[error("I/O error: {0}")]
    Io(#[from] std::io::Error),
    /// Protocol or machine error.
    #[error("{0}")]
    Protocol(String),
}

/// Common interface implemented by both `RivemuTarget` and `QemuGdbTarget`.
pub trait CosimTarget {
    /// Writes `data` into guest physical memory at `gpa`.
    fn load_ram(&mut self, gpa: u64, data: &[u8]) -> Result<(), TargetError>;
    /// Reads guest physical memory at `gpa` into `buf`.
    fn read_ram(&mut self, gpa: u64, buf: &mut [u8]) -> Result<(), TargetError>;
    /// Installs the M-mode trap handler used by a generated instruction block.
    fn set_trap_vector(&mut self, addr: u64) -> Result<(), TargetError>;
    /// Sets the complete architectural state of Hart 0.
    fn set_state(&mut self, state: &ArchState) -> Result<(), TargetError>;
    /// Reads the current architectural state of Hart 0.
    fn get_state(&mut self) -> Result<ArchState, TargetError>;
    /// Executes exactly 1 instruction.
    fn step_one(&mut self) -> Result<(), TargetError>;
    /// Runs until `pc == target_pc` (or an `ebreak` at `target_pc`), up to `max_insns`.
    fn run_until(&mut self, target_pc: u64, max_insns: u64) -> Result<StopReason, TargetError>;
}
