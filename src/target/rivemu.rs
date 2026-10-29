//! In-process `rivemu` cosimulation target.

use rivemu_core::size::MIB;
use rivemu_cpu_riscv::{Priv, csr::status};
use rivemu_machine::{Machine, MachineConfig};

use crate::{ArchState, CosimTarget, StopReason, TargetError};

/// In-process `rivemu` target wrapping a [`Machine`].
pub struct RivemuTarget {
    /// Underlying `virt` machine.
    pub machine: Machine,
}

impl RivemuTarget {
    /// Creates a bare-metal `rivemu` target (`-bios none`, 128 MiB RAM) for `RISU` blocks.
    pub fn new_bare(strict: bool) -> Result<Self, TargetError> {
        let cfg = MachineConfig {
            ram_size: 128 * MIB,
            smp: 1,
            icount: Some(0),
            strict_align: strict,
            svade: strict,
            strict_pmp: false,
            ..MachineConfig::default()
        };
        Self::from_config(cfg)
    }

    /// Creates a `rivemu` target from an explicit [`MachineConfig`].
    pub fn from_config(cfg: MachineConfig) -> Result<Self, TargetError> {
        let machine = Machine::new(cfg).map_err(|e| TargetError::Protocol(e.to_string()))?;
        Ok(Self { machine })
    }
}

impl CosimTarget for RivemuTarget {
    fn name(&self) -> &'static str {
        "rivemu"
    }

    fn supports_privileged_state(&self) -> bool {
        true
    }

    fn load_ram(&mut self, gpa: u64, data: &[u8]) -> Result<(), TargetError> {
        self.machine
            .bus
            .load_bytes(gpa, data)
            .map_err(|e| TargetError::Protocol(e.to_string()))?;
        for h in &mut self.machine.harts {
            h.invalidate_icache();
            h.invalidate_tlb();
        }
        Ok(())
    }

    fn read_ram(&mut self, gpa: u64, buf: &mut [u8]) -> Result<(), TargetError> {
        self.machine
            .bus
            .read_bytes(gpa, buf)
            .map_err(|e| TargetError::Protocol(e.to_string()))
    }

    fn set_trap_vector(&mut self, addr: u64) -> Result<(), TargetError> {
        self.machine.harts[0].csr.mtvec = addr;
        Ok(())
    }

    fn set_state(&mut self, state: &ArchState) -> Result<(), TargetError> {
        let h = &mut self.machine.harts[0];
        // Clear transient execution state, especially an LR/SC reservation left
        // by the previous block, before restoring the requested visible state.
        h.reset(state.pc);
        h.pc = state.pc;
        h.prv = match state.prv {
            0 => Priv::User,
            1 => Priv::Supervisor,
            _ => Priv::Machine,
        };
        h.x = state.x;
        h.x[0] = 0;
        h.f = state.f;
        h.csr.fflags = u64::from(state.fcsr & 0x1f);
        h.csr.frm = u64::from((state.fcsr >> 5) & 0x7);
        h.csr.mstatus = state.mstatus;
        h.csr.mepc = state.mepc;
        h.csr.mcause = state.mcause;
        h.csr.mtval = state.mtval;
        h.csr.sepc = state.sepc;
        h.csr.scause = state.scause;
        h.csr.stval = state.stval;
        h.csr.satp = state.satp;
        h.csr.mscratch = 0;
        h.csr.sscratch = 0;
        h.csr.medeleg = 0;
        h.csr.mideleg = 0;
        h.csr.stvec = 0;
        h.csr.senvcfg = 0;
        h.wfi = false;
        h.invalidate_icache();
        h.invalidate_tlb();
        Ok(())
    }

    fn get_state(&mut self) -> Result<ArchState, TargetError> {
        let h = &self.machine.harts[0];
        let fcsr = (((h.csr.frm & 0x7) << 5) | (h.csr.fflags & 0x1f)) as u32;
        Ok(ArchState {
            pc: h.pc,
            prv: h.prv as u8,
            x: h.x,
            f: h.f,
            fcsr,
            mstatus: h.csr.mstatus,
            mepc: h.csr.mepc,
            mcause: h.csr.mcause,
            mtval: h.csr.mtval,
            sstatus: h.csr.mstatus & status::S_READABLE,
            sepc: h.csr.sepc,
            scause: h.csr.scause,
            stval: h.csr.stval,
            satp: h.csr.satp,
        })
    }

    fn step_one(&mut self) -> Result<(), TargetError> {
        let h = &mut self.machine.harts[0];
        h.step(&self.machine.bus);
        if let Some(ic) = &self.machine.icount {
            ic.advance(1);
        }
        Ok(())
    }

    fn run_until(&mut self, target_pc: u64, max_insns: u64) -> Result<StopReason, TargetError> {
        let h = &mut self.machine.harts[0];
        for _ in 0..max_insns {
            if h.pc == target_pc {
                return Ok(StopReason::Breakpoint);
            }
            h.step(&self.machine.bus);
            if let Some(ic) = &self.machine.icount {
                ic.advance(1);
            }
        }
        if h.pc == target_pc {
            Ok(StopReason::Breakpoint)
        } else {
            Ok(StopReason::LimitReached)
        }
    }
}
