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
        h.csr.medeleg = state.medeleg;
        h.csr.mideleg = 0;
        h.csr.stvec = state.stvec;
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
            stvec: h.csr.stvec,
            medeleg: h.csr.medeleg,
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

#[cfg(test)]
mod tests {
    use rivemu_cpu_riscv::decode;

    use crate::risu::encode::{build_supervisor_page_fault_handler, build_supervisor_trap_handler};
    use crate::risu::harness::{CODE_BASE, S_TRAP_BASE, SCRATCH_BASE, SV39_TRAP_BASE};
    use crate::risu::sv39::{
        ALT_SENTINEL, INITIAL_PROBE_PTE, OLD_SENTINEL, PROBE_PTE_ADDR, REPLACEMENT_PTE,
        VM_SETUP_BASE,
    };
    use crate::risu::{RisuCase, Suite};

    use super::*;

    #[test]
    fn delegated_ecall_enters_and_returns_through_supervisor_handler() {
        const ECALL: u32 = 0x0000_0073;
        const MSTATUS_SPP: u64 = 1 << 8;

        let mut target = RivemuTarget::new_bare(false).unwrap();
        target.load_ram(CODE_BASE, &ECALL.to_le_bytes()).unwrap();
        target
            .load_ram(S_TRAP_BASE, &build_supervisor_trap_handler())
            .unwrap();

        for (origin, cause) in [(1, 9u64), (0, 8u64)] {
            let initial = ArchState {
                pc: CODE_BASE,
                prv: origin,
                stvec: S_TRAP_BASE,
                medeleg: 1 << cause,
                ..ArchState::default()
            };
            target.set_state(&initial).unwrap();

            target.step_one().unwrap();
            let trapped = target.get_state().unwrap();
            assert_eq!(trapped.pc, S_TRAP_BASE);
            assert_eq!(trapped.prv, 1);
            assert_eq!(trapped.scause, cause);
            assert_eq!(trapped.sepc, CODE_BASE);
            assert_eq!(trapped.mstatus & MSTATUS_SPP != 0, origin == 1);

            for _ in 0..8 {
                target.step_one().unwrap();
            }
            let returned = target.get_state().unwrap();
            assert_eq!(returned.pc, CODE_BASE + 4);
            assert_eq!(returned.prv, origin);
            assert_eq!(returned.sepc, CODE_BASE + 4);
        }
    }

    #[test]
    fn sv39_permission_faults_report_and_return_through_supervisor() {
        const MSTATUS_SPP: u64 = 1 << 8;

        let mut target = RivemuTarget::new_bare(false).unwrap();
        target
            .load_ram(SV39_TRAP_BASE, &build_supervisor_page_fault_handler())
            .unwrap();

        for (seed, expected_cause, origin) in [
            (0x5002, 13u64, 1u8),
            (0x5004, 13u64, 1u8),
            (0x5006, 13u64, 0u8),
            (0x5007, 15u64, 1u8),
        ] {
            let case = RisuCase::generate(Suite::Sv39, seed, 4).unwrap();
            target.load_ram(CODE_BASE, case.code_bytes()).unwrap();
            target.load_ram(SCRATCH_BASE, case.scratch()).unwrap();
            target.load_ram(VM_SETUP_BASE, case.vm_setup()).unwrap();
            target.set_state(case.init_state()).unwrap();

            let raw = u32::from_le_bytes(case.code_bytes()[..4].try_into().unwrap());
            let insn = decode::decode(raw);
            let fault_address =
                case.init_state().x[insn.rs1 as usize].wrapping_add(insn.imm as i64 as u64);

            target.step_one().unwrap();
            let trapped = target.get_state().unwrap();
            assert_eq!(trapped.pc, SV39_TRAP_BASE);
            assert_eq!(trapped.prv, 1);
            assert_eq!(trapped.scause, expected_cause);
            assert_eq!(trapped.sepc, CODE_BASE);
            assert_eq!(trapped.stval, fault_address);
            assert_eq!(trapped.mstatus & MSTATUS_SPP != 0, origin == 1);

            for _ in 0..10 {
                target.step_one().unwrap();
            }
            let returned = target.get_state().unwrap();
            assert_eq!(returned.pc, CODE_BASE + 4);
            assert_eq!(returned.prv, origin);
        }

        for seed in [0x5003, 0x5005] {
            let case = RisuCase::generate(Suite::Sv39, seed, 1).unwrap();
            target.load_ram(CODE_BASE, case.code_bytes()).unwrap();
            target.load_ram(SCRATCH_BASE, case.scratch()).unwrap();
            target.load_ram(VM_SETUP_BASE, case.vm_setup()).unwrap();
            target.set_state(case.init_state()).unwrap();

            target.step_one().unwrap();
            let state = target.get_state().unwrap();
            assert_eq!(state.pc, CODE_BASE + 4);
            assert_eq!(state.prv, 1);
            assert_eq!(state.scause, 0);
        }
    }

    #[test]
    fn sv39_global_sfence_observes_guest_pte_rewrite() {
        let case = RisuCase::generate(Suite::Sv39, 0x5008, 8).unwrap();
        let mut target = RivemuTarget::new_bare(false).unwrap();
        target.load_ram(CODE_BASE, case.code_bytes()).unwrap();
        target.load_ram(SCRATCH_BASE, case.scratch()).unwrap();
        target.load_ram(VM_SETUP_BASE, case.vm_setup()).unwrap();
        target.set_state(case.init_state()).unwrap();

        let mut pte = [0; 8];
        target.read_ram(PROBE_PTE_ADDR, &mut pte).unwrap();
        assert_eq!(u64::from_le_bytes(pte), INITIAL_PROBE_PTE);

        target.step_one().unwrap(); // alternate-page load
        assert_eq!(target.get_state().unwrap().x[10], ALT_SENTINEL);
        target.step_one().unwrap(); // PTE-page translation prewarm
        target.step_one().unwrap(); // probe translation warmup
        assert_eq!(target.get_state().unwrap().x[9], OLD_SENTINEL);
        target.step_one().unwrap(); // fence rw, rw

        target.read_ram(PROBE_PTE_ADDR, &mut pte).unwrap();
        assert_eq!(u64::from_le_bytes(pte), INITIAL_PROBE_PTE);
        target.step_one().unwrap(); // guest leaf-PTE replacement
        target.read_ram(PROBE_PTE_ADDR, &mut pte).unwrap();
        assert_eq!(u64::from_le_bytes(pte), REPLACEMENT_PTE);

        target.step_one().unwrap(); // sfence.vma x0, x0
        target.step_one().unwrap(); // post-fence probe load
        assert_eq!(target.get_state().unwrap().x[11], ALT_SENTINEL);
        target.step_one().unwrap(); // equality witness
        let final_state = target.get_state().unwrap();
        assert_eq!(final_state.x[12], 0);
        assert_eq!(final_state.pc, case.end_pc());
    }
}
