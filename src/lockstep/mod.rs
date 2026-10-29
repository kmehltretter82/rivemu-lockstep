//! Firmware & kernel lockstep runner (OpenSBI / bare-metal ELF / Linux).

use std::path::Path;

use rivemu_core::size::MIB;
use rivemu_cpu_riscv::{Priv, csr::status, decode};
use rivemu_machine::{MachineConfig, virt::memmap};

use crate::risu::BisectReport;
use crate::risu::Suite;
use crate::target::{QemuGdbTarget, RivemuTarget};
use crate::{CosimTarget, StopReason, TargetError};

struct TempDtb(std::path::PathBuf);

impl TempDtb {
    fn path(&self) -> &Path {
        &self.0
    }
}

impl Drop for TempDtb {
    fn drop(&mut self) {
        let _ = std::fs::remove_file(&self.0);
    }
}

/// Runs an early M-mode CPU smoke test for `bios`, with an optional `kernel` staged in memory.
///
/// This stops before paging, lower-privilege execution, enabled interrupts, or `wfi`, because
/// [`RivemuTarget::step_one`] deliberately steps a hart without running the machine device loop.
pub fn run_firmware_lockstep(
    qemu_bin: &Path,
    bios: &Path,
    kernel: Option<&Path>,
    max_steps: usize,
    check_csrs: bool,
) -> Result<Option<BisectReport>, TargetError> {
    let cfg = MachineConfig {
        ram_size: 128 * MIB,
        smp: 1,
        bios: Some(bios.to_path_buf()),
        kernel: kernel.map(Path::to_path_buf),
        icount: Some(0),
        ..MachineConfig::default()
    };
    let mut rivemu = RivemuTarget::from_config(cfg)?;

    // Export rivemu's generated FDT from guest RAM to a temporary file so QEMU uses the exact same DTB.
    let fdt_addr = rivemu.machine.fdt_addr;
    let mut hdr = [0u8; 8];
    rivemu.read_ram(fdt_addr, &mut hdr)?;
    let fdt_magic = u32::from_be_bytes([hdr[0], hdr[1], hdr[2], hdr[3]]);
    let fdt_size = u32::from_be_bytes([hdr[4], hdr[5], hdr[6], hdr[7]]) as usize;
    if fdt_magic != 0xd00d_feed || !(64..=1024 * 1024).contains(&fdt_size) {
        return Err(TargetError::Protocol(format!(
            "invalid generated FDT header at {fdt_addr:#x}: magic={fdt_magic:#010x}, size={fdt_size}"
        )));
    }
    let mut fdt_bytes = vec![0u8; fdt_size];
    rivemu.read_ram(fdt_addr, &mut fdt_bytes)?;
    let dtb =
        TempDtb(std::env::temp_dir().join(format!("rivemu-lockstep-{}.dtb", std::process::id())));
    std::fs::write(dtb.path(), &fdt_bytes)?;

    let bios_str = bios.to_string_lossy().into_owned();
    let dtb_str = dtb.path().to_string_lossy().into_owned();
    let mut args = vec![
        "-machine",
        "virt",
        "-cpu",
        "rv64,c=true,h=false,sv57=false,zba=true,zbb=true,zbc=true,zbs=true,zicbom=true,zicboz=true,svinval=true,svpbmt=true,sstc=true",
        "-m",
        "128M",
        "-smp",
        "1",
        "-bios",
        &bios_str,
        "-dtb",
        &dtb_str,
    ];
    let kernel_str;
    if let Some(k) = kernel {
        kernel_str = k.to_string_lossy().into_owned();
        args.push("-kernel");
        args.push(&kernel_str);
    }

    let mut qemu = QemuGdbTarget::spawn_with_args(qemu_bin, &args)?;
    qemu.sync_csrs = check_csrs;

    // Advance both emulators through their MROM reset stub to DRAM_BASE (0x8000_0000) and align initial state.
    for (name, reason) in [
        ("rivemu", rivemu.run_until(memmap::DRAM_BASE, 64)?),
        ("QEMU", qemu.run_until(memmap::DRAM_BASE, 64)?),
    ] {
        if reason != StopReason::Breakpoint {
            return Err(TargetError::Protocol(format!(
                "{name} did not reach the firmware entry: {reason:?}"
            )));
        }
    }
    let init_state = rivemu.get_state()?;
    qemu.set_state(&init_state)?;

    let mut pre_state = init_state;
    for step_index in 0..max_steps {
        if pre_state.prv != Priv::Machine as u8
            || pre_state.satp != 0
            || pre_state.mstatus & status::MIE != 0
        {
            return Err(TargetError::Protocol(format!(
                "early boot lockstep reached unsupported machine state at step {step_index}: \
                 priv={}, satp={:#x}, mstatus.MIE={}; stop before paging, lower privilege, or enabled interrupts",
                pre_state.prv,
                pre_state.satp,
                u8::from(pre_state.mstatus & status::MIE != 0)
            )));
        }

        let pc = pre_state.pc;
        let mut word_bytes = [0u8; 4];
        rivemu.read_ram(pc, &mut word_bytes)?;
        let insn_word = u32::from_le_bytes(word_bytes);
        if insn_word == 0x1050_0073 {
            return Err(TargetError::Protocol(format!(
                "early boot lockstep reached wfi at step {step_index}; device-aware stepping is not implemented"
            )));
        }

        rivemu.step_one()?;
        qemu.step_one()?;

        // Synchronize `rdtime` (`csrrs rd, time, x0` -> `0xc010_2073`) from QEMU to rivemu.
        if (insn_word & 0xfff0_707f) == 0xc010_2073 {
            let rd = ((insn_word >> 7) & 0x1f) as usize;
            if rd != 0 {
                let q_val = qemu.read_reg(rd as u32)?;
                rivemu.machine.harts[0].x[rd] = q_val;
            }
        }

        let rivemu_post = rivemu.get_state()?;
        let qemu_post = qemu.get_state()?;
        let diffs = rivemu_post.diff(&qemu_post, check_csrs);
        if !diffs.is_empty() {
            let decoded = format!("{:?}", decode::decode(insn_word));
            return Ok(Some(BisectReport {
                suite: Suite::All,
                seed: 0,
                step_index,
                pc,
                insn_word,
                decoded,
                pre_state,
                rivemu_post,
                qemu_post,
                diffs,
            }));
        }
        pre_state = rivemu_post;
    }
    Ok(None)
}
