//! Firmware & kernel lockstep runner (OpenSBI / bare-metal ELF / Linux).

use std::path::Path;

use rivemu_core::size::MIB;
use rivemu_cpu_riscv::decode;
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

/// Runs an instruction-by-instruction lockstep verification for `bios`, with an optional
/// `kernel` staged in memory, across M/S/U privilege transitions and `Sv39`/`Sv48` translation.
///
/// This stops only if `wfi` is reached (`RivemuTarget::step_one` steps a hart without ticking
/// asynchronous device timers).
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
        "rv64,c=true,h=false,sv57=false,zba=true,zbb=true,zbc=true,zbs=true,zicbom=true,zicboz=true,zicond=true,svinval=true,svpbmt=true,sstc=true",
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
        let pc = pre_state.pc;
        let mut low_bytes = [0u8; 2];
        let (insn_word, insn_len, decoded_insn) = if rivemu.read_ram(pc, &mut low_bytes).is_ok() {
            let low = u16::from_le_bytes(low_bytes);
            if low & 3 != 3 {
                (u32::from(low), 2u8, decode::decode_compressed(low))
            } else {
                let mut high_bytes = [0u8; 2];
                rivemu.read_ram(pc.wrapping_add(2), &mut high_bytes)?;
                let raw = u32::from(low) | (u32::from(u16::from_le_bytes(high_bytes)) << 16);
                (raw, 4u8, decode::decode(raw))
            }
        } else {
            (0, 4u8, decode::decode(0))
        };

        if insn_len == 4 && insn_word == 0x1050_0073 {
            return Err(TargetError::Protocol(format!(
                "early boot lockstep reached wfi at step {step_index}; device-aware stepping is not implemented"
            )));
        }

        rivemu.step_one()?;
        qemu.step_one()?;

        // Synchronize hardware counter CSR reads (`time`, `cycle`, `instret`, `mcycle`, `minstret`)
        // from QEMU to rivemu when the instruction retired without trapping.
        if insn_len == 4
            && matches!(
                insn_word & 0xfff0_707f,
                0xc000_2073 | 0xc010_2073 | 0xc020_2073 | 0xb000_2073 | 0xb020_2073
            )
        {
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
            let decoded = format!("{decoded_insn:?}");
            return Ok(Some(BisectReport {
                suite: Suite::All,
                seed: 0,
                step_index,
                pc,
                insn_word,
                insn_len,
                decoded,
                pre_state,
                candidate_name: rivemu.name(),
                reference_name: qemu.name(),
                candidate_post: rivemu_post,
                reference_post: qemu_post,
                diffs,
            }));
        }
        pre_state = rivemu_post;
    }
    Ok(None)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn firmware_lockstep_crosses_mret_sv39_and_compressed_insns() {
        let qemu_bin = Path::new("/opt/homebrew/bin/qemu-system-riscv64");
        if !qemu_bin.exists() {
            return;
        }

        // Build a flat firmware binary loaded at 0x8000_0000:
        // - M-mode installs a 1 GiB Sv39 root leaf PTE at 0x8000_1000 (mapping 0x8000_0000..0xbfff_ffff
        //   with V|R|W|X|A|D = 0xcf, PPN = 0x80000 -> PTE = 0x2000_00cf).
        // - Configures medeleg = 1 << 9 (S-mode ecall), stvec = 0x8000_0100, mepc = 0x8000_0040,
        //   mstatus.MPP = S (1 << 11), satp = (8 << 60) | 0x80001, and executes mret into S-mode
        //   with Sv39 translation active.
        // - S-mode at 0x8000_0040 executes sfence.vma, 16-bit compressed instructions (c.li, c.addi),
        //   32-bit Zicond (czero.eqz), ecall -> S-mode trap handler at 0x8000_0100 -> sret -> loop.
        let mut image = vec![0u8; 0x2000];
        fn emit32(image: &mut [u8], offset: usize, word: u32) {
            image[offset..offset + 4].copy_from_slice(&word.to_le_bytes());
        }
        fn emit16(image: &mut [u8], offset: usize, half: u16) {
            image[offset..offset + 2].copy_from_slice(&half.to_le_bytes());
        }

        // 0x0000: M-mode entry
        emit32(&mut image, 0x0000, 0x8000_12b7); // lui t0, 0x80001          (t0 = 0x8000_1000)
        emit32(&mut image, 0x0004, 0x2000_0337); // lui t1, 0x20000          (t1 = 0x2000_0000)
        emit32(&mut image, 0x0008, 0x0cf3_0313); // addi t1, t1, 0xcf        (t1 = 0x2000_00cf)
        emit32(&mut image, 0x000c, 0x0062_b023); // sd t1, 0(t0)
        emit32(&mut image, 0x0010, 0x0062_b823); // sd t1, 16(t0)            (root PTE[2] = 1 GiB leaf for 0x8000_0000)
        emit32(&mut image, 0x0014, 0x2000_0293); // li t0, 0x200             (1 << 9)
        emit32(&mut image, 0x0018, 0x3022_9073); // csrw medeleg, t0
        emit32(&mut image, 0x001c, 0x8000_02b7); // lui t0, 0x80000
        emit32(&mut image, 0x0020, 0x1002_8293); // addi t0, t0, 0x100       (stvec = 0x8000_0100)
        emit32(&mut image, 0x0024, 0x1052_9073); // csrw stvec, t0
        emit32(&mut image, 0x0028, 0x8000_02b7); // lui t0, 0x80000
        emit32(&mut image, 0x002c, 0x0602_8293); // addi t0, t0, 0x60        (mepc = 0x8000_0060)
        emit32(&mut image, 0x0030, 0x3412_9073); // csrw mepc, t0
        emit32(&mut image, 0x0034, 0x0000_12b7); // lui t0, 0x1              (0x1000)
        emit32(&mut image, 0x0038, 0x8002_8293); // addi t0, t0, -2048       (0x800 = MPP_S)
        emit32(&mut image, 0x003c, 0x3002_a073); // csrs mstatus, t0
        emit32(&mut image, 0x0040, 0x0010_0293); // li t0, 1
        emit32(&mut image, 0x0044, 0x03f2_9293); // slli t0, t0, 63          (0x8000_0000_0000_0000 = Sv39)
        emit32(&mut image, 0x0048, 0x0008_0337); // lui t1, 0x80             (0x80000)
        emit32(&mut image, 0x004c, 0x0013_0313); // addi t1, t1, 1           (0x80001 = PPN of 0x8000_1000)
        emit32(&mut image, 0x0050, 0x0062_e2b3); // or t0, t0, t1
        emit32(&mut image, 0x0054, 0x1802_9073); // csrw satp, t0
        emit32(&mut image, 0x0058, 0x3020_0073); // mret -> S-mode @ 0x8000_0060 with Sv39 active

        // 0x0060: S-mode entry under Sv39 translation
        emit32(&mut image, 0x0060, 0x1200_0073); // sfence.vma x0, x0
        emit16(&mut image, 0x0064, 0x4515);      // c.li a0, 5
        emit16(&mut image, 0x0066, 0x0509);      // c.addi a0, 2             (a0 = 7)
        emit16(&mut image, 0x0068, 0x4581);      // c.li a1, 0
        emit16(&mut image, 0x006a, 0x0001);      // c.nop
        emit32(&mut image, 0x006c, 0x0e05_d633 | (11 << 20) | (10 << 15) | (12 << 7)); // czero.eqz a2, a0, a1 -> 0
        emit32(&mut image, 0x0070, 0x0000_0073); // ecall -> S-mode stvec @ 0x8000_0100
        emit16(&mut image, 0x0074, 0x0505);      // c.addi a0, 1             (a0 = 8)
        emit16(&mut image, 0x0076, 0xa001);      // c.j 0x8000_0076 (infinite loop)

        // 0x0100: S-mode trap handler under Sv39 translation
        emit32(&mut image, 0x0100, 0x1410_22f3); // csrr t0, sepc
        emit16(&mut image, 0x0104, 0x0291);      // c.addi t0, 4
        emit32(&mut image, 0x0106, 0x1412_9073); // csrw sepc, t0
        emit32(&mut image, 0x010a, 0x1020_0073); // sret

        let bios_path = std::env::temp_dir().join(format!(
            "rivemu-lockstep-p16-test-{}.bin",
            std::process::id()
        ));
        std::fs::write(&bios_path, &image).unwrap();
        let res = run_firmware_lockstep(qemu_bin, &bios_path, None, 32, true);
        let _ = std::fs::remove_file(&bios_path);

        let report = res.expect("firmware lockstep should succeed");
        assert!(report.is_none(), "unexpected divergence: {:?}", report);
    }
}
