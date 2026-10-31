//! Real `qemu-system-riscv64` cosimulation target driven over the GDB Remote Serial Protocol.

use std::io::{Read, Write};
use std::net::{TcpListener, TcpStream};
use std::path::Path;
use std::process::{Child, Command, Stdio};
use std::time::{Duration, Instant};

use rivemu_cpu_riscv::csr;

use crate::{ArchState, CosimTarget, StopReason, TargetError};

/// Base GDB register index for RISC-V CSRs in QEMU (`regnum = CSR_GDB_BASE + csr_addr`).
const CSR_GDB_BASE: u32 = 66;
/// GDB register index for `priv` (`riscv-64bit-virtual.xml`).
const PRIV_GDB_REG: u32 = 65;

/// Persistent `qemu-system-riscv64` process controlled via GDB RSP.
pub struct QemuGdbTarget {
    child: Child,
    stream: TcpStream,
    /// Whether to read/write privileged trap CSRs (`mstatus`, `mcause`, `mtval`, `mepc`, `satp`) on every state sync.
    pub sync_csrs: bool,
    pmp_enabled: bool,
    no_ack_mode: bool,
}

impl QemuGdbTarget {
    /// Spawns a bare-metal `qemu-system-riscv64` instance (`-bios none`) for `RISU` lockstep testing.
    pub fn spawn_bare(qemu_bin: &Path) -> Result<Self, TargetError> {
        Self::spawn_bare_with_pmp(qemu_bin, false)
    }

    /// Spawns a bare-metal `qemu-system-riscv64` instance (`-bios none`) with configurable PMP support.
    pub fn spawn_bare_with_pmp(qemu_bin: &Path, pmp_enabled: bool) -> Result<Self, TargetError> {
        let cpu_arg = if pmp_enabled {
            "rv64,c=true,h=false,pmp=true,smepmp=true,smstateen=true,sv57=true,svnapot=true,zawrs=true,zabha=true,zacas=true,zba=true,zbb=true,zbc=true,zbkb=true,zbkc=true,zbkx=true,zbs=true,zca=true,zcb=true,zcd=true,zcmop=true,zfa=true,zfbfmin=true,zfh=true,zfhmin=true,zicfilp=true,zicfiss=true,zicond=true,zicbom=true,zicbop=true,zicboz=true,zimop=true,zknd=true,zkne=true,zknh=true,zkr=true,zksed=true,zksh=true,zkt=true,ssnpm=true,smnpm=true,smmpm=true,x-svukte=true,svinval=true,svpbmt=true,svrsw60t59b=true,svvptc=true,sstc=true"
        } else {
            "rv64,c=true,h=false,pmp=false,smstateen=true,sv57=true,svnapot=true,zawrs=true,zabha=true,zacas=true,zba=true,zbb=true,zbc=true,zbkb=true,zbkc=true,zbkx=true,zbs=true,zca=true,zcb=true,zcd=true,zcmop=true,zfa=true,zfbfmin=true,zfh=true,zfhmin=true,zicfilp=true,zicfiss=true,zicond=true,zicbom=true,zicbop=true,zicboz=true,zimop=true,zknd=true,zkne=true,zknh=true,zkr=true,zksed=true,zksh=true,zkt=true,ssnpm=true,smnpm=true,smmpm=true,x-svukte=true,svinval=true,svpbmt=true,svrsw60t59b=true,svvptc=true,sstc=true"
        };
        let mut target = Self::spawn_with_args(
            qemu_bin,
            &[
                "-machine", "virt", "-cpu", cpu_arg, "-m", "128M", "-smp", "1", "-bios", "none",
            ],
        )?;
        target.pmp_enabled = pmp_enabled;
        // Ensure M-mode and mstatus.FS = Dirty (3 << 13) are initialized even when sync_csrs is false.
        let def = ArchState::default();
        target.write_reg(PRIV_GDB_REG, u64::from(def.prv))?;
        target.write_csr(csr::MSTATUS, def.mstatus)?;
        Ok(target)
    }

    /// Spawns `qemu-system-riscv64` with custom machine/boot arguments and connects to its GDB stub.
    pub fn spawn_with_args(qemu_bin: &Path, extra_args: &[&str]) -> Result<Self, TargetError> {
        let port = pick_free_port()?;
        let gdb_arg = format!("tcp:127.0.0.1:{port}");
        let mut cmd = Command::new(qemu_bin);
        cmd.args(extra_args)
            .args([
                "-nographic",
                "-monitor",
                "none",
                "-serial",
                "none",
                "-S",
                "-gdb",
                &gdb_arg,
            ])
            .stdin(Stdio::null())
            .stdout(Stdio::null())
            .stderr(Stdio::null());

        let mut child = cmd.spawn()?;
        let deadline = Instant::now() + Duration::from_secs(5);
        let stream = loop {
            if let Some(status) = child.try_wait()? {
                return Err(TargetError::Protocol(format!(
                    "qemu-system-riscv64 exited early with {status}"
                )));
            }
            match TcpStream::connect(("127.0.0.1", port)) {
                Ok(s) => break s,
                Err(_) if Instant::now() < deadline => {
                    std::thread::sleep(Duration::from_millis(15));
                }
                Err(e) => {
                    let _ = child.kill();
                    let _ = child.wait();
                    return Err(TargetError::Io(e));
                }
            }
        };
        stream.set_nodelay(true)?;
        stream.set_read_timeout(Some(Duration::from_secs(10)))?;

        let mut target = Self {
            child,
            stream,
            sync_csrs: true,
            pmp_enabled: false,
            no_ack_mode: false,
        };
        let supported = target.cmd("qSupported:multiprocess+;xmlRegisters=i386")?;
        if supported
            .split(';')
            .any(|feature| feature == "QStartNoAckMode+")
            && target.cmd("QStartNoAckMode")? == "OK"
        {
            target.no_ack_mode = true;
        }
        Ok(target)
    }

    /// Sends a GDB RSP command payload (without `$` or `#xx`) and returns the decoded response body.
    pub fn cmd(&mut self, payload: &str) -> Result<String, TargetError> {
        let sum: u8 = payload.bytes().fold(0u8, u8::wrapping_add);
        let frame = format!("${payload}#{sum:02x}");
        self.stream.write_all(frame.as_bytes())?;

        let mut buf = [0u8; 1];
        // Read until `$`
        loop {
            self.stream.read_exact(&mut buf)?;
            if buf[0] == b'$' {
                break;
            }
        }
        let mut body = Vec::with_capacity(64);
        loop {
            self.stream.read_exact(&mut buf)?;
            if buf[0] == b'#' {
                break;
            }
            body.push(buf[0]);
        }
        let mut chk = [0u8; 2];
        self.stream.read_exact(&mut chk)?;
        if !self.no_ack_mode {
            self.stream.write_all(b"+")?;
        }
        String::from_utf8(body).map_err(|e| TargetError::Protocol(e.to_string()))
    }

    /// Reads a single 64-bit GDB register by its GDB register number (`p <regnum>`).
    pub fn read_reg(&mut self, regnum: u32) -> Result<u64, TargetError> {
        let resp = self.cmd(&format!("p{regnum:x}"))?;
        decode_le_hex_u64(&resp)
    }

    /// Writes a single 64-bit GDB register by its GDB register number (`P <regnum>=<le_hex>`).
    pub fn write_reg(&mut self, regnum: u32, val: u64) -> Result<(), TargetError> {
        let hex = encode_le_hex_u64(val);
        let resp = self.cmd(&format!("P{regnum:x}={hex}"))?;
        if resp != "OK" {
            return Err(TargetError::Protocol(format!(
                "GDB P{regnum:x} failed: '{resp}'"
            )));
        }
        Ok(())
    }

    /// Reads a RISC-V CSR by its architectural 12-bit CSR address.
    pub fn read_csr(&mut self, csr_addr: u16) -> Result<u64, TargetError> {
        self.read_reg(CSR_GDB_BASE + u32::from(csr_addr))
    }

    /// Writes a RISC-V CSR by its architectural 12-bit CSR address.
    pub fn write_csr(&mut self, csr_addr: u16, val: u64) -> Result<(), TargetError> {
        self.write_reg(CSR_GDB_BASE + u32::from(csr_addr), val)
    }
}

impl CosimTarget for QemuGdbTarget {
    fn name(&self) -> &'static str {
        "QEMU"
    }

    fn supports_privileged_state(&self) -> bool {
        true
    }

    fn prepare_case_memory(&mut self) -> Result<(), TargetError> {
        // QEMU GDB memory packets use the current virtual-memory context.
        // Switch to M-mode/Bare before loading physical case images. Restoring
        // a nonzero SATP later also guarantees a TLB flush between cases.
        self.write_reg(PRIV_GDB_REG, 3)?;
        self.write_csr(csr::SATP, 0)
    }

    fn load_ram(&mut self, gpa: u64, data: &[u8]) -> Result<(), TargetError> {
        // Chunk writes into 1 KiB slices (2048 hex chars) to stay well within QEMU's 0x1000 PacketSize.
        for (i, chunk) in data.chunks(1024).enumerate() {
            let addr = gpa + (i * 1024) as u64;
            let mut hex = String::with_capacity(chunk.len() * 2);
            for &b in chunk {
                use std::fmt::Write as _;
                let _ = write!(hex, "{b:02x}");
            }
            let resp = self.cmd(&format!("M{addr:x},{:x}:{hex}", chunk.len()))?;
            if resp != "OK" {
                return Err(TargetError::Protocol(format!(
                    "GDB M{addr:#x} failed: '{resp}'"
                )));
            }
        }
        Ok(())
    }

    fn read_ram(&mut self, gpa: u64, buf: &mut [u8]) -> Result<(), TargetError> {
        for (i, chunk) in buf.chunks_mut(1024).enumerate() {
            let addr = gpa + (i * 1024) as u64;
            let resp = self.cmd(&format!("m{addr:x},{:x}", chunk.len()))?;
            if resp.len() != chunk.len() * 2 {
                return Err(TargetError::Protocol(format!(
                    "GDB m{addr:#x} returned '{}' (expected {} hex chars)",
                    resp,
                    chunk.len() * 2
                )));
            }
            for (j, slot) in chunk.iter_mut().enumerate() {
                *slot = u8::from_str_radix(&resp[j * 2..j * 2 + 2], 16)
                    .map_err(|e| TargetError::Protocol(e.to_string()))?;
            }
        }
        Ok(())
    }

    fn set_trap_vector(&mut self, addr: u64) -> Result<(), TargetError> {
        self.write_csr(csr::MTVEC, addr)
    }

    fn set_state(&mut self, state: &ArchState) -> Result<(), TargetError> {
        // Reset control state even when it is not compared. Leaving a CSR from a
        // previous block changes execution and makes seed replay unreliable.
        // Restore privileged CSRs from M-mode before installing the requested
        // final privilege. In particular, S-mode with TVM=1 cannot write satp.
        self.write_reg(PRIV_GDB_REG, 3)?;
        if self.pmp_enabled {
            self.write_csr(csr::PMPCFG0, 0)?;
            for i in 0..4u16 {
                self.write_csr(csr::PMPADDR0 + i, 0)?;
            }
        }
        self.write_csr(csr::MSTATUS, state.mstatus)?;
        self.write_csr(csr::MEPC, state.mepc)?;
        self.write_csr(csr::MCAUSE, state.mcause)?;
        self.write_csr(csr::MTVAL, state.mtval)?;
        self.write_csr(csr::SEPC, state.sepc)?;
        self.write_csr(csr::SCAUSE, state.scause)?;
        self.write_csr(csr::STVAL, state.stval)?;
        self.write_csr(csr::SATP, state.satp)?;
        self.write_csr(csr::MSCRATCH, 0)?;
        self.write_csr(csr::SSCRATCH, 0)?;
        self.write_csr(csr::MEDELEG, state.medeleg)?;
        self.write_csr(csr::MIDELEG, 0)?;
        self.write_csr(csr::STVEC, state.stvec)?;
        self.write_csr(csr::MENVCFG, 0)?;
        self.write_csr(csr::SENVCFG, 0)?;
        self.write_csr(csr::SSP, 0)?;
        let mut g_pkt = String::with_capacity(1 + 33 * 16);
        g_pkt.push('G');
        for (i, &reg) in state.x.iter().enumerate() {
            let v = if i == 0 { 0 } else { reg };
            g_pkt.push_str(&encode_le_hex_u64(v));
        }
        g_pkt.push_str(&encode_le_hex_u64(state.pc));
        let resp = self.cmd(&g_pkt)?;
        if resp != "OK" {
            return Err(TargetError::Protocol(format!("GDB G failed: '{resp}'")));
        }
        for (i, &reg) in state.f.iter().enumerate() {
            self.write_reg(33 + i as u32, reg)?;
        }
        self.write_csr(csr::FCSR, u64::from(state.fcsr & 0xff))?;
        self.write_reg(PRIV_GDB_REG, u64::from(state.prv))?;
        Ok(())
    }

    fn get_state(&mut self) -> Result<ArchState, TargetError> {
        let g_resp = self.cmd("g")?;
        if g_resp.len() < 33 * 16 {
            return Err(TargetError::Protocol(format!(
                "short GDB 'g' reply ({} chars)",
                g_resp.len()
            )));
        }
        let mut x = [0u64; 32];
        for i in 0..32 {
            x[i] = decode_le_hex_u64(&g_resp[i * 16..(i + 1) * 16])?;
        }
        let pc = decode_le_hex_u64(&g_resp[32 * 16..33 * 16])?;

        let mut f = [0u64; 32];
        for (i, value) in f.iter_mut().enumerate() {
            *value = self.read_reg(33 + i as u32)?;
        }
        let fcsr = (self.read_csr(csr::FCSR)? & 0xff) as u32;

        let (prv, mstatus, mepc, mcause, mtval, sstatus, sepc, scause, stval, stvec, medeleg, satp) =
            if self.sync_csrs {
                let prv = (self.read_reg(PRIV_GDB_REG)? & 3) as u8;
                let mstatus = self.read_csr(csr::MSTATUS)?;
                let mepc = self.read_csr(csr::MEPC)?;
                let mcause = self.read_csr(csr::MCAUSE)?;
                let mtval = self.read_csr(csr::MTVAL)?;
                let sstatus = self.read_csr(csr::SSTATUS)?;
                let sepc = self.read_csr(csr::SEPC)?;
                let scause = self.read_csr(csr::SCAUSE)?;
                let stval = self.read_csr(csr::STVAL)?;
                let stvec = self.read_csr(csr::STVEC)?;
                let medeleg = self.read_csr(csr::MEDELEG)?;
                let satp = if prv == 1 && mstatus & (1 << 20) != 0 {
                    // QEMU applies mstatus.TVM to debugger satp reads. Elevate
                    // only for this otherwise-unreadable sample; changing mode
                    // also clears QEMU's hidden LR/SC reservation state.
                    self.write_reg(PRIV_GDB_REG, 3)?;
                    let value = self.read_csr(csr::SATP);
                    let restore = self.write_reg(PRIV_GDB_REG, u64::from(prv));
                    match value {
                        Ok(value) => {
                            restore?;
                            value
                        }
                        Err(error) => {
                            let _ = restore;
                            return Err(error);
                        }
                    }
                } else {
                    self.read_csr(csr::SATP)?
                };
                (
                    prv, mstatus, mepc, mcause, mtval, sstatus, sepc, scause, stval, stvec,
                    medeleg, satp,
                )
            } else {
                (3, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0)
            };

        Ok(ArchState {
            pc,
            prv,
            x,
            f,
            fcsr,
            mstatus,
            mepc,
            mcause,
            mtval,
            sstatus,
            sepc,
            scause,
            stval,
            stvec,
            medeleg,
            satp,
        })
    }

    fn step_one(&mut self) -> Result<(), TargetError> {
        let resp = self.cmd("vCont;s:1")?;
        if !resp.starts_with('T') && !resp.starts_with('S') {
            return Err(TargetError::Protocol(format!(
                "unexpected step reply: '{resp}'"
            )));
        }
        Ok(())
    }

    fn run_until(&mut self, target_pc: u64, max_insns: u64) -> Result<StopReason, TargetError> {
        // A GDB continue cannot enforce an instruction count. Step instead so a
        // looping guest cannot be mistaken for a completed block.
        for _ in 0..max_insns {
            if self.read_reg(32)? == target_pc {
                return Ok(StopReason::Breakpoint);
            }
            self.step_one()?;
        }
        if self.read_reg(32)? == target_pc {
            Ok(StopReason::Breakpoint)
        } else {
            Ok(StopReason::LimitReached)
        }
    }
}

impl Drop for QemuGdbTarget {
    fn drop(&mut self) {
        let _ = self.child.kill();
        let _ = self.child.wait();
    }
}

fn pick_free_port() -> Result<u16, TargetError> {
    let listener = TcpListener::bind("127.0.0.1:0")?;
    Ok(listener.local_addr()?.port())
}

fn encode_le_hex_u64(val: u64) -> String {
    let mut s = String::with_capacity(16);
    for b in val.to_le_bytes() {
        use std::fmt::Write as _;
        let _ = write!(s, "{b:02x}");
    }
    s
}

fn decode_le_hex_u64(hex: &str) -> Result<u64, TargetError> {
    if hex.is_empty() {
        return Err(TargetError::Protocol(
            "QEMU GDB returned an empty register value".into(),
        ));
    }
    if hex.len() == 3
        && hex.starts_with('E')
        && hex[1..].bytes().all(|byte| byte.is_ascii_hexdigit())
    {
        return Err(TargetError::Protocol(format!(
            "QEMU GDB returned error '{hex}'"
        )));
    }
    if hex.len() % 2 != 0 {
        return Err(TargetError::Protocol(format!(
            "odd-length register value '{hex}'"
        )));
    }
    if hex.len() > 16 {
        return Err(TargetError::Protocol(format!(
            "hex value too long: '{hex}'"
        )));
    }
    let mut bytes = [0u8; 8];
    let n = hex.len() / 2;
    for (i, slot) in bytes.iter_mut().take(n).enumerate() {
        *slot = u8::from_str_radix(&hex[i * 2..i * 2 + 2], 16)
            .map_err(|e| TargetError::Protocol(e.to_string()))?;
    }
    Ok(u64::from_le_bytes(bytes))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn register_decoder_rejects_rsp_errors_and_odd_lengths() {
        assert!(decode_le_hex_u64("").is_err());
        assert!(decode_le_hex_u64("E14").is_err());
        assert!(decode_le_hex_u64("123").is_err());
        assert_eq!(decode_le_hex_u64("EF00000000000000").unwrap(), 0xef);
    }

    #[test]
    fn register_decoder_accepts_little_endian_values() {
        assert_eq!(
            decode_le_hex_u64("efcdab8967452301").unwrap(),
            0x0123_4567_89ab_cdef
        );
    }

    #[test]
    fn zicfilp_and_pointer_masking_match_qemu_in_lockstep() {
        let local_qemu =
            "/Users/kmehltretter/codex/linux-work/qemu/build-d7314928-riscv64/qemu-system-riscv64";
        let qemu_bin = if std::path::Path::new(local_qemu).exists() {
            local_qemu
        } else {
            "qemu-system-riscv64"
        };
        let Ok(mut qemu) = QemuGdbTarget::spawn_bare_with_pmp(Path::new(qemu_bin), false) else {
            return;
        };
        let mut rivemu = crate::target::RivemuTarget::new_bare(true).unwrap();

        let code_base = 0x8000_0000u64;
        let trap_base = 0x8000_2000u64;
        let insns: [u32; 25] = [
            0x0000_42b7, // 0x00: lui  t0, 0x4
            0x0132_9293, // 0x04: slli t0, t0, 19
            0x0042_e293, // 0x08: ori  t0, t0, 4
            0x30a2_9073, // 0x0c: csrw menvcfg, t0
            0x3020_0073, // 0x10: mret
            0x0000_0017, // 0x14: lpad 0 (auipc x0, 0)
            0x0210_0313, // 0x18: li   t1, 0x21
            0x0393_1313, // 0x1c: slli t1, t1, 57
            0x0083_6333, // 0x20: or   t1, t1, s0
            0x05a0_0393, // 0x24: li   t2, 0x5a
            0x0073_3023, // 0x28: sd   t2, 0(t1)
            0x0003_3503, // 0x2c: ld   a0, 0(t1)
            0x0000_0397, // 0x30: auipc t2, 0
            0x00c3_8393, // 0x34: addi  t2, t2, 12
            0x0003_8067, // 0x38: jalr  x0, 0(t2)
            0x0000_0317, // 0x3c: auipc t1, 0
            0x0103_0313, // 0x40: addi  t1, t1, 16
            0x0005_53b7, // 0x44: lui   t2, 0x55 (x7 = 0x55 << 12)
            0x0003_0067, // 0x48: jalr  x0, 0(t1)
            0x0005_5017, // 0x4c: lpad  0x55 (auipc x0, 0x55)
            0x0000_0317, // 0x50: auipc t1, 0
            0x00c3_0313, // 0x54: addi  t1, t1, 12
            0x0003_0067, // 0x58: jalr  x0, 0(t1)
            0x0007_7017, // 0x5c: lpad  0x77 (mismatches x7 -> SW_CHECK!)
            0x0010_0073, // 0x60: ebreak
        ];
        let mut code_bytes = Vec::with_capacity(insns.len() * 4);
        for word in insns {
            code_bytes.extend_from_slice(&word.to_le_bytes());
        }
        let trap_insns = crate::risu::encode::build_trap_handler();
        let mut trap_bytes = Vec::with_capacity(trap_insns.len() * 4);
        for word in trap_insns {
            trap_bytes.extend_from_slice(&word.to_le_bytes());
        }

        let mut init = ArchState::default();
        init.pc = code_base;
        init.prv = 3;
        init.x[8] = 0x8001_0000;
        init.mepc = code_base + 0x14;
        // MPP = S (1 << 11), MPELP = 1 (1 << 41)
        init.mstatus = 0x0000_020a_0000_0800;

        for target in [&mut rivemu as &mut dyn CosimTarget, &mut qemu] {
            target.load_ram(code_base, &code_bytes).unwrap();
            target.load_ram(trap_base, &trap_bytes).unwrap();
            target.load_ram(0x8001_0000, &[0u8; 64]).unwrap();
            target.set_state(&init).unwrap();
            target.set_trap_vector(trap_base).unwrap();
        }

        for step in 0..30 {
            rivemu.step_one().unwrap();
            qemu.step_one().unwrap();
            let r_state = rivemu.get_state().unwrap();
            let q_state = qemu.get_state().unwrap();
            let diffs = r_state.diff(&q_state, true);
            assert!(
                diffs.is_empty(),
                "step {step} at pc={:#x} diverged: {diffs:?}",
                r_state.pc
            );
            if r_state.pc == trap_base {
                assert_eq!(r_state.mcause, 18);
                assert_eq!(r_state.mtval, 2);
                assert_eq!((r_state.mstatus >> 41) & 1, 1);
                assert_eq!(r_state.x[10], 0x5a);
                return;
            }
        }
        panic!("expected SW_CHECK trap at 0x8000_005c");
    }

    #[test]
    fn zawrs_wrs_nto_and_wrs_sto_match_qemu_in_lockstep() {
        let local_qemu =
            "/Users/kmehltretter/codex/linux-work/qemu/build-d7314928-riscv64/qemu-system-riscv64";
        let qemu_bin = if std::path::Path::new(local_qemu).exists() {
            local_qemu
        } else {
            "qemu-system-riscv64"
        };
        let Ok(mut qemu) = QemuGdbTarget::spawn_bare_with_pmp(Path::new(qemu_bin), false) else {
            return;
        };
        let mut rivemu = crate::target::RivemuTarget::new_bare(true).unwrap();

        let code_base = 0x8000_0000u64;
        let trap_base = 0x8000_2000u64;
        let insns: [u32; 9] = [
            0x1004_352f, // 0x00: lr.d    a0, (s0)
            0x00d0_0073, // 0x04: wrs.nto (clears reservation, TW=0 in S-mode so no trap)
            0x18c4_35af, // 0x08: sc.d    a1, a2, (s0) -> fails (a1 = 1)
            0x1004_352f, // 0x0c: lr.d    a0, (s0)
            0x01d0_0073, // 0x10: wrs.sto (clears reservation)
            0x18c4_36af, // 0x14: sc.d    a3, a2, (s0) -> fails (a3 = 1)
            0x01d0_0073, // 0x18: wrs.sto (retires even when TW=1)
            0x00d0_0073, // 0x1c: wrs.nto (traps when TW=1 in S-mode)
            0x0010_0073, // 0x20: ebreak
        ];
        let mut code_bytes = Vec::with_capacity(insns.len() * 4);
        for word in insns {
            code_bytes.extend_from_slice(&word.to_le_bytes());
        }
        let trap_insns = crate::risu::encode::build_trap_handler();
        let mut trap_bytes = Vec::with_capacity(trap_insns.len() * 4);
        for word in trap_insns {
            trap_bytes.extend_from_slice(&word.to_le_bytes());
        }

        // Phase 1: S-mode with TW = 0: both wrs.nto and wrs.sto retire and clear LR reservation.
        let mut init = ArchState::default();
        init.pc = code_base;
        init.prv = 1; // S-mode
        init.x[8] = 0x8001_0000;
        init.x[12] = 0x77;

        for target in [&mut rivemu as &mut dyn CosimTarget, &mut qemu] {
            target.load_ram(code_base, &code_bytes).unwrap();
            target.load_ram(trap_base, &trap_bytes).unwrap();
            target.load_ram(0x8001_0000, &[0x11u8; 64]).unwrap();
            target.set_state(&init).unwrap();
            target.set_trap_vector(trap_base).unwrap();
        }

        for step in 0..6 {
            rivemu.step_one().unwrap();
            qemu.step_one().unwrap();
            let r_state = rivemu.get_state().unwrap();
            let q_state = qemu.get_state().unwrap();
            let diffs = r_state.diff(&q_state, true);
            assert!(
                diffs.is_empty(),
                "phase 1 step {step} diverged: {diffs:?}"
            );
        }
        let post_p1 = rivemu.get_state().unwrap();
        assert_eq!(post_p1.x[11], 1); // sc.d after wrs.nto failed
        assert_eq!(post_p1.x[13], 1); // sc.d after wrs.sto failed

        // Phase 2: S-mode with TW = 1 (1 << 21): wrs.sto at 0x18 retires, wrs.nto at 0x1c traps with ILLEGAL_INSN (2).
        init.pc = code_base + 0x18;
        init.mstatus |= 1 << 21; // TW
        for target in [&mut rivemu as &mut dyn CosimTarget, &mut qemu] {
            target.set_state(&init).unwrap();
            target.set_trap_vector(trap_base).unwrap();
        }

        for step in 0..2 {
            rivemu.step_one().unwrap();
            qemu.step_one().unwrap();
            let r_state = rivemu.get_state().unwrap();
            let q_state = qemu.get_state().unwrap();
            let diffs = r_state.diff(&q_state, true);
            assert!(
                diffs.is_empty(),
                "phase 2 step {step} diverged: {diffs:?}"
            );
        }
        let post_p2 = rivemu.get_state().unwrap();
        assert_eq!(post_p2.pc, trap_base);
        assert_eq!(post_p2.mcause, 2);
        assert_eq!(post_p2.mtval, 0x00d0_0073);
    }

    #[test]
    fn smepmp_and_smstateen_match_qemu_in_lockstep() {
        let local_qemu =
            "/Users/kmehltretter/codex/linux-work/qemu/build-d7314928-riscv64/qemu-system-riscv64";
        let qemu_bin = if std::path::Path::new(local_qemu).exists() {
            local_qemu
        } else {
            "qemu-system-riscv64"
        };
        let Ok(mut qemu) = QemuGdbTarget::spawn_bare_with_pmp(Path::new(qemu_bin), true) else {
            return;
        };
        let mut rivemu = crate::target::RivemuTarget::new_bare(true).unwrap();

        let code_base = 0x8000_0000u64;
        let scode_base = 0x8000_4000u64;
        let trap_base = 0x8000_2000u64;
        let data_base = 0x8001_0000u64;

        // M-mode code at 0x8000_0000:
        //   0x00: csrw mstateen0, x20        (0x30ca_1073)
        //   0x04: csrr x21, mstateen0        (0x30c0_2a_f3)
        //   0x08: csrw mseccfg, x22          (0x747b_1073) -> set RLB=1 (4)
        //   0x0c: csrw pmpaddr0, x23         (0x3b0b_9073) -> 0x8000_4000 >> 2 (covers code_base & trap_base)
        //   0x10: csrw pmpaddr1, x24         (0x3b1c_1073) -> 0x8000_8000 >> 2 (covers scode_base)
        //   0x14: csrw pmpaddr2, x25         (0x3b2c_9073) -> 0x8001_0000 >> 2 (bottom of data_base)
        //   0x18: csrw pmpaddr3, x26         (0x3b3d_1073) -> 0x8001_4000 >> 2 (covers data_base)
        //   0x1c: csrw pmpcfg0, x27          (0x3a0d_9073) -> lock entry 0 first
        //   0x20: csrw pmpcfg0, x28          (0x3a0e_1073) -> modify locked entry 0 via RLB=1 & stage shared entry 3
        //   0x24: csrw mseccfg, x29          (0x747e_9073) -> set MML|MMWP (3), clearing RLB
        //   0x28: ld   x11, 0(x10)           (0x0005_3583) -> M-mode load from shared data_base succeeds
        //   0x2c: sd   x12, 0(x10)           (0x00c5_3023) -> M-mode store to shared data_base succeeds
        //   0x30: mret                       (0x3020_0073) -> drop to S-mode at scode_base
        let m_insns: [u32; 13] = [
            0x30ca_1073,
            0x30c0_2af3,
            0x747b_1073,
            0x3b0b_9073,
            0x3b1c_1073,
            0x3b2c_9073,
            0x3b3d_1073,
            0x3a0d_9073,
            0x3a0e_1073,
            0x747e_9073,
            0x0005_3583,
            0x00c5_3023,
            0x3020_0073,
        ];
        // S-mode code at 0x8000_4000:
        //   0x00: csrr x13, sstateen0        (0x10c0_26f3) -> succeeds because mstateen0.SE=1
        //   0x04: csrr x14, senvcfg          (0x10a0_2773) -> traps (mcause=2) because mstateen0.ENVCFG=0!
        //   0x08: ld   x15, 0(x10)           (0x0005_3783) -> S-mode load from shared data_base succeeds
        //   0x0c: sd   x12, 0(x10)           (0x00c5_3023) -> S-mode store to shared data_base traps (mcause=7)!
        //   0x10: ebreak                     (0x0010_0073)
        let s_insns: [u32; 5] = [
            0x10c0_26f3,
            0x10a0_2773,
            0x0005_3783,
            0x00c5_3023,
            0x0010_0073,
        ];
        let mut m_bytes = Vec::with_capacity(m_insns.len() * 4);
        for w in m_insns {
            m_bytes.extend_from_slice(&w.to_le_bytes());
        }
        let mut s_bytes = Vec::with_capacity(s_insns.len() * 4);
        for w in s_insns {
            s_bytes.extend_from_slice(&w.to_le_bytes());
        }
        let trap_bytes = crate::risu::encode::build_trap_handler();

        let mut init = ArchState::default();
        init.pc = code_base;
        init.prv = 3; // M-mode
        init.mepc = scode_base;
        init.mstatus |= 1 << 11; // MPP = S
        init.x[10] = data_base;
        init.x[12] = 0xfeed_face_cafe_beef;
        init.x[20] = 1u64 << 63; // mstateen0 = SE (bit 63), ENVCFG = 0 (bit 62)
        init.x[22] = 4; // mseccfg = RLB
        init.x[23] = scode_base >> 2;
        init.x[24] = (scode_base + 0x4000) >> 2;
        init.x[25] = data_base >> 2;
        init.x[26] = (data_base + 0x4000) >> 2;
        init.x[27] = 0x00_00_00_8d; // entry 0 locked TOR R|X
        // Entry 0: L=1, TOR, X-only (0x8c) [0, 0x8000_4000)
        // Entry 1: L=0, TOR, X-only (0x0c) [0x8000_4000, 0x8000_8000) -> S-mode X-only under MML
        // Entry 2: OFF (0x00)
        // Entry 3: L=0, TOR, W=1, X=0 (0x0a) [0x8001_0000, 0x8001_4000) -> Shared M=RW, S/U=R under MML
        init.x[28] = 0x0a_00_0c_8c;
        init.x[29] = 3; // mseccfg = MML | MMWP

        for target in [&mut rivemu as &mut dyn CosimTarget, &mut qemu] {
            target.load_ram(code_base, &m_bytes).unwrap();
            target.load_ram(scode_base, &s_bytes).unwrap();
            target.load_ram(trap_base, &trap_bytes).unwrap();
            target.load_ram(data_base, &[0x42u8; 64]).unwrap();
            target.set_state(&init).unwrap();
            target.set_trap_vector(trap_base).unwrap();
        }

        // Step through M-mode setup + MRET (13 steps), sstateen0 read (1 step), and senvcfg trap (1 step) = 15 steps:
        for step in 0..15 {
            rivemu.step_one().unwrap();
            qemu.step_one().unwrap();
            let r_state = rivemu.get_state().unwrap();
            let q_state = qemu.get_state().unwrap();
            let diffs = r_state.diff(&q_state, true);
            assert!(
                diffs.is_empty(),
                "step {step} at pc={:#x} diverged: {diffs:?}",
                r_state.pc
            );
        }
        // At step 15, S-mode `csrr x14, senvcfg` trapped to trap_base with mcause = 2 (ILLEGAL_INSN)!
        let trap1 = rivemu.get_state().unwrap();
        assert_eq!(trap1.pc, trap_base);
        assert_eq!(trap1.mcause, 2);
        assert_eq!(trap1.mepc, scode_base + 4);

        // Step through the 8-instruction M-mode trap handler (which advances mepc to scode_base + 8 and executes mret)
        // followed by `ld x15, 0(x10)` and `sd x12, 0(x10)` in S-mode (8 + 2 = 10 steps):
        for step in 0..10 {
            rivemu.step_one().unwrap();
            qemu.step_one().unwrap();
            let r_state = rivemu.get_state().unwrap();
            let q_state = qemu.get_state().unwrap();
            let diffs = r_state.diff(&q_state, true);
            assert!(
                diffs.is_empty(),
                "S-mode shared data step {step} diverged: {diffs:?}"
            );
        }
        let trap2 = rivemu.get_state().unwrap();
        assert_eq!(trap2.x[15], 0xfeed_face_cafe_beef); // S-mode load observed M-mode's store!
        assert_eq!(trap2.pc, trap_base);
        assert_eq!(trap2.mcause, 7); // S-mode store to shared region faulted with STORE_ACCESS!
        assert_eq!(trap2.mtval, data_base);
    }
}
