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
}

impl QemuGdbTarget {
    /// Spawns a bare-metal `qemu-system-riscv64` instance (`-bios none`) for `RISU` lockstep testing.
    pub fn spawn_bare(qemu_bin: &Path) -> Result<Self, TargetError> {
        let mut target = Self::spawn_with_args(
            qemu_bin,
            &[
                "-machine",
                "virt",
                "-cpu",
                "rv64,c=true,h=false,pmp=false,sv57=false,zba=true,zbb=true,zbc=true,zbs=true,zicbom=true,zicboz=true,svinval=true,svpbmt=true,sstc=true",
                "-m",
                "128M",
                "-smp",
                "1",
                "-bios",
                "none",
            ],
        )?;
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
        };
        let _ = target.cmd("qSupported:multiprocess+;xmlRegisters=i386")?;
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
        self.stream.write_all(b"+")?;
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
        // Chunk writes into 2 KiB slices to stay well within GDB packet limits.
        for (i, chunk) in data.chunks(2048).enumerate() {
            let addr = gpa + (i * 2048) as u64;
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
        for (i, chunk) in buf.chunks_mut(2048).enumerate() {
            let addr = gpa + (i * 2048) as u64;
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
        self.write_csr(csr::SENVCFG, 0)?;
        let mut g_pkt = String::with_capacity(1 + 33 * 16);
        g_pkt.push('G');
        for i in 0..32 {
            let v = if i == 0 { 0 } else { state.x[i] };
            g_pkt.push_str(&encode_le_hex_u64(v));
        }
        g_pkt.push_str(&encode_le_hex_u64(state.pc));
        let resp = self.cmd(&g_pkt)?;
        if resp != "OK" {
            return Err(TargetError::Protocol(format!("GDB G failed: '{resp}'")));
        }
        for i in 0..32 {
            self.write_reg(33 + i as u32, state.f[i])?;
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
}
