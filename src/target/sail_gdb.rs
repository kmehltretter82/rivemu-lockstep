//! Sail RISC-V cosimulation target driven over the GDB Remote Serial Protocol.
//!
//! Unmodified Sail exposes integer registers, PC, floating-point registers,
//! and `fcsr`, but not privileged CSRs. Privileged setup is performed by a
//! bootstrap embedded in the ELF. Stock Sail uses binary `X` memory writes and
//! has a `P`-packet endian quirk; an explicit dialect selects patched behavior.

use std::io::{Read, Write};
use std::net::{TcpListener, TcpStream};
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Stdio};
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{Duration, Instant};

use crate::risu::RisuCase;
use crate::risu::Suite;
use crate::risu::encode::build_trap_handler;
use crate::risu::harness::{CODE_BASE, SCRATCH_BASE, TRAP_BASE};
use crate::risu::sv39::VM_SETUP_BASE;
use crate::target::sail_elf::{SailElfLayout, build_sail_elf};
use crate::{ArchState, CosimTarget, StopReason, TargetError};

const PC_GDB_REG: u32 = 32;
const FPR_GDB_BASE: u32 = 33;
const FCSR_GDB_REG: u32 = 65;
const PRIV_GDB_REG: u32 = 66;
const MTVEC_GDB_REG: u32 = 67;
const MSTATUS_GDB_REG: u32 = 68;
const MEPC_GDB_REG: u32 = 69;
const MCAUSE_GDB_REG: u32 = 70;
const MTVAL_GDB_REG: u32 = 71;
const SSTATUS_GDB_REG: u32 = 72;
const SEPC_GDB_REG: u32 = 73;
const SCAUSE_GDB_REG: u32 = 74;
const STVAL_GDB_REG: u32 = 75;
const SATP_GDB_REG: u32 = 76;
const STVEC_GDB_REG: u32 = 77;
const MSCRATCH_GDB_REG: u32 = 78;
const SSCRATCH_GDB_REG: u32 = 79;
const MEDELEG_GDB_REG: u32 = 80;
const MIDELEG_GDB_REG: u32 = 81;
const SENVCFG_GDB_REG: u32 = 82;
const DEFAULT_MEMORY_CHUNK: usize = 1024;
const MAX_MEMORY_CHUNK: usize = 2048;
/// Address of the bootstrap used to install `mtvec` in stock Sail.
pub const SAIL_BOOTSTRAP_BASE: u64 = 0x8000_3000;
static TEMP_ELF_SEQUENCE: AtomicU64 = AtomicU64::new(0);

/// Description of the privileged-state bootstrap embedded in a Sail test ELF.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct SailBootstrap {
    /// Address of the first bootstrap instruction.
    pub entry_pc: u64,
    /// Number of bootstrap instructions to single-step.
    pub instruction_count: u32,
    /// Trap-vector address installed by the bootstrap.
    pub trap_vector: u64,
}

impl SailBootstrap {
    /// Creates a bootstrap description.
    pub const fn new(entry_pc: u64, instruction_count: u32, trap_vector: u64) -> Self {
        Self {
            entry_pc,
            instruction_count,
            trap_vector,
        }
    }
}

/// Encoding used by Sail's `P` register-write packet parser.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum SailRegisterWriteEncoding {
    /// Stock Sail parses the payload as a numeric hexadecimal integer.
    NumericHex,
    /// A conforming patched server interprets the payload as target-endian bytes.
    LittleEndianBytes,
}

/// GDB RSP operation used to update model memory.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum SailMemoryWriteEncoding {
    /// Binary `X` packet implemented by stock Sail.
    BinaryX,
    /// Hexadecimal `M` packet, for a patched server that explicitly enables it.
    HexM,
}

/// Protocol behavior of the connected Sail GDB server.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct SailGdbDialect {
    /// Register-write payload encoding.
    pub register_write: SailRegisterWriteEncoding,
    /// Memory-write packet encoding.
    pub memory_write: SailMemoryWriteEncoding,
}

impl Default for SailGdbDialect {
    fn default() -> Self {
        Self {
            register_write: SailRegisterWriteEncoding::NumericHex,
            memory_write: SailMemoryWriteEncoding::BinaryX,
        }
    }
}

/// A fresh Sail RISC-V process controlled through its GDB server.
pub struct SailGdbTarget {
    child: Child,
    stream: TcpStream,
    bootstrap: SailBootstrap,
    dialect: SailGdbDialect,
    debug_v1: bool,
    memory_chunk: usize,
    owned_elf: Option<PathBuf>,
}

impl SailGdbTarget {
    /// Builds a case-specific ELF, starts a fresh Sail process, and owns the temporary image.
    pub fn spawn_case(sail_bin: &Path, case: &RisuCase) -> Result<Self, TargetError> {
        let layout = SailElfLayout {
            code_base: CODE_BASE,
            entry_addr: SAIL_BOOTSTRAP_BASE,
            code_addr: CODE_BASE,
            trap_addr: TRAP_BASE,
            bootstrap_addr: SAIL_BOOTSTRAP_BASE,
            scratch_addr: SCRATCH_BASE,
            vm_setup_addr: VM_SETUP_BASE,
        };
        let bootstrap_code = build_sail_bootstrap();
        let elf = build_sail_elf(
            layout,
            case.code_bytes(),
            &build_trap_handler(),
            &bootstrap_code,
            case.scratch(),
            case.vm_setup(),
        )
        .map_err(|error| TargetError::Protocol(format!("cannot build Sail ELF: {error}")))?;
        let elf_path = write_temp_elf(case.seed(), &elf)?;
        let bootstrap_insns = u32::try_from(bootstrap_code.len() / 4)
            .expect("Sail bootstrap instruction count fits u32");
        let bootstrap = SailBootstrap::new(SAIL_BOOTSTRAP_BASE, bootstrap_insns, TRAP_BASE);
        let spawn_result = if matches!(case.suite(), Suite::Privileged | Suite::Sv39) {
            // Model an implementation with no PMP entries so direct S/U-mode
            // execution and page-table walks can reach test RAM. Rivemu's bare
            // lockstep target uses the corresponding non-strict PMP policy.
            const NO_PMP_CONFIG: &str = concat!(
                env!("CARGO_MANIFEST_DIR"),
                "/configs/sail-lower-priv-no-pmp.json"
            );
            Self::spawn_with_args(
                sail_bin,
                &elf_path,
                &["--config-override", NO_PMP_CONFIG],
                bootstrap,
            )
        } else {
            Self::spawn(sail_bin, &elf_path, bootstrap)
        };
        match spawn_result {
            Ok(mut target) => {
                target.owned_elf = Some(elf_path);
                Ok(target)
            }
            Err(error) => {
                let _ = std::fs::remove_file(elf_path);
                Err(error)
            }
        }
    }

    /// Starts Sail with a prebuilt ELF and connects to its GDB server.
    pub fn spawn(
        sail_bin: &Path,
        elf_path: &Path,
        bootstrap: SailBootstrap,
    ) -> Result<Self, TargetError> {
        Self::spawn_with_args(sail_bin, elf_path, &[], bootstrap)
    }

    /// Starts Sail with additional model arguments placed before the GDB option.
    pub fn spawn_with_args(
        sail_bin: &Path,
        elf_path: &Path,
        extra_args: &[&str],
        bootstrap: SailBootstrap,
    ) -> Result<Self, TargetError> {
        Self::spawn_with_dialect(
            sail_bin,
            elf_path,
            extra_args,
            bootstrap,
            SailGdbDialect::default(),
        )
    }

    /// Starts Sail using an explicitly selected GDB-server dialect.
    pub fn spawn_with_dialect(
        sail_bin: &Path,
        elf_path: &Path,
        extra_args: &[&str],
        bootstrap: SailBootstrap,
        dialect: SailGdbDialect,
    ) -> Result<Self, TargetError> {
        if bootstrap.instruction_count == 0 {
            return Err(TargetError::Protocol(
                "Sail bootstrap must contain at least one instruction".into(),
            ));
        }

        let port = pick_free_port()?;
        let mut command = Command::new(sail_bin);
        command
            .args(extra_args)
            .arg("--gdb-server-port")
            .arg(port.to_string())
            .arg(elf_path)
            .stdin(Stdio::null())
            .stdout(Stdio::null())
            .stderr(Stdio::null());

        let mut child = command.spawn()?;
        let deadline = Instant::now() + Duration::from_secs(5);
        let stream = loop {
            if let Some(status) = child.try_wait()? {
                return Err(TargetError::Protocol(format!(
                    "Sail RISC-V exited before its GDB server was ready: {status}"
                )));
            }
            match TcpStream::connect(("127.0.0.1", port)) {
                Ok(stream) => break stream,
                Err(_) if Instant::now() < deadline => {
                    std::thread::sleep(Duration::from_millis(15));
                }
                Err(error) => {
                    let _ = child.kill();
                    let _ = child.wait();
                    return Err(TargetError::Io(error));
                }
            }
        };
        stream.set_nodelay(true)?;
        stream.set_read_timeout(Some(Duration::from_secs(10)))?;
        stream.set_write_timeout(Some(Duration::from_secs(10)))?;

        let mut target = Self {
            child,
            stream,
            bootstrap,
            dialect,
            debug_v1: false,
            memory_chunk: DEFAULT_MEMORY_CHUNK,
            owned_elf: None,
        };
        let response = target.cmd("qSupported:multiprocess+")?;
        if response.starts_with('E') {
            return Err(TargetError::Protocol(format!(
                "Sail rejected qSupported: '{response}'"
            )));
        }
        target.debug_v1 = response
            .split(';')
            .any(|feature| feature == "sail-riscv-debug-v1+");
        if target.debug_v1 {
            target.dialect = SailGdbDialect {
                register_write: SailRegisterWriteEncoding::LittleEndianBytes,
                memory_write: SailMemoryWriteEncoding::HexM,
            };
        }
        target.memory_chunk = memory_chunk_from_supported(&response);
        Ok(target)
    }

    /// Returns the configured GDB-server dialect.
    pub const fn dialect(&self) -> SailGdbDialect {
        self.dialect
    }

    /// Sends one GDB RSP command and returns its decoded response body.
    pub fn cmd(&mut self, payload: &str) -> Result<String, TargetError> {
        self.cmd_bytes(payload.as_bytes())
    }

    fn cmd_bytes(&mut self, payload: &[u8]) -> Result<String, TargetError> {
        let transmitted = encode_rsp_payload(payload);
        let checksum = rsp_checksum(&transmitted);
        let mut frame = Vec::with_capacity(transmitted.len() + 4);
        frame.push(b'$');
        frame.extend_from_slice(&transmitted);
        frame.extend_from_slice(format!("#{checksum:02x}").as_bytes());
        self.stream.write_all(&frame)?;

        loop {
            let body = self.receive_packet()?;
            if is_console_output_packet(&body) {
                continue;
            }
            return String::from_utf8(body)
                .map_err(|error| TargetError::Protocol(error.to_string()));
        }
    }

    /// Reads an integer register or PC using normal little-endian RSP encoding.
    pub fn read_reg(&mut self, regnum: u32) -> Result<u64, TargetError> {
        let response = self.cmd(&format!("p{regnum:x}"))?;
        decode_le_hex_u64(&response)
    }

    /// Writes an integer register or PC using the selected Sail dialect.
    pub fn write_reg(&mut self, regnum: u32, value: u64) -> Result<(), TargetError> {
        let encoded = self.encode_register_u64(value);
        self.write_register_packet(regnum, &encoded)
    }

    /// Reads the raw 64-bit value of one floating-point register.
    pub fn read_freg(&mut self, index: usize) -> Result<u64, TargetError> {
        if index >= 32 {
            return Err(TargetError::Protocol(format!(
                "invalid floating-point register f{index}"
            )));
        }
        self.read_reg(FPR_GDB_BASE + index as u32)
    }

    /// Writes the raw 64-bit value of one floating-point register.
    ///
    /// Stock Sail 0.16 interprets all multi-byte `P` writes as numeric hex.
    pub fn write_freg(&mut self, index: usize, value: u64) -> Result<(), TargetError> {
        if index >= 32 {
            return Err(TargetError::Protocol(format!(
                "invalid floating-point register f{index}"
            )));
        }
        let encoded = self.encode_register_u64(value);
        self.write_register_packet(FPR_GDB_BASE + index as u32, &encoded)
    }

    fn write_fcsr(&mut self, value: u32) -> Result<(), TargetError> {
        let encoded = match self.dialect.register_write {
            SailRegisterWriteEncoding::NumericHex => format!("{value:08x}"),
            SailRegisterWriteEncoding::LittleEndianBytes => encode_hex_bytes(&value.to_le_bytes()),
        };
        self.write_register_packet(FCSR_GDB_REG, &encoded)
    }

    fn write_privilege(&mut self, value: u8) -> Result<(), TargetError> {
        self.write_register_packet(PRIV_GDB_REG, &format!("{value:02x}"))
    }

    fn encode_register_u64(&self, value: u64) -> String {
        match self.dialect.register_write {
            SailRegisterWriteEncoding::NumericHex => format!("{value:016x}"),
            SailRegisterWriteEncoding::LittleEndianBytes => encode_le_hex_u64(value),
        }
    }

    fn read_fcsr(&mut self) -> Result<u32, TargetError> {
        let response = self.cmd(&format!("p{FCSR_GDB_REG:x}"))?;
        let bytes = decode_hex_bytes(&response)?;
        if bytes.len() != 4 {
            return Err(TargetError::Protocol(format!(
                "Sail returned {} bytes for 32-bit fcsr",
                bytes.len()
            )));
        }
        Ok(u32::from_le_bytes(
            bytes.try_into().expect("length checked"),
        ))
    }

    fn write_register_packet(&mut self, regnum: u32, encoded: &str) -> Result<(), TargetError> {
        let response = self.cmd(&format!("P{regnum:x}={encoded}"))?;
        if response != "OK" {
            return Err(TargetError::Protocol(format!(
                "Sail GDB P{regnum:x} failed: '{response}'"
            )));
        }
        Ok(())
    }

    fn receive_packet(&mut self) -> Result<Vec<u8>, TargetError> {
        for _ in 0..3 {
            let mut byte = [0u8; 1];
            loop {
                self.stream.read_exact(&mut byte)?;
                match byte[0] {
                    b'$' => break,
                    b'+' => continue,
                    b'-' => {
                        return Err(TargetError::Protocol(
                            "Sail GDB rejected an RSP packet checksum".into(),
                        ));
                    }
                    _ => continue,
                }
            }

            let mut transmitted = Vec::with_capacity(64);
            loop {
                self.stream.read_exact(&mut byte)?;
                if byte[0] == b'#' {
                    break;
                }
                transmitted.push(byte[0]);
            }
            let mut checksum_hex = [0u8; 2];
            self.stream.read_exact(&mut checksum_hex)?;
            let expected = parse_checksum(checksum_hex)?;
            if rsp_checksum(&transmitted) != expected {
                self.stream.write_all(b"-")?;
                continue;
            }
            self.stream.write_all(b"+")?;
            return decode_rsp_payload(&transmitted);
        }
        Err(TargetError::Protocol(
            "Sail GDB repeatedly returned corrupt RSP packets".into(),
        ))
    }
}

impl CosimTarget for SailGdbTarget {
    fn name(&self) -> &'static str {
        "Sail"
    }

    fn supports_replay(&self) -> bool {
        false
    }

    fn supports_privileged_state(&self) -> bool {
        self.debug_v1
    }

    fn load_ram(&mut self, gpa: u64, data: &[u8]) -> Result<(), TargetError> {
        for (index, chunk) in data.chunks(self.memory_chunk).enumerate() {
            let address = gpa + (index * self.memory_chunk) as u64;
            let response = match self.dialect.memory_write {
                SailMemoryWriteEncoding::BinaryX => {
                    let mut payload = format!("X{address:x},{:x}:", chunk.len()).into_bytes();
                    payload.extend_from_slice(chunk);
                    self.cmd_bytes(&payload)?
                }
                SailMemoryWriteEncoding::HexM => {
                    let encoded = encode_hex_bytes(chunk);
                    self.cmd(&format!("M{address:x},{:x}:{encoded}", chunk.len()))?
                }
            };
            if response != "OK" {
                return Err(TargetError::Protocol(format!(
                    "Sail GDB memory write at {address:#x} failed: '{response}'"
                )));
            }
        }
        Ok(())
    }

    fn read_ram(&mut self, gpa: u64, buffer: &mut [u8]) -> Result<(), TargetError> {
        for (index, chunk) in buffer.chunks_mut(self.memory_chunk).enumerate() {
            let address = gpa + (index * self.memory_chunk) as u64;
            let response = self.cmd(&format!("m{address:x},{:x}", chunk.len()))?;
            let bytes = decode_hex_bytes(&response)?;
            if bytes.len() != chunk.len() {
                return Err(TargetError::Protocol(format!(
                    "Sail GDB m{address:#x} returned {} bytes; expected {}",
                    bytes.len(),
                    chunk.len()
                )));
            }
            chunk.copy_from_slice(&bytes);
        }
        Ok(())
    }

    fn set_trap_vector(&mut self, address: u64) -> Result<(), TargetError> {
        if self.debug_v1 {
            return self.write_reg(MTVEC_GDB_REG, address);
        }
        if address != self.bootstrap.trap_vector {
            return Err(TargetError::Protocol(format!(
                "Sail bootstrap installs trap vector {:#x}, not requested {address:#x}",
                self.bootstrap.trap_vector
            )));
        }
        Ok(())
    }

    fn set_state(&mut self, state: &ArchState) -> Result<(), TargetError> {
        validate_seed_privilege(self.debug_v1, state.prv)?;

        if self.debug_v1 {
            self.write_reg(MSTATUS_GDB_REG, state.mstatus)?;
            self.write_reg(MEPC_GDB_REG, state.mepc)?;
            self.write_reg(MCAUSE_GDB_REG, state.mcause)?;
            self.write_reg(MTVAL_GDB_REG, state.mtval)?;
            self.write_reg(SSTATUS_GDB_REG, state.sstatus)?;
            self.write_reg(SEPC_GDB_REG, state.sepc)?;
            self.write_reg(SCAUSE_GDB_REG, state.scause)?;
            self.write_reg(STVAL_GDB_REG, state.stval)?;
            self.write_reg(SATP_GDB_REG, state.satp)?;
            self.write_reg(MTVEC_GDB_REG, self.bootstrap.trap_vector)?;
            self.write_reg(STVEC_GDB_REG, state.stvec)?;
            self.write_reg(MSCRATCH_GDB_REG, 0)?;
            self.write_reg(SSCRATCH_GDB_REG, 0)?;
            self.write_reg(MEDELEG_GDB_REG, state.medeleg)?;
            self.write_reg(MIDELEG_GDB_REG, 0)?;
            self.write_reg(SENVCFG_GDB_REG, 0)?;
        } else {
            let initial_pc = self.read_reg(PC_GDB_REG)?;
            if initial_pc != self.bootstrap.entry_pc {
                return Err(TargetError::Protocol(format!(
                    "stock Sail cannot rewind PC from {initial_pc:#x} to bootstrap {:#x}; use a fresh case target",
                    self.bootstrap.entry_pc
                )));
            }
            for _ in 0..self.bootstrap.instruction_count {
                self.step_one()?;
            }

            let bootstrapped_pc = self.read_reg(PC_GDB_REG)?;
            if bootstrapped_pc != state.pc {
                return Err(TargetError::Protocol(format!(
                    "Sail bootstrap ended at {bootstrapped_pc:#x}, expected initial PC {:#x}",
                    state.pc
                )));
            }
        }

        for (index, &value) in state.x.iter().enumerate().skip(1) {
            self.write_reg(index as u32, value)?;
        }
        for (index, &value) in state.f.iter().enumerate() {
            self.write_freg(index, value)?;
        }
        self.write_fcsr(state.fcsr & 0xff)?;
        if self.debug_v1 {
            self.write_reg(PC_GDB_REG, state.pc)?;
            self.write_privilege(state.prv)?;
        }
        Ok(())
    }

    fn get_state(&mut self) -> Result<ArchState, TargetError> {
        let mut x = [0u64; 32];
        for (index, value) in x.iter_mut().enumerate().skip(1) {
            *value = self.read_reg(index as u32)?;
        }
        let pc = self.read_reg(PC_GDB_REG)?;
        let mut f = [0u64; 32];
        for (index, value) in f.iter_mut().enumerate() {
            *value = self.read_freg(index)?;
        }
        let fcsr = self.read_fcsr()? & 0xff;

        let mut state = ArchState {
            pc,
            prv: 3,
            x,
            f,
            fcsr,
            mstatus: 0,
            mepc: 0,
            mcause: 0,
            mtval: 0,
            sstatus: 0,
            sepc: 0,
            scause: 0,
            stval: 0,
            stvec: 0,
            medeleg: 0,
            satp: 0,
        };
        if self.debug_v1 {
            state.prv = self.read_reg(PRIV_GDB_REG)? as u8;
            state.mstatus = self.read_reg(MSTATUS_GDB_REG)?;
            state.mepc = self.read_reg(MEPC_GDB_REG)?;
            state.mcause = self.read_reg(MCAUSE_GDB_REG)?;
            state.mtval = self.read_reg(MTVAL_GDB_REG)?;
            state.sstatus = self.read_reg(SSTATUS_GDB_REG)?;
            state.sepc = self.read_reg(SEPC_GDB_REG)?;
            state.scause = self.read_reg(SCAUSE_GDB_REG)?;
            state.stval = self.read_reg(STVAL_GDB_REG)?;
            state.stvec = self.read_reg(STVEC_GDB_REG)?;
            state.medeleg = self.read_reg(MEDELEG_GDB_REG)?;
            state.satp = self.read_reg(SATP_GDB_REG)?;
        }
        Ok(state)
    }

    fn step_one(&mut self) -> Result<(), TargetError> {
        let response = self.cmd("s")?;
        if !response.starts_with('S') && !response.starts_with('T') {
            return Err(TargetError::Protocol(format!(
                "unexpected Sail single-step reply: '{response}'"
            )));
        }
        Ok(())
    }

    fn run_until(&mut self, target_pc: u64, max_insns: u64) -> Result<StopReason, TargetError> {
        for _ in 0..max_insns {
            if self.read_reg(PC_GDB_REG)? == target_pc {
                return Ok(StopReason::Breakpoint);
            }
            self.step_one()?;
        }
        if self.read_reg(PC_GDB_REG)? == target_pc {
            Ok(StopReason::Breakpoint)
        } else {
            Ok(StopReason::LimitReached)
        }
    }
}

fn validate_seed_privilege(debug_v1: bool, privilege: u8) -> Result<(), TargetError> {
    if !matches!(privilege, 0 | 1 | 3) {
        return Err(TargetError::Protocol(format!(
            "invalid RISC-V privilege mode {privilege}"
        )));
    }
    if privilege != 3 && !debug_v1 {
        return Err(TargetError::Protocol(format!(
            "stock Sail GDB cannot seed privilege mode {privilege}; only M-mode is supported"
        )));
    }
    Ok(())
}

impl Drop for SailGdbTarget {
    fn drop(&mut self) {
        let _ = self.child.kill();
        let _ = self.child.wait();
        if let Some(path) = self.owned_elf.take() {
            let _ = std::fs::remove_file(path);
        }
    }
}

fn write_temp_elf(seed: u64, elf: &[u8]) -> Result<PathBuf, TargetError> {
    use std::fs::OpenOptions;

    for _ in 0..100 {
        let sequence = TEMP_ELF_SEQUENCE.fetch_add(1, Ordering::Relaxed);
        let path = std::env::temp_dir().join(format!(
            "rivemu-lockstep-sail-{}-{seed:016x}-{sequence}.elf",
            std::process::id()
        ));
        match OpenOptions::new().write(true).create_new(true).open(&path) {
            Ok(mut file) => {
                if let Err(error) = file.write_all(elf) {
                    let _ = std::fs::remove_file(&path);
                    return Err(TargetError::Io(error));
                }
                return Ok(path);
            }
            Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => continue,
            Err(error) => return Err(TargetError::Io(error)),
        }
    }
    Err(TargetError::Protocol(
        "could not allocate a unique temporary Sail ELF path".into(),
    ))
}

fn build_sail_bootstrap() -> Vec<u8> {
    let mut words = vec![
        0x0000_0297,           // auipc t0, 0
        0x8002_8293,           // addi  t0, t0, -2048
        0x8002_8293,           // addi  t0, t0, -2048
        encode_csrw(0x305, 5), // csrw  mtvec, t0
        0x0000_62b7,           // lui   t0, 0x6 (mstatus.FS=Dirty)
        encode_csrw(0x300, 5), // csrw  mstatus, t0
        encode_csrw(0x341, 0), // csrw  mepc, zero
        encode_csrw(0x342, 0), // csrw  mcause, zero
        encode_csrw(0x343, 0), // csrw  mtval, zero
        encode_csrw(0x141, 0), // csrw  sepc, zero
        encode_csrw(0x142, 0), // csrw  scause, zero
        encode_csrw(0x143, 0), // csrw  stval, zero
        encode_csrw(0x180, 0), // csrw  satp, zero (Bare)
        encode_csrw(0x340, 0), // csrw  mscratch, zero
        encode_csrw(0x140, 0), // csrw  sscratch, zero
        encode_csrw(0x302, 0), // csrw  medeleg, zero
        encode_csrw(0x303, 0), // csrw  mideleg, zero
        encode_csrw(0x105, 0), // csrw  stvec, zero
    ];
    let jump_pc = SAIL_BOOTSTRAP_BASE + (words.len() as u64) * 4;
    let jump_offset = i32::try_from(CODE_BASE as i64 - jump_pc as i64)
        .expect("Sail bootstrap jump fits a JAL immediate");
    words.push(encode_jal_zero(jump_offset));
    words.into_iter().flat_map(u32::to_le_bytes).collect()
}

const fn encode_csrw(csr: u16, rs1: u8) -> u32 {
    (csr as u32) << 20 | (rs1 as u32) << 15 | 0x1073
}

const fn encode_jal_zero(offset: i32) -> u32 {
    let bits = offset as u32;
    0x6f | (((bits >> 20) & 1) << 31)
        | (((bits >> 1) & 0x3ff) << 21)
        | (((bits >> 11) & 1) << 20)
        | (((bits >> 12) & 0xff) << 12)
}

fn memory_chunk_from_supported(response: &str) -> usize {
    let packet_size = response.split(';').find_map(|feature| {
        feature
            .strip_prefix("PacketSize=")
            .and_then(|hex| usize::from_str_radix(hex, 16).ok())
    });
    packet_size.map_or(DEFAULT_MEMORY_CHUNK, |size| {
        // Reads and hexadecimal writes use two characters per byte; binary X
        // writes can also double in the worst case due to RSP escaping.
        size.saturating_sub(64)
            .checked_div(2)
            .unwrap_or(0)
            .clamp(1, MAX_MEMORY_CHUNK)
    })
}

fn pick_free_port() -> Result<u16, TargetError> {
    let listener = TcpListener::bind("127.0.0.1:0")?;
    Ok(listener.local_addr()?.port())
}

fn rsp_checksum(payload: &[u8]) -> u8 {
    payload.iter().copied().fold(0u8, u8::wrapping_add)
}

fn encode_rsp_payload(payload: &[u8]) -> Vec<u8> {
    let mut encoded = Vec::with_capacity(payload.len());
    for &byte in payload {
        if matches!(byte, b'$' | b'#' | b'}' | b'*') {
            encoded.push(b'}');
            encoded.push(byte ^ 0x20);
        } else {
            encoded.push(byte);
        }
    }
    encoded
}

fn parse_checksum(hex: [u8; 2]) -> Result<u8, TargetError> {
    let text =
        std::str::from_utf8(&hex).map_err(|error| TargetError::Protocol(error.to_string()))?;
    u8::from_str_radix(text, 16).map_err(|error| TargetError::Protocol(error.to_string()))
}

fn decode_rsp_payload(transmitted: &[u8]) -> Result<Vec<u8>, TargetError> {
    let mut decoded = Vec::with_capacity(transmitted.len());
    let mut index = 0;
    while index < transmitted.len() {
        if transmitted[index] == b'}' {
            index += 1;
            let Some(&escaped) = transmitted.get(index) else {
                return Err(TargetError::Protocol(
                    "truncated RSP escape sequence".into(),
                ));
            };
            decoded.push(escaped ^ 0x20);
        } else if transmitted[index] == b'*' {
            return Err(TargetError::Protocol(
                "unexpected RSP run-length encoding in Sail reply".into(),
            ));
        } else {
            decoded.push(transmitted[index]);
        }
        index += 1;
    }
    Ok(decoded)
}

fn is_console_output_packet(body: &[u8]) -> bool {
    body.len() > 1
        && body[0] == b'O'
        && body[1..].iter().all(|byte| byte.is_ascii_hexdigit())
        && body.len() % 2 == 1
}

fn encode_le_hex_u64(value: u64) -> String {
    let mut encoded = String::with_capacity(16);
    for byte in value.to_le_bytes() {
        use std::fmt::Write as _;
        let _ = write!(encoded, "{byte:02x}");
    }
    encoded
}

fn encode_hex_bytes(bytes: &[u8]) -> String {
    let mut encoded = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        use std::fmt::Write as _;
        let _ = write!(encoded, "{byte:02x}");
    }
    encoded
}

fn decode_le_hex_u64(hex: &str) -> Result<u64, TargetError> {
    let bytes = decode_hex_bytes(hex)?;
    if bytes.len() > 8 {
        return Err(TargetError::Protocol(format!(
            "hex value is wider than 64 bits: '{hex}'"
        )));
    }
    let mut value = [0u8; 8];
    value[..bytes.len()].copy_from_slice(&bytes);
    Ok(u64::from_le_bytes(value))
}

fn decode_hex_bytes(hex: &str) -> Result<Vec<u8>, TargetError> {
    if hex.len() % 2 != 0 {
        return Err(TargetError::Protocol(format!(
            "odd-length hexadecimal response: '{hex}'"
        )));
    }
    if hex.starts_with('E') {
        return Err(TargetError::Protocol(format!(
            "Sail GDB returned error '{hex}'"
        )));
    }
    let mut bytes = Vec::with_capacity(hex.len() / 2);
    for index in (0..hex.len()).step_by(2) {
        bytes.push(
            u8::from_str_radix(&hex[index..index + 2], 16)
                .map_err(|error| TargetError::Protocol(error.to_string()))?,
        );
    }
    Ok(bytes)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn integer_register_hex_is_little_endian() {
        assert_eq!(encode_le_hex_u64(0x0123_4567_89ab_cdef), "efcdab8967452301");
        assert_eq!(
            decode_le_hex_u64("efcdab8967452301").unwrap(),
            0x0123_4567_89ab_cdef
        );
    }

    #[test]
    fn short_register_response_is_zero_extended() {
        assert_eq!(decode_le_hex_u64("78563412").unwrap(), 0x1234_5678);
    }

    #[test]
    fn malformed_hex_is_rejected() {
        assert!(decode_le_hex_u64("0").is_err());
        assert!(decode_le_hex_u64("000000000000000000").is_err());
        assert!(decode_hex_bytes("xy").is_err());
    }

    #[test]
    fn rsp_escapes_are_decoded() {
        assert_eq!(decode_rsp_payload(b"ab}]cd").unwrap(), b"ab}cd");
        assert!(decode_rsp_payload(b"ab}").is_err());
        assert!(decode_rsp_payload(b"ab* ").is_err());
    }

    #[test]
    fn console_packet_detection_does_not_swallow_ok() {
        assert!(is_console_output_packet(b"O6869"));
        assert!(!is_console_output_packet(b"OK"));
        assert!(!is_console_output_packet(b"O123"));
    }

    #[test]
    fn binary_rsp_payloads_escape_reserved_bytes() {
        let input = b"ab$#}*cd";
        let encoded = encode_rsp_payload(input);
        assert_eq!(decode_rsp_payload(&encoded).unwrap(), input);
    }

    #[test]
    fn memory_chunks_respect_advertised_packet_size() {
        assert_eq!(memory_chunk_from_supported("PacketSize=1000;foo+"), 2016);
        assert_eq!(memory_chunk_from_supported("PacketSize=400"), 480);
        assert_eq!(
            memory_chunk_from_supported("qXfer:features:read+"),
            DEFAULT_MEMORY_CHUNK
        );
    }

    #[test]
    fn debug_v1_accepts_all_architectural_privilege_modes() {
        for privilege in [0, 1, 3] {
            validate_seed_privilege(true, privilege).unwrap();
        }
        assert!(validate_seed_privilege(true, 2).is_err());
    }

    #[test]
    fn stock_endpoint_rejects_non_machine_privilege() {
        validate_seed_privilege(false, 3).unwrap();
        assert!(validate_seed_privilege(false, 0).is_err());
        assert!(validate_seed_privilege(false, 1).is_err());
    }

    #[test]
    fn bootstrap_installs_mtvec_and_jumps_to_code() {
        let bytes = build_sail_bootstrap();
        let words: Vec<u32> = bytes
            .chunks_exact(4)
            .map(|chunk| u32::from_le_bytes(chunk.try_into().unwrap()))
            .collect();
        assert_eq!(
            &words[..4],
            &[0x0000_0297, 0x8002_8293, 0x8002_8293, 0x3052_9073]
        );
        assert_eq!(words[4], 0x0000_62b7);
        assert_eq!(words[5], encode_csrw(0x300, 5));

        let jal_index = words.len() - 1;
        let jal = words[jal_index];
        let encoded_imm = (((jal >> 31) & 1) << 20)
            | (((jal >> 21) & 0x3ff) << 1)
            | (((jal >> 20) & 1) << 11)
            | (((jal >> 12) & 0xff) << 12);
        let signed_imm = ((encoded_imm << 11) as i32) >> 11;
        assert_eq!(
            (SAIL_BOOTSTRAP_BASE + (jal_index as u64) * 4)
                .wrapping_add_signed(i64::from(signed_imm)),
            CODE_BASE
        );
    }
}
