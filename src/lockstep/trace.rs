//! Trace-driven boot lockstep against QEMU (`boot-trace`).
//!
//! QEMU runs at full TCG speed with the `rivemu_trace` plugin
//! (`qemu-plugin/rivemu_trace.c`), which streams the PC of every executed
//! instruction, the value of the previous instruction's destination
//! register, every trap, the trap CSRs after each trap, and a full register
//! snapshot every 2^16 instructions. rivemu steps the same instructions and
//! checks each of them against the stream.
//!
//! QEMU is the reference for everything that depends on device timing:
//! - interrupts: when QEMU takes one, rivemu takes the same one
//!   ([`Hart::trap`](rivemu_cpu_riscv::Hart::trap)) at the same instruction;
//!   rivemu never takes interrupts on its own here;
//! - reads that rivemu marks with `nondeterministic_read` (MMIO loads and
//!   counter, `time`, `seed`, `tinfo` and `mip`/`sip` CSR reads): rivemu takes
//!   QEMU's result instead of comparing it.
//!
//! Everything else (results, control flow, exceptions with their trap CSRs,
//! and the periodic snapshots) must match exactly; `mstatus` is compared
//! under [`MSTATUS_COMPARE_MASK`] as in the other lockstep modes.

use std::fs::File;
use std::io::{BufReader, ErrorKind, Read};
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Stdio};
use std::time::Instant;

use rivemu_core::size::MIB;
use rivemu_cpu_riscv::Priv;
use rivemu_machine::{MachineConfig, virt::memmap};

use crate::target::RivemuTarget;
use crate::{CosimTarget, MSTATUS_COMPARE_MASK, StopReason, TargetError};

/// What to run.
#[derive(Clone, Debug)]
pub struct TraceConfig {
    /// `qemu-system-riscv64`.
    pub qemu: PathBuf,
    /// The `rivemu_trace` plugin (`librivemu_trace.so`).
    pub plugin: PathBuf,
    /// Firmware (OpenSBI `fw_dynamic.bin`).
    pub bios: PathBuf,
    /// Kernel image.
    pub kernel: Option<PathBuf>,
    /// Initial ramdisk.
    pub initrd: Option<PathBuf>,
    /// Kernel command line.
    pub append: Option<String>,
    /// Guest RAM in MiB.
    pub ram_mib: u64,
    /// Stop after this many compared instructions.
    pub max_insns: u64,
    /// Stop once the guest console has printed this.
    pub until_console: Option<String>,
    /// Enable the H extension on both sides.
    pub hypervisor: bool,
}

/// Counts from a run.
#[derive(Clone, Debug, Default)]
pub struct TraceOutcome {
    /// Instructions both executed and compared.
    pub instructions: u64,
    /// Interrupts QEMU took and rivemu took at the same instruction.
    pub interrupts: u64,
    /// Exceptions both took (same target and trap CSRs).
    pub exceptions: u64,
    /// Device-dependent results copied from QEMU.
    pub copied_reads: u64,
    /// Full register snapshots compared.
    pub snapshots: u64,
    /// `mstatus`/`sstatus` reads that differed only in fields the spec
    /// leaves to the implementation (WARL `UXL`/`SXL`, and the `FS`/`VS`/`SD`
    /// dirty state), taken from QEMU.
    pub warl_status_reads: u64,
    /// `mstatus` reads that differed in `GVA` (and possibly the fields of
    /// `warl_status_reads`), taken from QEMU: QEMU 11.1 does not set GVA as
    /// the spec does (see [`MSTATUS_COMPARE_MASK`]).
    pub qemu_gva_reads: u64,
    /// Whether `until_console` appeared.
    pub reached_console: bool,
    /// The guest console as rivemu printed it (the last 4 KiB).
    pub console_tail: String,
    /// The first difference, if any.
    pub divergence: Option<String>,
}

struct Qemu {
    child: Child,
    fifo: PathBuf,
    dtb: PathBuf,
}

impl Drop for Qemu {
    fn drop(&mut self) {
        let _ = self.child.kill();
        let _ = self.child.wait();
        let _ = std::fs::remove_file(&self.fifo);
        let _ = std::fs::remove_file(&self.dtb);
    }
}

/// The trace stream.
struct Trace {
    reader: BufReader<File>,
}

impl Trace {
    /// The next record tag, or `None` at the end of the stream.
    fn tag(&mut self) -> Result<Option<u8>, TargetError> {
        let mut b = [0u8; 1];
        match self.reader.read_exact(&mut b) {
            Ok(()) => Ok(Some(b[0])),
            Err(e) if e.kind() == ErrorKind::UnexpectedEof => Ok(None),
            Err(e) => Err(e.into()),
        }
    }

    /// The next tag without consuming it.
    fn peek(&mut self) -> Result<Option<u8>, TargetError> {
        use std::io::BufRead;
        Ok(self.reader.fill_buf()?.first().copied())
    }

    fn u8(&mut self) -> Result<u8, TargetError> {
        let mut b = [0u8; 1];
        self.reader.read_exact(&mut b)?;
        Ok(b[0])
    }

    fn u64(&mut self) -> Result<u64, TargetError> {
        let mut b = [0u8; 8];
        self.reader.read_exact(&mut b)?;
        Ok(u64::from_le_bytes(b))
    }

    fn u64s<const N: usize>(&mut self) -> Result<[u64; N], TargetError> {
        let mut out = [0u64; N];
        for v in &mut out {
            *v = self.u64()?;
        }
        Ok(out)
    }
}

/// The privilege level as QEMU's `priv` register reports it: the mode in
/// bits 1:0 and the virtualization mode V in bit 2.
fn priv_code(h: &rivemu_cpu_riscv::Hart) -> u64 {
    let p = match h.prv {
        Priv::User => 0,
        Priv::Supervisor => 1,
        Priv::Machine => 3,
    };
    p | (u64::from(h.virt) << 2)
}

/// QEMU's CPU options for the trace, with or without H.
fn qemu_cpu(hypervisor: bool) -> String {
    let cpu = crate::target::qemu_gdb::QEMU_CPU_PMP;
    if hypervisor {
        cpu.replace("h=false", "h=true")
    } else {
        cpu.to_string()
    }
}

/// The interrupt code to raise in rivemu for an interrupt that QEMU took
/// with cause `cause`, landing in privilege `prv` (QEMU's encoding). A
/// VS-level interrupt taken in VS-mode reports the S-level code (VSSI 2 as
/// SSI 1, and so on); rivemu's `trap` wants the VS-level code.
fn interrupt_code(cause: u64, prv: u64) -> u64 {
    let code = cause & !(1 << 63);
    if prv == 5 && matches!(code, 1 | 5 | 9) {
        code + 1
    } else {
        code
    }
}

/// `mstatus` fields whose read value the spec leaves to the implementation:
/// `SD`, `SXL`, `UXL`, `FS` and `VS` (dirty tracking may be conservative).
const STATUS_IMPL_DEFINED: u64 = (1 << 63) | (0xf << 32) | 0x6000 | 0x600;

/// `mstatus.GVA`.
const STATUS_GVA: u64 = 1 << 38;

/// The CSR read by the instruction at `pc` (a SYSTEM instruction with a
/// CSR funct3), if any.
fn csr_read_at(machine: &rivemu_machine::Machine, pc: u64) -> Option<u16> {
    let h = &machine.harts[0];
    let pa = h.debug_translate(&machine.bus, pc)?;
    let lo = machine.bus.read(pa, rivemu_core::AccessSize::Half).ok()? as u32;
    if lo & 3 != 3 || lo & 0x7f != 0x73 || (lo >> 12) & 7 == 0 {
        return None;
    }
    let pa_hi = h.debug_translate(&machine.bus, pc.wrapping_add(2))?;
    let hi = machine
        .bus
        .read(pa_hi, rivemu_core::AccessSize::Half)
        .ok()? as u32;
    Some(((lo | (hi << 16)) >> 20) as u16)
}

/// Reads an 'S' record (after its tag) and compares it with `h`.
fn compare_snapshot(
    trace: &mut Trace,
    h: &rivemu_cpu_riscv::Hart,
) -> Result<Option<String>, TargetError> {
    let regs = trace.u64s::<31>()?;
    let [prv, mstatus, satp] = trace.u64s::<3>()?;
    if let Some(r) = (1..32).find(|&r| h.x[r] != regs[r - 1]) {
        return Ok(Some(format!(
            "snapshot x{r}: rivemu {:#x}, QEMU {:#x}",
            h.x[r],
            regs[r - 1]
        )));
    }
    if priv_code(h) != prv
        || (h.csr.mstatus ^ mstatus) & MSTATUS_COMPARE_MASK != 0
        || h.csr.satp != satp
    {
        return Ok(Some(format!(
            "snapshot privilege/mstatus/satp: rivemu {}/{:#x}/{:#x}, QEMU {prv}/{mstatus:#x}/{satp:#x}",
            priv_code(h),
            h.csr.mstatus,
            h.csr.satp
        )));
    }
    Ok(None)
}

/// Recent PCs, for divergence reports.
struct History {
    pcs: [u64; 16],
    next: usize,
}

impl History {
    fn push(&mut self, pc: u64) {
        self.pcs[self.next % 16] = pc;
        self.next += 1;
    }

    fn last(&self) -> Option<u64> {
        (self.next > 0).then(|| self.pcs[(self.next - 1) % 16])
    }

    fn render(&self) -> String {
        let n = self.next.min(16);
        (0..n)
            .map(|i| format!("{:#x}", self.pcs[(self.next - n + i) % 16]))
            .collect::<Vec<_>>()
            .join(" ")
    }
}

fn spawn_qemu(cfg: &TraceConfig, rivemu: &mut RivemuTarget) -> Result<Qemu, TargetError> {
    // QEMU gets rivemu's device tree byte for byte, and the initrd through
    // the generic loader at rivemu's address: `-initrd` and `-append` would
    // make QEMU rewrite /chosen.
    let fdt_addr = rivemu.machine.fdt_addr;
    let mut hdr = [0u8; 8];
    rivemu.read_ram(fdt_addr, &mut hdr)?;
    let fdt_size = u32::from_be_bytes([hdr[4], hdr[5], hdr[6], hdr[7]]) as usize;
    if u32::from_be_bytes([hdr[0], hdr[1], hdr[2], hdr[3]]) != 0xd00d_feed {
        return Err(TargetError::Protocol(format!(
            "no device tree at {fdt_addr:#x}"
        )));
    }
    let mut fdt = vec![0u8; fdt_size];
    rivemu.read_ram(fdt_addr, &mut fdt)?;
    // Unique per run: tests run several traces in one process.
    static RUNS: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);
    let run = RUNS.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
    let tag = format!("rivemu-boot-trace-{}-{run}", std::process::id());
    let dtb = std::env::temp_dir().join(format!("{tag}.dtb"));
    std::fs::write(&dtb, &fdt)?;
    let fifo = std::env::temp_dir().join(format!("{tag}.fifo"));
    let _ = std::fs::remove_file(&fifo);
    let status = Command::new("mkfifo").arg(&fifo).status()?;
    if !status.success() {
        return Err(TargetError::Protocol(format!(
            "mkfifo {} failed",
            fifo.display()
        )));
    }

    // Implementation-defined reset values that rivemu chose differently.
    let h = &rivemu.machine.harts[0];
    let plugin = format!(
        "{},out={},init=menvcfg:{:x},init=senvcfg:{:x},init=stimecmp:{:x}",
        cfg.plugin.display(),
        fifo.display(),
        h.csr.menvcfg,
        h.csr.senvcfg,
        h.csr.stimecmp
    );
    let mut cmd = Command::new(&cfg.qemu);
    cmd.args(["-machine", "virt", "-cpu", &qemu_cpu(cfg.hypervisor)])
        .args(["-m", &format!("{}M", cfg.ram_mib), "-smp", "1"])
        .arg("-bios")
        .arg(&cfg.bios)
        .arg("-dtb")
        .arg(&dtb)
        .args(["-display", "none", "-serial", "null", "-monitor", "none"])
        .args(["-plugin", &plugin]);
    if let Some(k) = &cfg.kernel {
        cmd.arg("-kernel").arg(k);
    }
    if let (Some(path), Some((start, _))) = (&cfg.initrd, rivemu.machine.boot.initrd) {
        cmd.args([
            "-device",
            &format!(
                "loader,file={},addr={start:#x},force-raw=on",
                path.display()
            ),
        ]);
    }
    let child = cmd
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::inherit())
        .spawn()?;
    Ok(Qemu { child, fifo, dtb })
}

/// Runs the trace-driven lockstep described in the module documentation.
pub fn run_trace_lockstep(cfg: &TraceConfig) -> Result<TraceOutcome, TargetError> {
    let mut rivemu = RivemuTarget::from_config(MachineConfig {
        ram_size: cfg.ram_mib * MIB,
        smp: 1,
        bios: Some(cfg.bios.clone()),
        kernel: cfg.kernel.clone(),
        initrd: cfg.initrd.clone(),
        append: cfg.append.clone(),
        icount: Some(0),
        hypervisor: cfg.hypervisor,
        ..MachineConfig::default()
    })?;
    let qemu = spawn_qemu(cfg, &mut rivemu)?;
    let mut trace = Trace {
        reader: BufReader::with_capacity(1 << 20, File::open(&qemu.fifo)?),
    };
    if rivemu.run_until(memmap::DRAM_BASE, 64)? != StopReason::Breakpoint {
        return Err(TargetError::Protocol(
            "rivemu did not reach the firmware entry".into(),
        ));
    }

    let mut out = TraceOutcome::default();
    let mut console = String::new();
    let mut history = History {
        pcs: [0; 16],
        next: 0,
    };
    // The previous instruction's result comes from QEMU (MMIO, counters).
    let mut copy_result = false;
    // An interrupt QEMU took, waiting for its 'C' record: (from, to).
    let mut pending_interrupt: Option<(u64, u64)> = None;
    let started = Instant::now();

    macro_rules! diverge {
        ($($arg:tt)*) => {{
            out.divergence = Some(format!(
                "after {} instructions: {} (recent PCs: {})",
                out.instructions,
                format!($($arg)*),
                history.render()
            ));
            break;
        }};
    }

    while let Some(tag) = trace.tag()? {
        match tag {
            b'I' => {
                let pc = trace.u64()?;
                let rd = usize::from(trace.u8()?);
                let value = trace.u64()?;
                if pending_interrupt.is_some() {
                    return Err(TargetError::Protocol(
                        "trace: interrupt without its CSR record".into(),
                    ));
                }
                let ours = if rd != 0 && rd < 32 {
                    rivemu.machine.harts[0].x[rd]
                } else {
                    value
                };
                if rd != 0 && rd < 32 {
                    if copy_result {
                        rivemu.machine.harts[0].x[rd] = value;
                        out.copied_reads += 1;
                    } else if ours != value {
                        // QEMU keeps UXL writable (RV32 user mode); rivemu
                        // fixes it at 64 bits. Linux's compat_mode_detect
                        // writes UXL and reads it back. Both are legal.
                        let read = history
                            .last()
                            .and_then(|last| csr_read_at(&rivemu.machine, last));
                        let status_read = matches!(read, Some(0x100 | 0x300));
                        let diff = (ours ^ value) & !STATUS_IMPL_DEFINED;
                        if status_read && diff == 0 {
                            rivemu.machine.harts[0].x[rd] = value;
                            out.warl_status_reads += 1;
                        } else if read == Some(0x300) && diff == STATUS_GVA {
                            rivemu.machine.harts[0].x[rd] = value;
                            out.qemu_gva_reads += 1;
                        } else {
                            diverge!("x{rd}: rivemu {ours:#x}, QEMU {value:#x}");
                        }
                    }
                }
                let h = &mut rivemu.machine.harts[0];
                if h.pc != pc {
                    diverge!("pc: rivemu {:#x}, QEMU {pc:#x}", h.pc);
                }
                if out.instructions >= cfg.max_insns {
                    break;
                }
                // A snapshot after an 'I' record is the state before its
                // instruction.
                if trace.peek()? == Some(b'S') {
                    trace.tag()?;
                    out.snapshots += 1;
                    if let Some(d) = compare_snapshot(&mut trace, &rivemu.machine.harts[0])? {
                        diverge!("{d}");
                    }
                }
                let h = &mut rivemu.machine.harts[0];
                history.push(pc);
                h.nondeterministic_read = false;
                h.step(&rivemu.machine.bus);
                // A WFI that does not trap retires; QEMU then waits for the
                // interrupt that the trace shows next.
                h.wfi = false;
                copy_result = h.nondeterministic_read;
                out.instructions += 1;
                if out.instructions & 0xf_ffff == 0 {
                    let bytes = rivemu.machine.uart.take_output();
                    console.push_str(&String::from_utf8_lossy(&bytes));
                    if console.len() > 8192 {
                        console.drain(..console.len() - 4096);
                    }
                    if let Some(stop) = &cfg.until_console {
                        if console.contains(stop.as_str()) {
                            out.reached_console = true;
                            break;
                        }
                    }
                    if out.instructions % 50_000_000 == 0 {
                        eprintln!(
                            "boot-trace: {} M instructions, {} interrupts, {:.0} s",
                            out.instructions / 1_000_000,
                            out.interrupts,
                            started.elapsed().as_secs_f64()
                        );
                    }
                }
            }
            b'D' => {
                let h = &mut rivemu.machine.harts[0];
                let kind = trace.u8()?;
                let from = trace.u64()?;
                let to = trace.u64()?;
                match kind {
                    1 => {
                        if h.pc != from {
                            diverge!(
                                "QEMU took an interrupt at {from:#x}, rivemu is at {:#x}",
                                h.pc
                            );
                        }
                        pending_interrupt = Some((from, to));
                    }
                    2 => {
                        // A fault on fetching (or decoding) the instruction at
                        // `from` comes without an 'I' record: QEMU never
                        // executed it. rivemu takes it by stepping once.
                        if h.pc == from && from != to {
                            h.nondeterministic_read = false;
                            h.step(&rivemu.machine.bus);
                            h.wfi = false;
                        }
                        if h.pc != to {
                            diverge!(
                                "QEMU trapped from {from:#x} to {to:#x}, rivemu is at {:#x}",
                                h.pc
                            );
                        }
                        out.exceptions += 1;
                    }
                    _ => {
                        return Err(TargetError::Protocol(format!(
                            "trace: unexpected discontinuity kind {kind}"
                        )));
                    }
                }
            }
            b'C' => {
                let h = &mut rivemu.machine.harts[0];
                let [
                    prv,
                    mstatus,
                    mcause,
                    mepc,
                    mtval,
                    scause,
                    sepc,
                    stval,
                    satp,
                    hstatus,
                    htval,
                    mtval2,
                ] = trace.u64s::<12>()?;
                if let Some((_, to)) = pending_interrupt.take() {
                    let cause = if prv == 3 { mcause } else { scause };
                    if cause >> 63 == 0 {
                        diverge!("QEMU interrupt with cause {cause:#x}");
                    }
                    h.trap(interrupt_code(cause, prv), true, 0);
                    out.interrupts += 1;
                    if h.pc != to {
                        diverge!(
                            "interrupt {:#x}: rivemu entered {:#x}, QEMU {to:#x}",
                            cause & !(1 << 63),
                            h.pc
                        );
                    }
                }
                let c = &h.csr;
                let h_csr = |num| h.csr_read(num).unwrap_or(0);
                // The first CSR that differs (`diverge!` must not run inside
                // a `for`, where its `break` would only end the `for`).
                let mismatch = [
                    ("privilege", priv_code(h), prv),
                    (
                        "mstatus (compared bits)",
                        c.mstatus & MSTATUS_COMPARE_MASK,
                        mstatus & MSTATUS_COMPARE_MASK,
                    ),
                    ("mcause", c.mcause, mcause),
                    ("mepc", c.mepc, mepc),
                    ("mtval", c.mtval, mtval),
                    ("scause", c.scause, scause),
                    ("sepc", c.sepc, sepc),
                    ("stval", c.stval, stval),
                    ("satp", c.satp, satp),
                    ("hstatus", h_csr(0x600), hstatus),
                    ("htval", h_csr(0x643), htval),
                    ("mtval2", h_csr(0x34b), mtval2),
                ]
                .into_iter()
                .find(|&(_, ours, theirs)| ours != theirs);
                if let Some((name, ours, theirs)) = mismatch {
                    diverge!("{name} after a trap: rivemu {ours:#x}, QEMU {theirs:#x}");
                }
            }
            b'S' => {
                out.snapshots += 1;
                if let Some(d) = compare_snapshot(&mut trace, &rivemu.machine.harts[0])? {
                    diverge!("{d}");
                }
            }
            other => {
                return Err(TargetError::Protocol(format!(
                    "trace: unknown record tag {other:#x}"
                )));
            }
        }
    }
    let bytes = rivemu.machine.uart.take_output();
    console.push_str(&String::from_utf8_lossy(&bytes));
    if let Some(stop) = &cfg.until_console {
        out.reached_console |= console.contains(stop.as_str());
    }
    let keep = console.len().saturating_sub(4096);
    let keep = (keep..console.len())
        .find(|&i| console.is_char_boundary(i))
        .unwrap_or(console.len());
    out.console_tail = console[keep..].to_string();
    drop(qemu);
    Ok(out)
}

/// Default location of the plugin built by `scripts/build-qemu-plugin.sh`.
pub fn default_plugin() -> PathBuf {
    std::env::var_os("RIVEMU_TRACE_PLUGIN").map_or_else(
        || Path::new(env!("CARGO_MANIFEST_DIR")).join("target/qemu-plugin/librivemu_trace.so"),
        PathBuf::from,
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Five million instructions of OpenSBI and early Linux in trace
    /// lockstep. Skipped unless QEMU, the plugin and rivemu's Linux test
    /// images are present; `RIVEMU_LOCKSTEP_REQUIRE_TRACE=1` turns a skip
    /// into a failure.
    #[test]
    fn trace_lockstep_runs_opensbi_and_early_linux_without_divergence() {
        let Some(qemu) = crate::tools::qemu_for_test(
            "trace_lockstep_runs_opensbi_and_early_linux_without_divergence",
        ) else {
            return;
        };
        let images = Path::new(env!("CARGO_MANIFEST_DIR")).join("../qemu_rust/images");
        let cfg = TraceConfig {
            qemu,
            plugin: default_plugin(),
            bios: images.join("linux-test/fw_dynamic.bin"),
            kernel: Some(images.join("linux-src/Image")),
            initrd: Some(images.join("linux-src/rootfs.cpio")),
            append: Some("console=ttyS0".into()),
            ram_mib: 256,
            max_insns: 5_000_000,
            until_console: None,
            hypervisor: false,
        };
        let missing: Vec<_> = [&cfg.plugin, &cfg.bios]
            .into_iter()
            .chain(cfg.kernel.iter())
            .chain(cfg.initrd.iter())
            .filter(|p| !p.is_file())
            .collect();
        if !missing.is_empty() {
            assert!(
                std::env::var_os("RIVEMU_LOCKSTEP_REQUIRE_TRACE").is_none(),
                "missing {missing:?}"
            );
            eprintln!("skipping trace lockstep test: missing {missing:?}");
            return;
        }
        let out = run_trace_lockstep(&cfg).expect("trace lockstep runs");
        assert_eq!(out.divergence, None);
        assert_eq!(out.instructions, cfg.max_insns);
        assert!(out.snapshots > 70, "snapshots: {}", out.snapshots);
        assert!(out.exceptions > 0, "OpenSBI and Linux take traps early");
    }

    /// The H-extension test firmware (`firmware/h_test.S`, built by
    /// `scripts/build-h-firmware.sh`) with H on both sides, to its own
    /// verdict. Skipped like the test above.
    #[test]
    fn trace_lockstep_runs_the_h_extension_firmware_without_divergence() {
        let Some(qemu) = crate::tools::qemu_for_test(
            "trace_lockstep_runs_the_h_extension_firmware_without_divergence",
        ) else {
            return;
        };
        let cfg = TraceConfig {
            qemu,
            plugin: default_plugin(),
            bios: Path::new(env!("CARGO_MANIFEST_DIR")).join("target/firmware/h_test.bin"),
            kernel: None,
            initrd: None,
            append: None,
            ram_mib: 256,
            max_insns: u64::MAX,
            until_console: Some("H-TEST PASS".into()),
            hypervisor: true,
        };
        let missing: Vec<_> = [&cfg.plugin, &cfg.bios]
            .into_iter()
            .filter(|p| !p.is_file())
            .collect();
        if !missing.is_empty() {
            assert!(
                std::env::var_os("RIVEMU_LOCKSTEP_REQUIRE_TRACE").is_none(),
                "missing {missing:?}"
            );
            eprintln!("skipping H firmware trace lockstep: missing {missing:?}");
            return;
        }
        let out = run_trace_lockstep(&cfg).expect("trace lockstep runs");
        assert_eq!(out.divergence, None);
        assert!(out.reached_console, "console: {}", out.console_tail);
        assert!(out.exceptions > 50, "exceptions: {}", out.exceptions);
        assert!(out.interrupts >= 4, "interrupts: {}", out.interrupts);
    }

    /// The H firmware built with `-DSPEC` adds the checks where QEMU 11.1.3
    /// differs from the privileged spec (the Sail model passes them, see
    /// `docs/evidence/2026-11-03-h-extension/`), so it runs on rivemu alone.
    #[test]
    fn h_spec_firmware_passes_on_rivemu_alone() {
        let bios = Path::new(env!("CARGO_MANIFEST_DIR")).join("target/firmware/h_test_spec.bin");
        if !bios.is_file() {
            assert!(
                std::env::var_os("RIVEMU_LOCKSTEP_REQUIRE_TRACE").is_none(),
                "missing {}",
                bios.display()
            );
            eprintln!("skipping: missing {}", bios.display());
            return;
        }
        let mut rivemu = RivemuTarget::from_config(MachineConfig {
            ram_size: 256 * MIB,
            smp: 1,
            bios: Some(bios),
            hypervisor: true,
            ..MachineConfig::default()
        })
        .expect("machine");
        // The machine's own run loop (interrupts included), until the
        // firmware powers off.
        let m = &mut rivemu.machine;
        let mut console = String::new();
        for _ in 0..10_000 {
            let event = m.run_slice();
            console.push_str(&String::from_utf8_lossy(&m.uart.take_output()));
            if event.is_some() {
                break;
            }
        }
        assert!(console.contains("H-TEST PASS"), "console:\n{console}");
    }
}
