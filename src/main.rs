//! CLI entrypoint for `rivemu-lockstep` (`risu` fuzzer and early `boot` CPU smoke test).

#![forbid(unsafe_code)]

use std::path::{Path, PathBuf};
use std::process::ExitCode;
use std::sync::Mutex;
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::time::{Duration, Instant};

use rivemu_lockstep::lockstep::run_firmware_lockstep;
use rivemu_lockstep::lockstep::trace::{TraceConfig, default_plugin, run_trace_lockstep};
use rivemu_lockstep::risu::{BisectReport, RisuCase, RisuHarness, Suite};
use rivemu_lockstep::target::{QemuGdbTarget, RivemuTarget, SailGdbTarget};

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum RisuReference {
    Sail,
    Qemu,
}

impl RisuReference {
    fn parse(value: &str) -> Option<Self> {
        match value {
            "sail" => Some(Self::Sail),
            "qemu" => Some(Self::Qemu),
            _ => None,
        }
    }

    const fn name(self) -> &'static str {
        match self {
            Self::Sail => "sail",
            Self::Qemu => "qemu",
        }
    }
}

fn print_usage() {
    eprintln!(
        "\
Usage:
  rivemu-lockstep risu [OPTIONS]
  rivemu-lockstep campaign [OPTIONS]
  rivemu-lockstep boot --bios <PATH> [--kernel <PATH>] [OPTIONS]
  rivemu-lockstep boot-trace --bios <PATH> [--kernel <PATH>] [--initrd <PATH>] [OPTIONS]

RISU / Campaign Options:
  --reference <sail|qemu>                       Reference model [default: sail]
  --suite <alu|control|fence-i|mul|bitmanip|crypto|float|fp-edges|mem|csr|privileged|sv39|sv48|pmp|cfi|atomics|compressed|vector|all>
                                                 Instruction suite [default: all]
  --blocks <N>                                   Number of random blocks [default: 50]
  --workers <N>                                  Parallel worker threads for campaign mode [default: 2]
  --duration <SECS>                              Optional time budget in seconds for campaign mode
  --emit-repro <PATH>                            Write minimized Rust regression test on divergence
  --insns <K>                                    Instructions per block [default: 32]
  --seed <HEX_OR_DEC>                            Starting PRNG seed [default: 0x1000]
  --check-csrs                                   Compare privileged CSRs at checkpoints
  --step-check                                   Compare after every instruction [always on for Sail]
  --strict                                       Enable rivemu -strict mode
  --sail <PATH>                                  Path to sail_riscv_sim
  --qemu <PATH>                                  Path to qemu-system-riscv64

Early Boot CPU Smoke Options:
  --bios <PATH>                                  Firmware ELF/binary (e.g. OpenSBI fw_dynamic.bin)
  --kernel <PATH>                                Optional kernel staged in guest memory
  --steps <N>                                    Early M-mode instructions to compare [default: 1000]
  --check-csrs                                   Compare privileged CSRs on every step
  --qemu <PATH>                                  Path to qemu-system-riscv64

Trace Boot Lockstep Options (boot-trace; QEMU runs freely with the
rivemu_trace plugin, see scripts/build-qemu-plugin.sh):
  --bios/--kernel <PATH>                         As for boot
  --initrd <PATH>                                Initial ramdisk
  --append <ARGS>                                Kernel command line
  --memory <MiB>                                 Guest RAM [default: 256]
  --steps <N>                                    Instructions to compare [default: unlimited]
  --until-console <TEXT>                         Stop once the console printed TEXT
  --plugin <PATH>                                librivemu_trace.so [default: target/qemu-plugin/]
  --qemu <PATH>                                  Path to qemu-system-riscv64"
    );
}

fn parse_u64(s: &str) -> Result<u64, String> {
    if let Some(hex) = s.strip_prefix("0x").or_else(|| s.strip_prefix("0X")) {
        u64::from_str_radix(hex, 16).map_err(|e| e.to_string())
    } else {
        s.parse::<u64>().map_err(|e| e.to_string())
    }
}

fn option_value<'a>(
    args: &'a [String],
    index: &mut usize,
    option: &str,
) -> Result<&'a str, String> {
    *index += 1;
    args.get(*index)
        .map(String::as_str)
        .ok_or_else(|| format!("{option} requires a value"))
}

fn parse_usize_option(args: &[String], index: &mut usize, option: &str) -> Result<usize, String> {
    let value = option_value(args, index, option)?;
    value
        .parse()
        .map_err(|e| format!("invalid value for {option} ('{value}'): {e}"))
}

fn main() -> ExitCode {
    let args: Vec<String> = std::env::args().skip(1).collect();
    let mode = args.first().map(String::as_str).unwrap_or("risu");
    if matches!(mode, "-h" | "--help" | "help") {
        print_usage();
        return ExitCode::SUCCESS;
    }

    let mut suite = Suite::All;
    let mut blocks = 50usize;
    let mut blocks_explicit = false;
    let mut workers = 2usize;
    let mut duration_secs: Option<u64> = None;
    let mut emit_repro: Option<PathBuf> = None;
    let mut insns = 32usize;
    let mut start_seed = 0x1000u64;
    let mut check_csrs = false;
    let mut step_check = false;
    let mut strict = false;
    let mut reference = RisuReference::Sail;
    let mut sail_bin = rivemu_lockstep::tools::default_sail();
    let mut qemu_bin = rivemu_lockstep::tools::default_qemu();
    let mut bios: Option<PathBuf> = None;
    let mut kernel: Option<PathBuf> = None;
    let mut steps = 1000usize;
    let mut steps_explicit = false;
    let mut initrd: Option<PathBuf> = None;
    let mut append: Option<String> = None;
    let mut memory_mib = 256u64;
    let mut until_console: Option<String> = None;
    let mut plugin = default_plugin();

    macro_rules! value_or_exit {
        ($result:expr) => {
            match $result {
                Ok(value) => value,
                Err(error) => {
                    eprintln!("error: {error}");
                    return ExitCode::from(2);
                }
            }
        };
    }

    let mut i = if matches!(mode, "risu" | "campaign" | "boot" | "boot-trace") {
        1
    } else {
        0
    };
    while i < args.len() {
        match args[i].as_str() {
            "--reference" | "--oracle" => {
                let flag = args[i].as_str();
                let value = value_or_exit!(option_value(&args, &mut i, flag));
                let Some(parsed) = RisuReference::parse(value) else {
                    eprintln!("error: invalid value for {flag} ('{value}')");
                    return ExitCode::from(2);
                };
                reference = parsed;
            }
            "--suite" => {
                let value = value_or_exit!(option_value(&args, &mut i, "--suite"));
                let Some(s) = Suite::parse(value) else {
                    eprintln!("error: invalid value for --suite ('{value}')");
                    return ExitCode::from(2);
                };
                suite = s;
            }
            "--blocks" | "--seeds" => {
                let flag = args[i].as_str();
                blocks = value_or_exit!(parse_usize_option(&args, &mut i, flag));
                blocks_explicit = true;
            }
            "--workers" => {
                workers = value_or_exit!(parse_usize_option(&args, &mut i, "--workers"));
            }
            "--duration" => {
                let value = value_or_exit!(option_value(&args, &mut i, "--duration"));
                let secs = value_or_exit!(
                    parse_u64(value)
                        .map_err(|e| format!("invalid value for --duration ('{value}'): {e}"))
                );
                duration_secs = Some(secs);
            }
            "--emit-repro" => {
                emit_repro = Some(PathBuf::from(value_or_exit!(option_value(
                    &args,
                    &mut i,
                    "--emit-repro"
                ))));
            }
            "--insns" => {
                insns = value_or_exit!(parse_usize_option(&args, &mut i, "--insns"));
            }
            "--seed" => {
                let value = value_or_exit!(option_value(&args, &mut i, "--seed"));
                start_seed = value_or_exit!(
                    parse_u64(value)
                        .map_err(|e| format!("invalid value for --seed ('{value}'): {e}"))
                );
            }
            "--check-csrs" => check_csrs = true,
            "--step-check" => step_check = true,
            "--strict" => strict = true,
            "--sail" => {
                sail_bin = PathBuf::from(value_or_exit!(option_value(&args, &mut i, "--sail")));
            }
            "--qemu" => {
                qemu_bin = PathBuf::from(value_or_exit!(option_value(&args, &mut i, "--qemu")));
            }
            "--bios" => {
                bios = Some(PathBuf::from(value_or_exit!(option_value(
                    &args, &mut i, "--bios"
                ))));
            }
            "--kernel" => {
                kernel = Some(PathBuf::from(value_or_exit!(option_value(
                    &args, &mut i, "--kernel"
                ))));
            }
            "--steps" => {
                steps = value_or_exit!(parse_usize_option(&args, &mut i, "--steps"));
                steps_explicit = true;
            }
            "--initrd" => {
                initrd = Some(PathBuf::from(value_or_exit!(option_value(
                    &args, &mut i, "--initrd"
                ))));
            }
            "--append" => {
                append = Some(value_or_exit!(option_value(&args, &mut i, "--append")).to_string());
            }
            "--memory" => {
                memory_mib = value_or_exit!(parse_usize_option(&args, &mut i, "--memory")) as u64;
            }
            "--until-console" => {
                until_console = Some(
                    value_or_exit!(option_value(&args, &mut i, "--until-console")).to_string(),
                );
            }
            "--plugin" => {
                plugin = PathBuf::from(value_or_exit!(option_value(&args, &mut i, "--plugin")));
            }
            "-h" | "--help" => {
                print_usage();
                return ExitCode::SUCCESS;
            }
            other => {
                eprintln!("error: unknown argument '{other}'");
                print_usage();
                return ExitCode::from(2);
            }
        }
        i += 1;
    }

    if blocks == 0 {
        eprintln!("error: --blocks must be greater than zero");
        return ExitCode::from(2);
    }
    if workers == 0 {
        eprintln!("error: --workers must be greater than zero");
        return ExitCode::from(2);
    }
    if insns == 0 {
        eprintln!("error: --insns must be greater than zero");
        return ExitCode::from(2);
    }
    if steps == 0 {
        eprintln!("error: --steps must be greater than zero");
        return ExitCode::from(2);
    }

    if mode == "boot-trace" {
        let Some(bios) = bios else {
            eprintln!("error: `boot-trace` mode requires `--bios <PATH>`");
            return ExitCode::from(2);
        };
        let cfg = TraceConfig {
            qemu: qemu_bin,
            plugin,
            bios,
            kernel,
            initrd,
            append,
            ram_mib: memory_mib,
            max_insns: if steps_explicit {
                steps as u64
            } else {
                u64::MAX
            },
            until_console,
        };
        let t0 = Instant::now();
        return match run_trace_lockstep(&cfg) {
            Ok(out) => {
                println!(
                    "boot-trace: {} instructions compared in {:.1} s ({} interrupts mirrored, {} exceptions, {} device-dependent reads copied, {} WARL status reads, {} snapshots)",
                    out.instructions,
                    t0.elapsed().as_secs_f64(),
                    out.interrupts,
                    out.exceptions,
                    out.copied_reads,
                    out.warl_status_reads,
                    out.snapshots
                );
                println!("--- console (last 4 KiB) ---\n{}\n---", out.console_tail);
                if let Some(d) = out.divergence {
                    println!("DIVERGENCE: {d}");
                    ExitCode::from(1)
                } else if cfg.until_console.is_some() && !out.reached_console {
                    println!("FAIL: the console never printed {:?}", cfg.until_console);
                    ExitCode::from(1)
                } else {
                    println!("PASS: 0 divergences");
                    ExitCode::SUCCESS
                }
            }
            Err(e) => {
                eprintln!("error: {e}");
                ExitCode::from(2)
            }
        };
    }

    if mode == "boot" {
        let Some(bios_path) = bios else {
            eprintln!("error: `boot` mode requires `--bios <PATH>`");
            return ExitCode::from(2);
        };
        let t0 = Instant::now();
        match run_firmware_lockstep(
            &qemu_bin,
            &bios_path,
            kernel.as_deref(),
            steps,
            check_csrs,
            true,
        ) {
            Ok(None) => {
                println!(
                    "PASS: early boot CPU lockstep completed {} instructions in {:.2?} with 0 divergences.",
                    steps,
                    t0.elapsed()
                );
                ExitCode::SUCCESS
            }
            Ok(Some(report)) => {
                print!("{report}");
                ExitCode::from(1)
            }
            Err(e) => {
                eprintln!("error: {e}");
                ExitCode::from(2)
            }
        }
    } else if mode == "campaign" {
        let max_blocks = if duration_secs.is_some() && !blocks_explicit {
            usize::MAX
        } else {
            blocks
        };
        run_campaign(
            reference,
            suite,
            workers,
            max_blocks,
            duration_secs.map(Duration::from_secs),
            insns,
            start_seed,
            check_csrs,
            step_check,
            strict,
            &sail_bin,
            &qemu_bin,
            emit_repro.as_deref(),
        )
    } else {
        let t0 = Instant::now();
        let effective_check_csrs = check_csrs
            || matches!(
                suite,
                Suite::Privileged | Suite::Sv39 | Suite::Sv48 | Suite::Pmp | Suite::Cfi
            );
        let effective_step_check = step_check
            || reference == RisuReference::Sail
            || matches!(
                suite,
                Suite::FpEdges
                    | Suite::Privileged
                    | Suite::Sv39
                    | Suite::Sv48
                    | Suite::Pmp
                    | Suite::Cfi
            );
        match reference {
            RisuReference::Qemu => {
                let rivemu = match RivemuTarget::new_bare(strict) {
                    Ok(target) => target,
                    Err(error) => {
                        eprintln!("error initializing rivemu: {error}");
                        return ExitCode::from(2);
                    }
                };
                let qemu = match QemuGdbTarget::spawn_bare_with_pmp(&qemu_bin, suite == Suite::Pmp)
                {
                    Ok(target) => target,
                    Err(error) => {
                        eprintln!("error spawning {}: {error}", qemu_bin.display());
                        return ExitCode::from(2);
                    }
                };
                let mut harness = match RisuHarness::new(rivemu, qemu, effective_check_csrs) {
                    Ok(harness) => harness,
                    Err(error) => {
                        eprintln!("error setting up RISU harness: {error}");
                        return ExitCode::from(2);
                    }
                };
                harness.set_step_check(effective_step_check);

                for block in 0..blocks {
                    let seed = start_seed.wrapping_add(block as u64);
                    match harness.run_seed(suite, seed, insns) {
                        Ok(None) => {}
                        Ok(Some(report)) => {
                            println!(
                                "Divergence found after {block}/{blocks} blocks ({:.2?}):",
                                t0.elapsed()
                            );
                            emit_divergence_report(&report, emit_repro.as_deref());
                            return ExitCode::from(1);
                        }
                        Err(error) => {
                            eprintln!("error at block {block} (seed={seed:#x}): {error}");
                            return ExitCode::from(2);
                        }
                    }
                }
            }
            RisuReference::Sail => {
                for block in 0..blocks {
                    let seed = start_seed.wrapping_add(block as u64);
                    let case = match RisuCase::generate(suite, seed, insns) {
                        Ok(case) => case,
                        Err(error) => {
                            eprintln!("error generating block {block} (seed={seed:#x}): {error}");
                            return ExitCode::from(2);
                        }
                    };
                    let rivemu = match RivemuTarget::new_bare(strict) {
                        Ok(target) => target,
                        Err(error) => {
                            eprintln!("error initializing rivemu: {error}");
                            return ExitCode::from(2);
                        }
                    };
                    let sail = match SailGdbTarget::spawn_case(&sail_bin, &case) {
                        Ok(target) => target,
                        Err(error) => {
                            eprintln!("error spawning {}: {error}", sail_bin.display());
                            return ExitCode::from(2);
                        }
                    };
                    let mut harness =
                        match RisuHarness::from_targets(rivemu, sail, effective_check_csrs) {
                            Ok(harness) => harness,
                            Err(error) => {
                                eprintln!("error setting up RISU harness: {error}");
                                return ExitCode::from(2);
                            }
                        };
                    harness.set_step_check(true);
                    match harness.run_case(&case) {
                        Ok(None) => {}
                        Ok(Some(report)) => {
                            println!(
                                "Divergence found after {block}/{blocks} blocks ({:.2?}):",
                                t0.elapsed()
                            );
                            emit_divergence_report(&report, emit_repro.as_deref());
                            return ExitCode::from(1);
                        }
                        Err(error) => {
                            eprintln!("error at block {block} (seed={seed:#x}): {error}");
                            return ExitCode::from(2);
                        }
                    }
                }
            }
        }
        println!(
            "PASS: reference={} suite={} blocks={} requested_insns_per_block={} requested_insns_total={} start_seed={:#x} step_check={} elapsed={:.2?}",
            reference.name(),
            suite.name(),
            blocks,
            insns,
            blocks * insns,
            start_seed,
            effective_step_check,
            t0.elapsed()
        );
        ExitCode::SUCCESS
    }
}

fn emit_divergence_report(report: &BisectReport, emit_repro: Option<&Path>) {
    print!("{report}");
    let rust_test = report.minimized_rust_test();
    println!("\n--- Minimized Rust Regression Test ---\n{rust_test}");
    #[allow(clippy::collapsible_if)]
    if let Some(path) = emit_repro {
        if let Err(error) = std::fs::write(path, &rust_test) {
            eprintln!(
                "warning: could not write reproducer to {}: {error}",
                path.display()
            );
        }
    }
}

#[allow(clippy::too_many_arguments)]
fn run_campaign(
    reference: RisuReference,
    suite: Suite,
    workers: usize,
    max_blocks: usize,
    duration: Option<Duration>,
    insns: usize,
    start_seed: u64,
    check_csrs: bool,
    step_check: bool,
    strict: bool,
    sail_bin: &Path,
    qemu_bin: &Path,
    emit_repro: Option<&Path>,
) -> ExitCode {
    let t0 = Instant::now();
    let deadline = duration.map(|d| t0 + d);
    let next_block = AtomicUsize::new(0);
    let completed_blocks = AtomicUsize::new(0);
    let stop = AtomicBool::new(false);
    let first_divergence: Mutex<Option<(usize, BisectReport)>> = Mutex::new(None);
    let first_error: Mutex<Option<String>> = Mutex::new(None);

    let suites: &[Suite] = if suite == Suite::All {
        &Suite::CAMPAIGN_SUITES
    } else {
        std::slice::from_ref(&suite)
    };

    println!(
        "START: campaign reference={} suite={} workers={} max_blocks={} insns_per_block={} start_seed={start_seed:#x}",
        reference.name(),
        suite.name(),
        workers,
        max_blocks,
        insns
    );
    let _ = std::io::Write::flush(&mut std::io::stdout());

    let progress_interval = match reference {
        RisuReference::Sail => 10usize,
        RisuReference::Qemu => 25usize,
    };

    std::thread::scope(|scope| {
        for _ in 0..workers {
            scope.spawn(|| {
                let mut cached_qemu_no_pmp: Option<RisuHarness> = None;
                let mut cached_qemu_pmp: Option<RisuHarness> = None;

                while !stop.load(Ordering::Relaxed) {
                    if deadline.is_some_and(|limit| Instant::now() >= limit) {
                        break;
                    }
                    let block = next_block.fetch_add(1, Ordering::Relaxed);
                    if block >= max_blocks {
                        break;
                    }
                    let active_suite = suites[block % suites.len()];
                    let seed = start_seed.wrapping_add(block as u64);
                    let effective_check_csrs = check_csrs
                        || matches!(
                            active_suite,
                            Suite::Privileged
                                | Suite::Sv39
                                | Suite::Sv48
                                | Suite::Pmp
                                | Suite::Cfi
                        );
                    let effective_step_check = step_check
                        || reference == RisuReference::Sail
                        || matches!(
                            active_suite,
                            Suite::FpEdges
                                | Suite::Privileged
                                | Suite::Sv39
                                | Suite::Sv48
                                | Suite::Pmp
                                | Suite::Cfi
                        );

                    let outcome = match RisuCase::generate(active_suite, seed, insns) {
                        Ok(case) => match reference {
                            RisuReference::Qemu => {
                                let pmp_needed = active_suite == Suite::Pmp;
                                let slot = if pmp_needed {
                                    &mut cached_qemu_pmp
                                } else {
                                    &mut cached_qemu_no_pmp
                                };
                                if slot.is_none() {
                                    let created = RivemuTarget::new_bare(strict)
                                        .and_then(|rivemu| {
                                            QemuGdbTarget::spawn_bare_with_pmp(qemu_bin, pmp_needed)
                                                .and_then(|qemu| {
                                                    RisuHarness::new(
                                                        rivemu,
                                                        qemu,
                                                        effective_check_csrs,
                                                    )
                                                })
                                        });
                                    match created {
                                        Ok(h) => {
                                            *slot = Some(h);
                                            Ok(())
                                        }
                                        Err(e) => Err(e),
                                    }
                                } else {
                                    Ok(())
                                }
                                .and_then(|()| {
                                    let harness = slot.as_mut().unwrap();
                                    harness.check_csrs = effective_check_csrs;
                                    harness.reference.sync_csrs = effective_check_csrs;
                                    harness.set_step_check(effective_step_check);
                                    harness.run_case(&case)
                                })
                            }
                            RisuReference::Sail => {
                                RivemuTarget::new_bare(strict).and_then(|rivemu| {
                                    SailGdbTarget::spawn_case(sail_bin, &case)
                                        .and_then(|sail| {
                                            RisuHarness::from_targets(
                                                rivemu,
                                                sail,
                                                effective_check_csrs,
                                            )
                                        })
                                        .and_then(|mut harness| {
                                            harness.set_step_check(true);
                                            harness.run_case(&case)
                                        })
                                })
                            }
                        },
                        Err(error) => Err(error),
                    };

                    match outcome {
                        Ok(None) => {
                            let done = completed_blocks.fetch_add(1, Ordering::Relaxed) + 1;
                            if done % progress_interval == 0 {
                                println!(
                                    "PROGRESS: reference={} suite={} completed_blocks={} insns_tested={} latest_seed={seed:#x} elapsed={:.2?}",
                                    reference.name(),
                                    suite.name(),
                                    done,
                                    done * insns,
                                    t0.elapsed()
                                );
                                let _ = std::io::Write::flush(&mut std::io::stdout());
                            }
                        }
                        Ok(Some(report)) => {
                            stop.store(true, Ordering::Relaxed);
                            let mut slot = first_divergence.lock().unwrap();
                            if slot.is_none() {
                                *slot = Some((block, report));
                            }
                            break;
                        }
                        Err(error) => {
                            stop.store(true, Ordering::Relaxed);
                            let mut slot = first_error.lock().unwrap();
                            if slot.is_none() {
                                *slot = Some(format!(
                                    "error at block {block} (suite={}, seed={seed:#x}): {error}",
                                    active_suite.name()
                                ));
                            }
                            break;
                        }
                    }
                }
            });
        }
    });

    if let Some((block, report)) = first_divergence.into_inner().unwrap() {
        println!(
            "Divergence found at campaign block {block} ({:.2?}):",
            t0.elapsed()
        );
        emit_divergence_report(&report, emit_repro);
        return ExitCode::from(1);
    }
    if let Some(error) = first_error.into_inner().unwrap() {
        eprintln!("{error}");
        return ExitCode::from(2);
    }

    let done = completed_blocks.load(Ordering::Relaxed);
    println!(
        "PASS: campaign reference={} suite={} workers={} blocks={} requested_insns_per_block={} requested_insns_total={} start_seed={:#x} elapsed={:.2?}",
        reference.name(),
        suite.name(),
        workers,
        done,
        insns,
        done * insns,
        start_seed,
        t0.elapsed()
    );
    ExitCode::SUCCESS
}
