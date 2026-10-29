//! CLI entrypoint for `rivemu-lockstep` (`risu` fuzzer and early `boot` CPU smoke test).

#![forbid(unsafe_code)]

use std::path::{Path, PathBuf};
use std::process::ExitCode;
use std::time::Instant;

use rivemu_lockstep::lockstep::run_firmware_lockstep;
use rivemu_lockstep::risu::{RisuHarness, Suite};
use rivemu_lockstep::target::{QemuGdbTarget, RivemuTarget};

fn default_qemu() -> PathBuf {
    let brew = Path::new("/opt/homebrew/bin/qemu-system-riscv64");
    if brew.exists() {
        brew.to_path_buf()
    } else {
        PathBuf::from("qemu-system-riscv64")
    }
}

fn print_usage() {
    eprintln!(
        "\
Usage:
  rivemu-lockstep risu [OPTIONS]
  rivemu-lockstep boot --bios <PATH> [--kernel <PATH>] [OPTIONS]

RISU Options:
  --suite <alu|mul|bitmanip|float|mem|csr|all>   Instruction suite [default: all]
  --blocks <N>                                   Number of random blocks [default: 50]
  --insns <K>                                    Instructions per block [default: 32]
  --seed <HEX_OR_DEC>                            Starting PRNG seed [default: 0x1000]
  --check-csrs                                   Compare privileged CSRs at checkpoints
  --step-check                                   Compare state and scratch RAM after every instruction
  --strict                                       Enable rivemu -strict mode
  --qemu <PATH>                                  Path to qemu-system-riscv64

Early Boot CPU Smoke Options:
  --bios <PATH>                                  Firmware ELF/binary (e.g. OpenSBI fw_dynamic.bin)
  --kernel <PATH>                                Optional kernel staged in guest memory
  --steps <N>                                    Early M-mode instructions to compare [default: 1000]
  --check-csrs                                   Compare privileged CSRs on every step
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
    let mut insns = 32usize;
    let mut start_seed = 0x1000u64;
    let mut check_csrs = false;
    let mut step_check = false;
    let mut strict = false;
    let mut qemu_bin = default_qemu();
    let mut bios: Option<PathBuf> = None;
    let mut kernel: Option<PathBuf> = None;
    let mut steps = 1000usize;

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

    let mut i = if matches!(mode, "risu" | "boot") {
        1
    } else {
        0
    };
    while i < args.len() {
        match args[i].as_str() {
            "--suite" => {
                let value = value_or_exit!(option_value(&args, &mut i, "--suite"));
                let Some(s) = Suite::parse(value) else {
                    eprintln!("error: invalid value for --suite ('{value}')");
                    return ExitCode::from(2);
                };
                suite = s;
            }
            "--blocks" => {
                blocks = value_or_exit!(parse_usize_option(&args, &mut i, "--blocks"));
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
    if insns == 0 {
        eprintln!("error: --insns must be greater than zero");
        return ExitCode::from(2);
    }
    if steps == 0 {
        eprintln!("error: --steps must be greater than zero");
        return ExitCode::from(2);
    }

    if mode == "boot" {
        let Some(bios_path) = bios else {
            eprintln!("error: `boot` mode requires `--bios <PATH>`");
            return ExitCode::from(2);
        };
        let t0 = Instant::now();
        match run_firmware_lockstep(&qemu_bin, &bios_path, kernel.as_deref(), steps, check_csrs) {
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
    } else {
        let t0 = Instant::now();
        let rivemu = match RivemuTarget::new_bare(strict) {
            Ok(r) => r,
            Err(e) => {
                eprintln!("error initializing rivemu: {e}");
                return ExitCode::from(2);
            }
        };
        let qemu = match QemuGdbTarget::spawn_bare(&qemu_bin) {
            Ok(q) => q,
            Err(e) => {
                eprintln!("error spawning {}: {e}", qemu_bin.display());
                return ExitCode::from(2);
            }
        };
        let mut harness = match RisuHarness::new(rivemu, qemu, check_csrs) {
            Ok(h) => h,
            Err(e) => {
                eprintln!("error setting up RISU harness: {e}");
                return ExitCode::from(2);
            }
        };
        harness.set_step_check(step_check);

        for b in 0..blocks {
            let seed = start_seed.wrapping_add(b as u64);
            match harness.run_seed(suite, seed, insns) {
                Ok(None) => {}
                Ok(Some(report)) => {
                    println!(
                        "Divergence found after {b}/{blocks} blocks ({:.2?}):",
                        t0.elapsed()
                    );
                    print!("{report}");
                    return ExitCode::from(1);
                }
                Err(e) => {
                    eprintln!("error at block {b} (seed={seed:#x}): {e}");
                    return ExitCode::from(2);
                }
            }
        }
        println!(
            "PASS: suite={} blocks={} requested_insns_per_block={} requested_insns_total={} start_seed={:#x} step_check={} elapsed={:.2?}",
            suite.name(),
            blocks,
            insns,
            blocks * insns,
            start_seed,
            step_check,
            t0.elapsed()
        );
        ExitCode::SUCCESS
    }
}
