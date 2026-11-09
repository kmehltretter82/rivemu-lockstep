//! Writes the code bytes of one RISU case to a file for disassembly.
//! Usage: cargo run --example dump_case -- <suite> <seed> <insns> <out.bin>
use rivemu_lockstep::risu::{RisuCase, Suite};

fn main() {
    let args: Vec<String> = std::env::args().collect();
    let suite = Suite::parse(&args[1]).expect("suite");
    let seed = u64::from_str_radix(args[2].trim_start_matches("0x"), 16).expect("hex seed");
    let insns: usize = args[3].parse().expect("insns");
    let case = RisuCase::generate(suite, seed, insns).expect("generate");
    std::fs::write(&args[4], case.code_bytes()).expect("write");
}
