//! Measures QEMU GDB-stub latency for single steps, state reads and register reads.
//! Usage: cargo run --release --example qemu_latency [qemu-binary]
use rivemu_lockstep::CosimTarget;
use rivemu_lockstep::target::QemuGdbTarget;
use std::time::Instant;

fn main() {
    let qemu = std::env::args()
        .nth(1)
        .map_or_else(rivemu_lockstep::tools::default_qemu, Into::into);
    let mut target = QemuGdbTarget::spawn_bare(&qemu).expect("spawn QEMU");
    let n = 2000;
    for (name, sync_csrs) in [("get_state (no CSRs)", false), ("get_state (CSRs)", true)] {
        target.sync_csrs = sync_csrs;
        let start = Instant::now();
        for _ in 0..n {
            target.get_state().expect("get_state");
        }
        println!(
            "{name}: {:.1} us",
            start.elapsed().as_secs_f64() * 1e6 / f64::from(n)
        );
    }
    let start = Instant::now();
    for _ in 0..n {
        target.read_reg(33).expect("p");
    }
    println!(
        "single p: {:.1} us",
        start.elapsed().as_secs_f64() * 1e6 / f64::from(n)
    );
    let payloads: Vec<String> = (33..67).map(|r: u32| format!("p{r:x}")).collect();
    let start = Instant::now();
    for _ in 0..n {
        target.cmd_batch(&payloads).expect("batch");
    }
    println!(
        "34 p batched: {:.1} us",
        start.elapsed().as_secs_f64() * 1e6 / f64::from(n)
    );
    let start = Instant::now();
    for _ in 0..n {
        for p in &payloads {
            target.cmd(p).expect("p");
        }
    }
    println!(
        "34 p sequential: {:.1} us",
        start.elapsed().as_secs_f64() * 1e6 / f64::from(n)
    );
    let start = Instant::now();
    for _ in 0..n {
        target.step_one().expect("step");
    }
    println!(
        "step: {:.1} us",
        start.elapsed().as_secs_f64() * 1e6 / f64::from(n)
    );
}
