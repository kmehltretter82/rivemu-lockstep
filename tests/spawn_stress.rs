//! Concurrent reference-model startup stress test.
//!
//! Multi-worker campaigns start many Sail and QEMU processes in parallel. The
//! previous transport picked a TCP port by binding and dropping a probe
//! listener and then polled `connect()`. A probe listener dropped while another
//! thread was inside `Command::spawn` survived in the child's copy of the fd
//! table until `execve`, accepted the connection, and reset it once the child
//! exec'd ("Connection reset by peer"). This test starts many targets from six
//! threads at once and checks that every one answers its first commands.
//!
//! Opt-in because it takes tens of seconds: set `RIVEMU_LOCKSTEP_STRESS=1`.

use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};

use rivemu_lockstep::risu::{RisuCase, Suite};
use rivemu_lockstep::target::{QemuGdbTarget, SailGdbTarget};
use rivemu_lockstep::tools;

const THREADS: usize = 6;

fn stress_enabled(test: &str) -> bool {
    let enabled = std::env::var_os("RIVEMU_LOCKSTEP_STRESS").is_some();
    if !enabled {
        eprintln!("skipping {test} (set RIVEMU_LOCKSTEP_STRESS=1 to run it)");
    }
    enabled
}

fn spawns_per_thread() -> usize {
    std::env::var("RIVEMU_LOCKSTEP_STRESS_SPAWNS")
        .ok()
        .and_then(|value| value.parse().ok())
        .unwrap_or(40)
}

/// Runs `spawn_one(thread, iteration)` from `THREADS` threads and returns the
/// failure messages.
fn run_concurrently(spawn_one: impl Fn(usize, usize) -> Result<(), String> + Sync) -> Vec<String> {
    let failures = Mutex::new(Vec::new());
    let started = AtomicUsize::new(0);
    std::thread::scope(|scope| {
        for thread in 0..THREADS {
            let failures = &failures;
            let started = &started;
            let spawn_one = &spawn_one;
            scope.spawn(move || {
                for iteration in 0..spawns_per_thread() {
                    started.fetch_add(1, Ordering::Relaxed);
                    if let Err(error) = spawn_one(thread, iteration) {
                        failures
                            .lock()
                            .unwrap()
                            .push(format!("thread {thread} spawn {iteration}: {error}"));
                    }
                }
            });
        }
    });
    eprintln!("started {} targets", started.load(Ordering::Relaxed));
    failures.into_inner().unwrap()
}

#[test]
fn concurrent_qemu_startups_all_connect() {
    let test = "concurrent_qemu_startups_all_connect";
    if !stress_enabled(test) {
        return;
    }
    let Some(qemu) = tools::qemu_for_test(test) else {
        return;
    };
    let failures = run_concurrently(|_, _| {
        let mut target = QemuGdbTarget::spawn_bare(&qemu).map_err(|e| e.to_string())?;
        target.cmd("g").map_err(|e| e.to_string())?;
        Ok(())
    });
    assert!(
        failures.is_empty(),
        "{} failures:\n{}",
        failures.len(),
        failures.join("\n")
    );
}

#[test]
fn concurrent_sail_startups_all_connect() {
    let test = "concurrent_sail_startups_all_connect";
    if !stress_enabled(test) {
        return;
    }
    let Some(sail) = tools::sail_for_test(test) else {
        return;
    };
    let sail = Arc::new(sail);
    let failures = run_concurrently(|thread, iteration| {
        let seed = 0x5000 + (thread * 1000 + iteration) as u64;
        let case = RisuCase::generate(Suite::IntAlu, seed, 8).map_err(|e| e.to_string())?;
        let mut target = SailGdbTarget::spawn_case(&sail, &case).map_err(|e| e.to_string())?;
        target.cmd("g").map_err(|e| e.to_string())?;
        Ok(())
    });
    assert!(
        failures.is_empty(),
        "{} failures:\n{}",
        failures.len(),
        failures.join("\n")
    );
}
