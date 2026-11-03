//! Locating the reference simulators, shared by the CLI and the tests.
//!
//! Tests that need QEMU or Sail skip with a message on stderr when the tool is
//! missing, unless the matching `RIVEMU_LOCKSTEP_REQUIRE_*` variable is set
//! (as in CI). Then a missing tool fails the test instead of letting it pass
//! without checking anything.

use std::path::{Path, PathBuf};

/// Overrides the `qemu-system-riscv64` binary.
pub const QEMU_ENV: &str = "RIVEMU_LOCKSTEP_QEMU";
/// Overrides the `sail_riscv_sim` binary.
pub const SAIL_ENV: &str = "RIVEMU_LOCKSTEP_SAIL";
/// When set, QEMU-backed tests fail instead of skipping if QEMU is missing.
pub const REQUIRE_QEMU_ENV: &str = "RIVEMU_LOCKSTEP_REQUIRE_QEMU";
/// When set, Sail-backed tests fail instead of skipping if Sail is missing.
pub const REQUIRE_SAIL_ENV: &str = "RIVEMU_LOCKSTEP_REQUIRE_SAIL";

/// `$RIVEMU_LOCKSTEP_QEMU`, otherwise `qemu-system-riscv64` from `PATH`.
pub fn default_qemu() -> PathBuf {
    std::env::var_os(QEMU_ENV).map_or_else(|| PathBuf::from("qemu-system-riscv64"), PathBuf::from)
}

/// `$RIVEMU_LOCKSTEP_SAIL`, otherwise the patched and then the stock Sail build
/// in the sibling `../third_party` directory, otherwise `sail_riscv_sim` from
/// `PATH`.
pub fn default_sail() -> PathBuf {
    if let Some(path) = std::env::var_os(SAIL_ENV) {
        return PathBuf::from(path);
    }
    let manifest = Path::new(env!("CARGO_MANIFEST_DIR"));
    for relative in [
        "../third_party/sail-riscv-0.16-debug-v1/bin/sail_riscv_sim",
        "../third_party/sail-riscv-0.16/bin/sail_riscv_sim",
    ] {
        let candidate = manifest.join(relative);
        if candidate.exists() {
            return candidate;
        }
    }
    PathBuf::from("sail_riscv_sim")
}

/// Resolves `program` to an existing file: paths containing a separator are
/// checked directly, bare names are searched in `PATH`.
pub fn resolve(program: &Path) -> Option<PathBuf> {
    if program.components().count() > 1 {
        return program.is_file().then(|| program.to_path_buf());
    }
    std::env::split_paths(&std::env::var_os("PATH")?)
        .map(|dir| dir.join(program))
        .find(|candidate| candidate.is_file())
}

/// QEMU for test `test`, or `None` after printing why it is skipped.
///
/// # Panics
///
/// Panics when QEMU is missing and `RIVEMU_LOCKSTEP_REQUIRE_QEMU` is set.
pub fn qemu_for_test(test: &str) -> Option<PathBuf> {
    tool_for_test(test, &default_qemu(), REQUIRE_QEMU_ENV)
}

/// Sail for test `test`, or `None` after printing why it is skipped.
///
/// # Panics
///
/// Panics when Sail is missing and `RIVEMU_LOCKSTEP_REQUIRE_SAIL` is set.
pub fn sail_for_test(test: &str) -> Option<PathBuf> {
    tool_for_test(test, &default_sail(), REQUIRE_SAIL_ENV)
}

fn tool_for_test(test: &str, program: &Path, require_env: &str) -> Option<PathBuf> {
    if let Some(path) = resolve(program) {
        return Some(path);
    }
    assert!(
        std::env::var_os(require_env).is_none(),
        "{test}: {} not found and {require_env} is set",
        program.display()
    );
    eprintln!(
        "skipping {test}: {} not found (set {require_env}=1 to make this a failure)",
        program.display()
    );
    None
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn resolve_checks_explicit_paths_directly() {
        assert!(resolve(Path::new("/nonexistent/qemu-system-riscv64")).is_none());
        assert!(
            resolve(
                Path::new(env!("CARGO_MANIFEST_DIR"))
                    .join("Cargo.toml")
                    .as_path()
            )
            .is_some()
        );
    }
}
