//! Pluggable cosimulation targets (`RivemuTarget` and `QemuGdbTarget`).

pub mod qemu_gdb;
pub mod rivemu;

pub use qemu_gdb::QemuGdbTarget;
pub use rivemu::RivemuTarget;
