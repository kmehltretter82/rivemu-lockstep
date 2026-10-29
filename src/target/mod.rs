//! Pluggable cosimulation targets (`RivemuTarget` and `QemuGdbTarget`).

pub mod qemu_gdb;
pub mod rivemu;
pub mod sail_elf;
pub mod sail_gdb;

pub use qemu_gdb::QemuGdbTarget;
pub use rivemu::RivemuTarget;
pub use sail_gdb::SailGdbTarget;
