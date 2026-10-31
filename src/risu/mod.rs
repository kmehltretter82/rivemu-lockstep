//! `RISU`-style constrained-random instruction & system-state fuzzing engine.

pub(crate) mod cfi;
pub mod encode;
mod fp_edges;
pub mod harness;
pub(crate) mod pmp;
pub mod seed;
pub mod suite;
pub(crate) mod sv39;
pub(crate) mod vector;

pub use harness::{BisectReport, RisuCase, RisuHarness};
pub use suite::Suite;
