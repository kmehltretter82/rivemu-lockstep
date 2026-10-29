//! `RISU`-style constrained-random instruction & system-state fuzzing engine.

pub mod encode;
pub mod harness;
pub mod seed;
pub mod suite;

pub use harness::{BisectReport, RisuHarness};
pub use suite::Suite;
