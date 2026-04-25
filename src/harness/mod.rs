mod ceva_emu;
mod ceva_target;
mod standard;
mod translate_node_link;

use std::ops::Range;

use libafl::{executors::ExitKind, inputs::BytesInput};

use crate::{bitdefender::BDEngine, scan_profile::ScanProfile};

pub use ceva_emu::CevaEmuHarness;
pub use ceva_target::{CevaTarget, CevaTargetKind};
pub use standard::Harness;

pub const MAX_INPUT_SIZE: usize = 1_048_576;
pub const MAX_TARGET_INPUT_SIZE: usize = 307_200;
pub const FILE_PATH_SIZE: usize = 1024;
pub const G_MMAP_FILE_SIZE: usize = 280;

pub trait FuzzHarness {
    fn snapshot_excludes(&self) -> Vec<Range<u64>>;
    fn bd_engine(&self) -> &BDEngine;
    fn run(&self, input: &BytesInput, scan_profile: Option<&ScanProfile>) -> ExitKind;
}

pub enum AnyHarness<'a> {
    Standard(Harness<'a>),
    CevaEmu(CevaEmuHarness<'a>),
}

impl FuzzHarness for AnyHarness<'_> {
    fn snapshot_excludes(&self) -> Vec<Range<u64>> {
        match self {
            AnyHarness::Standard(harness) => harness.snapshot_excludes(),
            AnyHarness::CevaEmu(harness) => harness.snapshot_excludes(),
        }
    }

    fn bd_engine(&self) -> &BDEngine {
        match self {
            AnyHarness::Standard(harness) => &harness.bd_engine,
            AnyHarness::CevaEmu(harness) => &harness.bd_engine,
        }
    }

    fn run(&self, input: &BytesInput, scan_profile: Option<&ScanProfile>) -> ExitKind {
        match self {
            AnyHarness::Standard(harness) => harness.run(input, scan_profile),
            AnyHarness::CevaEmu(harness) => harness.run(input, scan_profile),
        }
    }
}
