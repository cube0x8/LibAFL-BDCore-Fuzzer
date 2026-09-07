use libafl::{executors::ExitKind, Error};
use libafl_qemu::{GuestReg, Qemu};

use super::cevakrnl::CevaEmuHarness;
use super::unpackers::fsg::FsgPostdecodeTarget;
use super::unpackers::pec3::{
    Pec3A4Target, Pec3HashTarget, Pec3Operation11Mode2Target, Pec3Operation11Target,
    Pec3PeviewerHeapPoisonTarget, Pec3PeviewerTarget, Pec3PostdecodeTarget, Pec3Read28Target,
    Pec3Read40Target,
};
use super::unpackers::pelock::PelockTarget;

pub trait CevaTarget {
    fn name(&self) -> &'static str;

    fn initialize(
        &mut self,
        _harness: &mut CevaEmuHarness<'_>,
        _max_bp_hit_count: Option<u64>,
    ) -> Result<(), Error> {
        Ok(())
    }

    fn prepare_input(&self, qemu: &Qemu, input: &[u8], input_len: GuestReg) -> Result<(), Error>;

    fn reset(&self, _harness: &CevaEmuHarness<'_>) -> Result<(), Error> {
        Ok(())
    }

    fn handle_breakpoint(&self, _harness: &CevaEmuHarness<'_>) -> Result<bool, Error> {
        Ok(false)
    }

    fn after_run(&self, _harness: &CevaEmuHarness<'_>, _execs: u64) -> Result<(), Error> {
        Ok(())
    }

    fn exit_kind(&self) -> ExitKind {
        ExitKind::Ok
    }
}

#[derive(Clone, Copy, Debug)]
pub enum CevaTargetKind {
    FsgPostdecode,
    Pelock,
    Pec3A4,
    Pec3Read40,
    Pec3Read28,
    Pec3Peviewer,
    Pec3PeviewerHeapPoison,
    Pec3Hash,
    Pec3Operation11,
    Pec3Operation11Mode2,
    Pec3Postdecode,
}

impl CevaTargetKind {
    pub fn build(self) -> Box<dyn CevaTarget> {
        match self {
            Self::FsgPostdecode => Box::new(FsgPostdecodeTarget::default()),
            Self::Pelock => Box::new(PelockTarget::default()),
            Self::Pec3A4 => Box::new(Pec3A4Target::default()),
            Self::Pec3Read40 => Box::new(Pec3Read40Target::default()),
            Self::Pec3Read28 => Box::new(Pec3Read28Target::default()),
            Self::Pec3Peviewer => Box::new(Pec3PeviewerTarget::default()),
            Self::Pec3PeviewerHeapPoison => Box::new(Pec3PeviewerHeapPoisonTarget::default()),
            Self::Pec3Hash => Box::new(Pec3HashTarget::default()),
            Self::Pec3Operation11 => Box::new(Pec3Operation11Target::default()),
            Self::Pec3Operation11Mode2 => Box::new(Pec3Operation11Mode2Target::default()),
            Self::Pec3Postdecode => Box::new(Pec3PostdecodeTarget::default()),
        }
    }
}
