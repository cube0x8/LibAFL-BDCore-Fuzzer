use libafl::Error;
use libafl_qemu::{GuestReg, Qemu};

use super::ceva_emu::decode_execute_cold_path::DecodeExecuteColdPath;
use super::ceva_emu::translate_node_link::TranslateNodeLinkTarget;
use super::cevakrnl::CevaEmuHarness;
use super::unpackers::aspack::AspackWorkerTarget;
use super::unpackers::beria::BeriaVmTarget;
use super::unpackers::morphinep::MorphinepTarget;
use super::unpackers::pelock::PelockTarget;
use super::unpackers::pec3::{
    Pec3A4Target, Pec3HashTarget, Pec3PeviewerTarget, Pec3Read28Target, Pec3Read40Target,
};
use super::unpackers::petite::{Petite2000Target, PetiteA4Target};

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
}

#[derive(Clone, Copy, Debug)]
pub enum CevaTargetKind {
    TranslateNodeLink,
    DecodeExecuteColdPath,
    BeriaVm,
    AspackWorker,
    PetiteA4,
    Petite2000,
    Morphinep,
    Pelock,
    Pec3A4,
    Pec3Read40,
    Pec3Read28,
    Pec3Peviewer,
    Pec3Hash,
}

impl CevaTargetKind {
    pub fn build(self) -> Box<dyn CevaTarget> {
        match self {
            CevaTargetKind::TranslateNodeLink => Box::new(TranslateNodeLinkTarget::default()),
            CevaTargetKind::DecodeExecuteColdPath => Box::new(DecodeExecuteColdPath::default()),
            CevaTargetKind::BeriaVm => Box::new(BeriaVmTarget::default()),
            CevaTargetKind::AspackWorker => Box::new(AspackWorkerTarget::default()),
            CevaTargetKind::PetiteA4 => Box::new(PetiteA4Target::default()),
            CevaTargetKind::Petite2000 => Box::new(Petite2000Target::default()),
            CevaTargetKind::Morphinep => Box::new(MorphinepTarget::default()),
            CevaTargetKind::Pelock => Box::new(PelockTarget::default()),
            CevaTargetKind::Pec3A4 => Box::new(Pec3A4Target::default()),
            CevaTargetKind::Pec3Read40 => Box::new(Pec3Read40Target::default()),
            CevaTargetKind::Pec3Read28 => Box::new(Pec3Read28Target::default()),
            CevaTargetKind::Pec3Peviewer => Box::new(Pec3PeviewerTarget::default()),
            CevaTargetKind::Pec3Hash => Box::new(Pec3HashTarget::default()),
        }
    }
}
