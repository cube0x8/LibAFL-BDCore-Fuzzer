use libafl::Error;
use libafl_qemu::{GuestReg, Qemu};

use super::beria_vm::BeriaVmTarget;
use super::ceva_emu::CevaEmuHarness;
use super::decode_execute_cold_path::DecodeExecuteColdPath;
use super::pec3_unpack::{Pec3A4Target, Pec3Read28Target, Pec3Read40Target};
use super::petite_unpack::{Petite2000Target, PetiteA4Target};
use super::translate_node_link::TranslateNodeLinkTarget;

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
}

#[derive(Clone, Copy, Debug)]
pub enum CevaTargetKind {
    TranslateNodeLink,
    DecodeExecuteColdPath,
    BeriaVm,
    PetiteA4,
    Petite2000,
    Pec3A4,
    Pec3Read40,
    Pec3Read28,
}

impl CevaTargetKind {
    pub fn build(self) -> Box<dyn CevaTarget> {
        match self {
            CevaTargetKind::TranslateNodeLink => Box::new(TranslateNodeLinkTarget::default()),
            CevaTargetKind::DecodeExecuteColdPath => Box::new(DecodeExecuteColdPath::default()),
            CevaTargetKind::BeriaVm => Box::new(BeriaVmTarget::default()),
            CevaTargetKind::PetiteA4 => Box::new(PetiteA4Target::default()),
            CevaTargetKind::Petite2000 => Box::new(Petite2000Target::default()),
            CevaTargetKind::Pec3A4 => Box::new(Pec3A4Target::default()),
            CevaTargetKind::Pec3Read40 => Box::new(Pec3Read40Target::default()),
            CevaTargetKind::Pec3Read28 => Box::new(Pec3Read28Target::default()),
        }
    }
}
