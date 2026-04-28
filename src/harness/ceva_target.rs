use libafl::Error;
use libafl_qemu::{GuestReg, Qemu};

use super::ceva_emu::CevaEmuHarness;
use super::translate_node_link::TranslateNodeLinkTarget;
use super::decode_execute_cold_path::DecodeExecuteColdPath;

pub trait CevaTarget {
    fn name(&self) -> &'static str;

    fn initialize(
        &mut self,
        _harness: &mut CevaEmuHarness<'_>,
        _max_bp_hit_count: Option<u64>,
    ) -> Result<(), Error> {
        Ok(())
    }

    fn prepare_input(
        &self,
        qemu: &Qemu,
        input: &[u8],
        input_len: GuestReg,
    ) -> Result<(), Error>;

    fn reset(
        &self,
        _harness: &CevaEmuHarness<'_>,
    ) -> Result<(), Error> {
        Ok(())
    }
}

#[derive(Clone, Copy, Debug)]
pub enum CevaTargetKind {
    TranslateNodeLink,
    DecodeExecuteColdPath,
}

impl CevaTargetKind {
    pub fn build(self) -> Box<dyn CevaTarget> {
        match self {
            CevaTargetKind::TranslateNodeLink => Box::new(TranslateNodeLinkTarget::default()),
            CevaTargetKind::DecodeExecuteColdPath => Box::new(DecodeExecuteColdPath::default()),
        }
    }
}
