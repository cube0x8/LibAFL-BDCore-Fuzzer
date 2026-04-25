use libafl::Error;
use libafl_qemu::{GuestAddr, GuestReg, Qemu};

use crate::bitdefender::BDEngine;

use super::translate_node_link::TranslateNodeLinkTarget;

pub trait CevaTarget {
    fn name(&self) -> &'static str;

    fn initialize(
        &mut self,
        _qemu: &Qemu,
        _bd: &BDEngine,
    ) -> Result<(), Error> {
        Ok(())
    }

    fn prepare_input(
        &self,
        qemu: &Qemu,
        input: &[u8],
        input_len: GuestReg,
    ) -> Result<(), Error>;
}

#[derive(Clone, Copy, Debug)]
pub enum CevaTargetKind {
    TranslateNodeLink,
}

impl CevaTargetKind {
    pub fn build(self) -> Box<dyn CevaTarget> {
        match self {
            CevaTargetKind::TranslateNodeLink => Box::new(TranslateNodeLinkTarget::default()),
        }
    }
}
