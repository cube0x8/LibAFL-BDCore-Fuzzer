use std::cell::Cell;

use libafl::Error;
use libafl_qemu::{GuestAddr, GuestReg, Qemu, Regs};

use crate::harness::{CevaEmuHarness, CevaTarget};
use crate::harness::unpackers::stream::{MemoryBackedStream, StreamOverlay};

const MORPHINEP_SEEK_THUNK_OFFSET: GuestAddr = 0x658;
const MORPHINEP_READ_THUNK_OFFSET: GuestAddr = 0x668;
const MORPHINEP_STAGE0_SEEK_OFFSET: usize = 0x400;
const MORPHINEP_STAGE0_LEN: usize = 0x4000;
const MORPHINEP_STAGE1_SEEK_OFFSET: usize = 0x600;
const MORPHINEP_STAGE1_LEN: usize = 0x100;

#[derive(Default)]
pub struct MorphinepTarget {
    seek_pc: Cell<GuestAddr>,
    read_pc: Cell<GuestAddr>,
    stream: MemoryBackedStream,
}

fn restore_nonvolatile_regs(harness: &CevaEmuHarness<'_>) -> Result<(), Error> {
    let qemu = harness.qemu();

    qemu.write_reg(Regs::Rbx, GuestReg::try_from(harness.rbx).unwrap())
        .map_err(|e| Error::unknown(format!("Failed to restore RBX: {e:?}")))?;
    qemu.write_reg(Regs::Rbp, GuestReg::try_from(harness.rbp).unwrap())
        .map_err(|e| Error::unknown(format!("Failed to restore RBP: {e:?}")))?;
    qemu.write_reg(Regs::Rdi, GuestReg::try_from(harness.rdi).unwrap())
        .map_err(|e| Error::unknown(format!("Failed to restore RDI: {e:?}")))?;
    qemu.write_reg(Regs::Rsi, GuestReg::try_from(harness.rsi).unwrap())
        .map_err(|e| Error::unknown(format!("Failed to restore RSI: {e:?}")))?;
    qemu.write_reg(Regs::R12, GuestReg::try_from(harness.r12).unwrap())
        .map_err(|e| Error::unknown(format!("Failed to restore R12: {e:?}")))?;
    qemu.write_reg(Regs::R13, GuestReg::try_from(harness.r13).unwrap())
        .map_err(|e| Error::unknown(format!("Failed to restore R13: {e:?}")))?;
    qemu.write_reg(Regs::R14, GuestReg::try_from(harness.r14).unwrap())
        .map_err(|e| Error::unknown(format!("Failed to restore R14: {e:?}")))?;
    qemu.write_reg(Regs::R15, GuestReg::try_from(harness.r15).unwrap())
        .map_err(|e| Error::unknown(format!("Failed to restore R15: {e:?}")))?;

    Ok(())
}

impl MorphinepTarget {
    const STREAM_LAYOUT: [StreamOverlay; 2] = [
        StreamOverlay {
            input_offset: 0,
            stream_offset: MORPHINEP_STAGE0_SEEK_OFFSET,
            max_len: MORPHINEP_STAGE0_LEN,
        },
        StreamOverlay {
            input_offset: MORPHINEP_STAGE0_LEN,
            stream_offset: MORPHINEP_STAGE1_SEEK_OFFSET,
            max_len: MORPHINEP_STAGE1_LEN,
        },
    ];
}

impl CevaTarget for MorphinepTarget {
    fn name(&self) -> &'static str {
        "Morphinep"
    }

    fn initialize(
        &mut self,
        harness: &mut CevaEmuHarness<'_>,
        _max_bp_hit_count: Option<u64>,
    ) -> Result<(), Error> {
        let seek_pc = harness.entry_point + MORPHINEP_SEEK_THUNK_OFFSET;
        let read_pc = harness.entry_point + MORPHINEP_READ_THUNK_OFFSET;

        self.seek_pc.set(seek_pc);
        self.read_pc.set(read_pc);

        harness.qemu().set_breakpoint(seek_pc);
        harness.qemu().set_breakpoint(read_pc);

        log::debug!(
            "Morphinep init: entry={:#x} seek_hook={seek_pc:#x} read_hook={read_pc:#x}",
            harness.entry_point,
        );

        Ok(())
    }

    fn prepare_input(&self, _qemu: &Qemu, input: &[u8], input_len: GuestReg) -> Result<(), Error> {
        let final_input_len = (input_len as usize).min(input.len());
        self.stream
            .rebuild_with_overlays(&input[..final_input_len], &Self::STREAM_LAYOUT);
        Ok(())
    }

    fn reset(&self, harness: &CevaEmuHarness<'_>) -> Result<(), Error> {
        restore_nonvolatile_regs(harness)?;
        self.stream.reset();
        Ok(())
    }

    fn handle_breakpoint(&self, harness: &CevaEmuHarness<'_>) -> Result<bool, Error> {
        let qemu = harness.qemu();
        let pc: GuestAddr = qemu.read_reg(Regs::Pc).unwrap().try_into().unwrap();

        if pc == self.seek_pc.get() {
            self.stream.emulate_seek(qemu)?;
            return Ok(true);
        }

        if pc == self.read_pc.get() {
            self.stream.emulate_read(qemu)?;
            return Ok(true);
        }

        Ok(false)
    }
}
