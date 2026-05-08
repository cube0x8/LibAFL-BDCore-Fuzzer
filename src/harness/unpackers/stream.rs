use std::cell::RefCell;

use libafl::Error;
use libafl_qemu::{ArchExtras, GuestAddr, GuestReg, Qemu, Regs};

#[derive(Clone, Copy, Debug)]
pub struct StreamOverlay {
    pub input_offset: usize,
    pub stream_offset: usize,
    pub max_len: usize,
}

#[derive(Default)]
struct MemoryBackedStreamState {
    data: Vec<u8>,
    pos: usize,
}

#[derive(Default)]
pub struct MemoryBackedStream {
    state: RefCell<MemoryBackedStreamState>,
}

#[derive(Default)]
struct StagedReadStreamState {
    stages: Vec<Vec<u8>>,
    next_stage: usize,
    pos: usize,
}

#[derive(Default)]
pub struct StagedReadStream {
    state: RefCell<StagedReadStreamState>,
}

fn skip_guest_call(qemu: &Qemu, ret_value: u64) -> Result<(), Error> {
    let ret_addr: GuestAddr = qemu.read_return_address().unwrap().try_into().unwrap();
    let rsp: GuestAddr = qemu.read_reg(Regs::Sp).unwrap().try_into().unwrap();

    qemu.write_reg(Regs::Rax, GuestReg::try_from(ret_value).unwrap())
        .map_err(|e| Error::unknown(format!("Failed to set RAX: {e:?}")))?;
    qemu.write_reg(Regs::Sp, GuestReg::try_from(rsp + 8).unwrap())
        .map_err(|e| Error::unknown(format!("Failed to advance RSP: {e:?}")))?;
    qemu.write_reg(Regs::Pc, GuestReg::try_from(ret_addr).unwrap())
        .map_err(|e| Error::unknown(format!("Failed to set PC to return address: {e:?}")))?;

    Ok(())
}

impl MemoryBackedStream {
    pub fn rebuild_with_overlays(&self, input: &[u8], overlays: &[StreamOverlay]) {
        let mut stream_len = 0usize;

        for overlay in overlays {
            let copy_len = input
                .len()
                .saturating_sub(overlay.input_offset)
                .min(overlay.max_len);
            stream_len = stream_len.max(overlay.stream_offset + copy_len);
        }

        let mut state = self.state.borrow_mut();
        state.data.clear();
        state.data.resize(stream_len, 0);

        for overlay in overlays {
            let copy_len = input
                .len()
                .saturating_sub(overlay.input_offset)
                .min(overlay.max_len);
            if copy_len == 0 {
                continue;
            }

            let input_end = overlay.input_offset + copy_len;
            let stream_end = overlay.stream_offset + copy_len;
            state.data[overlay.stream_offset..stream_end]
                .copy_from_slice(&input[overlay.input_offset..input_end]);
        }

        state.pos = 0;
    }

    pub fn reset(&self) {
        self.state.borrow_mut().pos = 0;
    }

    pub fn emulate_seek(&self, qemu: &Qemu) -> Result<(), Error> {
        let off: i64 = qemu.read_reg(Regs::Rdx).unwrap().try_into().unwrap();
        let action: u64 = qemu.read_reg(Regs::R8).unwrap().try_into().unwrap();

        let mut state = self.state.borrow_mut();
        let len = state.data.len() as i64;
        let base = match action {
            0 => 0,
            1 => state.pos as i64,
            2 => len,
            _ => state.pos as i64,
        };
        let new_pos = (base.saturating_add(off)).clamp(0, len) as usize;
        state.pos = new_pos;

        skip_guest_call(qemu, new_pos as u64)
    }

    pub fn emulate_read(&self, qemu: &Qemu) -> Result<(), Error> {
        let dst: GuestAddr = qemu.read_reg(Regs::Rdx).unwrap().try_into().unwrap();
        let requested: usize = qemu
            .read_reg(Regs::R8)
            .unwrap()
            .try_into()
            .unwrap_or(usize::MAX);

        let mut state = self.state.borrow_mut();
        let available = state.data.len().saturating_sub(state.pos);
        let to_copy = requested.min(available);
        let end = state.pos + to_copy;
        let src = &state.data[state.pos..end];

        if !src.is_empty() {
            qemu.write_mem(dst, src).map_err(|e| {
                Error::unknown(format!("Failed to write emulated read buffer: {e:?}"))
            })?;
        }

        state.pos = end;
        skip_guest_call(qemu, to_copy as u64)
    }
}

impl StagedReadStream {
    pub fn set_stages(&self, stages: Vec<Vec<u8>>) {
        let mut state = self.state.borrow_mut();
        state.stages = stages;
        state.next_stage = 0;
        state.pos = 0;
    }

    pub fn reset(&self) {
        let mut state = self.state.borrow_mut();
        state.next_stage = 0;
        state.pos = 0;
    }

    pub fn emulate_seek(&self, qemu: &Qemu) -> Result<(), Error> {
        let off: i64 = qemu.read_reg(Regs::Rdx).unwrap().try_into().unwrap();
        let action: u64 = qemu.read_reg(Regs::R8).unwrap().try_into().unwrap();

        let mut state = self.state.borrow_mut();
        let end = state
            .stages
            .iter()
            .map(|stage| stage.len())
            .sum::<usize>() as i64;
        let base = match action {
            0 => 0,
            1 => state.pos as i64,
            2 => end,
            _ => state.pos as i64,
        };
        let new_pos = (base.saturating_add(off)).clamp(0, end) as usize;
        state.pos = new_pos;

        skip_guest_call(qemu, new_pos as u64)
    }

    pub fn emulate_read(&self, qemu: &Qemu) -> Result<(), Error> {
        let dst: GuestAddr = qemu.read_reg(Regs::Rdx).unwrap().try_into().unwrap();
        let requested: usize = qemu
            .read_reg(Regs::R8)
            .unwrap()
            .try_into()
            .unwrap_or(usize::MAX);

        let mut state = self.state.borrow_mut();
        let stage = state.stages.get(state.next_stage).cloned().unwrap_or_default();
        let to_copy = requested.min(stage.len());

        if to_copy != 0 {
            qemu.write_mem(dst, &stage[..to_copy]).map_err(|e| {
                Error::unknown(format!("Failed to write staged read buffer: {e:?}"))
            })?;
        }

        state.next_stage = state.next_stage.saturating_add(1);
        state.pos = state.pos.saturating_add(to_copy);
        skip_guest_call(qemu, to_copy as u64)
    }
}
