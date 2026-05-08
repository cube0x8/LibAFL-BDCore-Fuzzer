use std::cell::{Cell, RefCell};

use libafl::Error;
use libafl_qemu::{ArchExtras, GuestAddr, GuestReg, Qemu, Regs};

use crate::harness::{CevaEmuHarness, CevaTarget};

const MORPHINEP_SEEK_THUNK_OFFSET: GuestAddr = 0x658;
const MORPHINEP_READ_THUNK_OFFSET: GuestAddr = 0x668;
const MORPHINEP_STAGE0_SEEK_OFFSET: usize = 0x400;
const MORPHINEP_STAGE0_LEN: usize = 0x4000;
const MORPHINEP_STAGE1_SEEK_OFFSET: usize = 0x600;
const MORPHINEP_STAGE1_LEN: usize = 0x100;

#[derive(Default)]
struct FakeStream {
    data: Vec<u8>,
    pos: usize,
}

#[derive(Default)]
pub struct MorphinepTarget {
    seek_pc: Cell<GuestAddr>,
    read_pc: Cell<GuestAddr>,
    stream: RefCell<FakeStream>,
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

impl MorphinepTarget {
    fn rebuild_stream(&self, input: &[u8]) {
        let stage0_len = input.len().min(MORPHINEP_STAGE0_LEN);
        let stage1_len = input
            .len()
            .saturating_sub(MORPHINEP_STAGE0_LEN)
            .min(MORPHINEP_STAGE1_LEN);
        let stream_len = (MORPHINEP_STAGE0_SEEK_OFFSET + stage0_len)
            .max(MORPHINEP_STAGE1_SEEK_OFFSET + stage1_len);

        let mut stream = self.stream.borrow_mut();
        stream.data.clear();
        stream.data.resize(stream_len, 0);

        let stage0_dst = MORPHINEP_STAGE0_SEEK_OFFSET;
        let stage0_end = stage0_dst + stage0_len;
        stream.data[stage0_dst..stage0_end].copy_from_slice(&input[..stage0_len]);

        if stage1_len > 0 {
            let stage1_src = MORPHINEP_STAGE0_LEN;
            let stage1_dst = MORPHINEP_STAGE1_SEEK_OFFSET;
            let stage1_end = stage1_dst + stage1_len;
            stream.data[stage1_dst..stage1_end]
                .copy_from_slice(&input[stage1_src..stage1_src + stage1_len]);
        }

        stream.pos = 0;
    }

    fn emulate_seek(&self, qemu: &Qemu) -> Result<(), Error> {
        let off: i64 = qemu.read_reg(Regs::Rdx).unwrap().try_into().unwrap();
        let action: u64 = qemu.read_reg(Regs::R8).unwrap().try_into().unwrap();

        let mut stream = self.stream.borrow_mut();
        let len = stream.data.len() as i64;
        let base = match action {
            0 => 0,
            1 => stream.pos as i64,
            2 => len,
            _ => stream.pos as i64,
        };
        let new_pos = (base.saturating_add(off)).clamp(0, len) as usize;
        stream.pos = new_pos;

        skip_guest_call(qemu, new_pos as u64)
    }

    fn emulate_read(&self, qemu: &Qemu) -> Result<(), Error> {
        let dst: GuestAddr = qemu.read_reg(Regs::Rdx).unwrap().try_into().unwrap();
        let requested: usize = qemu
            .read_reg(Regs::R8)
            .unwrap()
            .try_into()
            .unwrap_or(usize::MAX);

        let mut stream = self.stream.borrow_mut();
        let available = stream.data.len().saturating_sub(stream.pos);
        let to_copy = requested.min(available);
        let end = stream.pos + to_copy;
        let src = &stream.data[stream.pos..end];

        if !src.is_empty() {
            qemu.write_mem(dst, src).map_err(|e| {
                Error::unknown(format!("Failed to write emulated read buffer: {e:?}"))
            })?;
        }

        stream.pos = end;
        skip_guest_call(qemu, to_copy as u64)
    }
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
        self.rebuild_stream(&input[..final_input_len]);
        Ok(())
    }

    fn reset(&self, harness: &CevaEmuHarness<'_>) -> Result<(), Error> {
        restore_nonvolatile_regs(harness)?;
        self.stream.borrow_mut().pos = 0;
        Ok(())
    }

    fn handle_breakpoint(&self, harness: &CevaEmuHarness<'_>) -> Result<bool, Error> {
        let qemu = harness.qemu();
        let pc: GuestAddr = qemu.read_reg(Regs::Pc).unwrap().try_into().unwrap();

        if pc == self.seek_pc.get() {
            self.emulate_seek(qemu)?;
            return Ok(true);
        }

        if pc == self.read_pc.get() {
            self.emulate_read(qemu)?;
            return Ok(true);
        }

        Ok(false)
    }
}
