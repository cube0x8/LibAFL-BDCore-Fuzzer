use std::cell::Cell;

use libafl::Error;
use libafl_qemu::{GuestAddr, GuestReg, Qemu, Regs};

use crate::harness::unpackers::stream::StagedReadStream;
use crate::harness::{CevaEmuHarness, CevaTarget};

const DEBUG_INPUT_BYTES_LEN: usize = 32;
const PEC3_STAGE40_LEN: usize = 0x40;
const PEC3_STAGE28_LEN: usize = 0x28;
const PEC3_SEEK_THUNK_OFFSET: GuestAddr = 0x2C00;
const PEC3_READ_THUNK_OFFSET: GuestAddr = 0x2C10;

fn format_bytes(bytes: &[u8]) -> String {
    bytes
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect::<Vec<_>>()
        .join(" ")
}

fn read_stack_arg_u64(qemu: &Qemu, rsp: GuestAddr, offset: GuestAddr) -> Result<u64, Error> {
    let mut buf = [0u8; 8];
    qemu.read_mem(rsp + offset, &mut buf).map_err(|e| {
        Error::unknown(format!(
            "Failed to read stack arg at rsp+{offset:#x}: {e:?}"
        ))
    })?;
    Ok(u64::from_le_bytes(buf))
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

fn initialize_worker_stream_stage(
    harness: &mut CevaEmuHarness<'_>,
    seek_pc: GuestAddr,
    read_pc: GuestAddr,
    target_name: &str,
) -> Result<(), Error> {
    harness.qemu().set_breakpoint(seek_pc);
    harness.qemu().set_breakpoint(read_pc);

    log::debug!(
        "{target_name} init: worker={:#x} seek_hook={seek_pc:#x} read_hook={read_pc:#x}",
        harness.entry_point,
    );

    Ok(())
}

fn read_entry_stub_prefix(qemu: &Qemu, want_len: usize) -> Result<Vec<u8>, Error> {
    let a4: GuestAddr = qemu.read_reg(Regs::R9).unwrap().try_into().unwrap();
    let rsp: GuestAddr = qemu.read_reg(Regs::Sp).unwrap().try_into().unwrap();
    let a5 = read_stack_arg_u64(qemu, rsp, 0x28)? as usize;

    let read_len = want_len.min(a5);
    let mut out = vec![0u8; want_len];
    if read_len != 0 {
        qemu.read_mem(a4, &mut out[..read_len]).map_err(|e| {
            Error::unknown(format!("Failed to read pec3 entry stub prefix: {e:?}"))
        })?;
    }
    Ok(out)
}

#[derive(Default)]
pub struct Pec3A4Target;

impl CevaTarget for Pec3A4Target {
    fn name(&self) -> &'static str {
        "Pec3A4"
    }

    fn prepare_input(&self, qemu: &Qemu, input: &[u8], input_len: GuestReg) -> Result<(), Error> {
        let a4: GuestAddr = qemu.read_reg(Regs::R9).unwrap().try_into().unwrap();
        let rsp: GuestAddr = qemu.read_reg(Regs::Sp).unwrap().try_into().unwrap();
        let a5 = read_stack_arg_u64(qemu, rsp, 0x28)?;

        let final_input_len: usize = (a5 as usize).min(input_len as usize);
        let input_buf = &input[..final_input_len];

        let mut before_write = vec![0u8; final_input_len];
        let _ = qemu.read_mem(a4, &mut before_write);
        log::debug!(
            "Pec3A4 prepare_input: a4={a4:#x} a5={a5:#x} input_len={} final_input_len={}",
            input.len(),
            final_input_len,
        );
        log::debug!(
            "Pec3A4 prepare_input: input_before_write=[{}] guest_before_write=[{}]",
            format_bytes(&input_buf[..input_buf.len().min(DEBUG_INPUT_BYTES_LEN)]),
            format_bytes(&before_write[..before_write.len().min(DEBUG_INPUT_BYTES_LEN)]),
        );

        qemu.write_mem(a4, input_buf)
            .map_err(|e| Error::unknown(format!("Failed to write pec3 a4 buffer: {e:?}")))?;

        let mut after_write = vec![0u8; final_input_len];
        let _ = qemu.read_mem(a4, &mut after_write);
        log::debug!(
            "Pec3A4 prepare_input: guest_after_write=[{}]",
            format_bytes(&after_write[..after_write.len().min(DEBUG_INPUT_BYTES_LEN)]),
        );
        Ok(())
    }

    fn reset(&self, harness: &CevaEmuHarness<'_>) -> Result<(), Error> {
        restore_nonvolatile_regs(harness)
    }
}

#[derive(Default)]
pub struct Pec3Read40Target {
    seek_pc: Cell<GuestAddr>,
    read_pc: Cell<GuestAddr>,
    stream: StagedReadStream,
}

impl CevaTarget for Pec3Read40Target {
    fn name(&self) -> &'static str {
        "Pec3Read40"
    }

    fn initialize(
        &mut self,
        harness: &mut CevaEmuHarness<'_>,
        _max_bp_hit_count: Option<u64>,
    ) -> Result<(), Error> {
        let seek_pc = harness.entry_point + PEC3_SEEK_THUNK_OFFSET;
        let read_pc = harness.entry_point + PEC3_READ_THUNK_OFFSET;

        self.seek_pc.set(seek_pc);
        self.read_pc.set(read_pc);

        initialize_worker_stream_stage(harness, seek_pc, read_pc, self.name())
    }

    fn prepare_input(&self, qemu: &Qemu, input: &[u8], input_len: GuestReg) -> Result<(), Error> {
        let final_input_len: usize = PEC3_STAGE40_LEN.min(input_len as usize);
        let mut stages = Vec::with_capacity(2);
        stages.push(input[..final_input_len].to_vec());
        stages.push(read_entry_stub_prefix(qemu, PEC3_STAGE28_LEN)?);
        self.stream.set_stages(stages);
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

#[derive(Default)]
pub struct Pec3Read28Target {
    seek_pc: Cell<GuestAddr>,
    read_pc: Cell<GuestAddr>,
    stream: StagedReadStream,
}

impl CevaTarget for Pec3Read28Target {
    fn name(&self) -> &'static str {
        "Pec3Read28"
    }

    fn initialize(
        &mut self,
        harness: &mut CevaEmuHarness<'_>,
        _max_bp_hit_count: Option<u64>,
    ) -> Result<(), Error> {
        let seek_pc = harness.entry_point + PEC3_SEEK_THUNK_OFFSET;
        let read_pc = harness.entry_point + PEC3_READ_THUNK_OFFSET;

        self.seek_pc.set(seek_pc);
        self.read_pc.set(read_pc);

        initialize_worker_stream_stage(harness, seek_pc, read_pc, self.name())
    }

    fn prepare_input(&self, qemu: &Qemu, input: &[u8], input_len: GuestReg) -> Result<(), Error> {
        let final_input_len: usize = PEC3_STAGE28_LEN.min(input_len as usize);
        let mut stages = Vec::with_capacity(2);
        stages.push(read_entry_stub_prefix(qemu, PEC3_STAGE40_LEN)?);
        stages.push(input[..final_input_len].to_vec());
        self.stream.set_stages(stages);
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
