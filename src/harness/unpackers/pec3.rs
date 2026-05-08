use libafl::Error;
use libafl_qemu::{GuestAddr, GuestReg, Qemu, Regs};

use crate::harness::{CevaEmuHarness, CevaTarget};

const DEBUG_INPUT_BYTES_LEN: usize = 32;
const PEC3_POST_READ40_OFFSET: GuestAddr = 0xBC;
const PEC3_POST_READ28_OFFSET: GuestAddr = 0x1A9;
const PEC3_STAGE40_LEN: usize = 0x40;
const PEC3_STAGE28_LEN: usize = 0x28;
const PEC3_STAGE_STACK_OFFSET: GuestAddr = 0x110;

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

fn prepare_fixed_buffer_input(
    qemu: &Qemu,
    buffer_addr: GuestAddr,
    stage_len: usize,
    target_name: &str,
    input: &[u8],
    input_len: GuestReg,
) -> Result<(), Error> {
    let final_input_len: usize = stage_len.min(input_len as usize);
    let input_buf = &input[..final_input_len];

    let mut before_write = vec![0u8; final_input_len];
    let _ = qemu.read_mem(buffer_addr, &mut before_write);
    log::debug!(
        "{target_name} prepare_input: buf={buffer_addr:#x} stage_len={stage_len:#x} input_len={} final_input_len={}",
        input.len(),
        final_input_len,
    );
    log::debug!(
        "{target_name} prepare_input: input_before_write=[{}] guest_before_write=[{}]",
        format_bytes(&input_buf[..input_buf.len().min(DEBUG_INPUT_BYTES_LEN)]),
        format_bytes(&before_write[..before_write.len().min(DEBUG_INPUT_BYTES_LEN)]),
    );

    qemu.write_mem(buffer_addr, input_buf)
        .map_err(|e| Error::unknown(format!("Failed to write {target_name} buffer: {e:?}")))?;

    let mut after_write = vec![0u8; final_input_len];
    let _ = qemu.read_mem(buffer_addr, &mut after_write);
    log::debug!(
        "{target_name} prepare_input: guest_after_write=[{}]",
        format_bytes(&after_write[..after_write.len().min(DEBUG_INPUT_BYTES_LEN)]),
    );
    Ok(())
}

fn initialize_post_read_stage(
    harness: &mut CevaEmuHarness<'_>,
    post_read_offset: GuestAddr,
    target_name: &str,
) -> Result<(), Error> {
    let current_pc: GuestAddr = harness
        .qemu()
        .read_reg(Regs::Pc)
        .unwrap()
        .try_into()
        .unwrap();

    let entry_point = harness.entry_point;
    harness.qemu().remove_breakpoint(entry_point);

    let post_read_pc = current_pc + post_read_offset;
    harness.qemu().set_breakpoint(post_read_pc);

    log::debug!(
        "{target_name} init: current_pc={current_pc:#x} setting post-read breakpoint at {post_read_pc:#x}"
    );

    unsafe {
        let _ = harness.qemu().run();
    };

    harness.qemu().remove_breakpoint(post_read_pc);

    let final_pc: GuestAddr = harness
        .qemu()
        .read_reg(Regs::Pc)
        .unwrap()
        .try_into()
        .unwrap();
    let rbp: GuestAddr = harness
        .qemu()
        .read_reg(Regs::Rbp)
        .unwrap()
        .try_into()
        .unwrap();
    let stage_buf = rbp + PEC3_STAGE_STACK_OFFSET;
    log::debug!(
        "{target_name} init: reached post-read breakpoint at pc={final_pc:#x} rbp={rbp:#x} stage_buf={stage_buf:#x}"
    );

    Ok(())
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
pub struct Pec3Read40Target;

impl CevaTarget for Pec3Read40Target {
    fn name(&self) -> &'static str {
        "Pec3Read40"
    }

    fn initialize(
        &mut self,
        harness: &mut CevaEmuHarness<'_>,
        _max_bp_hit_count: Option<u64>,
    ) -> Result<(), Error> {
        initialize_post_read_stage(harness, PEC3_POST_READ40_OFFSET, self.name())
    }

    fn prepare_input(&self, qemu: &Qemu, input: &[u8], input_len: GuestReg) -> Result<(), Error> {
        let rbp: GuestAddr = qemu.read_reg(Regs::Rbp).unwrap().try_into().unwrap();
        let stage_buf = rbp + PEC3_STAGE_STACK_OFFSET;
        prepare_fixed_buffer_input(
            qemu,
            stage_buf,
            PEC3_STAGE40_LEN,
            self.name(),
            input,
            input_len,
        )
    }

    fn reset(&self, harness: &CevaEmuHarness<'_>) -> Result<(), Error> {
        restore_nonvolatile_regs(harness)
    }
}

#[derive(Default)]
pub struct Pec3Read28Target;

impl CevaTarget for Pec3Read28Target {
    fn name(&self) -> &'static str {
        "Pec3Read28"
    }

    fn initialize(
        &mut self,
        harness: &mut CevaEmuHarness<'_>,
        _max_bp_hit_count: Option<u64>,
    ) -> Result<(), Error> {
        initialize_post_read_stage(harness, PEC3_POST_READ28_OFFSET, self.name())
    }

    fn prepare_input(&self, qemu: &Qemu, input: &[u8], input_len: GuestReg) -> Result<(), Error> {
        let rbp: GuestAddr = qemu.read_reg(Regs::Rbp).unwrap().try_into().unwrap();
        let stage_buf = rbp + PEC3_STAGE_STACK_OFFSET;
        prepare_fixed_buffer_input(
            qemu,
            stage_buf,
            PEC3_STAGE28_LEN,
            self.name(),
            input,
            input_len,
        )
    }

    fn reset(&self, harness: &CevaEmuHarness<'_>) -> Result<(), Error> {
        restore_nonvolatile_regs(harness)
    }
}
