use libafl::Error;
use libafl_qemu::{GuestAddr, GuestReg, Qemu, Regs};

use super::{ceva_emu::CevaEmuHarness, ceva_target::CevaTarget};

const DEBUG_INPUT_BYTES_LEN: usize = 32;
const PETITE_POST_READ_OFFSET: GuestAddr = 0x737;
const PETITE_SECOND_STAGE_LEN: usize = 0x2000;

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

#[derive(Default)]
pub struct PetiteA4Target;

impl CevaTarget for PetiteA4Target {
    fn name(&self) -> &'static str {
        "PetiteA4"
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
            "PetiteA4 prepare_input: a4={a4:#x} a5={a5:#x} input_len={} final_input_len={}",
            input.len(),
            final_input_len,
        );
        log::debug!(
            "PetiteA4 prepare_input: input_before_write=[{}] guest_before_write=[{}]",
            format_bytes(&input_buf[..input_buf.len().min(DEBUG_INPUT_BYTES_LEN)]),
            format_bytes(&before_write[..before_write.len().min(DEBUG_INPUT_BYTES_LEN)]),
        );

        qemu.write_mem(a4, input_buf)
            .map_err(|e| Error::unknown(format!("Failed to write petite a4 buffer: {e:?}")))?;

        let mut after_write = vec![0u8; final_input_len];
        let _ = qemu.read_mem(a4, &mut after_write);
        log::debug!(
            "PetiteA4 prepare_input: guest_after_write=[{}]",
            format_bytes(&after_write[..after_write.len().min(DEBUG_INPUT_BYTES_LEN)]),
        );
        Ok(())
    }

    fn reset(&self, harness: &CevaEmuHarness<'_>) -> Result<(), Error> {
        restore_nonvolatile_regs(harness)
    }
}

#[derive(Default)]
pub struct Petite2000Target;

impl CevaTarget for Petite2000Target {
    fn name(&self) -> &'static str {
        "Petite2000"
    }

    fn initialize(
        &mut self,
        harness: &mut CevaEmuHarness<'_>,
        _max_bp_hit_count: Option<u64>,
    ) -> Result<(), Error> {
        let current_pc: GuestAddr = harness
            .qemu()
            .read_reg(Regs::Pc)
            .unwrap()
            .try_into()
            .unwrap();

        let entry_point = harness.entry_point;
        harness.qemu().remove_breakpoint(entry_point);

        let after_second_stage_read = current_pc + PETITE_POST_READ_OFFSET;
        harness.qemu().set_breakpoint(after_second_stage_read);

        log::debug!(
            "Petite2000 init: current_pc={current_pc:#x} setting post-read breakpoint at {after_second_stage_read:#x}"
        );

        unsafe {
            let _ = harness.qemu().run();
        };

        harness.qemu().remove_breakpoint(after_second_stage_read);

        harness.pc = harness
            .qemu()
            .read_reg(Regs::Pc)
            .unwrap()
            .try_into()
            .unwrap();
        harness.stack_ptr = harness
            .qemu()
            .read_reg(Regs::Sp)
            .unwrap()
            .try_into()
            .unwrap();
        harness.rbx = harness
            .qemu()
            .read_reg(Regs::Rbx)
            .unwrap()
            .try_into()
            .unwrap();
        harness.rbp = harness
            .qemu()
            .read_reg(Regs::Rbp)
            .unwrap()
            .try_into()
            .unwrap();
        harness.rdi = harness
            .qemu()
            .read_reg(Regs::Rdi)
            .unwrap()
            .try_into()
            .unwrap();
        harness.rsi = harness
            .qemu()
            .read_reg(Regs::Rsi)
            .unwrap()
            .try_into()
            .unwrap();
        harness.r12 = harness
            .qemu()
            .read_reg(Regs::R12)
            .unwrap()
            .try_into()
            .unwrap();
        harness.r13 = harness
            .qemu()
            .read_reg(Regs::R13)
            .unwrap()
            .try_into()
            .unwrap();
        harness.r14 = harness
            .qemu()
            .read_reg(Regs::R14)
            .unwrap()
            .try_into()
            .unwrap();
        harness.r15 = harness
            .qemu()
            .read_reg(Regs::R15)
            .unwrap()
            .try_into()
            .unwrap();

        log::debug!(
            "Petite2000 init: reached post-read breakpoint at pc={:#x} second_stage_buf={:#x}",
            harness.pc,
            harness.rdi,
        );

        Ok(())
    }

    fn prepare_input(&self, qemu: &Qemu, input: &[u8], input_len: GuestReg) -> Result<(), Error> {
        let second_stage_buf: GuestAddr = qemu.read_reg(Regs::Rdi).unwrap().try_into().unwrap();
        let final_input_len: usize = PETITE_SECOND_STAGE_LEN.min(input_len as usize);
        let input_buf = &input[..final_input_len];

        let mut before_write = vec![0u8; final_input_len];
        let _ = qemu.read_mem(second_stage_buf, &mut before_write);
        log::debug!(
            "Petite2000 prepare_input: second_stage_buf={second_stage_buf:#x} stage_len={:#x} input_len={} final_input_len={}",
            PETITE_SECOND_STAGE_LEN,
            input.len(),
            final_input_len,
        );
        log::debug!(
            "Petite2000 prepare_input: input_before_write=[{}] guest_before_write=[{}]",
            format_bytes(&input_buf[..input_buf.len().min(DEBUG_INPUT_BYTES_LEN)]),
            format_bytes(&before_write[..before_write.len().min(DEBUG_INPUT_BYTES_LEN)]),
        );

        qemu.write_mem(second_stage_buf, input_buf).map_err(|e| {
            Error::unknown(format!("Failed to write petite second-stage buffer: {e:?}"))
        })?;

        let mut after_write = vec![0u8; final_input_len];
        let _ = qemu.read_mem(second_stage_buf, &mut after_write);
        log::debug!(
            "Petite2000 prepare_input: guest_after_write=[{}]",
            format_bytes(&after_write[..after_write.len().min(DEBUG_INPUT_BYTES_LEN)]),
        );
        Ok(())
    }

    fn reset(&self, harness: &CevaEmuHarness<'_>) -> Result<(), Error> {
        restore_nonvolatile_regs(harness)
    }
}
