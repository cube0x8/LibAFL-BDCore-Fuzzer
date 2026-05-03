use libafl::Error;
use libafl_qemu::{GuestAddr, GuestReg, Qemu, Regs};

use super::{ceva_emu::CevaEmuHarness, ceva_target::CevaTarget};

const DEBUG_INPUT_BYTES_LEN: usize = 32;

fn format_bytes(bytes: &[u8]) -> String {
    bytes
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect::<Vec<_>>()
        .join(" ")
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
pub struct BeriaVmTarget;

impl CevaTarget for BeriaVmTarget {
    fn name(&self) -> &'static str {
        "BeriaVMParser"
    }

    fn prepare_input(&self, qemu: &Qemu, input: &[u8], input_len: GuestReg) -> Result<(), Error> {
        let exec_ctx: GuestAddr = qemu.read_reg(Regs::Rcx).unwrap().try_into().unwrap();

        let mut ptr_buf = [0u8; 8];
        let mut len_buf = [0u8; 4];

        qemu.read_mem(exec_ctx + 0x18, &mut ptr_buf).map_err(|e| {
            Error::unknown(format!(
                "Failed to read Beria exec_ctx->work_buf at {:#x}: {e:?}",
                exec_ctx + 0x18
            ))
        })?;
        qemu.read_mem(exec_ctx + 0x20, &mut len_buf).map_err(|e| {
            Error::unknown(format!(
                "Failed to read Beria exec_ctx->work_size at {:#x}: {e:?}",
                exec_ctx + 0x20
            ))
        })?;

        let work_buf: GuestAddr = u64::from_le_bytes(ptr_buf).try_into().unwrap();
        let work_size = u32::from_le_bytes(len_buf) as usize;
        let final_input_len = work_size.min(input_len as usize);
        let input_buf = &input[..final_input_len];

        let mut before_write = vec![0u8; final_input_len];
        let _ = qemu.read_mem(work_buf, &mut before_write);

        log::debug!(
            "BeriaVMParser prepare_input: exec_ctx={exec_ctx:#x} work_buf={work_buf:#x} work_size={work_size:#x} input_len={} final_input_len={}",
            input.len(),
            final_input_len,
        );
        log::debug!(
            "BeriaVMParser prepare_input: input_before_write=[{}] guest_before_write=[{}]",
            format_bytes(&input_buf[..input_buf.len().min(DEBUG_INPUT_BYTES_LEN)]),
            format_bytes(&before_write[..before_write.len().min(DEBUG_INPUT_BYTES_LEN)]),
        );

        qemu.write_mem(work_buf, input_buf).map_err(|e| {
            Error::unknown(format!(
                "Failed to write Beria working buffer at {work_buf:#x}: {e:?}"
            ))
        })?;

        let mut after_write = vec![0u8; final_input_len];
        let _ = qemu.read_mem(work_buf, &mut after_write);
        log::debug!(
            "BeriaVMParser prepare_input: guest_after_write=[{}]",
            format_bytes(&after_write[..after_write.len().min(DEBUG_INPUT_BYTES_LEN)]),
        );

        Ok(())
    }

    fn reset(&self, harness: &CevaEmuHarness<'_>) -> Result<(), Error> {
        restore_nonvolatile_regs(harness)
    }
}
