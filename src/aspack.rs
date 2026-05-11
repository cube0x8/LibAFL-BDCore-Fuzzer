use libafl::Error;
use libafl_qemu::{GuestAddr, GuestReg, Qemu, Regs};

use crate::harness::unpackers::health::UnpackerHealth;
use crate::harness::{CevaEmuHarness, CevaTarget};

const SLOT_BUFFER_WRITE: usize = 0;
const SLOT_FULL_WRITE: usize = 1;
const SLOT_TRUNCATED_WRITE: usize = 2;
const SLOT_COMPLETED: usize = 3;

const ASPACK_HEALTH_SLOTS: &[&str] = &[
    "buffer_write",
    "full_write",
    "truncated_write",
    "completed",
];

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

pub struct AspackWorkerTarget {
    health: UnpackerHealth,
}

impl Default for AspackWorkerTarget {
    fn default() -> Self {
        Self {
            health: UnpackerHealth::new("AspackWorker", ASPACK_HEALTH_SLOTS),
        }
    }
}

impl CevaTarget for AspackWorkerTarget {
    fn name(&self) -> &'static str {
        "AspackWorker"
    }

    fn prepare_input(&self, qemu: &Qemu, input: &[u8], input_len: GuestReg) -> Result<(), Error> {
        let ctx: GuestAddr = qemu.read_reg(Regs::Rcx).unwrap().try_into().unwrap();

        let mut ptr_buf = [0u8; 8];
        qemu.read_mem(ctx + 0x18, &mut ptr_buf)
            .map_err(|e| Error::unknown(format!("Failed to read aspack buffer pointer: {e:?}")))?;
        let buf: GuestAddr = u64::from_le_bytes(ptr_buf)
            .try_into()
            .map_err(|_| Error::unknown("Failed to convert aspack buffer pointer".to_string()))?;

        let mut len_buf = [0u8; 4];
        qemu.read_mem(ctx + 0x20, &mut len_buf)
            .map_err(|e| Error::unknown(format!("Failed to read aspack buffer length: {e:?}")))?;
        let buf_len = u32::from_le_bytes(len_buf) as usize;

        let final_input_len = buf_len.min(input_len as usize);
        qemu.write_mem(buf, &input[..final_input_len])
            .map_err(|e| Error::unknown(format!("Failed to write aspack worker buffer: {e:?}")))?;

        self.health.hit(SLOT_BUFFER_WRITE);
        if final_input_len == buf_len {
            self.health.hit(SLOT_FULL_WRITE);
        } else {
            self.health.hit(SLOT_TRUNCATED_WRITE);
        }

        Ok(())
    }

    fn reset(&self, harness: &CevaEmuHarness<'_>) -> Result<(), Error> {
        restore_nonvolatile_regs(harness)?;
        self.health.reset_run();
        Ok(())
    }

    fn after_run(&self, harness: &CevaEmuHarness<'_>, execs: u64) -> Result<(), Error> {
        if !harness.health_signals_enabled() {
            return Ok(());
        }

        self.health.hit(SLOT_COMPLETED);
        self.health.record_run(execs, harness.health_log_every());
        Ok(())
    }
}
