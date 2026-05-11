use libafl::Error;
use libafl_qemu::{GuestAddr, GuestReg, Qemu, Regs};

use crate::harness::unpackers::health::UnpackerHealth;
use crate::harness::{CevaEmuHarness, CevaTarget};

const SLOT_BUFFER_WRITE: usize = 0;
const SLOT_FULL_WRITE: usize = 1;
const SLOT_TRUNCATED_WRITE: usize = 2;
const SLOT_COMPLETED: usize = 3;
const SLOT_SUCCESS_RET: usize = 4;
const SLOT_NAME_PRESENT: usize = 5;
const SLOT_NAME_ASPACK: usize = 6;
const SLOT_NAME_OTHER: usize = 7;
const SLOT_VERSION_PRESENT: usize = 8;
const SLOT_VERSION_212: usize = 9;
const SLOT_VERSION_10803: usize = 10;
const SLOT_VERSION_10804: usize = 11;
const SLOT_VERSION_OTHER: usize = 12;
const SLOT_PARTIAL_IDENT: usize = 13;
const SLOT_FULL_IDENT: usize = 14;

const ASPACK_HEALTH_SLOTS: &[&str] = &[
    "buffer_write",
    "full_write",
    "truncated_write",
    "completed",
    "success_ret",
    "name_present",
    "name_aspack",
    "name_other",
    "version_present",
    "version_212",
    "version_10803",
    "version_10804",
    "version_other",
    "partial_ident",
    "full_ident",
];

fn read_u64(qemu: &Qemu, addr: GuestAddr) -> Option<u64> {
    let mut buf = [0u8; 8];
    qemu.read_mem(addr, &mut buf).ok()?;
    Some(u64::from_le_bytes(buf))
}

fn read_c_string(qemu: &Qemu, addr: GuestAddr, max_len: usize) -> Option<String> {
    let mut out = Vec::new();
    for idx in 0..max_len {
        let mut byte = [0u8; 1];
        qemu.read_mem(addr + idx as GuestAddr, &mut byte).ok()?;
        if byte[0] == 0 {
            break;
        }
        out.push(byte[0]);
    }
    String::from_utf8(out).ok()
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

        let qemu = harness.qemu();
        let ret: GuestReg = qemu.read_reg(Regs::Rax).unwrap_or(0);
        let success_ret = (ret & 0xff) != 0;
        if success_ret {
            self.health.hit(SLOT_SUCCESS_RET);
        }

        let ctx = harness.rcx;
        let mut saw_name = false;
        let mut saw_aspack_name = false;
        if let Some(name_slot) = read_u64(qemu, ctx + 0x28) {
            if let Some(name_ptr) = read_u64(qemu, name_slot as GuestAddr) {
                if let Some(name) = read_c_string(qemu, name_ptr as GuestAddr, 32) {
                    if !name.is_empty() {
                        saw_name = true;
                        self.health.hit(SLOT_NAME_PRESENT);
                        if name == "ASPack" {
                            saw_aspack_name = true;
                            self.health.hit(SLOT_NAME_ASPACK);
                        } else {
                            self.health.hit(SLOT_NAME_OTHER);
                        }
                    }
                }
            }
        }

        let mut saw_version = false;
        if let Some(version_slot) = read_u64(qemu, ctx + 0x30) {
            if let Some(version_ptr) = read_u64(qemu, version_slot as GuestAddr) {
                if let Some(version) = read_c_string(qemu, version_ptr as GuestAddr, 32) {
                    if !version.is_empty() {
                        saw_version = true;
                        self.health.hit(SLOT_VERSION_PRESENT);
                        match version.as_str() {
                            "2.12" => self.health.hit(SLOT_VERSION_212),
                            "1.08.03" => self.health.hit(SLOT_VERSION_10803),
                            "1.08.04" => self.health.hit(SLOT_VERSION_10804),
                            _ => self.health.hit(SLOT_VERSION_OTHER),
                        }
                    }
                }
            }
        }

        if success_ret && saw_version && !saw_name {
            self.health.hit(SLOT_PARTIAL_IDENT);
        }
        if success_ret && saw_aspack_name && saw_version {
            self.health.hit(SLOT_FULL_IDENT);
        }

        self.health.record_run(execs, harness.health_log_every());
        Ok(())
    }
}
