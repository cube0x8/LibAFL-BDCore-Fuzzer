use std::cell::Cell;

use libafl::Error;
use libafl_qemu::{GuestAddr, GuestReg, Qemu, Regs};

use crate::harness::unpackers::health::UnpackerHealth;
use crate::harness::unpackers::stream::StagedReadStream;
use crate::harness::{CevaEmuHarness, CevaTarget};

const DEBUG_INPUT_BYTES_LEN: usize = 32;
const PETITE_STAGE2_LEN: usize = 0x2000;
const PETITE_SEEK_THUNK_OFFSET: GuestAddr = 0xDF8;
const PETITE_READ_THUNK_OFFSET: GuestAddr = 0xE08;

const SLOT_STAGE0_SEEK: usize = 0;
const SLOT_STAGE0_READ: usize = 1;
const SLOT_STAGE0_EQUAL: usize = 2;
const SLOT_STAGE0_SHORT: usize = 3;
const SLOT_STAGE0_ZERO: usize = 4;
const SLOT_COMPLETED: usize = 5;
const PETITE_HEALTH_SLOTS: &[&str] = &[
    "stage0_seek",
    "stage0_read",
    "stage0_equal",
    "stage0_short",
    "stage0_zero",
    "completed",
];

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

pub struct Petite2000Target {
    seek_pc: Cell<GuestAddr>,
    read_pc: Cell<GuestAddr>,
    read_count: Cell<u32>,
    health: UnpackerHealth,
    stream: StagedReadStream,
}

impl Default for Petite2000Target {
    fn default() -> Self {
        Self {
            seek_pc: Cell::new(0),
            read_pc: Cell::new(0),
            read_count: Cell::new(0),
            health: UnpackerHealth::new("Petite2000", PETITE_HEALTH_SLOTS),
            stream: StagedReadStream::default(),
        }
    }
}

impl CevaTarget for Petite2000Target {
    fn name(&self) -> &'static str {
        "Petite2000"
    }

    fn initialize(
        &mut self,
        harness: &mut CevaEmuHarness<'_>,
        _max_bp_hit_count: Option<u64>,
    ) -> Result<(), Error> {
        let seek_pc = harness.entry_point + PETITE_SEEK_THUNK_OFFSET;
        let read_pc = harness.entry_point + PETITE_READ_THUNK_OFFSET;

        self.seek_pc.set(seek_pc);
        self.read_pc.set(read_pc);

        initialize_worker_stream_stage(harness, seek_pc, read_pc, self.name())
    }

    fn prepare_input(&self, _qemu: &Qemu, input: &[u8], input_len: GuestReg) -> Result<(), Error> {
        let final_input_len: usize = PETITE_STAGE2_LEN.min(input_len as usize);
        self.stream
            .set_stages(vec![input[..final_input_len].to_vec()]);
        Ok(())
    }

    fn reset(&self, harness: &CevaEmuHarness<'_>) -> Result<(), Error> {
        restore_nonvolatile_regs(harness)?;
        self.stream.reset();
        self.read_count.set(0);
        self.health.reset_run();
        Ok(())
    }

    fn handle_breakpoint(&self, harness: &CevaEmuHarness<'_>) -> Result<bool, Error> {
        let qemu = harness.qemu();
        let pc: GuestAddr = qemu.read_reg(Regs::Pc).unwrap().try_into().unwrap();

        if pc == self.seek_pc.get() {
            if harness.health_signals_enabled() {
                self.health.hit(SLOT_STAGE0_SEEK);
            }
            let _ = self.stream.emulate_seek(qemu)?;
            return Ok(true);
        }

        if pc == self.read_pc.get() {
            let requested: usize = qemu
                .read_reg(Regs::R8)
                .unwrap()
                .try_into()
                .unwrap_or(usize::MAX);
            let copied = self.stream.emulate_read(qemu)?;
            let read_index = self.read_count.get();
            self.read_count.set(read_index.saturating_add(1));

            if harness.health_signals_enabled() && read_index == 0 {
                if copied != 0 {
                    self.health.hit(SLOT_STAGE0_READ);
                }
                if copied == 0 {
                    self.health.hit(SLOT_STAGE0_ZERO);
                } else if copied == requested {
                    self.health.hit(SLOT_STAGE0_EQUAL);
                } else {
                    self.health.hit(SLOT_STAGE0_SHORT);
                }
            }
            return Ok(true);
        }

        Ok(false)
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
