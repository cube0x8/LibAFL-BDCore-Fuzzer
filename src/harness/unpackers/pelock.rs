use std::cell::Cell;

use libafl::Error;
use libafl_qemu::{GuestAddr, GuestReg, Qemu, Regs};

use crate::harness::unpackers::health::UnpackerHealth;
use crate::harness::unpackers::stream::{MemoryBackedStream, StreamOverlay};
use crate::harness::{CevaEmuHarness, CevaTarget};

const PELOCK_SEEK_THUNK_OFFSET: GuestAddr = 0xd4c0;
const PELOCK_READ_THUNK_OFFSET: GuestAddr = 0xd4d0;
const PELOCK_STAGE0_STREAM_OFFSET: usize = 0x400;
const PELOCK_STREAM_LEN: usize = 0x3a00;
const PELOCK_STAGE_READ_SIZES: [usize; 5] = [0x1400, 0x600, 0xa00, 0x400, 0x1200];

const SLOT_STAGE0_SEEK: usize = 0;
const SLOT_STAGE0_READ: usize = 1;
const SLOT_STAGE1_SEEK: usize = 2;
const SLOT_STAGE1_READ: usize = 3;
const SLOT_STAGE2_SEEK: usize = 4;
const SLOT_STAGE2_READ: usize = 5;
const SLOT_STAGE3_SEEK: usize = 6;
const SLOT_STAGE3_READ: usize = 7;
const SLOT_STAGE4_SEEK: usize = 8;
const SLOT_STAGE4_READ: usize = 9;
const SLOT_STAGE5_ZERO: usize = 10;
const SLOT_COMPLETED: usize = 11;

const PELOCK_HEALTH_SLOTS: &[&str] = &[
    "stage0_seek",
    "stage0_read",
    "stage1_seek",
    "stage1_read",
    "stage2_seek",
    "stage2_read",
    "stage3_seek",
    "stage3_read",
    "stage4_seek",
    "stage4_read",
    "stage5_zero",
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

pub struct PelockTarget {
    seek_pc: Cell<GuestAddr>,
    read_pc: Cell<GuestAddr>,
    read_count: Cell<u32>,
    health: UnpackerHealth,
    stream: MemoryBackedStream,
}

impl Default for PelockTarget {
    fn default() -> Self {
        Self {
            seek_pc: Cell::new(0),
            read_pc: Cell::new(0),
            read_count: Cell::new(0),
            health: UnpackerHealth::new("Pelock", PELOCK_HEALTH_SLOTS),
            stream: MemoryBackedStream::default(),
        }
    }
}

impl PelockTarget {
    const STREAM_LAYOUT: [StreamOverlay; 1] = [StreamOverlay {
        input_offset: 0,
        stream_offset: PELOCK_STAGE0_STREAM_OFFSET,
        max_len: PELOCK_STREAM_LEN,
    }];

    fn seek_slot(read_index: u32) -> Option<usize> {
        match read_index {
            0 => Some(SLOT_STAGE0_SEEK),
            1 => Some(SLOT_STAGE1_SEEK),
            2 => Some(SLOT_STAGE2_SEEK),
            3 => Some(SLOT_STAGE3_SEEK),
            4 => Some(SLOT_STAGE4_SEEK),
            _ => None,
        }
    }

    fn read_slot(read_index: u32) -> Option<usize> {
        match read_index {
            0 => Some(SLOT_STAGE0_READ),
            1 => Some(SLOT_STAGE1_READ),
            2 => Some(SLOT_STAGE2_READ),
            3 => Some(SLOT_STAGE3_READ),
            4 => Some(SLOT_STAGE4_READ),
            _ => None,
        }
    }
}

impl CevaTarget for PelockTarget {
    fn name(&self) -> &'static str {
        "Pelock"
    }

    fn initialize(
        &mut self,
        harness: &mut CevaEmuHarness<'_>,
        _max_bp_hit_count: Option<u64>,
    ) -> Result<(), Error> {
        let seek_pc = harness.entry_point + PELOCK_SEEK_THUNK_OFFSET;
        let read_pc = harness.entry_point + PELOCK_READ_THUNK_OFFSET;

        self.seek_pc.set(seek_pc);
        self.read_pc.set(read_pc);

        harness.qemu().set_breakpoint(seek_pc);
        harness.qemu().set_breakpoint(read_pc);

        log::debug!(
            "Pelock init: worker={:#x} seek_hook={seek_pc:#x} read_hook={read_pc:#x}",
            harness.entry_point,
        );

        Ok(())
    }

    fn prepare_input(&self, _qemu: &Qemu, input: &[u8], input_len: GuestReg) -> Result<(), Error> {
        let final_input_len = PELOCK_STREAM_LEN.min(input_len as usize).min(input.len());
        self.stream
            .rebuild_with_overlays(&input[..final_input_len], &Self::STREAM_LAYOUT);
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
                if let Some(slot) = Self::seek_slot(self.read_count.get()) {
                    self.health.hit(slot);
                }
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

            if harness.health_signals_enabled() {
                if let Some(slot) = Self::read_slot(read_index) {
                    if copied != 0 {
                        self.health.hit(slot);
                    }
                } else if read_index == 5 && requested == 0 && copied == 0 {
                    self.health.hit(SLOT_STAGE5_ZERO);
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
