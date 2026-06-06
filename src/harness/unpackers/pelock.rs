use std::cell::{Cell, RefCell};

use libafl::Error;
use libafl_qemu::{GuestAddr, GuestReg, Qemu, Regs};

use crate::harness::unpackers::health::UnpackerHealth;
use crate::harness::unpackers::stream::{MemoryBackedStream, StreamOverlay};
use crate::harness::{CevaEmuHarness, CevaTarget};

const PELOCK_SEEK_THUNK_OFFSET: GuestAddr = 0xd4c0;
const PELOCK_READ_THUNK_OFFSET: GuestAddr = 0xd4d0;
const PELOCK_07D60_CALLSITE_OFFSET: GuestAddr = 0x520e;
const PELOCK_STAGE0_STREAM_OFFSET: usize = 0x400;
const PELOCK_STREAM_LEN: usize = 0x3a00;
const PELOCK_STUB_PREFIX_LEN: usize = 10;
const PELOCK_07D60_WINDOW_LEN: usize = 0xab;
const PELOCK_STUB_IMM1_OFFSET: GuestAddr = 0x1;
const PELOCK_STUB_IMM2_OFFSET: GuestAddr = 0x6;
const PELOCK_STUB_IMM2_VALUE: u32 = 0x200;

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
    call_07d60_pc: Cell<GuestAddr>,
    read_count: Cell<u32>,
    has_stub_override: Cell<bool>,
    health: UnpackerHealth,
    stream: MemoryBackedStream,
    stub_prefix: RefCell<[u8; PELOCK_STUB_PREFIX_LEN]>,
    window_override: RefCell<[u8; PELOCK_07D60_WINDOW_LEN]>,
    has_window_override: Cell<bool>,
}

impl Default for PelockTarget {
    fn default() -> Self {
        Self {
            seek_pc: Cell::new(0),
            read_pc: Cell::new(0),
            call_07d60_pc: Cell::new(0),
            read_count: Cell::new(0),
            has_stub_override: Cell::new(false),
            health: UnpackerHealth::new("Pelock", PELOCK_HEALTH_SLOTS),
            stream: MemoryBackedStream::default(),
            stub_prefix: RefCell::new([0; PELOCK_STUB_PREFIX_LEN]),
            window_override: RefCell::new([0; PELOCK_07D60_WINDOW_LEN]),
            has_window_override: Cell::new(false),
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
        let call_07d60_pc = harness.entry_point + PELOCK_07D60_CALLSITE_OFFSET;
        let stub_buf: GuestAddr = harness
            .qemu()
            .read_reg(Regs::R9)
            .unwrap()
            .try_into()
            .unwrap();

        self.seek_pc.set(seek_pc);
        self.read_pc.set(read_pc);
        self.call_07d60_pc.set(call_07d60_pc);

        let mut stub_prefix = [0u8; PELOCK_STUB_PREFIX_LEN];
        harness
            .qemu()
            .read_mem(stub_buf, &mut stub_prefix)
            .map_err(|e| Error::unknown(format!("Failed to snapshot Pelock stub prefix: {e:?}")))?;
        *self.stub_prefix.borrow_mut() = stub_prefix;

        harness.qemu().set_breakpoint(seek_pc);
        harness.qemu().set_breakpoint(read_pc);
        harness.qemu().set_breakpoint(call_07d60_pc);

        log::debug!(
            "Pelock init: worker={:#x} seek_hook={seek_pc:#x} read_hook={read_pc:#x}",
            harness.entry_point,
        );

        Ok(())
    }

    fn prepare_input(&self, _qemu: &Qemu, input: &[u8], input_len: GuestReg) -> Result<(), Error> {
        let total_len = (input_len as usize).min(input.len());
        let prefixed_stream_len = PELOCK_STUB_PREFIX_LEN + PELOCK_STREAM_LEN;
        let full_prefixed_len = prefixed_stream_len + PELOCK_07D60_WINDOW_LEN;

        let (stub_prefix, stream_input, window_override) = if total_len >= full_prefixed_len {
            (
                &input[..PELOCK_STUB_PREFIX_LEN],
                &input[PELOCK_STUB_PREFIX_LEN..prefixed_stream_len],
                Some(&input[prefixed_stream_len..full_prefixed_len]),
            )
        } else if total_len > PELOCK_STREAM_LEN {
            let stub_end = PELOCK_STUB_PREFIX_LEN.min(total_len);
            (&input[..stub_end], &input[stub_end..total_len], None)
        } else {
            (&[][..], &input[..total_len], None)
        };

        if !stub_prefix.is_empty() {
            let mut patched_prefix = *self.stub_prefix.borrow();
            let copy_len = patched_prefix.len().min(stub_prefix.len());
            patched_prefix[..copy_len].copy_from_slice(&stub_prefix[..copy_len]);
            *self.stub_prefix.borrow_mut() = patched_prefix;
            self.has_stub_override.set(true);
        } else {
            self.has_stub_override.set(false);
        }

        if let Some(window_override) = window_override {
            let mut patched_window = [0u8; PELOCK_07D60_WINDOW_LEN];
            patched_window.copy_from_slice(window_override);
            *self.window_override.borrow_mut() = patched_window;
            self.has_window_override.set(true);
        } else {
            self.has_window_override.set(false);
        }

        let final_input_len = PELOCK_STREAM_LEN.min(stream_input.len());
        self.stream
            .rebuild_with_overlays(&stream_input[..final_input_len], &Self::STREAM_LAYOUT);
        Ok(())
    }

    fn reset(&self, harness: &CevaEmuHarness<'_>) -> Result<(), Error> {
        restore_nonvolatile_regs(harness)?;
        self.stream.reset();
        let mut patched_prefix = *self.stub_prefix.borrow();
        if !self.has_stub_override.get() {
            let out_va = (harness.r12 as u32).wrapping_add(0x100);
            patched_prefix[PELOCK_STUB_IMM1_OFFSET as usize..PELOCK_STUB_IMM1_OFFSET as usize + 4]
                .copy_from_slice(&out_va.to_le_bytes());
            patched_prefix[PELOCK_STUB_IMM2_OFFSET as usize..PELOCK_STUB_IMM2_OFFSET as usize + 4]
                .copy_from_slice(&PELOCK_STUB_IMM2_VALUE.to_le_bytes());
        }
        harness
            .qemu()
            .write_mem(harness.r9, &patched_prefix)
            .map_err(|e| Error::unknown(format!("Failed to patch Pelock stub prefix: {e:?}")))?;
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

        if pc == self.call_07d60_pc.get() {
            if self.has_window_override.get() {
                let rcx: GuestAddr = qemu.read_reg(Regs::Rcx).unwrap().try_into().unwrap_or(0);
                let rdx: u64 = qemu.read_reg(Regs::Rdx).unwrap_or(0);
                let capture_start = (rdx as u32).saturating_sub(0x10) as GuestAddr;
                let guest_addr = rcx.saturating_add(capture_start);
                let patched_window = *self.window_override.borrow();
                qemu.write_mem(guest_addr, &patched_window).map_err(|e| {
                    Error::unknown(format!(
                        "Failed to patch Pelock 07D60 callsite window at {guest_addr:#x}: {e:?}"
                    ))
                })?;
            }
            return Ok(false);
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
