use std::{
    cell::{Cell, RefCell},
    env, fs,
};

use libafl::Error;
use libafl_qemu::{ArchExtras, GuestAddr, GuestReg, Qemu, Regs};

use crate::harness::unpackers::health::UnpackerHealth;
use crate::harness::unpackers::stream::{MemoryBackedStream, StreamOverlay};
use crate::harness::unpackers::upack_progress::{
    record_read_window, seed_bootstrap_windows, UPACK_ENTRY_STUB_LEN, UPACK_MAX_STREAM_LEN,
    UPACK_MODULE_WORKER_OFF,
};
use crate::harness::{CevaEmuHarness, CevaTarget};

const UPACK_SEEK_THUNK_DELTA_FROM_WORKER: GuestAddr = 0x1610 - 0x840;
const UPACK_READ_THUNK_DELTA_FROM_WORKER: GuestAddr = 0x1630 - 0x840;

const SLOT_SEEK0: usize = 0;
const SLOT_SEEK1: usize = 1;
const SLOT_SEEK2: usize = 2;
const SLOT_SEEK3: usize = 3;
const SLOT_READ0: usize = 4;
const SLOT_READ1: usize = 5;
const SLOT_READ2: usize = 6;
const SLOT_READ3: usize = 7;
const SLOT_READ_EQUAL: usize = 8;
const SLOT_READ_SHORT: usize = 9;
const SLOT_READ_ZERO: usize = 10;
const SLOT_COMPLETED: usize = 11;

const UPACK_HEALTH_SLOTS: &[&str] = &[
    "seek0",
    "seek1",
    "seek2",
    "seek3",
    "read0",
    "read1",
    "read2",
    "read3",
    "read_equal",
    "read_short",
    "read_zero",
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

pub struct UpackTarget {
    seek_pc: Cell<GuestAddr>,
    read_pc: Cell<GuestAddr>,
    read_count: Cell<u32>,
    seek_count: Cell<u32>,
    entry_stub_addr: Cell<GuestAddr>,
    baseline_entry_stub: RefCell<[u8; UPACK_ENTRY_STUB_LEN]>,
    health: UnpackerHealth,
    stream: MemoryBackedStream,
}

impl Default for UpackTarget {
    fn default() -> Self {
        Self {
            seek_pc: Cell::new(0),
            read_pc: Cell::new(0),
            read_count: Cell::new(0),
            seek_count: Cell::new(0),
            entry_stub_addr: Cell::new(0),
            baseline_entry_stub: RefCell::new([0; UPACK_ENTRY_STUB_LEN]),
            health: UnpackerHealth::new("Upack", UPACK_HEALTH_SLOTS),
            stream: MemoryBackedStream::default(),
        }
    }
}

impl UpackTarget {
    const FULL_FILE_STREAM_LAYOUT: [StreamOverlay; 1] = [StreamOverlay {
        input_offset: 0,
        stream_offset: 0,
        max_len: UPACK_MAX_STREAM_LEN,
    }];

    const PREFIXED_STREAM_LAYOUT: [StreamOverlay; 1] = [StreamOverlay {
        input_offset: UPACK_ENTRY_STUB_LEN,
        stream_offset: 0,
        max_len: UPACK_MAX_STREAM_LEN,
    }];

    fn looks_like_pe_file(input: &[u8]) -> bool {
        input.starts_with(b"MZ")
    }

    fn seek_slot(seek_index: u32) -> Option<usize> {
        match seek_index {
            0 => Some(SLOT_SEEK0),
            1 => Some(SLOT_SEEK1),
            2 => Some(SLOT_SEEK2),
            3 => Some(SLOT_SEEK3),
            _ => None,
        }
    }

    fn read_slot(read_index: u32) -> Option<usize> {
        match read_index {
            0 => Some(SLOT_READ0),
            1 => Some(SLOT_READ1),
            2 => Some(SLOT_READ2),
            3 => Some(SLOT_READ3),
            _ => None,
        }
    }
}

impl CevaTarget for UpackTarget {
    fn name(&self) -> &'static str {
        "Upack"
    }

    fn initialize(
        &mut self,
        harness: &mut CevaEmuHarness<'_>,
        _max_bp_hit_count: Option<u64>,
    ) -> Result<(), Error> {
        let seek_pc = harness.entry_point + UPACK_SEEK_THUNK_DELTA_FROM_WORKER;
        let read_pc = harness.entry_point + UPACK_READ_THUNK_DELTA_FROM_WORKER;
        let entry_stub_addr: GuestAddr = harness
            .qemu()
            .read_reg(Regs::R9)
            .unwrap()
            .try_into()
            .unwrap();

        self.seek_pc.set(seek_pc);
        self.read_pc.set(read_pc);
        self.entry_stub_addr.set(entry_stub_addr);
        seed_bootstrap_windows();

        let mut entry_stub = [0u8; UPACK_ENTRY_STUB_LEN];
        harness
            .qemu()
            .read_mem(entry_stub_addr, &mut entry_stub)
            .map_err(|e| {
                Error::unknown(format!("Failed to snapshot UPack entry stub buffer: {e:?}"))
            })?;
        *self.baseline_entry_stub.borrow_mut() = entry_stub;
        if let Ok(path) = env::var("UPACK_DUMP_R9_STUB") {
            fs::write(&path, entry_stub)
                .map_err(|e| Error::unknown(format!("Failed to dump UPack R9 stub: {e:?}")))?;
            log::info!("Dumped UPack runtime R9 stub to {path}");
        }

        harness.qemu().set_breakpoint(seek_pc);
        harness.qemu().set_breakpoint(read_pc);

        log::debug!(
            "Upack init: worker={:#x} entry_stub={entry_stub_addr:#x} seek_hook={seek_pc:#x} read_hook={read_pc:#x}",
            harness.entry_point,
        );

        Ok(())
    }

    fn prepare_input(&self, qemu: &Qemu, input: &[u8], input_len: GuestReg) -> Result<(), Error> {
        let final_input_len = (input_len as usize).min(input.len());
        let input = &input[..final_input_len];

        if input.len() > UPACK_ENTRY_STUB_LEN && !Self::looks_like_pe_file(input) {
            qemu.write_mem(self.entry_stub_addr.get(), &input[..UPACK_ENTRY_STUB_LEN])
                .map_err(|e| {
                    Error::unknown(format!("Failed to patch UPack entry stub buffer: {e:?}"))
                })?;
            self.stream
                .rebuild_with_overlays(input, &Self::PREFIXED_STREAM_LAYOUT);
        } else {
            self.stream
                .rebuild_with_overlays(input, &Self::FULL_FILE_STREAM_LAYOUT);
        }

        Ok(())
    }

    fn reset(&self, harness: &CevaEmuHarness<'_>) -> Result<(), Error> {
        restore_nonvolatile_regs(harness)?;
        self.stream.reset();
        self.seek_count.set(0);
        self.read_count.set(0);
        self.health.reset_run();

        let baseline_entry_stub = *self.baseline_entry_stub.borrow();
        harness
            .qemu()
            .write_mem(self.entry_stub_addr.get(), &baseline_entry_stub)
            .map_err(|e| Error::unknown(format!("Failed to restore UPack entry stub: {e:?}")))?;

        Ok(())
    }

    fn handle_breakpoint(&self, harness: &CevaEmuHarness<'_>) -> Result<bool, Error> {
        let qemu = harness.qemu();
        let pc: GuestAddr = qemu.read_reg(Regs::Pc).unwrap().try_into().unwrap();

        if pc == self.seek_pc.get() {
            let seek_index = self.seek_count.get();
            self.seek_count.set(seek_index.saturating_add(1));
            let requested_off: i64 = qemu.read_reg(Regs::Rdx).unwrap().try_into().unwrap();
            let requested_whence: u64 = qemu.read_reg(Regs::R8).unwrap().try_into().unwrap();

            if harness.health_signals_enabled() {
                if let Some(slot) = Self::seek_slot(seek_index) {
                    self.health.hit(slot);
                }
            }

            let new_pos = self.stream.emulate_seek(qemu)?;
            log::debug!(
                "Upack seek idx={seek_index} off={requested_off:#x} whence={requested_whence} -> pos={new_pos:#x}"
            );
            return Ok(true);
        }

        if pc == self.read_pc.get() {
            let stream_offset = self.stream.position();
            let read_callsite = qemu
                .read_return_address()
                .ok()
                .and_then(|ret| GuestAddr::try_from(ret).ok())
                .map(|ret| ret.saturating_sub(5))
                .map(|callsite| {
                    callsite.saturating_sub(harness.entry_point - UPACK_MODULE_WORKER_OFF)
                });
            let requested: usize = qemu
                .read_reg(Regs::R8)
                .unwrap()
                .try_into()
                .unwrap_or(usize::MAX);
            let copied = self.stream.emulate_read(qemu)?;
            log::debug!(
                "Upack read idx={} callsite={} stream_off={stream_offset:#x} requested={requested:#x} copied={copied:#x}",
                self.read_count.get(),
                read_callsite
                    .map(|addr| format!("{addr:#x}"))
                    .unwrap_or_else(|| "unknown".to_string()),
            );
            if let Some(read_callsite) = read_callsite {
                record_read_window(read_callsite, stream_offset, copied.min(requested));
            }
            let read_index = self.read_count.get();
            self.read_count.set(read_index.saturating_add(1));

            if harness.health_signals_enabled() {
                if let Some(slot) = Self::read_slot(read_index) {
                    if copied != 0 {
                        self.health.hit(slot);
                    }
                }

                if copied == 0 {
                    self.health.hit(SLOT_READ_ZERO);
                } else if copied == requested {
                    self.health.hit(SLOT_READ_EQUAL);
                } else {
                    self.health.hit(SLOT_READ_SHORT);
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
