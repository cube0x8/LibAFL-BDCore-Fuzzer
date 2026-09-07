use std::cell::{Cell, RefCell};

use libafl::Error;
use libafl_qemu::{ArchExtras, GuestAddr, GuestReg, Qemu, Regs};

use crate::harness::unpackers::health::UnpackerHealth;
use crate::harness::unpackers::stream::{MemoryBackedStream, StreamOverlay};
use crate::harness::{CevaEmuHarness, CevaTarget};
use crate::inputs::pec3_operation11::{
    build_pec3_operation11_input, build_pec3_operation11_mode2_input, parse_pec3_operation11_input,
    parse_pec3_operation11_mode2_input, Pec3Operation11Mode2Entry,
};
use crate::utils::{
    read_guest_u16_opt as read_guest_u16, read_guest_u32_opt as read_guest_u32,
    read_guest_u64_opt as read_guest_u64,
};

const DEBUG_INPUT_BYTES_LEN: usize = 32;
const PEC3_SEEK_THUNK_OFFSET: GuestAddr = 0x2C00;
const PEC3_READ_THUNK_OFFSET: GuestAddr = 0x2C10;
const PEC3_MAX_STREAM_LEN: usize = 0x1_00000;
const PEC3_POSTDECODE_MAGIC: &[u8; 4] = b"P3PD";
const PEC3_POSTDECODE_HEADER_SIZE: usize = 12;
const PEC3_POSTDECODE_EXIT: &str = "pec3.xmd:+0x1e99";
const PEC3_OPERATION11_FROM_POSTDECODE: GuestAddr = 0x1353;
const PEC3_OPERATION11_MODE2_FROM_POSTDECODE: GuestAddr = 0x1173;
const PEC3_OPERATION4_FROM_WORKER: GuestAddr = 0x460;
const PEC3_PEVIEWER_FILE_SIZE: usize = 0x6E400;
const PEC3_SECTION_RECORD_SIZE: GuestAddr = 0x1C;
const PEC3_MAX_SECTION_RECORDS: u32 = 0x100;
const PEC3_POISON_CHUNK_SIZE: usize = 0x1000;
const PEC3_CALLBACK_IMAGE_PTR_OFFSET: GuestAddr = 0x18;
const PEC3_CALLBACK_IMAGE_SIZE_OFFSET: GuestAddr = 0x20;
const PEC3_OPERATION11_MAX_SEED_PAYLOAD: usize = 0x10_0000;

const SLOT_STAGE0_SEEK: usize = 0;
const SLOT_STAGE1_SEEK: usize = 1;
const SLOT_STAGE0_READ: usize = 2;
const SLOT_STAGE1_READ: usize = 3;
const SLOT_STAGE0_EQUAL: usize = 4;
const SLOT_STAGE0_SHORT: usize = 5;
const SLOT_STAGE0_ZERO: usize = 6;
const SLOT_STAGE1_EQUAL: usize = 7;
const SLOT_STAGE1_SHORT: usize = 8;
const SLOT_STAGE1_ZERO: usize = 9;
const SLOT_COMPLETED: usize = 10;

const PEC3_HEALTH_SLOTS: &[&str] = &[
    "stage0_seek",
    "stage1_seek",
    "stage0_read",
    "stage1_read",
    "stage0_equal",
    "stage0_short",
    "stage0_zero",
    "stage1_equal",
    "stage1_short",
    "stage1_zero",
    "completed",
];

const PEC3_FAMILY_HEALTH_SLOTS: &[&str] = &[
    "stage0_seek",
    "stage1_seek",
    "stage2_seek",
    "stage3_seek",
    "stage0_read",
    "stage1_read",
    "stage2_read",
    "stage3_read",
    "stage0_equal",
    "stage1_equal",
    "stage2_equal",
    "stage3_equal",
    "stage0_short",
    "stage1_short",
    "stage2_short",
    "stage3_short",
    "stage0_zero",
    "stage1_zero",
    "stage2_zero",
    "stage3_zero",
    "completed",
];

const FAMILY_SLOT_STAGE0_SEEK: usize = 0;
const FAMILY_SLOT_STAGE1_SEEK: usize = 1;
const FAMILY_SLOT_STAGE2_SEEK: usize = 2;
const FAMILY_SLOT_STAGE3_SEEK: usize = 3;
const FAMILY_SLOT_STAGE0_READ: usize = 4;
const FAMILY_SLOT_STAGE1_READ: usize = 5;
const FAMILY_SLOT_STAGE2_READ: usize = 6;
const FAMILY_SLOT_STAGE3_READ: usize = 7;
const FAMILY_SLOT_STAGE0_EQUAL: usize = 8;
const FAMILY_SLOT_STAGE1_EQUAL: usize = 9;
const FAMILY_SLOT_STAGE2_EQUAL: usize = 10;
const FAMILY_SLOT_STAGE3_EQUAL: usize = 11;
const FAMILY_SLOT_STAGE0_SHORT: usize = 12;
const FAMILY_SLOT_STAGE1_SHORT: usize = 13;
const FAMILY_SLOT_STAGE2_SHORT: usize = 14;
const FAMILY_SLOT_STAGE3_SHORT: usize = 15;
const FAMILY_SLOT_STAGE0_ZERO: usize = 16;
const FAMILY_SLOT_STAGE1_ZERO: usize = 17;
const FAMILY_SLOT_STAGE2_ZERO: usize = 18;
const FAMILY_SLOT_STAGE3_ZERO: usize = 19;
const FAMILY_SLOT_COMPLETED: usize = 20;

#[derive(Clone, Copy)]
struct Pec3FamilySpec {
    target_name: &'static str,
}

const PEC3_PEVIEWER_SPEC: Pec3FamilySpec = Pec3FamilySpec {
    target_name: "Pec3Peviewer",
};

const PEC3_HASH_SPEC: Pec3FamilySpec = Pec3FamilySpec {
    target_name: "Pec3Hash",
};

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

fn hit_family_seek(health: &UnpackerHealth, stage: u32) {
    match stage {
        0 => health.hit(FAMILY_SLOT_STAGE0_SEEK),
        1 => health.hit(FAMILY_SLOT_STAGE1_SEEK),
        2 => health.hit(FAMILY_SLOT_STAGE2_SEEK),
        3 => health.hit(FAMILY_SLOT_STAGE3_SEEK),
        _ => {}
    }
}

fn hit_family_read(health: &UnpackerHealth, stage: u32, requested: usize, copied: usize) {
    match stage {
        0 => {
            if copied != 0 {
                health.hit(FAMILY_SLOT_STAGE0_READ);
            }
            if copied == 0 {
                health.hit(FAMILY_SLOT_STAGE0_ZERO);
            } else if copied == requested {
                health.hit(FAMILY_SLOT_STAGE0_EQUAL);
            } else {
                health.hit(FAMILY_SLOT_STAGE0_SHORT);
            }
        }
        1 => {
            if copied != 0 {
                health.hit(FAMILY_SLOT_STAGE1_READ);
            }
            if copied == 0 {
                health.hit(FAMILY_SLOT_STAGE1_ZERO);
            } else if copied == requested {
                health.hit(FAMILY_SLOT_STAGE1_EQUAL);
            } else {
                health.hit(FAMILY_SLOT_STAGE1_SHORT);
            }
        }
        2 => {
            if copied != 0 {
                health.hit(FAMILY_SLOT_STAGE2_READ);
            }
            if copied == 0 {
                health.hit(FAMILY_SLOT_STAGE2_ZERO);
            } else if copied == requested {
                health.hit(FAMILY_SLOT_STAGE2_EQUAL);
            } else {
                health.hit(FAMILY_SLOT_STAGE2_SHORT);
            }
        }
        3 => {
            if copied != 0 {
                health.hit(FAMILY_SLOT_STAGE3_READ);
            }
            if copied == 0 {
                health.hit(FAMILY_SLOT_STAGE3_ZERO);
            } else if copied == requested {
                health.hit(FAMILY_SLOT_STAGE3_EQUAL);
            } else {
                health.hit(FAMILY_SLOT_STAGE3_SHORT);
            }
        }
        _ => {}
    }
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

pub struct Pec3Read40Target {
    seek_pc: Cell<GuestAddr>,
    read_pc: Cell<GuestAddr>,
    read_count: Cell<u32>,
    health: UnpackerHealth,
    stream: MemoryBackedStream,
}

impl Default for Pec3Read40Target {
    fn default() -> Self {
        Self {
            seek_pc: Cell::new(0),
            read_pc: Cell::new(0),
            read_count: Cell::new(0),
            health: UnpackerHealth::new("Pec3Read40", PEC3_HEALTH_SLOTS),
            stream: MemoryBackedStream::default(),
        }
    }
}

impl Pec3Read40Target {
    const STREAM_LAYOUT: [StreamOverlay; 1] = [StreamOverlay {
        input_offset: 0,
        stream_offset: 0,
        max_len: PEC3_MAX_STREAM_LEN,
    }];
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

    fn prepare_input(&self, _qemu: &Qemu, input: &[u8], input_len: GuestReg) -> Result<(), Error> {
        let final_input_len: usize = PEC3_MAX_STREAM_LEN.min(input_len as usize).min(input.len());
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
                match self.read_count.get() {
                    0 => self.health.hit(SLOT_STAGE0_SEEK),
                    1 => self.health.hit(SLOT_STAGE1_SEEK),
                    _ => {}
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
                match read_index {
                    0 => {
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
                    1 => {
                        if copied != 0 {
                            self.health.hit(SLOT_STAGE1_READ);
                        }
                        if copied == 0 {
                            self.health.hit(SLOT_STAGE1_ZERO);
                        } else if copied == requested {
                            self.health.hit(SLOT_STAGE1_EQUAL);
                        } else {
                            self.health.hit(SLOT_STAGE1_SHORT);
                        }
                    }
                    _ => {}
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

pub struct Pec3Read28Target {
    seek_pc: Cell<GuestAddr>,
    read_pc: Cell<GuestAddr>,
    read_count: Cell<u32>,
    health: UnpackerHealth,
    stream: MemoryBackedStream,
}

impl Default for Pec3Read28Target {
    fn default() -> Self {
        Self {
            seek_pc: Cell::new(0),
            read_pc: Cell::new(0),
            read_count: Cell::new(0),
            health: UnpackerHealth::new("Pec3Read28", PEC3_HEALTH_SLOTS),
            stream: MemoryBackedStream::default(),
        }
    }
}

impl Pec3Read28Target {
    const STREAM_LAYOUT: [StreamOverlay; 1] = [StreamOverlay {
        input_offset: 0,
        stream_offset: 0,
        max_len: PEC3_MAX_STREAM_LEN,
    }];
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

    fn prepare_input(&self, _qemu: &Qemu, input: &[u8], input_len: GuestReg) -> Result<(), Error> {
        let final_input_len: usize = PEC3_MAX_STREAM_LEN.min(input_len as usize).min(input.len());
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
                match self.read_count.get() {
                    0 => self.health.hit(SLOT_STAGE0_SEEK),
                    1 => self.health.hit(SLOT_STAGE1_SEEK),
                    _ => {}
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
                match read_index {
                    0 => {
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
                    1 => {
                        if copied != 0 {
                            self.health.hit(SLOT_STAGE1_READ);
                        }
                        if copied == 0 {
                            self.health.hit(SLOT_STAGE1_ZERO);
                        } else if copied == requested {
                            self.health.hit(SLOT_STAGE1_EQUAL);
                        } else {
                            self.health.hit(SLOT_STAGE1_SHORT);
                        }
                    }
                    _ => {}
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

struct Pec3FamilyTarget {
    spec: Pec3FamilySpec,
    seek_pc: Cell<GuestAddr>,
    read_pc: Cell<GuestAddr>,
    read_count: Cell<u32>,
    health: UnpackerHealth,
    stream: MemoryBackedStream,
}

impl Pec3FamilyTarget {
    fn new(spec: Pec3FamilySpec) -> Self {
        Self {
            spec,
            seek_pc: Cell::new(0),
            read_pc: Cell::new(0),
            read_count: Cell::new(0),
            health: UnpackerHealth::new(spec.target_name, PEC3_FAMILY_HEALTH_SLOTS),
            stream: MemoryBackedStream::default(),
        }
    }
}

impl Pec3FamilyTarget {
    const STREAM_LAYOUT: [StreamOverlay; 1] = [StreamOverlay {
        input_offset: 0,
        stream_offset: 0,
        max_len: PEC3_MAX_STREAM_LEN,
    }];
}

impl CevaTarget for Pec3FamilyTarget {
    fn name(&self) -> &'static str {
        self.spec.target_name
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

    fn prepare_input(&self, _qemu: &Qemu, input: &[u8], input_len: GuestReg) -> Result<(), Error> {
        let final_input_len: usize = PEC3_MAX_STREAM_LEN.min(input_len as usize).min(input.len());
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
                hit_family_seek(&self.health, self.read_count.get());
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
                hit_family_read(&self.health, read_index, requested, copied);
            }
            return Ok(true);
        }

        Ok(false)
    }

    fn after_run(&self, harness: &CevaEmuHarness<'_>, execs: u64) -> Result<(), Error> {
        if !harness.health_signals_enabled() {
            return Ok(());
        }

        self.health.hit(FAMILY_SLOT_COMPLETED);
        self.health.record_run(execs, harness.health_log_every());
        Ok(())
    }
}

pub struct Pec3PeviewerTarget(Pec3FamilyTarget);

impl Default for Pec3PeviewerTarget {
    fn default() -> Self {
        Self(Pec3FamilyTarget::new(PEC3_PEVIEWER_SPEC))
    }
}

pub struct Pec3PeviewerHeapPoisonTarget {
    family: Pec3FamilyTarget,
    operation4_pc: Cell<GuestAddr>,
    poison_pattern: RefCell<Vec<u8>>,
}

impl Default for Pec3PeviewerHeapPoisonTarget {
    fn default() -> Self {
        Self {
            family: Pec3FamilyTarget::new(PEC3_PEVIEWER_SPEC),
            operation4_pc: Cell::new(0),
            poison_pattern: RefCell::new(Vec::new()),
        }
    }
}

impl Pec3PeviewerHeapPoisonTarget {
    fn poison_uninitialized_scan_gaps(&self, qemu: &Qemu) -> Result<(), Error> {
        let callback_state: GuestAddr = qemu
            .read_reg(Regs::Rcx)
            .ok()
            .and_then(|value| value.try_into().ok())
            .unwrap_or_default();
        let descriptor: GuestAddr = qemu
            .read_reg(Regs::Rdx)
            .ok()
            .and_then(|value| value.try_into().ok())
            .unwrap_or_default();
        let Some(metadata_value) = read_guest_u64(qemu, descriptor) else {
            return Ok(());
        };
        let Ok(metadata) = GuestAddr::try_from(metadata_value) else {
            return Ok(());
        };
        let Some(table_offset) = read_guest_u32(qemu, descriptor + 0xC) else {
            return Ok(());
        };
        let Some(section_count) = read_guest_u32(qemu, descriptor + 0x10) else {
            return Ok(());
        };
        let Some(image_value) = read_guest_u64(qemu, callback_state + 0x18) else {
            return Ok(());
        };
        let Ok(image) = GuestAddr::try_from(image_value) else {
            return Ok(());
        };
        let Some(image_size) = read_guest_u32(qemu, callback_state + 0x20) else {
            return Ok(());
        };
        let pattern = self.poison_pattern.borrow();
        if pattern.is_empty() || image == 0 || image_size == 0 {
            return Ok(());
        }

        let mut sections = Vec::new();
        for index in 0..section_count.min(PEC3_MAX_SECTION_RECORDS) {
            let Some(record) = metadata
                .checked_add(table_offset as GuestAddr)
                .and_then(|base| base.checked_add(index as GuestAddr * PEC3_SECTION_RECORD_SIZE))
            else {
                break;
            };
            let (Some(offset), Some(size), Some(flags)) = (
                read_guest_u32(qemu, record),
                read_guest_u32(qemu, record + 8),
                read_guest_u16(qemu, record + 0x10),
            ) else {
                break;
            };
            sections.push((offset, size, flags));
        }

        for &(scan_offset, scan_size, scan_flags) in &sections {
            if scan_flags & 8 == 0 {
                continue;
            }
            let initialized_end = sections
                .iter()
                .filter(|(offset, _, flags)| *offset == scan_offset && *flags & 0x10 != 0)
                .filter_map(|(offset, size, _)| offset.checked_add(*size))
                .max();
            let Some(start) = initialized_end else {
                continue;
            };
            let end = scan_offset
                .checked_add(scan_size)
                .unwrap_or(u32::MAX)
                .min(image_size);
            if start >= end {
                continue;
            }

            let mut chunk = vec![0u8; PEC3_POISON_CHUNK_SIZE];
            let mut cursor = start as usize;
            let end = end as usize;
            while cursor < end {
                let length = PEC3_POISON_CHUNK_SIZE.min(end - cursor);
                for (index, byte) in chunk[..length].iter_mut().enumerate() {
                    *byte = pattern[(cursor - start as usize + index) % pattern.len()];
                }
                qemu.write_mem(image + cursor as GuestAddr, &chunk[..length])
                    .map_err(|error| {
                        Error::unknown(format!(
                            "Pec3PeviewerHeapPoison failed at image+{cursor:#x}: {error:?}"
                        ))
                    })?;
                cursor += length;
            }
        }
        Ok(())
    }
}

impl CevaTarget for Pec3PeviewerHeapPoisonTarget {
    fn name(&self) -> &'static str {
        "Pec3PeviewerHeapPoison"
    }

    fn initialize(
        &mut self,
        harness: &mut CevaEmuHarness<'_>,
        max_bp_hit_count: Option<u64>,
    ) -> Result<(), Error> {
        self.family.initialize(harness, max_bp_hit_count)?;
        let operation4_pc = harness
            .entry_point
            .checked_sub(PEC3_OPERATION4_FROM_WORKER)
            .ok_or_else(|| Error::unknown("PEC3 worker address is below operation-4 callback"))?;
        self.operation4_pc.set(operation4_pc);
        harness.qemu().set_breakpoint(operation4_pc);
        Ok(())
    }

    fn prepare_input(&self, qemu: &Qemu, input: &[u8], _input_len: GuestReg) -> Result<(), Error> {
        let stream_len = input.len().min(PEC3_PEVIEWER_FILE_SIZE);
        self.family
            .prepare_input(qemu, &input[..stream_len], stream_len as GuestReg)?;
        self.poison_pattern.replace(
            input
                .get(PEC3_PEVIEWER_FILE_SIZE..)
                .unwrap_or_default()
                .to_vec(),
        );
        Ok(())
    }

    fn reset(&self, harness: &CevaEmuHarness<'_>) -> Result<(), Error> {
        self.family.reset(harness)?;
        harness.qemu().set_breakpoint(self.operation4_pc.get());
        Ok(())
    }

    fn handle_breakpoint(&self, harness: &CevaEmuHarness<'_>) -> Result<bool, Error> {
        let qemu = harness.qemu();
        let pc: GuestAddr = qemu.read_reg(Regs::Pc).unwrap().try_into().unwrap();
        if pc == self.operation4_pc.get() {
            qemu.remove_breakpoint(pc);
            self.poison_uninitialized_scan_gaps(qemu)?;
            return Ok(true);
        }
        self.family.handle_breakpoint(harness)
    }

    fn after_run(&self, harness: &CevaEmuHarness<'_>, execs: u64) -> Result<(), Error> {
        self.family.after_run(harness, execs)
    }
}

impl CevaTarget for Pec3PeviewerTarget {
    fn name(&self) -> &'static str {
        self.0.name()
    }

    fn initialize(
        &mut self,
        harness: &mut CevaEmuHarness<'_>,
        max_bp_hit_count: Option<u64>,
    ) -> Result<(), Error> {
        self.0.initialize(harness, max_bp_hit_count)
    }

    fn prepare_input(&self, qemu: &Qemu, input: &[u8], input_len: GuestReg) -> Result<(), Error> {
        self.0.prepare_input(qemu, input, input_len)
    }

    fn reset(&self, harness: &CevaEmuHarness<'_>) -> Result<(), Error> {
        self.0.reset(harness)
    }

    fn handle_breakpoint(&self, harness: &CevaEmuHarness<'_>) -> Result<bool, Error> {
        self.0.handle_breakpoint(harness)
    }

    fn after_run(&self, harness: &CevaEmuHarness<'_>, execs: u64) -> Result<(), Error> {
        self.0.after_run(harness, execs)
    }
}

pub struct Pec3HashTarget(Pec3FamilyTarget);

impl Default for Pec3HashTarget {
    fn default() -> Self {
        Self(Pec3FamilyTarget::new(PEC3_HASH_SPEC))
    }
}

impl CevaTarget for Pec3HashTarget {
    fn name(&self) -> &'static str {
        self.0.name()
    }

    fn initialize(
        &mut self,
        harness: &mut CevaEmuHarness<'_>,
        max_bp_hit_count: Option<u64>,
    ) -> Result<(), Error> {
        self.0.initialize(harness, max_bp_hit_count)
    }

    fn prepare_input(&self, qemu: &Qemu, input: &[u8], input_len: GuestReg) -> Result<(), Error> {
        self.0.prepare_input(qemu, input, input_len)
    }

    fn reset(&self, harness: &CevaEmuHarness<'_>) -> Result<(), Error> {
        self.0.reset(harness)
    }

    fn handle_breakpoint(&self, harness: &CevaEmuHarness<'_>) -> Result<bool, Error> {
        self.0.handle_breakpoint(harness)
    }

    fn after_run(&self, harness: &CevaEmuHarness<'_>, execs: u64) -> Result<(), Error> {
        self.0.after_run(harness, execs)
    }
}

#[derive(Default)]
pub struct Pec3Operation11Target {
    image: Cell<GuestAddr>,
    image_size: Cell<usize>,
    descriptor: Cell<GuestAddr>,
}

impl CevaTarget for Pec3Operation11Target {
    fn name(&self) -> &'static str {
        "PEC3 operation-11 callback"
    }

    fn initialize(
        &mut self,
        harness: &mut CevaEmuHarness<'_>,
        _max_bp_hit_count: Option<u64>,
    ) -> Result<(), Error> {
        let qemu = *harness.qemu();
        if let Some(bootstrap_path) = std::env::var_os("BDCORE_PEC3_OP11_BOOTSTRAP") {
            let bootstrap = std::fs::read(&bootstrap_path).map_err(|error| {
                Error::unknown(format!(
                    "Failed to read PEC3 operation-11 bootstrap {bootstrap_path:?}: {error}"
                ))
            })?;
            let decoded: GuestAddr = qemu
                .read_reg(Regs::Rbx)
                .map_err(|error| {
                    Error::unknown(format!("Failed to read PEC3 bootstrap RBX: {error:?}"))
                })?
                .try_into()
                .map_err(|error| {
                    Error::unknown(format!("Invalid PEC3 bootstrap decoded pointer: {error:?}"))
                })?;
            let decoded_size: usize = qemu
                .read_reg(Regs::Rdi)
                .map_err(|error| {
                    Error::unknown(format!("Failed to read PEC3 bootstrap RDI: {error:?}"))
                })?
                .try_into()
                .map_err(|error| {
                    Error::unknown(format!("Invalid PEC3 bootstrap decoded size: {error:?}"))
                })?;
            if bootstrap.len() != PEC3_POSTDECODE_HEADER_SIZE + decoded_size
                || bootstrap.get(..4) != Some(PEC3_POSTDECODE_MAGIC)
            {
                return Err(Error::unknown(format!(
                    "Invalid PEC3 operation-11 bootstrap size/magic: input={:#x} expected={:#x}",
                    bootstrap.len(),
                    PEC3_POSTDECODE_HEADER_SIZE + decoded_size
                )));
            }
            let declared_size = u32::from_le_bytes(bootstrap[4..8].try_into().unwrap()) as usize;
            if declared_size != decoded_size {
                return Err(Error::unknown(format!(
                    "PEC3 operation-11 bootstrap size mismatch: {declared_size:#x}/{decoded_size:#x}"
                )));
            }
            qemu.write_mem(decoded, &bootstrap[PEC3_POSTDECODE_HEADER_SIZE..])
                .map_err(|error| {
                    Error::unknown(format!(
                        "Failed to inject PEC3 operation-11 bootstrap: {error:?}"
                    ))
                })?;

            let operation11_pc = harness
                .entry_point
                .checked_sub(PEC3_OPERATION11_FROM_POSTDECODE)
                .ok_or_else(|| {
                    Error::unknown("PEC3 postdecode entry is below operation-11 callback")
                })?;
            qemu.remove_breakpoint(harness.entry_point);
            qemu.set_breakpoint(operation11_pc);
            unsafe {
                let _ = qemu.run();
            }
            let pc: GuestAddr = qemu
                .read_reg(Regs::Pc)
                .map_err(|error| {
                    Error::unknown(format!("Failed to read PEC3 bootstrap PC: {error:?}"))
                })?
                .try_into()
                .map_err(|error| Error::unknown(format!("Invalid PEC3 bootstrap PC: {error:?}")))?;
            qemu.remove_breakpoint(operation11_pc);
            if pc != operation11_pc {
                return Err(Error::unknown(format!(
                    "PEC3 operation-11 bootstrap stopped at {pc:#x}, expected {operation11_pc:#x}"
                )));
            }
            harness.entry_point = operation11_pc;
            harness.exit_point = qemu
                .read_return_address()
                .map_err(|error| {
                    Error::unknown(format!(
                        "Failed to read PEC3 operation-11 return address: {error:?}"
                    ))
                })?
                .try_into()
                .map_err(|error| {
                    Error::unknown(format!(
                        "Invalid PEC3 operation-11 return address: {error:?}"
                    ))
                })?;
        }
        let context: GuestAddr = qemu
            .read_reg(Regs::Rcx)
            .map_err(|error| {
                Error::unknown(format!("Failed to read PEC3 callback RCX: {error:?}"))
            })?
            .try_into()
            .map_err(|error| Error::unknown(format!("Invalid PEC3 callback context: {error:?}")))?;
        let descriptor: GuestAddr = qemu
            .read_reg(Regs::Rdx)
            .map_err(|error| {
                Error::unknown(format!("Failed to read PEC3 callback RDX: {error:?}"))
            })?
            .try_into()
            .map_err(|error| {
                Error::unknown(format!("Invalid PEC3 callback descriptor: {error:?}"))
            })?;
        let image: GuestAddr = read_guest_u64(&qemu, context + PEC3_CALLBACK_IMAGE_PTR_OFFSET)
            .ok_or_else(|| Error::unknown("Failed to read PEC3 callback image pointer"))?
            .try_into()
            .map_err(|error| {
                Error::unknown(format!("Invalid PEC3 callback image pointer: {error:?}"))
            })?;
        let image_size = read_guest_u32(&qemu, context + PEC3_CALLBACK_IMAGE_SIZE_OFFSET)
            .ok_or_else(|| Error::unknown("Failed to read PEC3 callback image size"))?
            as usize;
        if context == 0 || descriptor == 0 || image == 0 || image_size == 0 {
            return Err(Error::unknown(format!(
                "Invalid PEC3 operation-11 state context={context:#x} descriptor={descriptor:#x} image={image:#x}:{image_size:#x}"
            )));
        }

        self.image.set(image);
        self.image_size.set(image_size);
        self.descriptor.set(descriptor);

        if let Some(output) = std::env::var_os("BDCORE_PEC3_OP11_SEED_OUT") {
            let source_offset = read_guest_u32(&qemu, descriptor + 8).unwrap_or(0);
            let destination_offset = read_guest_u32(&qemu, descriptor + 0xc).unwrap_or(0);
            let transform_parameter = read_guest_u32(&qemu, descriptor + 0x10).unwrap_or(0);
            let source_length = read_guest_u32(&qemu, descriptor + 0x18).unwrap_or(0);
            let transform_selector = read_guest_u32(&qemu, descriptor + 0x1c).unwrap_or(0);

            let (seed_source_offset, seed_source_length) = if source_offset < image_size as u32 {
                let available = image_size - source_offset as usize;
                let length = (source_length as usize)
                    .min(available)
                    .min(PEC3_OPERATION11_MAX_SEED_PAYLOAD);
                (source_offset, length)
            } else {
                (0, image_size.min(0x1000))
            };
            let mut payload = vec![0u8; seed_source_length];
            qemu.read_mem(image + seed_source_offset as GuestAddr, &mut payload)
                .map_err(|error| {
                    Error::unknown(format!(
                        "Failed to capture PEC3 operation-11 source payload: {error:?}"
                    ))
                })?;
            let seed = build_pec3_operation11_input(
                image_size as u32,
                seed_source_offset,
                destination_offset,
                seed_source_length as u32,
                transform_parameter,
                transform_selector,
                0,
                &payload,
            );
            std::fs::write(&output, seed).map_err(|error| {
                Error::unknown(format!(
                    "Failed to write PEC3 operation-11 seed {output:?}: {error}"
                ))
            })?;
            eprintln!(
                "PEC3_OP11_SEED image={image:#x}:{image_size:#x} descriptor={descriptor:#x} source={seed_source_offset:#x}:{seed_source_length:#x} destination={destination_offset:#x} parameter={transform_parameter:#x} selector={transform_selector:#x} output={output:?}"
            );
        }

        Ok(())
    }

    fn prepare_input(&self, qemu: &Qemu, input: &[u8], input_len: GuestReg) -> Result<(), Error> {
        let input = &input[..(input_len as usize).min(input.len())];
        let Some(parsed) = parse_pec3_operation11_input(input) else {
            return Ok(());
        };
        if parsed.image_size as usize != self.image_size.get() {
            return Ok(());
        }

        if let Some(end) = (parsed.source_offset as usize).checked_add(parsed.payload.len()) {
            if end <= self.image_size.get() {
                qemu.write_mem(
                    self.image.get() + parsed.source_offset as GuestAddr,
                    parsed.payload,
                )
                .map_err(|error| {
                    Error::unknown(format!(
                        "Failed to inject PEC3 operation-11 payload: {error:?}"
                    ))
                })?;
            }
        }

        let mut descriptor = [0u8; 0x20];
        descriptor[8..0xc].copy_from_slice(&parsed.source_offset.to_le_bytes());
        descriptor[0xc..0x10].copy_from_slice(&parsed.destination_offset.to_le_bytes());
        descriptor[0x10..0x14].copy_from_slice(&parsed.transform_parameter.to_le_bytes());
        if parsed.prefix_length != 0 {
            let prefix_end =
                (parsed.source_offset as usize).checked_add(parsed.prefix_length as usize);
            if prefix_end.is_some_and(|end| end <= self.image_size.get()) {
                descriptor[..8].copy_from_slice(
                    &(self.image.get() + parsed.source_offset as GuestAddr).to_le_bytes(),
                );
                descriptor[0x14..0x18].copy_from_slice(&parsed.prefix_length.to_le_bytes());
            }
        }
        descriptor[0x18..0x1c].copy_from_slice(&parsed.source_length.to_le_bytes());
        descriptor[0x1c..0x20].copy_from_slice(&parsed.transform_selector.to_le_bytes());
        qemu.write_mem(self.descriptor.get(), &descriptor)
            .map_err(|error| {
                Error::unknown(format!(
                    "Failed to inject PEC3 operation-11 descriptor: {error:?}"
                ))
            })
    }

    fn reset(&self, harness: &CevaEmuHarness<'_>) -> Result<(), Error> {
        restore_nonvolatile_regs(harness)
    }
}

#[derive(Default)]
pub struct Pec3Operation11Mode2Target {
    image: Cell<GuestAddr>,
    image_size: Cell<usize>,
    descriptor: Cell<GuestAddr>,
    selector_table: Cell<GuestAddr>,
    implicit_table: Cell<GuestAddr>,
    table_capacity: Cell<usize>,
}

impl CevaTarget for Pec3Operation11Mode2Target {
    fn name(&self) -> &'static str {
        "PEC3 operation-11 mode-2 callback"
    }

    fn initialize(
        &mut self,
        harness: &mut CevaEmuHarness<'_>,
        _max_bp_hit_count: Option<u64>,
    ) -> Result<(), Error> {
        let qemu = *harness.qemu();
        let bootstrap_path = std::env::var_os("BDCORE_PEC3_OP11_MODE2_BOOTSTRAP")
            .ok_or_else(|| Error::unknown("BDCORE_PEC3_OP11_MODE2_BOOTSTRAP is required"))?;
        let bootstrap = std::fs::read(&bootstrap_path).map_err(|error| {
            Error::unknown(format!(
                "Failed to read PEC3 operation-11 mode-2 bootstrap {bootstrap_path:?}: {error}"
            ))
        })?;
        let decoded: GuestAddr = qemu
            .read_reg(Regs::Rbx)
            .map_err(|error| {
                Error::unknown(format!("Failed to read PEC3 bootstrap RBX: {error:?}"))
            })?
            .try_into()
            .map_err(|error| {
                Error::unknown(format!("Invalid PEC3 bootstrap decoded pointer: {error:?}"))
            })?;
        let decoded_size: usize = qemu
            .read_reg(Regs::Rdi)
            .map_err(|error| {
                Error::unknown(format!("Failed to read PEC3 bootstrap RDI: {error:?}"))
            })?
            .try_into()
            .map_err(|error| {
                Error::unknown(format!("Invalid PEC3 bootstrap decoded size: {error:?}"))
            })?;
        if bootstrap.len() != PEC3_POSTDECODE_HEADER_SIZE + decoded_size
            || bootstrap.get(..4) != Some(PEC3_POSTDECODE_MAGIC)
        {
            return Err(Error::unknown(format!(
                "Invalid PEC3 operation-11 mode-2 bootstrap size/magic: input={:#x} expected={:#x}",
                bootstrap.len(),
                PEC3_POSTDECODE_HEADER_SIZE + decoded_size
            )));
        }
        let declared_size = u32::from_le_bytes(bootstrap[4..8].try_into().unwrap()) as usize;
        if declared_size != decoded_size {
            return Err(Error::unknown(format!(
                "PEC3 operation-11 mode-2 bootstrap size mismatch: {declared_size:#x}/{decoded_size:#x}"
            )));
        }
        qemu.write_mem(decoded, &bootstrap[PEC3_POSTDECODE_HEADER_SIZE..])
            .map_err(|error| {
                Error::unknown(format!(
                    "Failed to inject PEC3 operation-11 mode-2 bootstrap: {error:?}"
                ))
            })?;

        let operation11_pc = harness
            .entry_point
            .checked_sub(PEC3_OPERATION11_MODE2_FROM_POSTDECODE)
            .ok_or_else(|| {
                Error::unknown("PEC3 postdecode entry is below operation-11 mode-2 callback")
            })?;
        qemu.remove_breakpoint(harness.entry_point);
        qemu.set_breakpoint(operation11_pc);
        unsafe {
            let _ = qemu.run();
        }
        let pc: GuestAddr = qemu
            .read_reg(Regs::Pc)
            .map_err(|error| {
                Error::unknown(format!("Failed to read PEC3 bootstrap PC: {error:?}"))
            })?
            .try_into()
            .map_err(|error| Error::unknown(format!("Invalid PEC3 bootstrap PC: {error:?}")))?;
        qemu.remove_breakpoint(operation11_pc);
        if pc != operation11_pc {
            return Err(Error::unknown(format!(
                "PEC3 operation-11 mode-2 bootstrap stopped at {pc:#x}, expected {operation11_pc:#x}"
            )));
        }
        harness.entry_point = operation11_pc;
        harness.exit_point = qemu
            .read_return_address()
            .map_err(|error| {
                Error::unknown(format!(
                    "Failed to read PEC3 operation-11 mode-2 return address: {error:?}"
                ))
            })?
            .try_into()
            .map_err(|error| {
                Error::unknown(format!(
                    "Invalid PEC3 operation-11 mode-2 return address: {error:?}"
                ))
            })?;

        let context: GuestAddr = qemu
            .read_reg(Regs::Rcx)
            .map_err(|error| {
                Error::unknown(format!("Failed to read PEC3 callback RCX: {error:?}"))
            })?
            .try_into()
            .map_err(|error| Error::unknown(format!("Invalid PEC3 callback context: {error:?}")))?;
        let descriptor: GuestAddr = qemu
            .read_reg(Regs::Rdx)
            .map_err(|error| {
                Error::unknown(format!("Failed to read PEC3 callback RDX: {error:?}"))
            })?
            .try_into()
            .map_err(|error| {
                Error::unknown(format!("Invalid PEC3 callback descriptor: {error:?}"))
            })?;
        let image: GuestAddr = read_guest_u64(&qemu, context + PEC3_CALLBACK_IMAGE_PTR_OFFSET)
            .ok_or_else(|| Error::unknown("Failed to read PEC3 callback image pointer"))?
            .try_into()
            .map_err(|error| {
                Error::unknown(format!("Invalid PEC3 callback image pointer: {error:?}"))
            })?;
        let image_size = read_guest_u32(&qemu, context + PEC3_CALLBACK_IMAGE_SIZE_OFFSET)
            .ok_or_else(|| Error::unknown("Failed to read PEC3 callback image size"))?
            as usize;
        let table_capacity = read_guest_u16(&qemu, descriptor + 0x18).unwrap_or(0) as usize;
        let selector_table: GuestAddr = read_guest_u64(&qemu, descriptor + 0x20)
            .unwrap_or(0)
            .try_into()
            .unwrap_or(0);
        let implicit_table: GuestAddr = read_guest_u64(&qemu, descriptor + 0x28)
            .unwrap_or(0)
            .try_into()
            .unwrap_or(0);
        if context == 0
            || descriptor == 0
            || image == 0
            || image_size == 0
            || table_capacity == 0
            || selector_table == 0
            || implicit_table == 0
        {
            return Err(Error::unknown(format!(
                "Invalid PEC3 operation-11 mode-2 state context={context:#x} descriptor={descriptor:#x} image={image:#x}:{image_size:#x} tables={selector_table:#x}/{implicit_table:#x}:{table_capacity}"
            )));
        }
        self.image.set(image);
        self.image_size.set(image_size);
        self.descriptor.set(descriptor);
        self.selector_table.set(selector_table);
        self.implicit_table.set(implicit_table);
        self.table_capacity.set(table_capacity);

        if let Some(output) = std::env::var_os("BDCORE_PEC3_OP11_MODE2_SEED_OUT") {
            let source_offset = read_guest_u32(&qemu, descriptor + 8).unwrap_or(0);
            let destination_offset = read_guest_u32(&qemu, descriptor + 0xc).unwrap_or(0);
            let prefix_length = read_guest_u32(&qemu, descriptor + 0x10).unwrap_or(0);
            let total_length = read_guest_u32(&qemu, descriptor + 0x14).unwrap_or(0);
            let mut entries = Vec::with_capacity(table_capacity);
            for index in 0..table_capacity {
                let table_offset = (index * 8) as GuestAddr;
                let implicit_key_pointer: GuestAddr =
                    read_guest_u64(&qemu, implicit_table + table_offset)
                        .unwrap_or(0)
                        .try_into()
                        .unwrap_or(0);
                let implicit_key = if implicit_key_pointer != 0 {
                    let mut key = [0u8; 8];
                    qemu.read_mem(implicit_key_pointer, &mut key)
                        .map_err(|error| {
                            Error::unknown(format!(
                                "Failed to capture PEC3 mode-2 implicit key: {error:?}"
                            ))
                        })?;
                    Some(key)
                } else {
                    None
                };
                entries.push(Pec3Operation11Mode2Entry {
                    selector: read_guest_u32(&qemu, selector_table + table_offset).unwrap_or(0),
                    auxiliary: read_guest_u32(&qemu, selector_table + table_offset + 4)
                        .unwrap_or(0),
                    implicit_key,
                });
            }
            let (seed_source_offset, seed_payload_length) = if source_offset < image_size as u32 {
                (
                    source_offset,
                    (image_size - source_offset as usize).min(PEC3_OPERATION11_MAX_SEED_PAYLOAD),
                )
            } else {
                (0, image_size.min(0x1000))
            };
            let mut payload = vec![0u8; seed_payload_length];
            qemu.read_mem(image + seed_source_offset as GuestAddr, &mut payload)
                .map_err(|error| {
                    Error::unknown(format!(
                        "Failed to capture PEC3 operation-11 mode-2 payload: {error:?}"
                    ))
                })?;
            let seed = build_pec3_operation11_mode2_input(
                image_size as u32,
                seed_source_offset,
                destination_offset,
                prefix_length,
                total_length,
                table_capacity as u32,
                &entries,
                &payload,
            );
            std::fs::write(&output, seed).map_err(|error| {
                Error::unknown(format!(
                    "Failed to write PEC3 operation-11 mode-2 seed {output:?}: {error}"
                ))
            })?;
            eprintln!(
                "PEC3_OP11_MODE2_SEED image={image:#x}:{image_size:#x} descriptor={descriptor:#x} source={seed_source_offset:#x}:{seed_payload_length:#x} destination={destination_offset:#x} prefix={prefix_length:#x} total={total_length:#x} records={table_capacity} output={output:?}"
            );
        }

        Ok(())
    }

    fn prepare_input(&self, qemu: &Qemu, input: &[u8], input_len: GuestReg) -> Result<(), Error> {
        let input = &input[..(input_len as usize).min(input.len())];
        let Some(parsed) = parse_pec3_operation11_mode2_input(input) else {
            return Ok(());
        };
        if parsed.image_size as usize != self.image_size.get()
            || parsed.entry_capacity as usize != self.table_capacity.get()
            || parsed.record_count > parsed.entry_capacity
            || parsed.record_count > u16::MAX as u32
        {
            return Ok(());
        }

        if (parsed.source_offset as usize) < self.image_size.get() {
            let available = self.image_size.get() - parsed.source_offset as usize;
            let write_length = parsed.payload.len().min(available);
            qemu.write_mem(
                self.image.get() + parsed.source_offset as GuestAddr,
                &parsed.payload[..write_length],
            )
            .map_err(|error| {
                Error::unknown(format!(
                    "Failed to inject PEC3 operation-11 mode-2 payload: {error:?}"
                ))
            })?;
        }

        let key_scratch_size = self.table_capacity.get().saturating_mul(8);
        if key_scratch_size > self.image_size.get() {
            return Ok(());
        }
        let key_scratch =
            self.image.get() + (self.image_size.get() - key_scratch_size) as GuestAddr;

        for index in 0..self.table_capacity.get() {
            let Some(entry) = parsed.entry(index) else {
                return Ok(());
            };
            let table_offset = (index * 8) as GuestAddr;
            let mut selector_entry = [0u8; 8];
            selector_entry[..4].copy_from_slice(&entry.selector.to_le_bytes());
            selector_entry[4..].copy_from_slice(&entry.auxiliary.to_le_bytes());
            qemu.write_mem(self.selector_table.get() + table_offset, &selector_entry)
                .map_err(|error| {
                    Error::unknown(format!(
                        "Failed to inject PEC3 mode-2 selector entry: {error:?}"
                    ))
                })?;
            let implicit_key_pointer = if let Some(key) = entry.implicit_key {
                let key_address = key_scratch + table_offset;
                qemu.write_mem(key_address, &key).map_err(|error| {
                    Error::unknown(format!(
                        "Failed to inject PEC3 mode-2 implicit key: {error:?}"
                    ))
                })?;
                key_address
            } else {
                0
            };
            qemu.write_mem(
                self.implicit_table.get() + table_offset,
                &implicit_key_pointer.to_le_bytes(),
            )
            .map_err(|error| {
                Error::unknown(format!(
                    "Failed to inject PEC3 mode-2 implicit entry: {error:?}"
                ))
            })?;
        }

        let prefix_length = parsed.prefix_length.min(parsed.total_length);
        let mut descriptor = [0u8; 0x30];
        if prefix_length != 0
            && (parsed.source_offset as usize) < self.image_size.get()
            && (prefix_length as usize) <= parsed.payload.len()
            && (prefix_length as usize) <= self.image_size.get() - parsed.source_offset as usize
        {
            descriptor[..8].copy_from_slice(
                &(self.image.get() + parsed.source_offset as GuestAddr).to_le_bytes(),
            );
            descriptor[0x10..0x14].copy_from_slice(&prefix_length.to_le_bytes());
        }
        descriptor[8..0xc].copy_from_slice(&parsed.source_offset.to_le_bytes());
        descriptor[0xc..0x10].copy_from_slice(&parsed.destination_offset.to_le_bytes());
        descriptor[0x14..0x18].copy_from_slice(&parsed.total_length.to_le_bytes());
        descriptor[0x18..0x1a].copy_from_slice(&(parsed.record_count as u16).to_le_bytes());
        descriptor[0x20..0x28].copy_from_slice(&self.selector_table.get().to_le_bytes());
        descriptor[0x28..0x30].copy_from_slice(&self.implicit_table.get().to_le_bytes());
        qemu.write_mem(self.descriptor.get(), &descriptor)
            .map_err(|error| {
                Error::unknown(format!(
                    "Failed to inject PEC3 operation-11 mode-2 descriptor: {error:?}"
                ))
            })
    }

    fn reset(&self, harness: &CevaEmuHarness<'_>) -> Result<(), Error> {
        restore_nonvolatile_regs(harness)
    }
}

#[derive(Default)]
pub struct Pec3PostdecodeTarget {
    decoded: Cell<GuestAddr>,
    decoded_size: Cell<usize>,
    variant_offset: Cell<usize>,
    operation11_trace_pc: Cell<GuestAddr>,
}

impl CevaTarget for Pec3PostdecodeTarget {
    fn name(&self) -> &'static str {
        "Pec3Postdecode"
    }

    fn initialize(
        &mut self,
        harness: &mut CevaEmuHarness<'_>,
        _max_bp_hit_count: Option<u64>,
    ) -> Result<(), Error> {
        let qemu = harness.qemu();
        let decoded: GuestAddr = qemu
            .read_reg(Regs::Rbx)
            .map_err(|error| {
                Error::unknown(format!("Failed to read PEC3 decoded pointer: {error:?}"))
            })?
            .try_into()
            .map_err(|error| Error::unknown(format!("Invalid PEC3 decoded pointer: {error:?}")))?;
        let decoded_size: usize = qemu
            .read_reg(Regs::Rdi)
            .map_err(|error| {
                Error::unknown(format!("Failed to read PEC3 decoded size: {error:?}"))
            })?
            .try_into()
            .map_err(|error| Error::unknown(format!("Invalid PEC3 decoded size: {error:?}")))?;
        let variant_ptr: GuestAddr = qemu
            .read_reg(Regs::Rcx)
            .map_err(|error| {
                Error::unknown(format!("Failed to read PEC3 variant pointer: {error:?}"))
            })?
            .try_into()
            .map_err(|error| Error::unknown(format!("Invalid PEC3 variant pointer: {error:?}")))?;
        let variant_offset = variant_ptr
            .checked_sub(decoded)
            .ok_or_else(|| Error::unknown("PEC3 variant pointer precedes decoded buffer"))?
            as usize;
        if decoded == 0
            || decoded_size == 0
            || variant_offset
                .checked_add(12)
                .is_none_or(|end| end > decoded_size)
        {
            return Err(Error::unknown(format!(
                "Invalid PEC3 postdecode state decoded={decoded:#x} size={decoded_size:#x} variant_offset={variant_offset:#x}"
            )));
        }

        self.decoded.set(decoded);
        self.decoded_size.set(decoded_size);
        self.variant_offset.set(variant_offset);
        if std::env::var_os("BDCORE_PEC3_OP11_TRACE").is_some() {
            let operation11_trace_pc = harness
                .entry_point
                .checked_sub(PEC3_OPERATION11_FROM_POSTDECODE)
                .ok_or_else(|| {
                    Error::unknown("PEC3 postdecode entry is below operation-11 callback")
                })?;
            self.operation11_trace_pc.set(operation11_trace_pc);
            qemu.set_breakpoint(operation11_trace_pc);
        }
        harness.exit_point = harness
            .bd_engine
            .resolve_module_address(PEC3_POSTDECODE_EXIT, "PEC3 worker epilogue")?;
        log::info!(
            "PEC3 postdecode init: decoded={decoded:#x}:{decoded_size:#x} variant_offset={variant_offset:#x} exit={:#x}",
            harness.exit_point,
        );
        Ok(())
    }

    fn prepare_input(&self, qemu: &Qemu, input: &[u8], input_len: GuestReg) -> Result<(), Error> {
        let input = &input[..(input_len as usize).min(input.len())];
        if input.len() != PEC3_POSTDECODE_HEADER_SIZE + self.decoded_size.get()
            || input.get(..4) != Some(PEC3_POSTDECODE_MAGIC)
        {
            return Err(Error::unknown(format!(
                "Invalid PEC3 postdecode input size/magic: input={:#x} expected={:#x}",
                input.len(),
                PEC3_POSTDECODE_HEADER_SIZE + self.decoded_size.get()
            )));
        }
        let declared_size = u32::from_le_bytes(input[4..8].try_into().unwrap()) as usize;
        let declared_variant = u32::from_le_bytes(input[8..12].try_into().unwrap()) as usize;
        if declared_size != self.decoded_size.get() || declared_variant != self.variant_offset.get()
        {
            return Err(Error::unknown(format!(
                "PEC3 postdecode metadata mismatch size={declared_size:#x}/{:#x} variant={declared_variant:#x}/{:#x}",
                self.decoded_size.get(),
                self.variant_offset.get(),
            )));
        }
        qemu.write_mem(self.decoded.get(), &input[PEC3_POSTDECODE_HEADER_SIZE..])
            .map_err(|error| {
                Error::unknown(format!("Failed to inject PEC3 decoded buffer: {error:?}"))
            })
    }

    fn reset(&self, harness: &CevaEmuHarness<'_>) -> Result<(), Error> {
        restore_nonvolatile_regs(harness)
    }

    fn handle_breakpoint(&self, harness: &CevaEmuHarness<'_>) -> Result<bool, Error> {
        let qemu = harness.qemu();
        let pc: GuestAddr = qemu.read_reg(Regs::Pc).unwrap().try_into().unwrap();
        if pc != self.operation11_trace_pc.get() || pc == 0 {
            return Ok(false);
        }

        let descriptor: GuestAddr = qemu
            .read_reg(Regs::Rdx)
            .map_err(|error| {
                Error::unknown(format!("Failed to read PEC3 operation-11 RDX: {error:?}"))
            })?
            .try_into()
            .map_err(|error| {
                Error::unknown(format!("Invalid PEC3 operation-11 descriptor: {error:?}"))
            })?;
        let mut bytes = [0u8; 0x20];
        qemu.read_mem(descriptor, &mut bytes).map_err(|error| {
            Error::unknown(format!(
                "Failed to read PEC3 operation-11 descriptor at {descriptor:#x}: {error:?}"
            ))
        })?;
        eprintln!(
            "PEC3_OP11_DESCRIPTOR pc={pc:#x} ptr={descriptor:#x} bytes={}",
            bytes
                .iter()
                .map(|byte| format!("{byte:02x}"))
                .collect::<Vec<_>>()
                .join("")
        );
        qemu.remove_breakpoint(pc);
        self.operation11_trace_pc.set(0);
        Ok(true)
    }
}
