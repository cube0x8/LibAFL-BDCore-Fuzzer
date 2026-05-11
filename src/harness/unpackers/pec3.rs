use std::cell::Cell;

use libafl::Error;
use libafl_qemu::{GuestAddr, GuestReg, Qemu, Regs};

use crate::harness::unpackers::health::UnpackerHealth;
use crate::harness::unpackers::stream::StagedReadStream;
use crate::harness::{CevaEmuHarness, CevaTarget};

const DEBUG_INPUT_BYTES_LEN: usize = 32;
const PEC3_STAGE40_LEN: usize = 0x40;
const PEC3_STAGE10_LEN: usize = 0x10;
const PEC3_STAGE28_LEN: usize = 0x28;
const PEC3_SEEK_THUNK_OFFSET: GuestAddr = 0x2C00;
const PEC3_READ_THUNK_OFFSET: GuestAddr = 0x2C10;

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

const PEC3_PEVIEWER_STAGE10: [u8; PEC3_STAGE10_LEN] = [
    0x20, 0x3e, 0x18, 0x00, 0x30, 0x17, 0x00, 0x00, 0x34, 0x0a, 0x00, 0x00, 0x99, 0x49,
    0x18, 0x00,
];
const PEC3_HASH_STAGE10: [u8; PEC3_STAGE10_LEN] = [
    0xf4, 0x2f, 0x01, 0x00, 0xa0, 0x0e, 0x00, 0x00, 0xa4, 0x01, 0x00, 0x00, 0xd0, 0x36,
    0x01, 0x00,
];

#[derive(Clone, Copy)]
struct Pec3FamilySpec {
    target_name: &'static str,
    stage10: &'static [u8; PEC3_STAGE10_LEN],
    main_len: usize,
}

const PEC3_PEVIEWER_SPEC: Pec3FamilySpec = Pec3FamilySpec {
    target_name: "Pec3Peviewer",
    stage10: &PEC3_PEVIEWER_STAGE10,
    main_len: 2937,
};

const PEC3_HASH_SPEC: Pec3FamilySpec = Pec3FamilySpec {
    target_name: "Pec3Hash",
    stage10: &PEC3_HASH_STAGE10,
    main_len: 1756,
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

fn read_entry_stub_prefix(qemu: &Qemu, want_len: usize) -> Result<Vec<u8>, Error> {
    let a4: GuestAddr = qemu.read_reg(Regs::R9).unwrap().try_into().unwrap();
    let rsp: GuestAddr = qemu.read_reg(Regs::Sp).unwrap().try_into().unwrap();
    let a5 = read_stack_arg_u64(qemu, rsp, 0x28)? as usize;

    let read_len = want_len.min(a5);
    let mut out = vec![0u8; want_len];
    if read_len != 0 {
        qemu.read_mem(a4, &mut out[..read_len]).map_err(|e| {
            Error::unknown(format!("Failed to read pec3 entry stub prefix: {e:?}"))
        })?;
    }
    Ok(out)
}

fn fixed_stage(input: &[u8], offset: usize, len: usize) -> Vec<u8> {
    let mut out = vec![0u8; len];
    let available = input.len().saturating_sub(offset).min(len);
    if available != 0 {
        out[..available].copy_from_slice(&input[offset..offset + available]);
    }
    out
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
    stream: StagedReadStream,
}

impl Default for Pec3Read40Target {
    fn default() -> Self {
        Self {
            seek_pc: Cell::new(0),
            read_pc: Cell::new(0),
            read_count: Cell::new(0),
            health: UnpackerHealth::new("Pec3Read40", PEC3_HEALTH_SLOTS),
            stream: StagedReadStream::default(),
        }
    }
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

    fn prepare_input(&self, qemu: &Qemu, input: &[u8], input_len: GuestReg) -> Result<(), Error> {
        let final_input_len: usize = PEC3_STAGE40_LEN.min(input_len as usize);
        let mut stages = Vec::with_capacity(2);
        stages.push(input[..final_input_len].to_vec());
        stages.push(read_entry_stub_prefix(qemu, PEC3_STAGE28_LEN)?);
        self.stream.set_stages(stages);
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
    stream: StagedReadStream,
}

impl Default for Pec3Read28Target {
    fn default() -> Self {
        Self {
            seek_pc: Cell::new(0),
            read_pc: Cell::new(0),
            read_count: Cell::new(0),
            health: UnpackerHealth::new("Pec3Read28", PEC3_HEALTH_SLOTS),
            stream: StagedReadStream::default(),
        }
    }
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

    fn prepare_input(&self, qemu: &Qemu, input: &[u8], input_len: GuestReg) -> Result<(), Error> {
        let final_input_len: usize = PEC3_STAGE28_LEN.min(input_len as usize);
        let mut stages = Vec::with_capacity(2);
        stages.push(read_entry_stub_prefix(qemu, PEC3_STAGE40_LEN)?);
        stages.push(input[..final_input_len].to_vec());
        self.stream.set_stages(stages);
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
    stream: StagedReadStream,
}

impl Pec3FamilyTarget {
    fn new(spec: Pec3FamilySpec) -> Self {
        Self {
            spec,
            seek_pc: Cell::new(0),
            read_pc: Cell::new(0),
            read_count: Cell::new(0),
            health: UnpackerHealth::new(spec.target_name, PEC3_FAMILY_HEALTH_SLOTS),
            stream: StagedReadStream::default(),
        }
    }
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

    fn prepare_input(&self, _qemu: &Qemu, input: &[u8], _input_len: GuestReg) -> Result<(), Error> {
        let stage40 = fixed_stage(input, 0, PEC3_STAGE40_LEN);
        let stage28 = fixed_stage(input, PEC3_STAGE40_LEN, PEC3_STAGE28_LEN);
        let main = fixed_stage(
            input,
            PEC3_STAGE40_LEN + PEC3_STAGE28_LEN,
            self.spec.main_len,
        );
        self.stream.set_stages(vec![
            stage40,
            self.spec.stage10.to_vec(),
            stage28,
            main,
        ]);
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
