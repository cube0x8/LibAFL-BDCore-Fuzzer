use std::cell::{Cell, RefCell};

use libafl::Error;
use libafl_qemu::{GuestAddr, GuestReg, MmapPerms, Qemu, Regs};
use pe_mutator_core::pe::PeFile;

use crate::harness::unpackers::health::UnpackerHealth;
use crate::harness::unpackers::stream::{MemoryBackedStream, StreamOverlay};
use crate::harness::{CevaEmuHarness, CevaTarget};

const PELOCK_SEEK_THUNK_OFFSET: GuestAddr = 0x7500;
const PELOCK_READ_THUNK_OFFSET: GuestAddr = 0x7510;
const PELOCK_DECODER_CALL_OFFSET: GuestAddr = 0xb2a;
const PELOCK_DECODER_RETURN_OFFSET: GuestAddr = 0xb2f;
const PELOCK_DECODER_FREE_CALL_OFFSET: GuestAddr = 0xb56;
const PELOCK_DECODER_FREE_RETURN_OFFSET: GuestAddr = 0xb5b;
const PELOCK_SECOND_PARSE_CALL_OFFSET: GuestAddr = 0x51be;
const PELOCK_SECOND_PARSE_RETURN_OFFSET: GuestAddr = 0x51c3;
const PELOCK_POST_073F0_OFFSET: GuestAddr = 0x52b9;
const PELOCK_POST_073F0_GATES_OFFSET: GuestAddr = 0x52cd;
const PELOCK_POST_073F0_LOOP_OFFSET: GuestAddr = 0x52e0;
const PELOCK_POST_073F0_FAIL_OFFSET: GuestAddr = 0x56f7;
const PELOCK_FIRST_08180_RETURN_OFFSET: GuestAddr = 0x538b;
const PELOCK_SECOND_08180_RETURN_OFFSET: GuestAddr = 0x54b0;
const PELOCK_06E40_RETURN_OFFSET: GuestAddr = 0x555f;
const PELOCK_MODE5_06E40_CALL_OFFSET: GuestAddr = 0x58bb;
const PELOCK_MODE5_06E40_RETURN_OFFSET: GuestAddr = 0x58ea;
const PELOCK_ENTRY_STUB_LEN: usize = 4096;
const PELOCK_STUB_IMM1_OFFSET: GuestAddr = 0x1;
const PELOCK_STUB_IMM2_OFFSET: GuestAddr = 0x6;
const PELOCK_STUB_IMM2_VALUE: u32 = 0x200;

const DECODED_DESCRIPTOR_ENCODED_PAYLOAD_OFFSET: GuestAddr = 0x00;
const DECODED_DESCRIPTOR_DECODED_PAYLOAD_OFFSET: GuestAddr = 0x08;
const DECODED_DESCRIPTOR_ENCODED_SIZE_OFFSET: GuestAddr = 0x10;
const DECODED_DESCRIPTOR_DECODED_SIZE_HIGH_OFFSET: GuestAddr = 0x1c;

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
const SLOT_DECODED_STAGE_INJECTED: usize = 12;

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
    "decoded_stage_injected",
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
    decoder_call_pc: Cell<GuestAddr>,
    decoder_return_pc: Cell<GuestAddr>,
    decoder_free_call_pc: Cell<GuestAddr>,
    decoder_free_return_pc: Cell<GuestAddr>,
    second_parse_call_pc: Cell<GuestAddr>,
    second_parse_return_pc: Cell<GuestAddr>,
    post_073f0_pc: Cell<GuestAddr>,
    post_073f0_gates_pc: Cell<GuestAddr>,
    post_073f0_loop_pc: Cell<GuestAddr>,
    post_073f0_fail_pc: Cell<GuestAddr>,
    first_08180_return_pc: Cell<GuestAddr>,
    second_08180_return_pc: Cell<GuestAddr>,
    return_06e40_pc: Cell<GuestAddr>,
    mode5_06e40_call_pc: Cell<GuestAddr>,
    mode5_06e40_return_pc: Cell<GuestAddr>,
    diagnostic_trace: Cell<bool>,
    decoder_scratch: Cell<GuestAddr>,
    decoder_scratch_len: Cell<usize>,
    read_count: Cell<u32>,
    has_stub_override: Cell<bool>,
    stub_len: Cell<usize>,
    health: UnpackerHealth,
    stream: MemoryBackedStream,
    baseline_entry_stub: RefCell<[u8; PELOCK_ENTRY_STUB_LEN]>,
    entry_stub: RefCell<[u8; PELOCK_ENTRY_STUB_LEN]>,
}

impl Default for PelockTarget {
    fn default() -> Self {
        Self {
            seek_pc: Cell::new(0),
            read_pc: Cell::new(0),
            decoder_call_pc: Cell::new(0),
            decoder_return_pc: Cell::new(0),
            decoder_free_call_pc: Cell::new(0),
            decoder_free_return_pc: Cell::new(0),
            second_parse_call_pc: Cell::new(0),
            second_parse_return_pc: Cell::new(0),
            post_073f0_pc: Cell::new(0),
            post_073f0_gates_pc: Cell::new(0),
            post_073f0_loop_pc: Cell::new(0),
            post_073f0_fail_pc: Cell::new(0),
            first_08180_return_pc: Cell::new(0),
            second_08180_return_pc: Cell::new(0),
            return_06e40_pc: Cell::new(0),
            mode5_06e40_call_pc: Cell::new(0),
            mode5_06e40_return_pc: Cell::new(0),
            diagnostic_trace: Cell::new(false),
            decoder_scratch: Cell::new(0),
            decoder_scratch_len: Cell::new(0),
            read_count: Cell::new(0),
            has_stub_override: Cell::new(false),
            stub_len: Cell::new(PELOCK_ENTRY_STUB_LEN),
            health: UnpackerHealth::new("Pelock", PELOCK_HEALTH_SLOTS),
            stream: MemoryBackedStream::default(),
            baseline_entry_stub: RefCell::new([0; PELOCK_ENTRY_STUB_LEN]),
            entry_stub: RefCell::new([0; PELOCK_ENTRY_STUB_LEN]),
        }
    }
}

impl PelockTarget {
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
        let resolve_pc = |offset: GuestAddr, kind: &str| {
            harness
                .bd_engine
                .resolve_module_address(&format!("pelock.xmd:+{offset:#x}"), kind)
        };
        let seek_pc = resolve_pc(PELOCK_SEEK_THUNK_OFFSET, "Pelock seek hook")?;
        let read_pc = resolve_pc(PELOCK_READ_THUNK_OFFSET, "Pelock read hook")?;
        let decoder_call_pc = resolve_pc(PELOCK_DECODER_CALL_OFFSET, "Pelock decoder call hook")?;
        let decoder_return_pc = resolve_pc(PELOCK_DECODER_RETURN_OFFSET, "Pelock decoder return")?;
        let decoder_free_call_pc = resolve_pc(
            PELOCK_DECODER_FREE_CALL_OFFSET,
            "Pelock decoder cleanup hook",
        )?;
        let decoder_free_return_pc = resolve_pc(
            PELOCK_DECODER_FREE_RETURN_OFFSET,
            "Pelock decoder cleanup return",
        )?;
        let diagnostic_trace = std::env::var_os("PELOCK_DIAGNOSTIC_TRACE").is_some();
        let second_parse_call_pc = if diagnostic_trace {
            resolve_pc(PELOCK_SECOND_PARSE_CALL_OFFSET, "Pelock second parser call")?
        } else {
            0
        };
        let second_parse_return_pc = if diagnostic_trace {
            resolve_pc(
                PELOCK_SECOND_PARSE_RETURN_OFFSET,
                "Pelock second parser return",
            )?
        } else {
            0
        };
        let post_073f0_pc = if diagnostic_trace {
            resolve_pc(PELOCK_POST_073F0_OFFSET, "Pelock post-073F0 return")?
        } else {
            0
        };
        let post_073f0_gates_pc = if diagnostic_trace {
            resolve_pc(
                PELOCK_POST_073F0_GATES_OFFSET,
                "Pelock post-073F0 gates passed",
            )?
        } else {
            0
        };
        let post_073f0_loop_pc = if diagnostic_trace {
            resolve_pc(PELOCK_POST_073F0_LOOP_OFFSET, "Pelock post-073F0 loop")?
        } else {
            0
        };
        let post_073f0_fail_pc = if diagnostic_trace {
            resolve_pc(PELOCK_POST_073F0_FAIL_OFFSET, "Pelock post-073F0 failure")?
        } else {
            0
        };
        let first_08180_return_pc = if diagnostic_trace {
            resolve_pc(
                PELOCK_FIRST_08180_RETURN_OFFSET,
                "Pelock first 08180 return",
            )?
        } else {
            0
        };
        let second_08180_return_pc = if diagnostic_trace {
            resolve_pc(
                PELOCK_SECOND_08180_RETURN_OFFSET,
                "Pelock second 08180 return",
            )?
        } else {
            0
        };
        let return_06e40_pc = if diagnostic_trace {
            resolve_pc(PELOCK_06E40_RETURN_OFFSET, "Pelock 06E40 return")?
        } else {
            0
        };
        let mode5_06e40_call_pc = if diagnostic_trace {
            resolve_pc(PELOCK_MODE5_06E40_CALL_OFFSET, "Pelock mode-5 06E40 call")?
        } else {
            0
        };
        let mode5_06e40_return_pc = if diagnostic_trace {
            resolve_pc(
                PELOCK_MODE5_06E40_RETURN_OFFSET,
                "Pelock mode-5 06E40 return",
            )?
        } else {
            0
        };
        let stub_buf: GuestAddr = harness
            .qemu()
            .read_reg(Regs::R9)
            .unwrap()
            .try_into()
            .unwrap();

        self.seek_pc.set(seek_pc);
        self.read_pc.set(read_pc);
        self.decoder_call_pc.set(decoder_call_pc);
        self.decoder_return_pc.set(decoder_return_pc);
        self.decoder_free_call_pc.set(decoder_free_call_pc);
        self.decoder_free_return_pc.set(decoder_free_return_pc);
        self.second_parse_call_pc.set(second_parse_call_pc);
        self.second_parse_return_pc.set(second_parse_return_pc);
        self.post_073f0_pc.set(post_073f0_pc);
        self.post_073f0_gates_pc.set(post_073f0_gates_pc);
        self.post_073f0_loop_pc.set(post_073f0_loop_pc);
        self.post_073f0_fail_pc.set(post_073f0_fail_pc);
        self.first_08180_return_pc.set(first_08180_return_pc);
        self.second_08180_return_pc.set(second_08180_return_pc);
        self.return_06e40_pc.set(return_06e40_pc);
        self.mode5_06e40_call_pc.set(mode5_06e40_call_pc);
        self.mode5_06e40_return_pc.set(mode5_06e40_return_pc);
        self.diagnostic_trace.set(diagnostic_trace);

        let decoder_scratch_len = harness.max_target_input_size();
        let decoder_scratch = harness
            .qemu()
            .map_private(0, decoder_scratch_len, MmapPerms::ReadWrite)
            .map_err(|e| Error::unknown(format!("Failed to map Pelock decoder scratch: {e}")))?;
        self.decoder_scratch.set(decoder_scratch);
        self.decoder_scratch_len.set(decoder_scratch_len);

        let mut entry_stub = [0u8; PELOCK_ENTRY_STUB_LEN];
        harness
            .qemu()
            .read_mem(stub_buf, &mut entry_stub)
            .map_err(|e| Error::unknown(format!("Failed to snapshot Pelock entry stub: {e:?}")))?;
        *self.baseline_entry_stub.borrow_mut() = entry_stub;
        *self.entry_stub.borrow_mut() = entry_stub;
        self.stub_len.set(PELOCK_ENTRY_STUB_LEN);

        harness.qemu().set_breakpoint(seek_pc);
        harness.qemu().set_breakpoint(read_pc);
        harness.qemu().set_breakpoint(decoder_call_pc);
        harness.qemu().set_breakpoint(decoder_free_call_pc);
        if diagnostic_trace {
            harness.qemu().set_breakpoint(second_parse_call_pc);
            harness.qemu().set_breakpoint(second_parse_return_pc);
            harness.qemu().set_breakpoint(post_073f0_pc);
            harness.qemu().set_breakpoint(post_073f0_gates_pc);
            harness.qemu().set_breakpoint(post_073f0_loop_pc);
            harness.qemu().set_breakpoint(post_073f0_fail_pc);
            harness.qemu().set_breakpoint(first_08180_return_pc);
            harness.qemu().set_breakpoint(second_08180_return_pc);
            harness.qemu().set_breakpoint(return_06e40_pc);
            harness.qemu().set_breakpoint(mode5_06e40_call_pc);
            harness.qemu().set_breakpoint(mode5_06e40_return_pc);
        }

        log::debug!(
            "Pelock init: worker={:#x} seek_hook={seek_pc:#x} read_hook={read_pc:#x} decoder_hook={decoder_call_pc:#x} decoder_scratch={decoder_scratch:#x}:{decoder_scratch_len:#x}",
            harness.entry_point,
        );

        Ok(())
    }

    fn prepare_input(&self, qemu: &Qemu, input: &[u8], input_len: GuestReg) -> Result<(), Error> {
        let total_len = (input_len as usize).min(input.len());
        let input = &input[..total_len];

        let stream_overlay = StreamOverlay {
            input_offset: 0,
            stream_offset: 0,
            max_len: input.len(),
        };
        self.stream.rebuild_with_overlays(input, &[stream_overlay]);
        self.has_stub_override.set(false);

        let mut patched_stub = *self.baseline_entry_stub.borrow();
        let mut stub_len = PELOCK_ENTRY_STUB_LEN;

        match PeFile::parse(input) {
            Ok(file) => match file.entry_bytes(Some(PELOCK_ENTRY_STUB_LEN)) {
                Some(entry_bytes) if !entry_bytes.is_empty() => {
                    stub_len = patched_stub.len().min(entry_bytes.len());
                    patched_stub[..stub_len].copy_from_slice(&entry_bytes[..stub_len]);
                    self.has_stub_override.set(true);

                    if stub_len < PELOCK_ENTRY_STUB_LEN {
                        log::debug!(
                            "Pelock prepare_input: copied short PE entry stub ({stub_len}/{PELOCK_ENTRY_STUB_LEN} bytes)"
                        );
                    } else {
                        log::debug!(
                            "Pelock prepare_input: copied PE entry stub into R9 injection buffer"
                        );
                    }
                }
                Some(_) => {
                    log::debug!("Pelock prepare_input: PE entry-point byte slice is empty");
                }
                None => {
                    log::debug!(
                        "Pelock prepare_input: PE entry point does not resolve to raw bytes; using runtime stub"
                    );
                }
            },
            Err(_) => {
                log::debug!(
                    "Pelock prepare_input: input is not a parseable PE; using runtime stub"
                );
            }
        }

        if !self.has_stub_override.get() {
            let r12: u32 = qemu
                .read_reg(Regs::R12)
                .unwrap()
                .try_into()
                .unwrap_or_default();
            let out_va = r12.wrapping_add(0x100);
            patched_stub[PELOCK_STUB_IMM1_OFFSET as usize..PELOCK_STUB_IMM1_OFFSET as usize + 4]
                .copy_from_slice(&out_va.to_le_bytes());
            patched_stub[PELOCK_STUB_IMM2_OFFSET as usize..PELOCK_STUB_IMM2_OFFSET as usize + 4]
                .copy_from_slice(&PELOCK_STUB_IMM2_VALUE.to_le_bytes());
        }

        *self.entry_stub.borrow_mut() = patched_stub;
        self.stub_len.set(stub_len);

        let stub_buf: GuestAddr = qemu
            .read_reg(Regs::R9)
            .map_err(|e| Error::unknown(format!("Failed to read Pelock R9 stub pointer: {e:?}")))?
            .try_into()
            .map_err(|e| Error::unknown(format!("Invalid Pelock R9 stub pointer: {e:?}")))?;
        qemu.write_mem(stub_buf, &patched_stub[..stub_len])
            .map_err(|e| Error::unknown(format!("Failed to patch Pelock entry stub: {e:?}")))?;

        Ok(())
    }

    fn reset(&self, harness: &CevaEmuHarness<'_>) -> Result<(), Error> {
        restore_nonvolatile_regs(harness)?;
        self.stream.reset();
        self.read_count.set(0);
        self.health.reset_run();
        if self.diagnostic_trace.get() {
            harness
                .qemu()
                .set_breakpoint(self.second_parse_call_pc.get());
            harness
                .qemu()
                .set_breakpoint(self.second_parse_return_pc.get());
            harness.qemu().set_breakpoint(self.post_073f0_pc.get());
            harness
                .qemu()
                .set_breakpoint(self.post_073f0_gates_pc.get());
            harness.qemu().set_breakpoint(self.post_073f0_loop_pc.get());
            harness.qemu().set_breakpoint(self.post_073f0_fail_pc.get());
            harness
                .qemu()
                .set_breakpoint(self.first_08180_return_pc.get());
            harness
                .qemu()
                .set_breakpoint(self.second_08180_return_pc.get());
            harness.qemu().set_breakpoint(self.return_06e40_pc.get());
            harness
                .qemu()
                .set_breakpoint(self.mode5_06e40_call_pc.get());
            harness
                .qemu()
                .set_breakpoint(self.mode5_06e40_return_pc.get());
        }
        Ok(())
    }

    fn handle_breakpoint(&self, harness: &CevaEmuHarness<'_>) -> Result<bool, Error> {
        let qemu = harness.qemu();
        let pc: GuestAddr = qemu.read_reg(Regs::Pc).unwrap().try_into().unwrap();

        if self.diagnostic_trace.get() && pc == self.second_parse_call_pc.get() {
            let base: GuestAddr = qemu.read_reg(Regs::Rcx).unwrap().try_into().unwrap();
            let cursor: usize = qemu.read_reg(Regs::Rdx).unwrap().try_into().unwrap();
            let max_len: usize = qemu.read_reg(Regs::R8).unwrap().try_into().unwrap();
            let expected: u64 = qemu.read_reg(Regs::R9).unwrap().try_into().unwrap();
            let mut window = [0u8; 80];
            qemu.read_mem(base + cursor as GuestAddr, &mut window)
                .map_err(|e| {
                    Error::unknown(format!("Failed to read Pelock parser window: {e:?}"))
                })?;
            eprintln!(
                "PELOCK_DIAG second_parse_call rcx={base:#x} cursor={cursor:#x} max_len={max_len:#x} expected={expected:#x} window={}",
                window
                    .iter()
                    .map(|byte| format!("{byte:02x}"))
                    .collect::<Vec<_>>()
                    .join(" ")
            );
            qemu.remove_breakpoint(self.second_parse_call_pc.get());
            return Ok(true);
        }

        if self.diagnostic_trace.get() && pc == self.second_parse_return_pc.get() {
            let result: u32 = qemu.read_reg(Regs::Rax).unwrap().try_into().unwrap();
            eprintln!(
                "PELOCK_DIAG second_parse_return eax={result:#x} signed={}",
                result as i32
            );
            qemu.remove_breakpoint(self.second_parse_return_pc.get());
            return Ok(true);
        }

        if self.diagnostic_trace.get() && pc == self.post_073f0_pc.get() {
            let result: u32 = qemu.read_reg(Regs::Rax).unwrap().try_into().unwrap();
            let decoded_size: u32 = qemu.read_reg(Regs::R13).unwrap().try_into().unwrap();
            eprintln!(
                "PELOCK_DIAG post_073f0 eax={result:#x} signed={} decoded_size={decoded_size:#x}",
                result as i32
            );
            qemu.remove_breakpoint(self.post_073f0_pc.get());
            return Ok(true);
        }

        if self.diagnostic_trace.get() && pc == self.post_073f0_gates_pc.get() {
            eprintln!("PELOCK_DIAG post_073f0_initial_gates=passed");
            qemu.remove_breakpoint(self.post_073f0_gates_pc.get());
            return Ok(true);
        }

        if self.diagnostic_trace.get() && pc == self.post_073f0_loop_pc.get() {
            let cursor: u32 = qemu.read_reg(Regs::Rdi).unwrap().try_into().unwrap();
            let decoded_size: u32 = qemu.read_reg(Regs::R13).unwrap().try_into().unwrap();
            eprintln!(
                "PELOCK_DIAG post_073f0_loop cursor={cursor:#x} decoded_size={decoded_size:#x}"
            );
            qemu.remove_breakpoint(self.post_073f0_loop_pc.get());
            return Ok(true);
        }

        if self.diagnostic_trace.get() && pc == self.post_073f0_fail_pc.get() {
            let result = qemu.read_reg(Regs::R12).unwrap() as u32;
            let decoded_size = qemu.read_reg(Regs::R13).unwrap() as u32;
            let cursor = qemu.read_reg(Regs::Rdi).unwrap() as u32;
            eprintln!(
                "PELOCK_DIAG post_073f0_fail result={result:#x} decoded_size={decoded_size:#x} cursor={cursor:#x}"
            );
            qemu.remove_breakpoint(self.post_073f0_fail_pc.get());
            return Ok(true);
        }

        if self.diagnostic_trace.get() && pc == self.first_08180_return_pc.get() {
            let result = qemu.read_reg(Regs::Rax).unwrap() as u32;
            eprintln!(
                "PELOCK_DIAG first_08180_return eax={result:#x} signed={}",
                result as i32
            );
            qemu.remove_breakpoint(self.first_08180_return_pc.get());
            return Ok(true);
        }

        if self.diagnostic_trace.get() && pc == self.second_08180_return_pc.get() {
            let result = qemu.read_reg(Regs::Rax).unwrap() as u32;
            eprintln!(
                "PELOCK_DIAG second_08180_return eax={result:#x} signed={}",
                result as i32
            );
            qemu.remove_breakpoint(self.second_08180_return_pc.get());
            return Ok(true);
        }

        if self.diagnostic_trace.get() && pc == self.return_06e40_pc.get() {
            let result = qemu.read_reg(Regs::Rax).unwrap() as u32;
            eprintln!(
                "PELOCK_DIAG 06e40_return eax={result:#x} signed={}",
                result as i32
            );
            qemu.remove_breakpoint(self.return_06e40_pc.get());
            return Ok(true);
        }

        if self.diagnostic_trace.get() && pc == self.mode5_06e40_call_pc.get() {
            // This probe is at the basic-block boundary before the call arguments
            // are materialized. Their source values are still live here.
            let base = qemu.read_reg(Regs::R13).unwrap() as GuestAddr;
            let cursor = qemu.read_reg(Regs::Rdi).unwrap() as usize;
            let size = qemu.read_reg(Regs::R12).unwrap() as usize;
            let window_len = size.saturating_sub(cursor).min(256);
            let mut window = vec![0u8; window_len];
            qemu.read_mem(base + cursor as GuestAddr, &mut window)
                .map_err(|e| {
                    Error::unknown(format!("Failed to read Pelock mode-5 window: {e:?}"))
                })?;
            eprintln!(
                "PELOCK_DIAG mode5_06e40_call base={base:#x} cursor={cursor:#x} size={size:#x} window={}",
                window
                    .iter()
                    .map(|byte| format!("{byte:02x}"))
                    .collect::<Vec<_>>()
                    .join(" ")
            );
            qemu.remove_breakpoint(self.mode5_06e40_call_pc.get());
            return Ok(true);
        }

        if self.diagnostic_trace.get() && pc == self.mode5_06e40_return_pc.get() {
            let result = qemu.read_reg(Regs::Rax).unwrap() as u32;
            eprintln!(
                "PELOCK_DIAG mode5_06e40_return eax={result:#x} signed={}",
                result as i32
            );
            qemu.remove_breakpoint(self.mode5_06e40_return_pc.get());
            return Ok(true);
        }

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

        if pc == self.decoder_call_pc.get() {
            let descriptor: GuestAddr = qemu
                .read_reg(Regs::Rcx)
                .map_err(|e| {
                    Error::unknown(format!("Failed to read Pelock decoder descriptor: {e:?}"))
                })?
                .try_into()
                .map_err(|e| Error::unknown(format!("Invalid Pelock decoder descriptor: {e:?}")))?;
            let max_decoded_size: usize = qemu
                .read_reg(Regs::Rdi)
                .map_err(|e| {
                    Error::unknown(format!("Failed to read Pelock decoder capacity: {e:?}"))
                })?
                .try_into()
                .unwrap_or(usize::MAX);

            let mut encoded_payload_bytes = [0u8; 8];
            let mut encoded_size_bytes = [0u8; 4];
            qemu.read_mem(
                descriptor + DECODED_DESCRIPTOR_ENCODED_PAYLOAD_OFFSET,
                &mut encoded_payload_bytes,
            )
            .map_err(|e| {
                Error::unknown(format!(
                    "Failed to read Pelock encoded payload pointer: {e:?}"
                ))
            })?;
            qemu.read_mem(
                descriptor + DECODED_DESCRIPTOR_ENCODED_SIZE_OFFSET,
                &mut encoded_size_bytes,
            )
            .map_err(|e| {
                Error::unknown(format!("Failed to read Pelock encoded payload size: {e:?}"))
            })?;

            let encoded_payload: GuestAddr = u64::from_le_bytes(encoded_payload_bytes)
                .try_into()
                .map_err(|e| {
                Error::unknown(format!("Invalid Pelock encoded payload pointer: {e:?}"))
            })?;
            let encoded_size = u32::from_le_bytes(encoded_size_bytes) as usize;
            let decoded_size = max_decoded_size
                .saturating_sub(1)
                .min(encoded_size)
                .min(self.decoder_scratch_len.get());
            let decoder_scratch = self.decoder_scratch.get();

            if decoded_size != 0 {
                let mut decoded = vec![0u8; decoded_size];
                qemu.read_mem(encoded_payload, &mut decoded).map_err(|e| {
                    Error::unknown(format!(
                        "Failed to read Pelock manifest-selected decoded region at {encoded_payload:#x}: {e:?}"
                    ))
                })?;
                qemu.write_mem(decoder_scratch, &decoded).map_err(|e| {
                    Error::unknown(format!(
                        "Failed to write Pelock decoder scratch at {decoder_scratch:#x}: {e:?}"
                    ))
                })?;
            }

            qemu.write_mem(
                descriptor + DECODED_DESCRIPTOR_DECODED_PAYLOAD_OFFSET,
                &decoder_scratch.to_le_bytes(),
            )
            .map_err(|e| {
                Error::unknown(format!(
                    "Failed to set Pelock decoded payload pointer: {e:?}"
                ))
            })?;
            qemu.write_mem(
                descriptor + DECODED_DESCRIPTOR_DECODED_SIZE_HIGH_OFFSET,
                &(decoded_size as u32).to_le_bytes(),
            )
            .map_err(|e| {
                Error::unknown(format!("Failed to set Pelock decoded payload size: {e:?}"))
            })?;
            qemu.write_reg(
                Regs::Pc,
                GuestReg::try_from(self.decoder_return_pc.get()).unwrap(),
            )
            .map_err(|e| Error::unknown(format!("Failed to skip Pelock decoder call: {e:?}")))?;
            if harness.health_signals_enabled() {
                self.health.hit(SLOT_DECODED_STAGE_INJECTED);
            }
            return Ok(true);
        }

        if pc == self.decoder_free_call_pc.get() {
            qemu.write_reg(
                Regs::Pc,
                GuestReg::try_from(self.decoder_free_return_pc.get()).unwrap(),
            )
            .map_err(|e| {
                Error::unknown(format!(
                    "Failed to skip Pelock decoder scratch cleanup: {e:?}"
                ))
            })?;
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
