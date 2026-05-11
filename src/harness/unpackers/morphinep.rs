use std::cell::Cell;
use std::env;

use libafl::Error;
use libafl_qemu::{GuestAddr, GuestReg, Qemu, Regs};

use crate::harness::{CevaEmuHarness, CevaTarget};
use crate::harness::unpackers::health::UnpackerHealth;
use crate::harness::unpackers::stream::{MemoryBackedStream, StreamOverlay};

const MORPHINEP_SEEK_THUNK_OFFSET: GuestAddr = 0x658;
const MORPHINEP_READ_THUNK_OFFSET: GuestAddr = 0x668;
const MORPHINEP_ENTRYBUF_LEN: usize = 0x30;
const MORPHINEP_STAGE0_SEEK_OFFSET: usize = 0x400;
const MORPHINEP_STAGE0_LEN: usize = 0x4000;
const MORPHINEP_STAGE1_SEEK_OFFSET: usize = 0x600;
const MORPHINEP_STAGE1_LEN: usize = 0x100;
const MORPHINEP_A870_DELTA_FROM_WORKER: GuestAddr = 0x210;
const MORPHINEP_A8D0_DELTA_FROM_WORKER: GuestAddr = 0x1b0;
const MORPHINEP_A970_DELTA_FROM_WORKER: GuestAddr = 0x110;
const MORPHINEP_A970_FAULT_DELTA_FROM_A970: GuestAddr = 0x1c;

const SLOT_STAGE0_SEEK: usize = 0;
const SLOT_STAGE1_SEEK: usize = 1;
const SLOT_STAGE0_READ: usize = 2;
const SLOT_STAGE1_READ: usize = 3;
const SLOT_STAGE1_EQUAL: usize = 4;
const SLOT_STAGE1_SHORT: usize = 5;
const SLOT_STAGE1_ZERO: usize = 6;
const SLOT_COMPLETED: usize = 7;
const MORPHINEP_HEALTH_SLOTS: &[&str] = &[
    "stage0_seek",
    "stage1_seek",
    "stage0_read",
    "stage1_read",
    "stage1_equal",
    "stage1_short",
    "stage1_zero",
    "completed",
];

pub struct MorphinepTarget {
    seek_pc: Cell<GuestAddr>,
    read_pc: Cell<GuestAddr>,
    entry_buf_addr: Cell<GuestAddr>,
    a870_pc: Cell<GuestAddr>,
    a8d0_pc: Cell<GuestAddr>,
    a970_pc: Cell<GuestAddr>,
    a970_fault_pc: Cell<GuestAddr>,
    dispatch_probe_enabled: Cell<bool>,
    dispatch_probe_hit: Cell<bool>,
    a970_fault_probe_enabled: Cell<bool>,
    a970_fault_probe_hit: Cell<bool>,
    read_count: Cell<u32>,
    health: UnpackerHealth,
    stream: MemoryBackedStream,
}

impl Default for MorphinepTarget {
    fn default() -> Self {
        Self {
            seek_pc: Cell::new(0),
            read_pc: Cell::new(0),
            entry_buf_addr: Cell::new(0),
            a870_pc: Cell::new(0),
            a8d0_pc: Cell::new(0),
            a970_pc: Cell::new(0),
            a970_fault_pc: Cell::new(0),
            dispatch_probe_enabled: Cell::new(false),
            dispatch_probe_hit: Cell::new(false),
            a970_fault_probe_enabled: Cell::new(false),
            a970_fault_probe_hit: Cell::new(false),
            read_count: Cell::new(0),
            health: UnpackerHealth::new("Morphinep", MORPHINEP_HEALTH_SLOTS),
            stream: MemoryBackedStream::default(),
        }
    }
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

fn format_hex(bytes: &[u8]) -> String {
    let mut out = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        use std::fmt::Write as _;
        let _ = write!(&mut out, "{byte:02x}");
    }
    out
}

impl MorphinepTarget {
    const LEGACY_INPUT_LEN: usize = MORPHINEP_STAGE0_LEN + MORPHINEP_STAGE1_LEN;
    const STREAM_LAYOUT: [StreamOverlay; 2] = [
        StreamOverlay {
            input_offset: MORPHINEP_ENTRYBUF_LEN,
            stream_offset: MORPHINEP_STAGE0_SEEK_OFFSET,
            max_len: MORPHINEP_STAGE0_LEN,
        },
        StreamOverlay {
            input_offset: MORPHINEP_ENTRYBUF_LEN + MORPHINEP_STAGE0_LEN,
            stream_offset: MORPHINEP_STAGE1_SEEK_OFFSET,
            max_len: MORPHINEP_STAGE1_LEN,
        },
    ];
}

impl CevaTarget for MorphinepTarget {
    fn name(&self) -> &'static str {
        "Morphinep"
    }

    fn initialize(
        &mut self,
        harness: &mut CevaEmuHarness<'_>,
        _max_bp_hit_count: Option<u64>,
    ) -> Result<(), Error> {
        let seek_pc = harness.entry_point + MORPHINEP_SEEK_THUNK_OFFSET;
        let read_pc = harness.entry_point + MORPHINEP_READ_THUNK_OFFSET;
        let pe_addr: GuestAddr = harness
            .qemu()
            .read_reg(Regs::Rcx)
            .unwrap()
            .try_into()
            .unwrap();
        let entry_buf_addr: GuestAddr = harness
            .qemu()
            .read_reg(Regs::R9)
            .unwrap()
            .try_into()
            .unwrap();
        let a870_pc = harness.entry_point - MORPHINEP_A870_DELTA_FROM_WORKER;
        let a8d0_pc = harness.entry_point - MORPHINEP_A8D0_DELTA_FROM_WORKER;
        let a970_pc = harness.entry_point - MORPHINEP_A970_DELTA_FROM_WORKER;
        let a970_fault_pc = a970_pc + MORPHINEP_A970_FAULT_DELTA_FROM_A970;
        let dispatch_probe_enabled = env::var_os("MORPHINEP_DISPATCH_PROBE").is_some();
        let a970_fault_probe_enabled = env::var_os("MORPHINEP_A970_FAULT_PROBE").is_some();

        self.seek_pc.set(seek_pc);
        self.read_pc.set(read_pc);
        self.entry_buf_addr.set(entry_buf_addr);
        self.a870_pc.set(a870_pc);
        self.a8d0_pc.set(a8d0_pc);
        self.a970_pc.set(a970_pc);
        self.a970_fault_pc.set(a970_fault_pc);
        self.dispatch_probe_enabled.set(dispatch_probe_enabled);
        self.dispatch_probe_hit.set(false);
        self.a970_fault_probe_enabled.set(a970_fault_probe_enabled);
        self.a970_fault_probe_hit.set(false);

        harness.qemu().set_breakpoint(seek_pc);
        harness.qemu().set_breakpoint(read_pc);
        if dispatch_probe_enabled {
            harness.qemu().set_breakpoint(a870_pc);
            harness.qemu().set_breakpoint(a8d0_pc);
            harness.qemu().set_breakpoint(a970_pc);
        }
        if a970_fault_probe_enabled {
            harness.qemu().set_breakpoint(a970_fault_pc);
        }

        log::debug!(
            "Morphinep init: entry={:#x} pe={pe_addr:#x} entry_buf={entry_buf_addr:#x} seek_hook={seek_pc:#x} read_hook={read_pc:#x}",
            harness.entry_point,
        );
        let mut pe_ptr_buf = [0u8; 8];
        if harness.qemu().read_mem(pe_addr + 0x138, &mut pe_ptr_buf).is_ok() {
            let pe_ptr = u64::from_le_bytes(pe_ptr_buf) as GuestAddr;
            let mut addend_buf = [0u8; 4];
            if harness.qemu().read_mem(pe_ptr + 0x0c, &mut addend_buf).is_ok() {
                let addend = u32::from_le_bytes(addend_buf);
                log::info!(
                    "Morphinep pe_addend: pe={pe_addr:#x} ptr138={pe_ptr:#x} ptr138_plus_0xc={addend:#x}"
                );
            }
        }
        let mut entry_buf = [0u8; MORPHINEP_ENTRYBUF_LEN];
        if harness.qemu().read_mem(entry_buf_addr, &mut entry_buf).is_ok() {
            log::info!(
                "Morphinep baseline entry_buf[0x{:x}]={}",
                MORPHINEP_ENTRYBUF_LEN,
                format_hex(&entry_buf)
            );
        }
        if dispatch_probe_enabled {
            log::info!(
                "Morphinep dispatch probe enabled: a870={a870_pc:#x} a8d0={a8d0_pc:#x} a970={a970_pc:#x}"
            );
        }
        if a970_fault_probe_enabled {
            log::info!("Morphinep A970 fault probe enabled: a970_fault={a970_fault_pc:#x}");
        }

        Ok(())
    }

    fn prepare_input(&self, _qemu: &Qemu, input: &[u8], input_len: GuestReg) -> Result<(), Error> {
        let final_input_len = (input_len as usize).min(input.len());
        let (entry_patch, stream_input) = if final_input_len >= MORPHINEP_ENTRYBUF_LEN + Self::LEGACY_INPUT_LEN {
            (&input[..MORPHINEP_ENTRYBUF_LEN], &input[..final_input_len])
        } else {
            (&[][..], &input[..final_input_len])
        };

        if !entry_patch.is_empty() {
            _qemu
                .write_mem(self.entry_buf_addr.get(), entry_patch)
                .map_err(|e| Error::unknown(format!("Failed to patch Morphinep entry buffer: {e:?}")))?;
        }

        self.stream
            .rebuild_with_overlays(stream_input, &Self::STREAM_LAYOUT);
        Ok(())
    }

    fn reset(&self, harness: &CevaEmuHarness<'_>) -> Result<(), Error> {
        restore_nonvolatile_regs(harness)?;
        self.stream.reset();
        self.read_count.set(0);
        self.dispatch_probe_hit.set(false);
        self.a970_fault_probe_hit.set(false);
        self.health.reset_run();
        Ok(())
    }

    fn handle_breakpoint(&self, harness: &CevaEmuHarness<'_>) -> Result<bool, Error> {
        let qemu = harness.qemu();
        let pc: GuestAddr = qemu.read_reg(Regs::Pc).unwrap().try_into().unwrap();

        if self.dispatch_probe_enabled.get() {
            let label = if pc == self.a870_pc.get() {
                Some("a870")
            } else if pc == self.a8d0_pc.get() {
                Some("a8d0")
            } else if pc == self.a970_pc.get() {
                Some("a970")
            } else {
                None
            };

            if let Some(label) = label {
                let rsp: GuestAddr = qemu.read_reg(Regs::Sp).unwrap().try_into().unwrap();
                let rcx: GuestAddr = qemu.read_reg(Regs::Rcx).unwrap().try_into().unwrap();
                let rdx: GuestAddr = qemu.read_reg(Regs::Rdx).unwrap().try_into().unwrap();
                let r8: GuestAddr = qemu.read_reg(Regs::R8).unwrap().try_into().unwrap();
                let r9: GuestAddr = qemu.read_reg(Regs::R9).unwrap().try_into().unwrap();
                let rbp: GuestAddr = qemu.read_reg(Regs::Rbp).unwrap().try_into().unwrap();
                let mut arg3_buf = [0u8; 64];
                let arg3 = if qemu.read_mem(r8, &mut arg3_buf).is_ok() {
                    Some(arg3_buf.as_slice())
                } else {
                    None
                };
                if !self.dispatch_probe_hit.get() {
                    log::info!(
                        "Morphinep dispatch hit: label={label} pc={pc:#x} rsp={rsp:#x} rbp={rbp:#x} rcx={rcx:#x} rdx={rdx:#x} r8={r8:#x} r9={r9:#x} arg3_64={}",
                        arg3
                            .map(format_hex)
                            .unwrap_or_else(|| "<unreadable>".to_string())
                    );
                }
                self.dispatch_probe_hit.set(true);
                qemu.write_reg(Regs::Pc, GuestReg::try_from(harness.exit_point).unwrap())
                    .map_err(|e| Error::unknown(format!("Failed to redirect PC to exit point: {e:?}")))?;
                return Ok(true);
            }
        }

        if self.a970_fault_probe_enabled.get() && pc == self.a970_fault_pc.get() {
            let rsp: GuestAddr = qemu.read_reg(Regs::Sp).unwrap().try_into().unwrap();
            let rcx: GuestAddr = qemu.read_reg(Regs::Rcx).unwrap().try_into().unwrap();
            let rdx: GuestAddr = qemu.read_reg(Regs::Rdx).unwrap().try_into().unwrap();
            let r8: GuestAddr = qemu.read_reg(Regs::R8).unwrap().try_into().unwrap();
            let r9: GuestAddr = qemu.read_reg(Regs::R9).unwrap().try_into().unwrap();
            let mut a1_buf = [0u8; 32];
            let mut a3_buf = [0u8; 32];
            let a1 = if qemu.read_mem(rcx, &mut a1_buf).is_ok() {
                Some(a1_buf.as_slice())
            } else {
                None
            };
            let a3 = if qemu.read_mem(r8, &mut a3_buf).is_ok() {
                Some(a3_buf.as_slice())
            } else {
                None
            };
            if !self.a970_fault_probe_hit.get() {
                log::info!(
                    "Morphinep A970 fault probe: pc={pc:#x} rsp={rsp:#x} rcx={rcx:#x} rdx={rdx:#x} r8={r8:#x} r9={r9:#x} a1_32={} a3_32={}",
                    a1.map(format_hex).unwrap_or_else(|| "<unreadable>".to_string()),
                    a3.map(format_hex).unwrap_or_else(|| "<unreadable>".to_string()),
                );
            }
            self.a970_fault_probe_hit.set(true);
            qemu.write_reg(Regs::Pc, GuestReg::try_from(harness.exit_point).unwrap())
                .map_err(|e| Error::unknown(format!("Failed to redirect PC to exit point: {e:?}")))?;
            return Ok(true);
        }

        if pc == self.seek_pc.get() {
            let offset: i64 = qemu.read_reg(Regs::Rdx).unwrap().try_into().unwrap();
            let action: u64 = qemu.read_reg(Regs::R8).unwrap().try_into().unwrap();
            if harness.health_signals_enabled() && action == 0 {
                match usize::try_from(offset).ok() {
                    Some(MORPHINEP_STAGE0_SEEK_OFFSET) => self.health.hit(SLOT_STAGE0_SEEK),
                    Some(MORPHINEP_STAGE1_SEEK_OFFSET) => self.health.hit(SLOT_STAGE1_SEEK),
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
