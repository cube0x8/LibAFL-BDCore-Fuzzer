use std::{
    cell::RefCell,
    collections::hash_map::DefaultHasher,
    fmt::{self, Write},
    fs,
    hash::{Hash, Hasher},
    path::{Path, PathBuf},
    sync::{
        atomic::{AtomicBool, AtomicI32, AtomicU64, Ordering},
        Arc, Mutex,
    },
    time::Instant,
};

use libafl::{
    executors::ExitKind,
    inputs::HasTargetBytes,
    observers::{ConstMapObserver, ObserversTuple},
};
use libafl_bolts::AsSlice;
use libafl_qemu::{
    emu::EmulatorModules,
    modules::{EmulatorModule, EmulatorModuleTuple},
    qemu::Hook,
    GuestAddr, Qemu, Regs,
};
use nix::libc;

static mut TMIN_PC_STATE: [u8; 2] = [0; 2];
static CRASH_CONTEXT_FD: AtomicI32 = AtomicI32::new(libc::STDERR_FILENO);
static LAST_GUEST_BLOCK: AtomicU64 = AtomicU64::new(0);
static LAST_GUEST_BLOCK_FD: AtomicI32 = AtomicI32::new(-1);

fn append_diagnostic_line(path: &Path, line: &str) {
    let Ok(mut file) = fs::OpenOptions::new().create(true).append(true).open(path) else {
        return;
    };
    let _ = std::io::Write::write_all(&mut file, line.as_bytes());
    let _ = std::io::Write::write_all(&mut file, b"\n");
}

#[derive(Clone, Copy, Debug)]
pub struct CrashContextModule {
    crash_context_enabled: bool,
    last_block_enabled: bool,
}

fn append_crash_context_text(buffer: &mut [u8], cursor: &mut usize, text: &[u8]) {
    let remaining = buffer.len().saturating_sub(*cursor);
    let count = remaining.min(text.len());
    buffer[*cursor..*cursor + count].copy_from_slice(&text[..count]);
    *cursor += count;
}

fn append_crash_context_hex(buffer: &mut [u8], cursor: &mut usize, value: u64) {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    append_crash_context_text(buffer, cursor, b"0x");

    let mut started = false;
    for shift in (0..16).rev().map(|nibble| nibble * 4) {
        let digit = ((value >> shift) & 0xf) as usize;
        if digit != 0 || started || shift == 0 {
            started = true;
            append_crash_context_text(buffer, cursor, &HEX[digit..=digit]);
        }
    }
}

fn write_crash_context(qemu: Qemu, signal: i32) {
    let mut buffer = [0u8; 512];
    let mut cursor = 0;
    append_crash_context_text(&mut buffer, &mut cursor, b"BDCORE_CRASH_CONTEXT signal=");
    append_crash_context_hex(&mut buffer, &mut cursor, signal as u64);

    for (name, reg) in [
        (b" rip=".as_slice(), Regs::Rip),
        (b" rsp=".as_slice(), Regs::Rsp),
        (b" rax=".as_slice(), Regs::Rax),
        (b" rbx=".as_slice(), Regs::Rbx),
        (b" rcx=".as_slice(), Regs::Rcx),
        (b" rdx=".as_slice(), Regs::Rdx),
        (b" rsi=".as_slice(), Regs::Rsi),
        (b" rdi=".as_slice(), Regs::Rdi),
        (b" r8=".as_slice(), Regs::R8),
        (b" r9=".as_slice(), Regs::R9),
        (b" r10=".as_slice(), Regs::R10),
        (b" r11=".as_slice(), Regs::R11),
    ] {
        append_crash_context_text(&mut buffer, &mut cursor, name);
        append_crash_context_hex(
            &mut buffer,
            &mut cursor,
            qemu.read_reg(reg).unwrap_or_default(),
        );
    }
    append_crash_context_text(&mut buffer, &mut cursor, b"\n");

    // The callback runs from QEMU's nested target-signal handler. Avoid formatting,
    // allocation, and stdio locks because the executor calls _exit immediately after it.
    let fd = CRASH_CONTEXT_FD.load(Ordering::Relaxed);
    unsafe {
        libc::write(fd, buffer.as_ptr().cast::<libc::c_void>(), cursor);
    }
}

fn gen_last_guest_block<ET, I, S>(
    _qemu: Qemu,
    _emulator_modules: &mut EmulatorModules<ET, I, S>,
    _state: Option<&mut S>,
    pc: GuestAddr,
) -> Option<u64>
where
    ET: EmulatorModuleTuple<I, S>,
    I: Unpin,
    S: Unpin,
{
    Some(pc as u64)
}

fn exec_last_guest_block<ET, I, S>(
    _qemu: Qemu,
    _emulator_modules: &mut EmulatorModules<ET, I, S>,
    _state: Option<&mut S>,
    pc: u64,
) where
    ET: EmulatorModuleTuple<I, S>,
    I: Unpin,
    S: Unpin,
{
    LAST_GUEST_BLOCK.store(pc, Ordering::Relaxed);
    let fd = LAST_GUEST_BLOCK_FD.load(Ordering::Relaxed);
    if fd >= 0 {
        let bytes = pc.to_le_bytes();
        unsafe {
            libc::pwrite(fd, bytes.as_ptr().cast(), bytes.len(), 0);
        }
    }
}

pub fn write_timeout_last_guest_block() {
    let fd = LAST_GUEST_BLOCK_FD.load(Ordering::Relaxed);
    if fd < 0 {
        return;
    }

    let bytes = LAST_GUEST_BLOCK.load(Ordering::Relaxed).to_le_bytes();
    unsafe {
        libc::pwrite(fd, bytes.as_ptr().cast(), bytes.len(), 0);
    }
}

impl CrashContextModule {
    pub fn from_env() -> Self {
        Self {
            crash_context_enabled: std::env::var_os("BDCORE_CRASH_CONTEXT").is_some(),
            last_block_enabled: std::env::var_os("BDCORE_LAST_BLOCK_FILE").is_some(),
        }
    }
}

impl<I, S> EmulatorModule<I, S> for CrashContextModule
where
    I: Unpin,
    S: Unpin,
{
    fn first_exec<ET>(
        &mut self,
        _qemu: Qemu,
        emulator_modules: &mut EmulatorModules<ET, I, S>,
        _state: &mut S,
    ) where
        ET: libafl_qemu::modules::EmulatorModuleTuple<I, S>,
    {
        if !self.crash_context_enabled && !self.last_block_enabled {
            return;
        }

        if self.crash_context_enabled {
            let path = std::env::var("BDCORE_CRASH_CONTEXT_FILE")
                .unwrap_or_else(|_| "/tmp/bdcore_crash_context.log".to_string());
            if let Ok(path) = std::ffi::CString::new(path) {
                let fd = unsafe {
                    libc::open(
                        path.as_ptr(),
                        libc::O_WRONLY | libc::O_CREAT | libc::O_APPEND | libc::O_CLOEXEC,
                        0o600,
                    )
                };
                if fd >= 0 {
                    CRASH_CONTEXT_FD.store(fd, Ordering::Relaxed);
                    let armed = b"BDCORE_CRASH_CONTEXT armed\n";
                    unsafe {
                        libc::write(fd, armed.as_ptr().cast::<libc::c_void>(), armed.len());
                    }
                }
            }

            // Diagnostic-only hook. It runs in QEMU's target-signal context, immediately
            // before LibAFL persists the objective and terminates the crashing child.
            unsafe {
                emulator_modules.crash_closure(Box::new(|qemu, _modules, signal| {
                    write_crash_context(qemu, signal);
                }));
            }
        }

        if self.last_block_enabled {
            if let Some(path) = std::env::var_os("BDCORE_LAST_BLOCK_FILE") {
                if let Ok(path) = std::ffi::CString::new(path.as_encoded_bytes()) {
                    let fd = unsafe {
                        libc::open(
                            path.as_ptr(),
                            libc::O_WRONLY | libc::O_CREAT | libc::O_TRUNC | libc::O_CLOEXEC,
                            0o600,
                        )
                    };
                    LAST_GUEST_BLOCK_FD.store(fd, Ordering::Relaxed);
                }
            }

            emulator_modules.blocks(
                Hook::Function(gen_last_guest_block::<ET, I, S>),
                Hook::Empty,
                Hook::Function(exec_last_guest_block::<ET, I, S>),
            );
        }
    }

    fn pre_exec<ET>(
        &mut self,
        _qemu: Qemu,
        _emulator_modules: &mut EmulatorModules<ET, I, S>,
        _state: &mut S,
        _input: &I,
    ) where
        ET: EmulatorModuleTuple<I, S>,
    {
        if self.last_block_enabled {
            LAST_GUEST_BLOCK.store(0, Ordering::Relaxed);
        }
    }
}

pub type TMinPcObserver = ConstMapObserver<'static, u8, 2>;

pub fn tmin_pc_observer() -> TMinPcObserver {
    let map_ptr = core::ptr::addr_of_mut!(TMIN_PC_STATE);
    // SAFETY: the map has static storage, tmin is restricted to one client, and the
    // observer owns the only mutable view used to reset it between executions.
    unsafe {
        ConstMapObserver::from_mut_ptr(
            "tmin_pc_hit",
            core::ptr::NonNull::new(map_ptr).expect("tmin PC map pointer must be non-null"),
        )
    }
}

pub fn tmin_pc_was_hit() -> bool {
    // SAFETY: the instruction hook and observer execute serially in the single tmin client.
    unsafe { core::ptr::read_volatile(core::ptr::addr_of!(TMIN_PC_STATE[0])) != 0 }
}

#[derive(Clone, Copy, Debug)]
pub struct TMinPcHitModule {
    pc: u64,
}

impl TMinPcHitModule {
    pub fn new(pc: u64) -> Self {
        Self { pc }
    }
}

impl<I, S> EmulatorModule<I, S> for TMinPcHitModule
where
    I: Unpin,
    S: Unpin,
{
    fn first_exec<ET>(
        &mut self,
        _qemu: Qemu,
        emulator_modules: &mut EmulatorModules<ET, I, S>,
        _state: &mut S,
    ) where
        ET: libafl_qemu::modules::EmulatorModuleTuple<I, S>,
    {
        emulator_modules.instructions(
            self.pc.try_into().unwrap(),
            libafl_qemu::qemu::Hook::Closure(Box::new(move |_qemu, _mods, _state, _pc| {
                // SAFETY: tmin uses one client and QEMU invokes this hook synchronously.
                unsafe {
                    core::ptr::write_volatile(core::ptr::addr_of_mut!(TMIN_PC_STATE[0]), 1);
                }
            })),
            true,
        );
    }

    fn post_exec<OT, ET>(
        &mut self,
        _qemu: Qemu,
        _emulator_modules: &mut EmulatorModules<ET, I, S>,
        _state: &mut S,
        _input: &I,
        _observers: &mut OT,
        exit_kind: &mut ExitKind,
    ) where
        OT: ObserversTuple<I, S>,
        ET: libafl_qemu::modules::EmulatorModuleTuple<I, S>,
    {
        let status = if matches!(exit_kind, ExitKind::Ok) {
            1
        } else {
            2
        };
        // SAFETY: tmin uses one client and module callbacks are synchronous.
        unsafe {
            core::ptr::write_volatile(core::ptr::addr_of_mut!(TMIN_PC_STATE[1]), status);
        }
    }
}

pub struct UnpackerHealth {
    target_name: &'static str,
    slot_names: &'static [&'static str],
    run_hits: RefCell<Vec<bool>>,
    totals: RefCell<Vec<u64>>,
}

impl UnpackerHealth {
    pub fn new(target_name: &'static str, slot_names: &'static [&'static str]) -> Self {
        Self {
            target_name,
            slot_names,
            run_hits: RefCell::new(vec![false; slot_names.len()]),
            totals: RefCell::new(vec![0; slot_names.len()]),
        }
    }

    pub fn reset_run(&self) {
        self.run_hits.borrow_mut().fill(false);
    }

    pub fn hit(&self, slot: usize) {
        if let Some(hit) = self.run_hits.borrow_mut().get_mut(slot) {
            *hit = true;
        }
    }

    pub fn record_run(&self, execs: u64, log_every: u64) {
        let run_hits = self.run_hits.borrow();
        let mut totals = self.totals.borrow_mut();

        for (idx, hit) in run_hits.iter().enumerate() {
            if *hit {
                totals[idx] = totals[idx].saturating_add(1);
            }
        }

        if log_every == 0 || execs % log_every != 0 {
            return;
        }

        let mut summary = String::new();
        let _ = write!(&mut summary, "{} health: execs={}", self.target_name, execs);
        for (name, total) in self.slot_names.iter().zip(totals.iter()) {
            let _ = write!(&mut summary, " {}={}", name, total);
        }
        if log_every == 1 {
            eprintln!("{summary}");
        }
        log::info!("{summary}");
    }
}

#[derive(Clone, Copy, Debug)]
pub struct PcSignal {
    pub name: &'static str,
    pub pc: u64,
}

#[derive(Debug)]
struct PcSignalState {
    target_name: &'static str,
    report_every: u64,
    signals: Vec<PcSignal>,
    run_hits: Vec<AtomicBool>,
    run_events: Vec<AtomicU64>,
    run_to_hit_ns: Vec<AtomicU64>,
    totals: Vec<AtomicU64>,
    total_events: Vec<AtomicU64>,
    total_to_hit_ns: Vec<AtomicU64>,
    translator_run_max_next_cursor: AtomicU64,
    translator_run_capacity_at_max_cursor: AtomicU64,
    translator_run_max_overrun: AtomicU64,
    translator_run_overflow_next_cursor: AtomicU64,
    translator_run_overflow_capacity: AtomicU64,
    translator_run_near_capacity: AtomicBool,
    translator_run_at_capacity: AtomicBool,
    translator_run_overflow: AtomicBool,
    translator_global_max_next_cursor: AtomicU64,
    translator_global_max_overrun: AtomicU64,
    translator_above_baseline_runs: AtomicU64,
    translator_near_capacity_runs: AtomicU64,
    translator_at_capacity_runs: AtomicU64,
    translator_overflow_runs: AtomicU64,
    translator_captures: AtomicU64,
    execs: AtomicU64,
    run_started_at: Mutex<Instant>,
}

impl PcSignalState {
    fn new(target_name: &'static str, report_every: u64, signals: Vec<PcSignal>) -> Self {
        let signal_len = signals.len();
        Self {
            target_name,
            report_every,
            signals,
            run_hits: (0..signal_len).map(|_| AtomicBool::new(false)).collect(),
            run_events: (0..signal_len).map(|_| AtomicU64::new(0)).collect(),
            run_to_hit_ns: (0..signal_len).map(|_| AtomicU64::new(0)).collect(),
            totals: (0..signal_len).map(|_| AtomicU64::new(0)).collect(),
            total_events: (0..signal_len).map(|_| AtomicU64::new(0)).collect(),
            total_to_hit_ns: (0..signal_len).map(|_| AtomicU64::new(0)).collect(),
            translator_run_max_next_cursor: AtomicU64::new(0),
            translator_run_capacity_at_max_cursor: AtomicU64::new(0),
            translator_run_max_overrun: AtomicU64::new(0),
            translator_run_overflow_next_cursor: AtomicU64::new(0),
            translator_run_overflow_capacity: AtomicU64::new(0),
            translator_run_near_capacity: AtomicBool::new(false),
            translator_run_at_capacity: AtomicBool::new(false),
            translator_run_overflow: AtomicBool::new(false),
            translator_global_max_next_cursor: AtomicU64::new(0),
            translator_global_max_overrun: AtomicU64::new(0),
            translator_above_baseline_runs: AtomicU64::new(0),
            translator_near_capacity_runs: AtomicU64::new(0),
            translator_at_capacity_runs: AtomicU64::new(0),
            translator_overflow_runs: AtomicU64::new(0),
            translator_captures: AtomicU64::new(0),
            execs: AtomicU64::new(0),
            run_started_at: Mutex::new(Instant::now()),
        }
    }

    fn hit(&self, idx: usize) {
        if let Some(events) = self.run_events.get(idx) {
            events.fetch_add(1, Ordering::Relaxed);
        }
        if let Some(hit) = self.run_hits.get(idx) {
            if !hit.swap(true, Ordering::Relaxed) {
                let elapsed_ns = self
                    .run_started_at
                    .lock()
                    .map(|started| started.elapsed().as_nanos().min(u128::from(u64::MAX)) as u64)
                    .unwrap_or(0);
                self.run_to_hit_ns[idx].store(elapsed_ns, Ordering::Relaxed);
                if self.report_every == 1 {
                    if let Some(signal) = self.signals.get(idx) {
                        eprintln!(
                            "{} live progress: {} pc={:#x}",
                            self.target_name, signal.name, signal.pc
                        );
                    }
                }
            }
        }
    }

    fn mark_translator_record_append(&self, qemu: Qemu) {
        let builder = qemu.read_reg(Regs::Rcx).unwrap_or(0);
        if builder == 0 {
            return;
        }

        let mut cursor_bytes = [0u8; 4];
        let mut capacity_bytes = [0u8; 4];
        if qemu
            .read_mem(
                builder.saturating_add(0x68).try_into().unwrap(),
                &mut cursor_bytes,
            )
            .is_err()
            || qemu
                .read_mem(
                    builder.saturating_add(0x6c).try_into().unwrap(),
                    &mut capacity_bytes,
                )
                .is_err()
        {
            return;
        }

        let cursor = u64::from(u32::from_le_bytes(cursor_bytes));
        let capacity = u64::from(u32::from_le_bytes(capacity_bytes));
        let next_cursor = cursor.saturating_add(12);
        let previous_max = self
            .translator_run_max_next_cursor
            .fetch_max(next_cursor, Ordering::Relaxed);
        if next_cursor > previous_max {
            self.translator_run_capacity_at_max_cursor
                .store(capacity, Ordering::Relaxed);
        }

        if next_cursor >= capacity.saturating_sub(0x10) {
            self.translator_run_near_capacity
                .store(true, Ordering::Relaxed);
        }
        if next_cursor == capacity {
            self.translator_run_at_capacity
                .store(true, Ordering::Relaxed);
        }
        if next_cursor > capacity {
            self.translator_run_overflow.store(true, Ordering::Relaxed);
            let overrun = next_cursor - capacity;
            let previous_overrun = self
                .translator_run_max_overrun
                .fetch_max(overrun, Ordering::Relaxed);
            if overrun > previous_overrun {
                self.translator_run_overflow_next_cursor
                    .store(next_cursor, Ordering::Relaxed);
                self.translator_run_overflow_capacity
                    .store(capacity, Ordering::Relaxed);
            }
        }
    }

    fn capture_translator_input<I>(&self, input: &I)
    where
        I: HasTargetBytes,
    {
        if !self.translator_run_overflow.load(Ordering::Relaxed) {
            return;
        }
        let Some(output_dir) = std::env::var_os("BDCORE_CEVA_TRANSLATOR_CAPTURE_DIR") else {
            return;
        };

        let bytes = input.target_bytes();
        let bytes = bytes.as_slice();
        let max_next = self
            .translator_run_overflow_next_cursor
            .load(Ordering::Relaxed);
        let capacity = self
            .translator_run_overflow_capacity
            .load(Ordering::Relaxed);
        let max_overrun = self.translator_run_max_overrun.load(Ordering::Relaxed);
        let mut hasher = DefaultHasher::new();
        bytes.hash(&mut hasher);
        max_next.hash(&mut hasher);
        capacity.hash(&mut hasher);
        let hash = hasher.finish();

        let output_dir = PathBuf::from(output_dir);
        if let Err(err) = fs::create_dir_all(&output_dir) {
            log::warn!(
                "CEVA translator capture: failed to create {}: {err}",
                output_dir.display()
            );
            return;
        }

        let stem = format!("{hash:016x}_next_{max_next:08x}");
        let input_path = output_dir.join(format!("{stem}.bin"));
        let metadata_path = output_dir.join(format!("{stem}.txt"));
        if input_path.exists() && metadata_path.exists() {
            return;
        }

        let metadata = format!(
            "overflow_next_cursor={max_next:#x}\noverflow_capacity={capacity:#x}\nmax_overrun={max_overrun:#x}\ninput_size={:#x}\n",
            bytes.len()
        );
        match (
            fs::write(&input_path, bytes),
            fs::write(&metadata_path, metadata),
        ) {
            (Ok(()), Ok(())) => {
                self.translator_captures.fetch_add(1, Ordering::Relaxed);
                log::info!(
                    "CEVA translator captured per-append capacity violation {}",
                    input_path.display()
                );
            }
            (input_result, metadata_result) => {
                if let Err(err) = input_result {
                    log::warn!(
                        "CEVA translator capture: failed to write {}: {err}",
                        input_path.display()
                    );
                }
                if let Err(err) = metadata_result {
                    log::warn!(
                        "CEVA translator capture: failed to write {}: {err}",
                        metadata_path.display()
                    );
                }
            }
        }
    }

    fn profile_translator_uniform_opcode<I>(&self, input: &I)
    where
        I: HasTargetBytes,
    {
        let Some(output_dir) = std::env::var_os("BDCORE_CEVA_TRANSLATOR_OPCODE_PROFILE_DIR") else {
            return;
        };

        let bytes = input.target_bytes();
        let bytes = bytes.as_slice();
        let Some(&opcode) = bytes.first() else {
            return;
        };
        if bytes.iter().any(|byte| *byte != opcode) {
            return;
        }

        let max_next = self.translator_run_max_next_cursor.load(Ordering::Relaxed);
        let capacity = self
            .translator_run_capacity_at_max_cursor
            .load(Ordering::Relaxed);
        let output_dir = PathBuf::from(output_dir);
        if let Err(err) = fs::create_dir_all(&output_dir) {
            log::warn!(
                "CEVA translator opcode profile: failed to create {}: {err}",
                output_dir.display()
            );
            return;
        }

        let path = output_dir.join(format!("opcode_{opcode:02x}.txt"));
        let metadata = format!(
            "opcode={opcode:#04x}\nmax_next_cursor={max_next:#x}\ncapacity={capacity:#x}\ninput_size={:#x}\n",
            bytes.len()
        );
        if let Err(err) = fs::write(&path, metadata) {
            log::warn!(
                "CEVA translator opcode profile: failed to write {}: {err}",
                path.display()
            );
        }
    }

    fn reset_run(&self) {
        if let Ok(mut started) = self.run_started_at.lock() {
            *started = Instant::now();
        }
        for hit in &self.run_hits {
            hit.store(false, Ordering::Relaxed);
        }
        for elapsed in &self.run_to_hit_ns {
            elapsed.store(0, Ordering::Relaxed);
        }
        for events in &self.run_events {
            events.store(0, Ordering::Relaxed);
        }
        self.translator_run_max_next_cursor
            .store(0, Ordering::Relaxed);
        self.translator_run_capacity_at_max_cursor
            .store(0, Ordering::Relaxed);
        self.translator_run_max_overrun.store(0, Ordering::Relaxed);
        self.translator_run_overflow_next_cursor
            .store(0, Ordering::Relaxed);
        self.translator_run_overflow_capacity
            .store(0, Ordering::Relaxed);
        self.translator_run_near_capacity
            .store(false, Ordering::Relaxed);
        self.translator_run_at_capacity
            .store(false, Ordering::Relaxed);
        self.translator_run_overflow.store(false, Ordering::Relaxed);
    }

    fn record_run(&self) {
        let execs = self.execs.fetch_add(1, Ordering::Relaxed) + 1;

        for (idx, hit) in self.run_hits.iter().enumerate() {
            if hit.load(Ordering::Relaxed) {
                self.totals[idx].fetch_add(1, Ordering::Relaxed);
                self.total_to_hit_ns[idx].fetch_add(
                    self.run_to_hit_ns[idx].load(Ordering::Relaxed),
                    Ordering::Relaxed,
                );
            }
            self.total_events[idx].fetch_add(
                self.run_events[idx].load(Ordering::Relaxed),
                Ordering::Relaxed,
            );
        }

        let translator_max_next = self.translator_run_max_next_cursor.load(Ordering::Relaxed);
        if translator_max_next != 0 {
            self.translator_global_max_next_cursor
                .fetch_max(translator_max_next, Ordering::Relaxed);
            if translator_max_next > 0x3a8 {
                self.translator_above_baseline_runs
                    .fetch_add(1, Ordering::Relaxed);
            }
            if self.translator_run_near_capacity.load(Ordering::Relaxed) {
                self.translator_near_capacity_runs
                    .fetch_add(1, Ordering::Relaxed);
            }
            if self.translator_run_at_capacity.load(Ordering::Relaxed) {
                self.translator_at_capacity_runs
                    .fetch_add(1, Ordering::Relaxed);
            }
            if self.translator_run_overflow.load(Ordering::Relaxed) {
                self.translator_overflow_runs
                    .fetch_add(1, Ordering::Relaxed);
                self.translator_global_max_overrun.fetch_max(
                    self.translator_run_max_overrun.load(Ordering::Relaxed),
                    Ordering::Relaxed,
                );
            }
        }

        if self.report_every == 0 || execs % self.report_every != 0 {
            return;
        }

        let mut summary = String::new();
        let _ = write!(
            &mut summary,
            "{} progress: execs={}",
            self.target_name, execs
        );
        for (signal, total) in self.signals.iter().zip(self.totals.iter()) {
            let _ = write!(
                &mut summary,
                " {}={}",
                signal.name,
                total.load(Ordering::Relaxed)
            );
        }
        summary.push_str(" events=");
        for (idx, (signal, total)) in self
            .signals
            .iter()
            .zip(self.total_events.iter())
            .enumerate()
        {
            if idx != 0 {
                summary.push(',');
            }
            let _ = write!(
                &mut summary,
                "{}:{}",
                signal.name,
                total.load(Ordering::Relaxed)
            );
        }
        summary.push_str(" latency_us=");
        for (idx, (signal, total)) in self.signals.iter().zip(self.totals.iter()).enumerate() {
            if idx != 0 {
                summary.push(',');
            }
            let hits = total.load(Ordering::Relaxed);
            let avg_us = if hits == 0 {
                0
            } else {
                self.total_to_hit_ns[idx].load(Ordering::Relaxed) / hits / 1_000
            };
            let _ = write!(&mut summary, "{}:{}", signal.name, avg_us);
        }
        if self
            .signals
            .iter()
            .any(|signal| signal.name == "guest_translator_record_append")
        {
            let _ = write!(
                &mut summary,
                " translator_max_next={:#x} translator_max_overrun={:#x} translator_above_baseline={} translator_near_capacity={} translator_at_capacity={} translator_overflow={} translator_captures={}",
                self.translator_global_max_next_cursor.load(Ordering::Relaxed),
                self.translator_global_max_overrun.load(Ordering::Relaxed),
                self.translator_above_baseline_runs.load(Ordering::Relaxed),
                self.translator_near_capacity_runs.load(Ordering::Relaxed),
                self.translator_at_capacity_runs.load(Ordering::Relaxed),
                self.translator_overflow_runs.load(Ordering::Relaxed),
                self.translator_captures.load(Ordering::Relaxed),
            );
        }
        log::info!("{summary}");
        if let Some(path) = std::env::var_os("BDCORE_CEVA_HEALTH_LOG") {
            append_diagnostic_line(Path::new(&path), &summary);
        }
    }
}

#[derive(Clone)]
pub struct PcSignalModule {
    state: Arc<PcSignalState>,
}

impl PcSignalModule {
    pub fn disabled() -> Self {
        Self::new("UnpackerProgress", 0, Vec::new())
    }

    pub fn new(target_name: &'static str, report_every: u64, signals: Vec<PcSignal>) -> Self {
        Self {
            state: Arc::new(PcSignalState::new(target_name, report_every, signals)),
        }
    }
}

const PELOCK_RET_SLOT_ZERO: usize = 0;
const PELOCK_RET_SLOT_NEG1: usize = 1;
const PELOCK_RET_SLOT_NEG2: usize = 2;
const PELOCK_RET_SLOT_OTHER_NEG: usize = 3;
const PELOCK_RET_SLOT_POSITIVE: usize = 4;

const PELOCK_RET_SLOT_NAMES: &[&str] = &[
    "ret_07d60_zero",
    "ret_07d60_neg1",
    "ret_07d60_neg2",
    "ret_07d60_other_neg",
    "ret_07d60_positive",
];

#[derive(Debug)]
struct PelockRetState {
    report_every: u64,
    run_hits: Vec<AtomicBool>,
    totals: Vec<AtomicU64>,
    execs: AtomicU64,
}

impl PelockRetState {
    fn new(report_every: u64) -> Self {
        Self {
            report_every,
            run_hits: (0..PELOCK_RET_SLOT_NAMES.len())
                .map(|_| AtomicBool::new(false))
                .collect(),
            totals: (0..PELOCK_RET_SLOT_NAMES.len())
                .map(|_| AtomicU64::new(0))
                .collect(),
            execs: AtomicU64::new(0),
        }
    }

    fn mark_ret(&self, eax: i32) {
        let slot = match eax {
            0 => PELOCK_RET_SLOT_ZERO,
            -1 => PELOCK_RET_SLOT_NEG1,
            -2 => PELOCK_RET_SLOT_NEG2,
            v if v < 0 => PELOCK_RET_SLOT_OTHER_NEG,
            _ => PELOCK_RET_SLOT_POSITIVE,
        };
        self.run_hits[slot].store(true, Ordering::Relaxed);
    }

    fn reset_run(&self) {
        for hit in &self.run_hits {
            hit.store(false, Ordering::Relaxed);
        }
    }

    fn record_run(&self) {
        let execs = self.execs.fetch_add(1, Ordering::Relaxed) + 1;

        for (idx, hit) in self.run_hits.iter().enumerate() {
            if hit.load(Ordering::Relaxed) {
                self.totals[idx].fetch_add(1, Ordering::Relaxed);
            }
        }

        if self.report_every == 0 || execs % self.report_every != 0 {
            return;
        }

        let mut summary = String::new();
        let _ = write!(&mut summary, "Pelock07d60Ret health: execs={}", execs);
        for (name, total) in PELOCK_RET_SLOT_NAMES.iter().zip(self.totals.iter()) {
            let _ = write!(&mut summary, " {}={}", name, total.load(Ordering::Relaxed));
        }
        log::info!("{summary}");
    }
}

#[derive(Debug)]
struct PelockStage0CaptureState {
    report_every: u64,
    output_dir: PathBuf,
    run_hit: AtomicBool,
    captures: AtomicU64,
    execs: AtomicU64,
}

#[derive(Clone, Debug)]
struct Pelock07d60WindowCapture {
    input_hash: u64,
    base: u64,
    cursor: u32,
    limit: u32,
    capture_start: u32,
    bytes: Vec<u8>,
    ret_eax: Option<i32>,
    ret_r12d: Option<u32>,
    ret_slot1: Option<u32>,
}

#[derive(Debug)]
struct Pelock07d60WindowCaptureState {
    report_every: u64,
    output_dir: PathBuf,
    captures: AtomicU64,
    execs: AtomicU64,
    current_input_hash: AtomicU64,
    run_capture: Mutex<Option<Pelock07d60WindowCapture>>,
}

impl Pelock07d60WindowCaptureState {
    fn new(output_dir: PathBuf, report_every: u64) -> Self {
        Self {
            report_every,
            output_dir,
            captures: AtomicU64::new(0),
            execs: AtomicU64::new(0),
            current_input_hash: AtomicU64::new(0),
            run_capture: Mutex::new(None),
        }
    }

    fn hash_input(bytes: &[u8]) -> u64 {
        let mut hasher = DefaultHasher::new();
        bytes.hash(&mut hasher);
        hasher.finish()
    }

    fn set_current_input_hash<I>(&self, input: &I)
    where
        I: HasTargetBytes,
    {
        let input_bytes = input.target_bytes();
        let input_hash = Self::hash_input(input_bytes.as_slice());
        self.current_input_hash.store(input_hash, Ordering::Relaxed);
    }

    fn mark_callsite(&self, qemu: Qemu) {
        let rcx: u64 = qemu.read_reg(Regs::Rcx).unwrap_or(0);
        let rdx: u64 = qemu.read_reg(Regs::Rdx).unwrap_or(0);
        let r8: u64 = qemu.read_reg(Regs::R8).unwrap_or(0);
        if rcx == 0 || r8 == 0 {
            return;
        }
        let input_hash = self.current_input_hash.load(Ordering::Relaxed);
        let cursor = rdx as u32;
        let limit = r8 as u32;

        let capture_start = cursor.saturating_sub(0x10);
        let available = limit.saturating_sub(capture_start);
        if available == 0 {
            return;
        }
        let capture_len = available.min(0x100);
        let guest_addr = rcx.saturating_add(u64::from(capture_start));
        let mut bytes = vec![0u8; capture_len as usize];
        if qemu
            .read_mem(guest_addr.try_into().unwrap(), &mut bytes)
            .is_err()
        {
            return;
        }

        if let Ok(mut slot) = self.run_capture.lock() {
            *slot = Some(Pelock07d60WindowCapture {
                input_hash,
                base: rcx,
                cursor,
                limit,
                capture_start,
                bytes,
                ret_eax: None,
                ret_r12d: None,
                ret_slot1: None,
            });
        }
    }

    fn mark_return(&self, qemu: Qemu, eax: i32) {
        let r12d = qemu.read_reg(Regs::R12).unwrap_or(0) as u32;
        let rsp = qemu.read_reg(Regs::Rsp).unwrap_or(0);
        let slot1_addr = rsp.saturating_add(0x48);
        let mut slot1_bytes = [0u8; 4];
        let slot1 = if qemu
            .read_mem(slot1_addr.try_into().unwrap(), &mut slot1_bytes)
            .is_ok()
        {
            u32::from_le_bytes(slot1_bytes)
        } else {
            0
        };
        if let Ok(mut slot) = self.run_capture.lock() {
            if let Some(capture) = slot.as_mut() {
                capture.ret_eax = Some(eax);
                capture.ret_r12d = Some(r12d);
                capture.ret_slot1 = Some(slot1);
            }
        }
    }

    fn reset_run(&self) {
        if let Ok(mut slot) = self.run_capture.lock() {
            *slot = None;
        }
    }

    fn flush_capture(&self) {
        let capture = if let Ok(mut slot) = self.run_capture.lock() {
            slot.take()
        } else {
            None
        };
        let Some(capture) = capture else {
            return;
        };

        if let Err(err) = fs::create_dir_all(&self.output_dir) {
            log::warn!(
                "Pelock 07D60 window capture: failed to create {}: {err}",
                self.output_dir.display()
            );
            return;
        }

        let mut hasher = DefaultHasher::new();
        capture.input_hash.hash(&mut hasher);
        capture.base.hash(&mut hasher);
        capture.cursor.hash(&mut hasher);
        capture.limit.hash(&mut hasher);
        capture.capture_start.hash(&mut hasher);
        capture.bytes.hash(&mut hasher);
        capture.ret_eax.unwrap_or(i32::MIN).hash(&mut hasher);
        let hash = hasher.finish();

        let stem = format!(
            "{hash:016x}_ret_{:08x}",
            capture.ret_eax.unwrap_or(i32::MIN) as u32
        );
        let meta_path = self.output_dir.join(format!("{stem}.txt"));
        let bin_path = self.output_dir.join(format!("{stem}.bin"));
        if meta_path.exists() && bin_path.exists() {
            return;
        }

        let meta = format!(
            "input_hash={:016x}\nbase={:#x}\ncursor={:#x}\nlimit={:#x}\ncapture_start={:#x}\nlen={:#x}\nret_eax={:#x}\n",
            capture.input_hash,
            capture.base,
            capture.cursor,
            capture.limit,
            capture.capture_start,
            capture.bytes.len(),
            capture.ret_eax.unwrap_or(i32::MIN) as u32,
        );
        let meta = format!(
            "{}ret_r12d={:#x}\nret_slot1={:#x}\n",
            meta,
            capture.ret_r12d.unwrap_or(0),
            capture.ret_slot1.unwrap_or(0),
        );

        let meta_ok = fs::write(&meta_path, meta);
        let bin_ok = fs::write(&bin_path, &capture.bytes);
        match (meta_ok, bin_ok) {
            (Ok(()), Ok(())) => {
                self.captures.fetch_add(1, Ordering::Relaxed);
                log::info!(
                    "Pelock 07D60 window capture wrote {} and {}",
                    meta_path.display(),
                    bin_path.display()
                );
            }
            (meta_res, bin_res) => {
                if let Err(err) = meta_res {
                    log::warn!(
                        "Pelock 07D60 window capture: failed to write {}: {err}",
                        meta_path.display()
                    );
                }
                if let Err(err) = bin_res {
                    log::warn!(
                        "Pelock 07D60 window capture: failed to write {}: {err}",
                        bin_path.display()
                    );
                }
            }
        }
    }

    fn record_run(&self) {
        let execs = self.execs.fetch_add(1, Ordering::Relaxed) + 1;
        if self.report_every == 0 || execs % self.report_every != 0 {
            return;
        }

        let pending = self
            .run_capture
            .lock()
            .ok()
            .and_then(|slot| slot.as_ref().map(|capture| capture.ret_eax.is_some()))
            .unwrap_or(false);

        log::info!(
            "Pelock07d60WindowCapture health: execs={} captures={} pending_ret={}",
            execs,
            self.captures.load(Ordering::Relaxed),
            u8::from(pending)
        );
    }
}

impl PelockStage0CaptureState {
    fn new(output_dir: PathBuf, report_every: u64) -> Self {
        Self {
            report_every,
            output_dir,
            run_hit: AtomicBool::new(false),
            captures: AtomicU64::new(0),
            execs: AtomicU64::new(0),
        }
    }

    fn mark_hit(&self) {
        self.run_hit.store(true, Ordering::Relaxed);
    }

    fn reset_run(&self) {
        self.run_hit.store(false, Ordering::Relaxed);
    }

    fn hash_input(bytes: &[u8]) -> u64 {
        let mut hasher = DefaultHasher::new();
        bytes.hash(&mut hasher);
        hasher.finish()
    }

    fn capture<I>(&self, input: &I)
    where
        I: HasTargetBytes,
    {
        if !self.run_hit.load(Ordering::Relaxed) {
            return;
        }

        let bytes = input.target_bytes();
        let bytes = bytes.as_slice();
        if bytes.is_empty() {
            return;
        }

        if let Err(err) = fs::create_dir_all(&self.output_dir) {
            log::warn!(
                "Pelock stage0 capture: failed to create {}: {err}",
                self.output_dir.display()
            );
            return;
        }

        let hash = Self::hash_input(bytes);
        let path = self
            .output_dir
            .join(format!("{hash:016x}_{}.bin", bytes.len()));
        if path.exists() {
            return;
        }

        match fs::write(&path, bytes) {
            Ok(()) => {
                self.captures.fetch_add(1, Ordering::Relaxed);
                log::info!("Pelock stage0 capture wrote {}", path.display());
            }
            Err(err) => {
                log::warn!(
                    "Pelock stage0 capture: failed to write {}: {err}",
                    path.display()
                );
            }
        }
    }

    fn record_run(&self) {
        let execs = self.execs.fetch_add(1, Ordering::Relaxed) + 1;
        if self.report_every == 0 || execs % self.report_every != 0 {
            return;
        }

        log::info!(
            "PelockStage0Capture health: execs={} captures={} hit_this_run={}",
            execs,
            self.captures.load(Ordering::Relaxed),
            u8::from(self.run_hit.load(Ordering::Relaxed))
        );
    }
}

#[derive(Clone, Debug)]
pub struct PelockStage0CaptureModule {
    enabled: bool,
    pc: u64,
    state: Arc<PelockStage0CaptureState>,
}

impl PelockStage0CaptureModule {
    pub fn disabled() -> Self {
        Self {
            enabled: false,
            pc: 0,
            state: Arc::new(PelockStage0CaptureState::new(PathBuf::new(), 0)),
        }
    }

    pub fn new(pc: u64, output_dir: PathBuf, report_every: u64) -> Self {
        Self {
            enabled: true,
            pc,
            state: Arc::new(PelockStage0CaptureState::new(output_dir, report_every)),
        }
    }
}

impl<I, S> EmulatorModule<I, S> for PelockStage0CaptureModule
where
    I: HasTargetBytes + Unpin,
    S: Unpin,
{
    fn first_exec<ET>(
        &mut self,
        _qemu: Qemu,
        emulator_modules: &mut EmulatorModules<ET, I, S>,
        _state: &mut S,
    ) where
        ET: libafl_qemu::modules::EmulatorModuleTuple<I, S>,
    {
        if !self.enabled {
            return;
        }

        let state = Arc::clone(&self.state);
        emulator_modules.instructions(
            self.pc.try_into().unwrap(),
            libafl_qemu::qemu::Hook::Closure(Box::new(move |_qemu, _mods, _state, _pc| {
                state.mark_hit();
            })),
            true,
        );
    }

    fn pre_exec<ET>(
        &mut self,
        _qemu: Qemu,
        _emulator_modules: &mut EmulatorModules<ET, I, S>,
        _state: &mut S,
        _input: &I,
    ) where
        ET: libafl_qemu::modules::EmulatorModuleTuple<I, S>,
    {
        self.state.reset_run();
    }

    fn post_exec<OT, ET>(
        &mut self,
        _qemu: Qemu,
        _emulator_modules: &mut EmulatorModules<ET, I, S>,
        _state: &mut S,
        input: &I,
        _observers: &mut OT,
        _exit_kind: &mut ExitKind,
    ) where
        OT: ObserversTuple<I, S>,
        ET: libafl_qemu::modules::EmulatorModuleTuple<I, S>,
    {
        if self.enabled {
            self.state.capture(input);
            self.state.record_run();
        }
    }
}

#[derive(Clone, Debug)]
pub struct Pelock07d60RetModule {
    enabled: bool,
    pc: u64,
    state: Arc<PelockRetState>,
}

impl Pelock07d60RetModule {
    pub fn disabled() -> Self {
        Self {
            enabled: false,
            pc: 0,
            state: Arc::new(PelockRetState::new(0)),
        }
    }

    pub fn new(pc: u64, report_every: u64) -> Self {
        Self {
            enabled: true,
            pc,
            state: Arc::new(PelockRetState::new(report_every)),
        }
    }
}

impl<I, S> EmulatorModule<I, S> for Pelock07d60RetModule
where
    I: Unpin,
    S: Unpin,
{
    fn first_exec<ET>(
        &mut self,
        _qemu: Qemu,
        emulator_modules: &mut EmulatorModules<ET, I, S>,
        _state: &mut S,
    ) where
        ET: libafl_qemu::modules::EmulatorModuleTuple<I, S>,
    {
        if !self.enabled {
            return;
        }
        let state = Arc::clone(&self.state);
        emulator_modules.instructions(
            self.pc.try_into().unwrap(),
            libafl_qemu::qemu::Hook::Closure(Box::new(move |qemu, _mods, _state, _pc| {
                let eax: i32 = (qemu.read_reg(Regs::Rax).unwrap() as u64) as u32 as i32;
                state.mark_ret(eax);
            })),
            true,
        );
    }

    fn pre_exec<ET>(
        &mut self,
        _qemu: Qemu,
        _emulator_modules: &mut EmulatorModules<ET, I, S>,
        _state: &mut S,
        _input: &I,
    ) where
        ET: libafl_qemu::modules::EmulatorModuleTuple<I, S>,
    {
        self.state.reset_run();
    }

    fn post_exec<OT, ET>(
        &mut self,
        _qemu: Qemu,
        _emulator_modules: &mut EmulatorModules<ET, I, S>,
        _state: &mut S,
        _input: &I,
        _observers: &mut OT,
        _exit_kind: &mut ExitKind,
    ) where
        OT: ObserversTuple<I, S>,
        ET: libafl_qemu::modules::EmulatorModuleTuple<I, S>,
    {
        if self.enabled {
            self.state.record_run();
        }
    }
}

#[derive(Clone, Debug)]
pub struct Pelock07d60WindowCaptureModule {
    enabled: bool,
    call_pc: u64,
    ret_pc: u64,
    state: Arc<Pelock07d60WindowCaptureState>,
}

impl Pelock07d60WindowCaptureModule {
    pub fn disabled() -> Self {
        Self {
            enabled: false,
            call_pc: 0,
            ret_pc: 0,
            state: Arc::new(Pelock07d60WindowCaptureState::new(PathBuf::new(), 0)),
        }
    }

    pub fn new(call_pc: u64, ret_pc: u64, output_dir: PathBuf, report_every: u64) -> Self {
        Self {
            enabled: true,
            call_pc,
            ret_pc,
            state: Arc::new(Pelock07d60WindowCaptureState::new(output_dir, report_every)),
        }
    }
}

impl<I, S> EmulatorModule<I, S> for Pelock07d60WindowCaptureModule
where
    I: HasTargetBytes + Unpin,
    S: Unpin,
{
    fn first_exec<ET>(
        &mut self,
        _qemu: Qemu,
        emulator_modules: &mut EmulatorModules<ET, I, S>,
        _state: &mut S,
    ) where
        ET: libafl_qemu::modules::EmulatorModuleTuple<I, S>,
    {
        if !self.enabled {
            return;
        }

        let call_state = Arc::clone(&self.state);
        emulator_modules.instructions(
            self.call_pc.try_into().unwrap(),
            libafl_qemu::qemu::Hook::Closure(Box::new(move |qemu, _mods, _state, _pc| {
                call_state.mark_callsite(qemu);
            })),
            true,
        );

        let ret_state = Arc::clone(&self.state);
        emulator_modules.instructions(
            self.ret_pc.try_into().unwrap(),
            libafl_qemu::qemu::Hook::Closure(Box::new(move |qemu, _mods, _state, _pc| {
                let eax: i32 = (qemu.read_reg(Regs::Rax).unwrap() as u64) as u32 as i32;
                ret_state.mark_return(qemu, eax);
            })),
            true,
        );
    }

    fn pre_exec<ET>(
        &mut self,
        _qemu: Qemu,
        _emulator_modules: &mut EmulatorModules<ET, I, S>,
        _state: &mut S,
        input: &I,
    ) where
        ET: libafl_qemu::modules::EmulatorModuleTuple<I, S>,
    {
        self.state.set_current_input_hash(input);
        self.state.reset_run();
    }

    fn post_exec<OT, ET>(
        &mut self,
        _qemu: Qemu,
        _emulator_modules: &mut EmulatorModules<ET, I, S>,
        _state: &mut S,
        _input: &I,
        _observers: &mut OT,
        _exit_kind: &mut ExitKind,
    ) where
        OT: ObserversTuple<I, S>,
        ET: libafl_qemu::modules::EmulatorModuleTuple<I, S>,
    {
        if self.enabled {
            self.state.flush_capture();
            self.state.record_run();
        }
    }
}

impl fmt::Debug for PcSignalModule {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("PcSignalModule")
            .field("target_name", &self.state.target_name)
            .field("report_every", &self.state.report_every)
            .field("signals", &self.state.signals)
            .finish()
    }
}

impl<I, S> EmulatorModule<I, S> for PcSignalModule
where
    I: HasTargetBytes + Unpin,
    S: Unpin,
{
    fn first_exec<ET>(
        &mut self,
        _qemu: Qemu,
        emulator_modules: &mut EmulatorModules<ET, I, S>,
        _state: &mut S,
    ) where
        ET: libafl_qemu::modules::EmulatorModuleTuple<I, S>,
    {
        for (idx, signal) in self.state.signals.iter().enumerate() {
            let state = Arc::clone(&self.state);
            let signal_name = signal.name;
            let pelock_mode5_diag = std::env::var_os("PELOCK_MODE5_SIGNAL_DIAG").is_some();
            emulator_modules.instructions(
                signal.pc.try_into().unwrap(),
                libafl_qemu::qemu::Hook::Closure(Box::new(move |qemu, _mods, _state, _pc| {
                    if signal_name == "guest_translator_record_append" {
                        state.mark_translator_record_append(qemu);
                    } else if pelock_mode5_diag && signal_name == "mode5_06e40_call" {
                        let base = qemu.read_reg(Regs::R13).unwrap_or(0);
                        let cursor = qemu.read_reg(Regs::Rdi).unwrap_or(0);
                        let size = qemu.read_reg(Regs::R12).unwrap_or(0);
                        let window_len = size.saturating_sub(cursor).min(0x100) as usize;
                        let mut window = vec![0u8; window_len];
                        if qemu
                            .read_mem(base.saturating_add(cursor).try_into().unwrap(), &mut window)
                            .is_ok()
                        {
                            let line = format!(
                                "PELOCK_MODE5_DIAG call base={base:#x} cursor={cursor:#x} size={size:#x} window={}",
                                window
                                    .iter()
                                    .map(|byte| format!("{byte:02x}"))
                                    .collect::<Vec<_>>()
                                    .join(" ")
                            );
                            let path = Path::new("/tmp/pelock_mode5_06e40_call.log");
                            if !path.exists() {
                                let _ = fs::write(path, line);
                            }
                        }
                    } else if pelock_mode5_diag && signal_name == "mode5_06e40_return" {
                        let eax = qemu.read_reg(Regs::Rax).unwrap_or(0) as u32;
                        let line = format!(
                            "PELOCK_MODE5_DIAG return eax={eax:#x} signed={}",
                            eax as i32
                        );
                        let path = Path::new("/tmp/pelock_mode5_06e40_return.log");
                        if !path.exists() {
                            let _ = fs::write(path, line);
                        }
                    } else if pelock_mode5_diag && signal_name == "mode5_reparse_call" {
                        let base = qemu.read_reg(Regs::Rcx).unwrap_or(0);
                        let cursor = qemu.read_reg(Regs::Rdx).unwrap_or(0);
                        let size = qemu.read_reg(Regs::R8).unwrap_or(0);
                        let expected = qemu.read_reg(Regs::R9).unwrap_or(0);
                        let window_len = size.saturating_sub(cursor).min(0x100) as usize;
                        let mut window = vec![0u8; window_len];
                        if qemu
                            .read_mem(base.saturating_add(cursor).try_into().unwrap(), &mut window)
                            .is_ok()
                        {
                            let line = format!(
                                "PELOCK_MODE5_DIAG reparse_call base={base:#x} cursor={cursor:#x} size={size:#x} expected={expected:#x} window={}",
                                window
                                    .iter()
                                    .map(|byte| format!("{byte:02x}"))
                                    .collect::<Vec<_>>()
                                    .join(" ")
                            );
                            let path = Path::new("/tmp/pelock_mode5_reparse_call.log");
                            if !path.exists() {
                                let _ = fs::write(path, line);
                            }
                        }
                    } else if pelock_mode5_diag && signal_name == "mode5_reparse_return" {
                        let eax = qemu.read_reg(Regs::Rax).unwrap_or(0) as u32;
                        let line = format!(
                            "PELOCK_MODE5_DIAG reparse_return eax={eax:#x} signed={}",
                            eax as i32
                        );
                        let path = Path::new("/tmp/pelock_mode5_reparse_return.log");
                        if !path.exists() {
                            let _ = fs::write(path, line);
                        }
                    } else if pelock_mode5_diag && signal_name == "mode5_reparse_passed" {
                        let rsp = qemu.read_reg(Regs::Sp).unwrap_or(0);
                        let state = qemu.read_reg(Regs::Rdi).unwrap_or(0);
                        let section_index = qemu.read_reg(Regs::R15).unwrap_or(0) as u32;
                        let mut locals = [0u8; 0x14];
                        let mut section_count_bytes = [0u8; 2];
                        if qemu
                            .read_mem(rsp.saturating_add(0x60).try_into().unwrap(), &mut locals)
                            .is_ok()
                            && qemu
                                .read_mem(
                                    state.saturating_add(0x46).try_into().unwrap(),
                                    &mut section_count_bytes,
                                )
                                .is_ok()
                        {
                            let dword = |offset: usize| {
                                u32::from_le_bytes(locals[offset..offset + 4].try_into().unwrap())
                            };
                            let cursor = dword(0);
                            let out_len = dword(4);
                            let out_va = dword(8);
                            let image_base = dword(0x10);
                            let section_count = u16::from_le_bytes(section_count_bytes);
                            let line = format!(
                                "PELOCK_MODE5_DIAG reparse_passed section_index={section_index:#x} section_count={section_count:#x} cursor={cursor:#x} out_va={out_va:#x} out_len={out_len:#x} image_base={image_base:#x}"
                            );
                            let path = Path::new("/tmp/pelock_mode5_reparse_passed.log");
                            if !path.exists() {
                                let _ = fs::write(path, line);
                            }
                        }
                    } else if pelock_mode5_diag && signal_name == "late_dispatch_return" {
                        let base = qemu.read_reg(Regs::R13).unwrap_or(0);
                        let decoded_size = qemu.read_reg(Regs::R12).unwrap_or(0) as u32;
                        let rbp = qemu.read_reg(Regs::Rbp).unwrap_or(0);
                        let next_cursor = qemu.read_reg(Regs::Rax).unwrap_or(0) as u32;
                        let input_cursor = qemu.read_reg(Regs::Rsi).unwrap_or(0) as u32;
                        let cursor_window_len = decoded_size
                            .saturating_sub(input_cursor)
                            .min(0x10) as usize;
                        let mut cursor_window = vec![0u8; cursor_window_len];
                        if cursor_window_len != 0 {
                            let _ = qemu.read_mem(
                                base.saturating_add(input_cursor as u64)
                                    .try_into()
                                    .unwrap(),
                                &mut cursor_window,
                            );
                        }
                        let target_offset = cursor_window
                            .get(1..5)
                            .and_then(|bytes| <[u8; 4]>::try_from(bytes).ok())
                            .map(i32::from_le_bytes)
                            .map(|rel| input_cursor.wrapping_add(5).wrapping_add(rel as u32));
                        let mut target_window = [0u8; 0x10];
                        if let Some(target_offset) = target_offset {
                            let _ = qemu.read_mem(
                                base.saturating_add(target_offset as u64)
                                    .try_into()
                                    .unwrap(),
                                &mut target_window,
                            );
                        }
                        let mut record_offset_bytes = [0u8; 4];
                        if qemu
                            .read_mem(
                                rbp.saturating_sub(0x78).try_into().unwrap(),
                                &mut record_offset_bytes,
                            )
                            .is_ok()
                        {
                            let record_offset = u32::from_le_bytes(record_offset_bytes);
                            let window_len = decoded_size
                                .saturating_sub(record_offset)
                                .min(0x40) as usize;
                            let mut window = vec![0u8; window_len];
                            if window_len == 0
                                || qemu
                                    .read_mem(
                                        base.saturating_add(record_offset as u64)
                                            .try_into()
                                            .unwrap(),
                                        &mut window,
                                    )
                                    .is_ok()
                            {
                                let line = format!(
                                    "PELOCK_MODE5_DIAG dispatch_record_return input_cursor={input_cursor:#x} cursor_window={} target={} target_window={} eax={next_cursor:#x} record_off={record_offset:#x} decoded_size={decoded_size:#x} window={}",
                                    cursor_window
                                        .iter()
                                        .map(|byte| format!("{byte:02x}"))
                                        .collect::<Vec<_>>()
                                        .join(" "),
                                    target_offset
                                        .map(|offset| format!("{offset:#x}"))
                                        .unwrap_or_else(|| "n/a".to_string()),
                                    target_window
                                        .iter()
                                        .map(|byte| format!("{byte:02x}"))
                                        .collect::<Vec<_>>()
                                        .join(" "),
                                    window
                                        .iter()
                                        .map(|byte| format!("{byte:02x}"))
                                        .collect::<Vec<_>>()
                                        .join(" ")
                                );
                                let path = Path::new("/tmp/pelock_dispatch_record_return.log");
                                append_diagnostic_line(path, &line);
                            }
                        }
                    } else if pelock_mode5_diag && signal_name == "dispatch_06c50_return" {
                        let eax = qemu.read_reg(Regs::Rax).unwrap_or(0) as u32;
                        let rbp = qemu.read_reg(Regs::Rbp).unwrap_or(0);
                        let rsp = qemu.read_reg(Regs::Rsp).unwrap_or(0);
                        let mut out_kind_bytes = [0u8; 4];
                        let mut out_aux_bytes = [0u8; 4];
                        if qemu
                            .read_mem(
                                rbp.saturating_sub(0x50).try_into().unwrap(),
                                &mut out_kind_bytes,
                            )
                            .is_ok()
                            && qemu
                                .read_mem(
                                    rsp.saturating_add(0x7c).try_into().unwrap(),
                                    &mut out_aux_bytes,
                                )
                                .is_ok()
                        {
                            let out_kind = u32::from_le_bytes(out_kind_bytes);
                            let out_aux = u32::from_le_bytes(out_aux_bytes);
                            let line = format!(
                                "PELOCK_MODE5_DIAG dispatch_06c50_return eax={eax:#x} signed={} out_kind={out_kind:#x} out_aux={out_aux:#x}",
                                eax as i32
                            );
                            let path = Path::new("/tmp/pelock_dispatch_06c50_return.log");
                            append_diagnostic_line(path, &line);
                        }
                    } else if pelock_mode5_diag && signal_name == "dispatch_076f0_return" {
                        let eax = qemu.read_reg(Regs::Rax).unwrap_or(0) as u32;
                        let rbp = qemu.read_reg(Regs::Rbp).unwrap_or(0);
                        if let (Some(field_08), Some(field_10), Some(field_30)) = (
                            crate::utils::read_guest_u32_opt(
                                &qemu,
                                rbp.saturating_sub(0x18).try_into().unwrap(),
                            ),
                            crate::utils::read_guest_u32_opt(
                                &qemu,
                                rbp.saturating_sub(0x10).try_into().unwrap(),
                            ),
                            crate::utils::read_guest_u32_opt(
                                &qemu,
                                rbp.saturating_add(0x10).try_into().unwrap(),
                            ),
                        ) {
                            let line = format!(
                                "PELOCK_MODE5_DIAG dispatch_076f0_return eax={eax:#x} signed={} field_08={field_08:#x} field_10={field_10:#x} field_30={field_30:#x}",
                                eax as i32
                            );
                            let path = Path::new("/tmp/pelock_dispatch_076f0_return.log");
                            append_diagnostic_line(path, &line);
                        }
                    } else if pelock_mode5_diag && signal_name == "dispatch_handler_return" {
                        let eax = qemu.read_reg(Regs::Rax).unwrap_or(0) as u32;
                        let r14d = qemu.read_reg(Regs::R14).unwrap_or(0) as u32;
                        let esi = qemu.read_reg(Regs::Rsi).unwrap_or(0) as u32;
                        let line = format!(
                            "PELOCK_MODE5_DIAG dispatch_handler_return eax={eax:#x} signed={} loop_index={r14d:#x} next_cursor={esi:#x}",
                            eax as i32
                        );
                        append_diagnostic_line(
                            Path::new("/tmp/pelock_dispatch_handler_return.log"),
                            &line,
                        );
                    }
                    state.hit(idx);
                })),
                true,
            );
        }
    }

    fn pre_exec<ET>(
        &mut self,
        _qemu: Qemu,
        _emulator_modules: &mut EmulatorModules<ET, I, S>,
        _state: &mut S,
        _input: &I,
    ) where
        ET: libafl_qemu::modules::EmulatorModuleTuple<I, S>,
    {
        self.state.reset_run();
    }

    fn post_exec<OT, ET>(
        &mut self,
        _qemu: Qemu,
        _emulator_modules: &mut EmulatorModules<ET, I, S>,
        _state: &mut S,
        input: &I,
        _observers: &mut OT,
        _exit_kind: &mut ExitKind,
    ) where
        OT: ObserversTuple<I, S>,
        ET: libafl_qemu::modules::EmulatorModuleTuple<I, S>,
    {
        self.state.profile_translator_uniform_opcode(input);
        self.state.capture_translator_input(input);
        self.state.record_run();
    }
}
