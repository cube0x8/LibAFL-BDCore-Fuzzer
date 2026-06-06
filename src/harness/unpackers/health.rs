use std::{
    cell::RefCell,
    collections::hash_map::DefaultHasher,
    fmt::{self, Write},
    fs,
    hash::{Hash, Hasher},
    path::PathBuf,
    sync::{
        atomic::{AtomicBool, AtomicU64, Ordering},
        Arc, Mutex,
    },
};

use libafl::{executors::ExitKind, inputs::HasTargetBytes, observers::ObserversTuple};
use libafl_bolts::AsSlice;
use libafl_qemu::{emu::EmulatorModules, modules::EmulatorModule, Qemu, Regs};

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
    totals: Vec<AtomicU64>,
    execs: AtomicU64,
}

impl PcSignalState {
    fn new(target_name: &'static str, report_every: u64, signals: Vec<PcSignal>) -> Self {
        let signal_len = signals.len();
        Self {
            target_name,
            report_every,
            signals,
            run_hits: (0..signal_len).map(|_| AtomicBool::new(false)).collect(),
            totals: (0..signal_len).map(|_| AtomicU64::new(0)).collect(),
            execs: AtomicU64::new(0),
        }
    }

    fn hit(&self, idx: usize) {
        if let Some(hit) = self.run_hits.get(idx) {
            hit.store(true, Ordering::Relaxed);
        }
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
        log::info!("{summary}");
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
        for (idx, signal) in self.state.signals.iter().enumerate() {
            let state = Arc::clone(&self.state);
            emulator_modules.instructions(
                signal.pc.try_into().unwrap(),
                libafl_qemu::qemu::Hook::Closure(Box::new(move |_qemu, _mods, _state, _pc| {
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
        _input: &I,
        _observers: &mut OT,
        _exit_kind: &mut ExitKind,
    ) where
        OT: ObserversTuple<I, S>,
        ET: libafl_qemu::modules::EmulatorModuleTuple<I, S>,
    {
        self.state.record_run();
    }
}
