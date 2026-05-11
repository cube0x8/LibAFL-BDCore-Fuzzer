use std::{
    cell::RefCell,
    fmt::{self, Write},
    sync::{
        Arc,
        atomic::{AtomicBool, AtomicU64, Ordering},
    },
};

use libafl::{executors::ExitKind, observers::ObserversTuple};
use libafl_qemu::{
    Qemu,
    emu::EmulatorModules,
    modules::EmulatorModule,
};

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
        let _ = write!(&mut summary, "{} progress: execs={}", self.target_name, execs);
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
