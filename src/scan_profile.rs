use std::{
    fmt,
    sync::{
        atomic::{AtomicBool, AtomicU64, Ordering},
        Arc, Mutex,
    },
    time::{Duration, Instant},
};

use libafl_qemu::{
    emu::EmulatorModules,
    modules::{EmulatorModule, EmulatorModuleTuple},
    Qemu,
};

#[derive(Debug)]
pub struct ScanProfile {
    report_every: u64,
    iterations: AtomicU64,
    truncated_inputs: AtomicU64,
    incomplete_breakdowns: AtomicU64,
    total_input_bytes: AtomicU64,
    snapshot_capture_ns: AtomicU64,
    snapshot_restore_total_ns: AtomicU64,
    snapshot_restore_max_ns: AtomicU64,
    input_reset_total_ns: AtomicU64,
    input_reset_max_ns: AtomicU64,
    setup_total_ns: AtomicU64,
    setup_max_ns: AtomicU64,
    core_scan_total_ns: AtomicU64,
    core_scan_max_ns: AtomicU64,
    teardown_total_ns: AtomicU64,
    teardown_max_ns: AtomicU64,
    guest_exec_total_ns: AtomicU64,
    guest_exec_max_ns: AtomicU64,
    banner_logged: AtomicBool,
    restore_started_at: Mutex<Option<Instant>>,
}

impl ScanProfile {
    pub fn new(report_every: u64) -> Self {
        Self {
            report_every,
            iterations: AtomicU64::new(0),
            truncated_inputs: AtomicU64::new(0),
            incomplete_breakdowns: AtomicU64::new(0),
            total_input_bytes: AtomicU64::new(0),
            snapshot_capture_ns: AtomicU64::new(0),
            snapshot_restore_total_ns: AtomicU64::new(0),
            snapshot_restore_max_ns: AtomicU64::new(0),
            input_reset_total_ns: AtomicU64::new(0),
            input_reset_max_ns: AtomicU64::new(0),
            setup_total_ns: AtomicU64::new(0),
            setup_max_ns: AtomicU64::new(0),
            core_scan_total_ns: AtomicU64::new(0),
            core_scan_max_ns: AtomicU64::new(0),
            teardown_total_ns: AtomicU64::new(0),
            teardown_max_ns: AtomicU64::new(0),
            guest_exec_total_ns: AtomicU64::new(0),
            guest_exec_max_ns: AtomicU64::new(0),
            banner_logged: AtomicBool::new(false),
            restore_started_at: Mutex::new(None),
        }
    }

    pub fn record_snapshot_capture(&self, duration: Duration) {
        let elapsed_ns = duration_to_ns(duration);
        self.snapshot_capture_ns
            .store(elapsed_ns, Ordering::Relaxed);
        log::info!(
            "ScanFile profiling enabled: snapshot capture took {}. guest_exec measures ScanFile entry->return, so it includes wrapper + CoreSet(SCAN) + teardown.",
            HumanDuration(elapsed_ns)
        );
    }

    pub fn mark_restore_start(&self) {
        if let Ok(mut started_at) = self.restore_started_at.lock() {
            *started_at = Some(Instant::now());
        }
    }

    pub fn record_restore_end(&self) {
        if let Ok(mut started_at) = self.restore_started_at.lock() {
            if let Some(start) = started_at.take() {
                update_stats(
                    &self.snapshot_restore_total_ns,
                    &self.snapshot_restore_max_ns,
                    start.elapsed(),
                );
            }
        }
    }

    pub fn record_input_reset(&self, duration: Duration) {
        update_stats(
            &self.input_reset_total_ns,
            &self.input_reset_max_ns,
            duration,
        );
    }

    pub fn record_setup(&self, duration: Duration) {
        update_stats(&self.setup_total_ns, &self.setup_max_ns, duration);
    }

    pub fn record_core_scan(&self, duration: Duration) {
        update_stats(&self.core_scan_total_ns, &self.core_scan_max_ns, duration);
    }

    pub fn record_teardown(&self, duration: Duration) {
        update_stats(&self.teardown_total_ns, &self.teardown_max_ns, duration);
    }

    pub fn record_incomplete_breakdown(&self) {
        self.incomplete_breakdowns.fetch_add(1, Ordering::Relaxed);
    }

    pub fn record_guest_exec(&self, duration: Duration, input_len: usize, truncated: bool) {
        update_stats(&self.guest_exec_total_ns, &self.guest_exec_max_ns, duration);

        self.total_input_bytes
            .fetch_add(input_len as u64, Ordering::Relaxed);
        if truncated {
            self.truncated_inputs.fetch_add(1, Ordering::Relaxed);
        }

        let iteration = self.iterations.fetch_add(1, Ordering::Relaxed) + 1;
        if !self.banner_logged.swap(true, Ordering::Relaxed) {
            log::info!(
                "ScanFile timing reports will be emitted every {} iterations.",
                self.report_every
            );
        }

        if iteration % self.report_every == 0 {
            self.log_report(iteration);
        }
    }

    fn log_report(&self, iteration: u64) {
        let total_input_bytes = self.total_input_bytes.load(Ordering::Relaxed);
        let truncated_inputs = self.truncated_inputs.load(Ordering::Relaxed);
        let incomplete_breakdowns = self.incomplete_breakdowns.load(Ordering::Relaxed);
        let snapshot_capture_ns = self.snapshot_capture_ns.load(Ordering::Relaxed);
        let snapshot_restore_total_ns = self.snapshot_restore_total_ns.load(Ordering::Relaxed);
        let snapshot_restore_max_ns = self.snapshot_restore_max_ns.load(Ordering::Relaxed);
        let input_reset_total_ns = self.input_reset_total_ns.load(Ordering::Relaxed);
        let input_reset_max_ns = self.input_reset_max_ns.load(Ordering::Relaxed);
        let setup_total_ns = self.setup_total_ns.load(Ordering::Relaxed);
        let setup_max_ns = self.setup_max_ns.load(Ordering::Relaxed);
        let core_scan_total_ns = self.core_scan_total_ns.load(Ordering::Relaxed);
        let core_scan_max_ns = self.core_scan_max_ns.load(Ordering::Relaxed);
        let teardown_total_ns = self.teardown_total_ns.load(Ordering::Relaxed);
        let teardown_max_ns = self.teardown_max_ns.load(Ordering::Relaxed);
        let guest_exec_total_ns = self.guest_exec_total_ns.load(Ordering::Relaxed);
        let guest_exec_max_ns = self.guest_exec_max_ns.load(Ordering::Relaxed);

        log::info!(
            "ScanFile profile @ iter {}: snapshot_capture={} | restore avg={} max={} | reset avg={} max={} | setup avg={} max={} | corescan avg={} max={} | teardown avg={} max={} | guest_exec avg={} max={} | avg_input={} B | truncated={} | breakdown_misses={}",
            iteration,
            HumanDuration(snapshot_capture_ns),
            HumanDuration(snapshot_restore_total_ns / iteration),
            HumanDuration(snapshot_restore_max_ns),
            HumanDuration(input_reset_total_ns / iteration),
            HumanDuration(input_reset_max_ns),
            HumanDuration(setup_total_ns / iteration),
            HumanDuration(setup_max_ns),
            HumanDuration(core_scan_total_ns / iteration),
            HumanDuration(core_scan_max_ns),
            HumanDuration(teardown_total_ns / iteration),
            HumanDuration(teardown_max_ns),
            HumanDuration(guest_exec_total_ns / iteration),
            HumanDuration(guest_exec_max_ns),
            total_input_bytes / iteration,
            truncated_inputs,
            incomplete_breakdowns
        );
    }
}

fn update_stats(total: &AtomicU64, max: &AtomicU64, duration: Duration) {
    let elapsed_ns = duration_to_ns(duration);
    total.fetch_add(elapsed_ns, Ordering::Relaxed);
    max.fetch_max(elapsed_ns, Ordering::Relaxed);
}

fn duration_to_ns(duration: Duration) -> u64 {
    duration.as_nanos().min(u128::from(u64::MAX)) as u64
}

struct HumanDuration(u64);

impl fmt::Display for HumanDuration {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let ns = self.0;
        if ns >= 1_000_000_000 {
            write!(f, "{:.2}s", ns as f64 / 1_000_000_000.0)
        } else if ns >= 1_000_000 {
            write!(f, "{:.2}ms", ns as f64 / 1_000_000.0)
        } else if ns >= 1_000 {
            write!(f, "{:.2}us", ns as f64 / 1_000.0)
        } else {
            write!(f, "{ns}ns")
        }
    }
}

#[derive(Debug, Clone)]
pub struct ScanRestoreStartModule {
    profile: Arc<ScanProfile>,
}

impl ScanRestoreStartModule {
    pub fn new(profile: Arc<ScanProfile>) -> Self {
        Self { profile }
    }
}

impl<I, S> EmulatorModule<I, S> for ScanRestoreStartModule
where
    I: Unpin,
    S: Unpin,
{
    fn pre_exec<ET>(
        &mut self,
        _qemu: Qemu,
        _emulator_modules: &mut EmulatorModules<ET, I, S>,
        _state: &mut S,
        _input: &I,
    ) where
        ET: EmulatorModuleTuple<I, S>,
    {
        self.profile.mark_restore_start();
    }
}

#[derive(Debug, Clone)]
pub struct ScanRestoreEndModule {
    profile: Arc<ScanProfile>,
}

impl ScanRestoreEndModule {
    pub fn new(profile: Arc<ScanProfile>) -> Self {
        Self { profile }
    }
}

impl<I, S> EmulatorModule<I, S> for ScanRestoreEndModule
where
    I: Unpin,
    S: Unpin,
{
    fn pre_exec<ET>(
        &mut self,
        _qemu: Qemu,
        _emulator_modules: &mut EmulatorModules<ET, I, S>,
        _state: &mut S,
        _input: &I,
    ) where
        ET: EmulatorModuleTuple<I, S>,
    {
        self.profile.record_restore_end();
    }
}
