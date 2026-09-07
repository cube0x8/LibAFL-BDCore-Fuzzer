use core::{fmt::Debug, ptr::addr_of_mut};
use libafl::{
    corpus::{Corpus, CorpusId, HasCurrentCorpusId, InMemoryOnDiskCorpus, OnDiskCorpus, Testcase},
    events::{
        ClientDescription, EventFirer, EventReceiver, EventRestarter, ProgressReporter, SendExiting,
    },
    executors::{Executor, ShadowExecutor},
    feedback_and_fast, feedback_not, feedback_or, feedback_or_fast,
    feedbacks::{ConstFeedback, CrashFeedback, MaxMapFeedback, TimeFeedback, TimeoutFeedback},
    fuzzer::{Evaluator, ExecutesInput, Fuzzer, StdFuzzer},
    inputs::{BytesInput, ResizableMutator},
    mutators::{
        token_mutations::I2SRandReplace, HavocScheduledMutator, MutationResult, Mutator,
        StdMOptMutator,
    },
    observers::{CanTrack, HitcountsMapObserver, TimeObserver, VariableMapObserver},
    schedulers::{
        powersched::PowerSchedule, IndexesLenTimeMinimizerScheduler, PowerQueueScheduler,
        QueueScheduler,
    },
    stages::{
        calibrate::CalibrationStage, power::StdPowerMutationalStage, ObserverEqualityFactory,
        ShadowTracingStage, StagesTuple, StdMutationalStage, StdTMinMutationalStage,
        SyncFromDiskStage,
    },
    state::{HasCorpus, HasCurrentTestcase, StdState},
    Error, HasMetadata,
};
use libafl_bolts::{
    ownedref::OwnedMutSlice,
    rands::StdRand,
    tuples::{tuple_list, Prepend},
    Named,
};
use libafl_qemu::{
    modules::{
        cmplog::CmpLogObserver, snapshot::SnapshotModule, utils::filters::StdAddressFilter,
        EmulatorModuleTuple, StdEdgeCoverageModule,
    },
    Emulator, Qemu, QemuExecutor,
};
use std::borrow::Cow;
use std::io::Write as _;
use std::{
    collections::HashMap,
    fs,
    path::{Path, PathBuf},
    process,
    sync::{
        atomic::{AtomicBool, AtomicU64, Ordering},
        Arc,
    },
    thread,
    time::{Duration, Instant},
};

use crate::harness::write_timeout_last_guest_block;
use libafl_pe_mutator::{
    pe_manifest_hash_hex, write_pe_manifest_sidecar, BytesToPeMutator, PeInputManifestMetadata,
    PeLibAflInput, PeMutator, PeMutatorOptions, SectionBodyMutator,
};
use libafl_targets::{edges_map_mut_ptr, EDGES_MAP_DEFAULT_SIZE, MAX_EDGES_FOUND};
use nix::libc;
use pe_mutator_core::{
    pe::PeFile, AssemblyMutationMode, PeInputFingerprint, PeInputManifest, PeMutationCategory,
    PeMutationCategorySet, PeMutationKind, PeMutationSet, PeMutatorConfig, StackDepthConfig,
};
use serde::{Deserialize, Serialize};

use typed_builder::TypedBuilder;

pub type ClientState =
    StdState<InMemoryOnDiskCorpus<BytesInput>, BytesInput, StdRand, OnDiskCorpus<BytesInput>>;

const WATCHDOG_POLL_INTERVAL: Duration = Duration::from_millis(25);
const WATCHDOG_MIN_GRACE: Duration = Duration::from_secs(2);

#[derive(Debug)]
struct ExecutionWatchdogState {
    active: AtomicBool,
    deadline_ns: AtomicU64,
    owner_pid: AtomicU64,
}

#[derive(Debug)]
struct ExecutionWatchdog {
    state: Arc<ExecutionWatchdogState>,
    timeout_ns: u64,
}

struct ExecutionWatchdogGuard<'a> {
    active: &'a AtomicBool,
}

impl Drop for ExecutionWatchdogGuard<'_> {
    fn drop(&mut self) {
        self.active.store(false, Ordering::Release);
    }
}

impl ExecutionWatchdog {
    fn monotonic_ns() -> u64 {
        let mut now = libc::timespec {
            tv_sec: 0,
            tv_nsec: 0,
        };
        let result = unsafe { libc::clock_gettime(libc::CLOCK_MONOTONIC, &raw mut now) };
        if result != 0 {
            return 0;
        }

        (now.tv_sec as u64)
            .saturating_mul(1_000_000_000)
            .saturating_add(now.tv_nsec as u64)
    }

    fn new(timeout: Duration) -> Result<Self, Error> {
        let state = Arc::new(ExecutionWatchdogState {
            active: AtomicBool::new(false),
            deadline_ns: AtomicU64::new(0),
            owner_pid: AtomicU64::new(0),
        });

        // LibAFL's executor timer is authoritative. This thread exists only as a fallback for
        // executions that stop advancing while the normal timer is lost, so keep it well clear
        // of the primary timeout and client-restart window.
        let timeout_ns = timeout
            .saturating_add(timeout.max(WATCHDOG_MIN_GRACE))
            .as_nanos()
            .min(u128::from(u64::MAX)) as u64;
        Ok(Self { state, timeout_ns })
    }

    fn ensure_thread_for_current_process(&self) {
        let pid = u64::try_from(unsafe { libc::getpid() }).unwrap_or(0);
        let owner_pid = self.state.owner_pid.load(Ordering::Acquire);
        if owner_pid == pid {
            return;
        }
        if self
            .state
            .owner_pid
            .compare_exchange(owner_pid, pid, Ordering::AcqRel, Ordering::Acquire)
            .is_err()
        {
            return;
        }

        let thread_state = Arc::clone(&self.state);
        thread::Builder::new()
            .name("bdcore-exec-watchdog".to_string())
            .spawn(move || loop {
                if thread_state.active.load(Ordering::Acquire) {
                    let deadline_ns = thread_state.deadline_ns.load(Ordering::Acquire);
                    if deadline_ns != 0
                        && Self::monotonic_ns() >= deadline_ns
                        && thread_state
                            .active
                            .compare_exchange(true, false, Ordering::AcqRel, Ordering::Acquire)
                            .is_ok()
                    {
                        // The normal LibAFL timer handler is allowed to save timeout state first.
                        // If it deadlocks in signal-unsafe runtime code, do not enter that handler
                        // recursively: terminate the executor and let the broker restart it.
                        write_timeout_last_guest_block();
                        unsafe {
                            libc::_exit(55);
                        }
                    }
                }
                thread::sleep(WATCHDOG_POLL_INTERVAL);
            })
            .unwrap_or_else(|err| panic!("failed to start execution watchdog: {err}"));
    }

    fn run<T>(&self, run_target: impl FnOnce() -> T) -> T {
        if std::env::var_os("BDCORE_DISABLE_EXEC_WATCHDOG").is_some() {
            return run_target();
        }

        self.ensure_thread_for_current_process();
        let deadline_ns = Self::monotonic_ns().saturating_add(self.timeout_ns);
        self.state.deadline_ns.store(deadline_ns, Ordering::Release);
        self.state.active.store(true, Ordering::Release);
        let _guard = ExecutionWatchdogGuard {
            active: &self.state.active,
        };
        run_target()
    }
}

#[derive(Debug, Default)]
struct PeSectionReducer {
    next_candidate: usize,
}

impl PeSectionReducer {
    fn read_u16(bytes: &[u8], offset: usize) -> Option<u16> {
        Some(u16::from_le_bytes(
            bytes.get(offset..offset + 2)?.try_into().ok()?,
        ))
    }

    fn read_u32(bytes: &[u8], offset: usize) -> Option<u32> {
        Some(u32::from_le_bytes(
            bytes.get(offset..offset + 4)?.try_into().ok()?,
        ))
    }

    fn write_u32(bytes: &mut [u8], offset: usize, value: u32) -> Option<()> {
        bytes
            .get_mut(offset..offset + 4)?
            .copy_from_slice(&value.to_le_bytes());
        Some(())
    }
}

impl Named for PeSectionReducer {
    fn name(&self) -> &Cow<'static, str> {
        static NAME: Cow<'static, str> = Cow::Borrowed("PeSectionReducer");
        &NAME
    }
}

impl Mutator<BytesInput, ClientState> for PeSectionReducer {
    fn mutate(
        &mut self,
        _state: &mut ClientState,
        input: &mut BytesInput,
    ) -> Result<MutationResult, Error> {
        let bytes = input.as_ref();
        let size = bytes.len();
        let pe_offset = Self::read_u32(bytes, 0x3c).map(|value| value as usize);
        let Some(pe_offset) = pe_offset
            .filter(|offset| bytes.get(*offset..*offset + 4) == Some(b"PE\0\0".as_slice()))
        else {
            return Ok(MutationResult::Skipped);
        };

        let Some(section_count) = Self::read_u16(bytes, pe_offset + 6).map(|value| value as usize)
        else {
            return Ok(MutationResult::Skipped);
        };
        let Some(optional_size) = Self::read_u16(bytes, pe_offset + 20).map(|value| value as usize)
        else {
            return Ok(MutationResult::Skipped);
        };
        let optional_offset = pe_offset + 24;
        let section_table = optional_offset.saturating_add(optional_size);
        let Some(section_table_end) = section_count
            .checked_mul(40)
            .and_then(|size| section_table.checked_add(size))
            .filter(|end| *end <= bytes.len())
        else {
            return Ok(MutationResult::Skipped);
        };

        let entry_point = Self::read_u32(bytes, optional_offset + 16).unwrap_or_default() as usize;
        let file_alignment = Self::read_u32(bytes, optional_offset + 36)
            .map(|value| value as usize)
            .filter(|value| value.is_power_of_two() && *value <= 0x10000)
            .unwrap_or(0x200);
        let mut max_raw_end = section_table_end;
        let mut sections = Vec::with_capacity(section_count);
        let mut reducible_sections = Vec::new();
        for index in 0..section_count {
            let section = section_table + index * 40;
            let Some(virtual_size) = Self::read_u32(bytes, section + 8).map(|value| value as usize)
            else {
                return Ok(MutationResult::Skipped);
            };
            let Some(virtual_address) =
                Self::read_u32(bytes, section + 12).map(|value| value as usize)
            else {
                return Ok(MutationResult::Skipped);
            };
            let Some(raw_size) = Self::read_u32(bytes, section + 16).map(|value| value as usize)
            else {
                return Ok(MutationResult::Skipped);
            };
            let Some(raw_offset) = Self::read_u32(bytes, section + 20).map(|value| value as usize)
            else {
                return Ok(MutationResult::Skipped);
            };
            max_raw_end = max_raw_end.max(raw_offset.saturating_add(raw_size));
            let virtual_end = virtual_address.saturating_add(virtual_size.max(raw_size));
            let contains_entry_point = virtual_address <= entry_point && entry_point < virtual_end;
            let minimum_raw_size = if contains_entry_point {
                entry_point
                    .saturating_sub(virtual_address)
                    .saturating_add(0x40)
                    .div_ceil(file_alignment)
                    .saturating_mul(file_alignment)
                    .min(raw_size)
            } else {
                0
            };
            sections.push((section, raw_offset, raw_size));
            if raw_size > minimum_raw_size
                && raw_offset >= section_table_end
                && raw_offset.saturating_add(raw_size) <= size
            {
                reducible_sections.push((index, minimum_raw_size));
            }
        }

        if size > max_raw_end {
            input.resize(max_raw_end, 0);
            let bytes = input.as_mut();
            Self::repair_security_directory(bytes, optional_offset, max_raw_end, None);
            return Ok(MutationResult::Mutated);
        }

        let mut candidates = Vec::new();
        for (section_index, minimum_raw_size) in reducible_sections {
            let section_size = sections[section_index].2;
            let available_blocks = section_size.saturating_sub(minimum_raw_size) / file_alignment;
            let mut reduction_blocks = [
                1,
                2,
                4,
                8,
                available_blocks / 4,
                available_blocks / 2,
                available_blocks,
            ]
            .into_iter()
            .filter(|blocks| *blocks != 0 && *blocks <= available_blocks)
            .collect::<Vec<_>>();
            reduction_blocks.sort_unstable();
            reduction_blocks.dedup();
            Extend::extend(
                &mut candidates,
                reduction_blocks
                    .into_iter()
                    .map(|blocks| (section_index, blocks)),
            );
        }
        if candidates.is_empty() {
            return Ok(MutationResult::Skipped);
        }
        let (removed_index, reduction_blocks) = candidates[self.next_candidate % candidates.len()];
        self.next_candidate = self.next_candidate.wrapping_add(1);
        let (_, section_offset, section_size) = sections[removed_index];
        let removed_size = reduction_blocks * file_alignment;
        let removed_end = section_offset.saturating_add(section_size);
        let removed_offset = removed_end.saturating_sub(removed_size);
        if removed_offset < section_table_end || removed_end > size || removed_size == 0 {
            return Ok(MutationResult::Skipped);
        }
        if sections
            .iter()
            .enumerate()
            .any(|(index, (_, raw_offset, raw_size))| {
                index != removed_index
                    && *raw_size != 0
                    && *raw_offset < removed_end
                    && raw_offset.saturating_add(*raw_size) > removed_offset
            })
        {
            return Ok(MutationResult::Skipped);
        }

        input.as_mut().drain(removed_offset..removed_end);
        let new_len = size - removed_size;
        let bytes = input.as_mut();
        for (index, (section, raw_offset, raw_size)) in sections.into_iter().enumerate() {
            if index == removed_index {
                let _ = Self::write_u32(bytes, section + 16, (raw_size - removed_size) as u32);
            } else if raw_offset >= removed_end {
                let Some(new_offset) = raw_offset.checked_sub(removed_size) else {
                    return Ok(MutationResult::Skipped);
                };
                let _ = Self::write_u32(bytes, section + 20, new_offset as u32);
            }
        }

        let coff_symbols = Self::read_u32(bytes, pe_offset + 12).unwrap_or_default() as usize;
        if coff_symbols >= removed_end {
            let _ = Self::write_u32(bytes, pe_offset + 12, (coff_symbols - removed_size) as u32);
        } else if coff_symbols >= removed_offset {
            let _ = Self::write_u32(bytes, pe_offset + 12, 0);
            let _ = Self::write_u32(bytes, pe_offset + 16, 0);
        }
        Self::repair_security_directory(
            bytes,
            optional_offset,
            new_len,
            Some((removed_offset, removed_end)),
        );

        Ok(MutationResult::Mutated)
    }

    fn post_exec(
        &mut self,
        _state: &mut ClientState,
        _new_corpus_id: Option<CorpusId>,
    ) -> Result<(), Error> {
        Ok(())
    }
}

impl PeSectionReducer {
    fn repair_security_directory(
        bytes: &mut [u8],
        optional_offset: usize,
        new_len: usize,
        removed_range: Option<(usize, usize)>,
    ) {
        let optional_magic = Self::read_u16(bytes, optional_offset).unwrap_or_default();
        let (data_directory, number_of_directories) = match optional_magic {
            0x10b => (optional_offset + 96, optional_offset + 92),
            0x20b => (optional_offset + 112, optional_offset + 108),
            _ => return,
        };
        if Self::read_u32(bytes, number_of_directories).unwrap_or_default() > 4 {
            let security = data_directory + 4 * 8;
            let security_offset = Self::read_u32(bytes, security).unwrap_or_default() as usize;
            let security_size = Self::read_u32(bytes, security + 4).unwrap_or_default() as usize;
            let security_end = security_offset.saturating_add(security_size);
            if let Some((removed_offset, removed_end)) = removed_range {
                if security_offset >= removed_end {
                    let _ = Self::write_u32(
                        bytes,
                        security,
                        (security_offset - (removed_end - removed_offset)) as u32,
                    );
                    return;
                }
                if security_end > removed_offset {
                    let _ = Self::write_u32(bytes, security, 0);
                    let _ = Self::write_u32(bytes, security + 4, 0);
                    return;
                }
            }
            if security_end > new_len {
                let _ = Self::write_u32(bytes, security, 0);
                let _ = Self::write_u32(bytes, security + 4, 0);
            }
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct SeedCorpusEntryMetadata;

libafl_bolts::impl_serdeany!(SeedCorpusEntryMetadata);

#[derive(Debug)]
enum CampaignScheduler<MS, PS> {
    Minimized(MS),
    Direct(PS),
}

impl<MS, PS, I, S> libafl::schedulers::RemovableScheduler<I, S> for CampaignScheduler<MS, PS>
where
    MS: libafl::schedulers::RemovableScheduler<I, S>,
    PS: libafl::schedulers::RemovableScheduler<I, S>,
{
    fn on_remove(
        &mut self,
        state: &mut S,
        id: CorpusId,
        testcase: &Option<Testcase<I>>,
    ) -> Result<(), Error> {
        match self {
            Self::Minimized(scheduler) => scheduler.on_remove(state, id, testcase),
            Self::Direct(scheduler) => scheduler.on_remove(state, id, testcase),
        }
    }

    fn on_replace(&mut self, state: &mut S, id: CorpusId, prev: &Testcase<I>) -> Result<(), Error> {
        match self {
            Self::Minimized(scheduler) => scheduler.on_replace(state, id, prev),
            Self::Direct(scheduler) => scheduler.on_replace(state, id, prev),
        }
    }
}

impl<MS, PS, I, S> libafl::schedulers::Scheduler<I, S> for CampaignScheduler<MS, PS>
where
    MS: libafl::schedulers::Scheduler<I, S>,
    PS: libafl::schedulers::Scheduler<I, S>,
{
    fn on_add(&mut self, state: &mut S, id: CorpusId) -> Result<(), Error> {
        match self {
            Self::Minimized(scheduler) => scheduler.on_add(state, id),
            Self::Direct(scheduler) => scheduler.on_add(state, id),
        }
    }

    fn on_evaluation<OT>(&mut self, state: &mut S, input: &I, observers: &OT) -> Result<(), Error>
    where
        OT: libafl_bolts::tuples::MatchName,
    {
        match self {
            Self::Minimized(scheduler) => scheduler.on_evaluation(state, input, observers),
            Self::Direct(scheduler) => scheduler.on_evaluation(state, input, observers),
        }
    }

    fn next(&mut self, state: &mut S) -> Result<CorpusId, Error> {
        match self {
            Self::Minimized(scheduler) => scheduler.next(state),
            Self::Direct(scheduler) => scheduler.next(state),
        }
    }

    fn set_current_scheduled(
        &mut self,
        state: &mut S,
        next_id: Option<CorpusId>,
    ) -> Result<(), Error> {
        match self {
            Self::Minimized(scheduler) => scheduler.set_current_scheduled(state, next_id),
            Self::Direct(scheduler) => scheduler.set_current_scheduled(state, next_id),
        }
    }
}

#[derive(Debug)]
struct SeedOnlyScheduler<CS> {
    inner: CS,
    enabled: bool,
    seed_ids: Vec<CorpusId>,
    next_seed_index: usize,
    seed_ids_initialized: bool,
}

#[derive(Debug)]
struct SeedOnlyRestartStage<ST> {
    inner: ST,
}

impl<ST> SeedOnlyRestartStage<ST> {
    fn new(inner: ST) -> Self {
        Self { inner }
    }
}

impl<E, EM, S, ST, Z> libafl::stages::Stage<E, EM, S, Z> for SeedOnlyRestartStage<ST>
where
    ST: libafl::stages::Stage<E, EM, S, Z>,
{
    fn perform(
        &mut self,
        fuzzer: &mut Z,
        executor: &mut E,
        state: &mut S,
        manager: &mut EM,
    ) -> Result<(), Error> {
        self.inner.perform(fuzzer, executor, state, manager)
    }
}

impl<S, ST> libafl::stages::Restartable<S> for SeedOnlyRestartStage<ST> {
    fn should_restart(&mut self, _state: &mut S) -> Result<bool, Error> {
        Ok(true)
    }

    fn clear_progress(&mut self, _state: &mut S) -> Result<(), Error> {
        Ok(())
    }
}

impl<CS> SeedOnlyScheduler<CS> {
    fn new(inner: CS, enabled: bool) -> Self {
        Self {
            inner,
            enabled,
            seed_ids: Vec::new(),
            next_seed_index: 0,
            seed_ids_initialized: false,
        }
    }

    fn is_seed<I, S>(state: &S, id: CorpusId) -> Result<bool, Error>
    where
        S: HasCorpus<I>,
    {
        Ok(state
            .corpus()
            .get(id)?
            .borrow()
            .has_metadata::<SeedCorpusEntryMetadata>())
    }

    fn initialize_seed_ids<I, S>(&mut self, state: &S) -> Result<(), Error>
    where
        S: HasCorpus<I>,
    {
        if self.seed_ids_initialized {
            return Ok(());
        }

        self.seed_ids.clear();
        for id in state.corpus().ids() {
            if Self::is_seed(state, id)? {
                self.seed_ids.push(id);
            }
        }
        self.next_seed_index = 0;
        self.seed_ids_initialized = true;
        Ok(())
    }
}

impl<CS, I, S> libafl::schedulers::RemovableScheduler<I, S> for SeedOnlyScheduler<CS>
where
    CS: libafl::schedulers::RemovableScheduler<I, S>,
{
    fn on_remove(
        &mut self,
        state: &mut S,
        id: CorpusId,
        testcase: &Option<libafl::corpus::Testcase<I>>,
    ) -> Result<(), Error> {
        self.inner.on_remove(state, id, testcase)?;
        if let Some(index) = self.seed_ids.iter().position(|seed_id| *seed_id == id) {
            self.seed_ids.remove(index);
            if index < self.next_seed_index {
                self.next_seed_index -= 1;
            }
            if !self.seed_ids.is_empty() {
                self.next_seed_index %= self.seed_ids.len();
            } else {
                self.next_seed_index = 0;
            }
        }
        Ok(())
    }

    fn on_replace(
        &mut self,
        state: &mut S,
        id: CorpusId,
        prev: &libafl::corpus::Testcase<I>,
    ) -> Result<(), Error> {
        self.inner.on_replace(state, id, prev)
    }
}

impl<CS, I, S> libafl::schedulers::Scheduler<I, S> for SeedOnlyScheduler<CS>
where
    CS: libafl::schedulers::Scheduler<I, S>,
    S: HasCorpus<I>,
{
    fn on_add(&mut self, state: &mut S, id: CorpusId) -> Result<(), Error> {
        self.inner.on_add(state, id)
    }

    fn on_evaluation<OT>(&mut self, state: &mut S, input: &I, observers: &OT) -> Result<(), Error>
    where
        OT: libafl_bolts::tuples::MatchName,
    {
        self.inner.on_evaluation(state, input, observers)
    }

    fn next(&mut self, state: &mut S) -> Result<CorpusId, Error> {
        if !self.enabled {
            return self.inner.next(state);
        }

        self.initialize_seed_ids(state)?;
        if self.seed_ids.is_empty() {
            return Err(Error::empty(
                "No seed-tagged entries are available for mutation scheduling.",
            ));
        }

        let id = self.seed_ids[self.next_seed_index];
        self.next_seed_index = (self.next_seed_index + 1) % self.seed_ids.len();
        self.inner.set_current_scheduled(state, Some(id))?;
        Ok(id)
    }

    fn set_current_scheduled(
        &mut self,
        state: &mut S,
        next_id: Option<CorpusId>,
    ) -> Result<(), Error> {
        self.inner.set_current_scheduled(state, next_id)
    }
}

use crate::{
    harness::{tmin_pc_observer, tmin_pc_was_hit, FuzzHarness},
    mutators::{
        havoc_fixed_size_mutations, BDCoreMutator, FsgPostdecodeMutator,
        Pec3Operation11Mode2Mutator, Pec3Operation11Mutator, Pec3PostdecodeMutator,
        Pec3StreamWindowMutator, PelockDeepMutator,
    },
    options::FuzzerOptions,
    scan_profile::ScanProfile,
    utils,
};

fn pe_mutator_config_from_options(options: &FuzzerOptions) -> PeMutatorConfig {
    let mut enabled_categories = PeMutationCategorySet::ALL;
    let mut enabled_mutations = PeMutationSet::ALL;

    if options.pelock {
        enabled_categories = PeMutationCategorySet::NONE;
        enabled_mutations = PeMutationSet::NONE;
        enabled_categories.insert(PeMutationCategory::Assembly);
        if !options.pelock_pe_only {
            enabled_mutations.insert(PeMutationKind::EntryPoint);
        }
        if options.assembly {
            enabled_mutations.insert(PeMutationKind::ExecutableChunkAssembly);
        }
    } else if options.pe_header
        || options.sections
        || options.assembly
        || options.export_dir
        || options.resource_dir
        || options.data_dir
    {
        enabled_categories = PeMutationCategorySet::NONE;
        enabled_mutations = PeMutationSet::NONE;

        if options.pe_header {
            enabled_categories.insert(PeMutationCategory::Architecture);
            enabled_mutations.insert(PeMutationKind::Architecture);
        }

        if options.sections {
            enabled_categories.insert(PeMutationCategory::Headers);
            enabled_categories.insert(PeMutationCategory::Sections);
            enabled_mutations.insert(PeMutationKind::SectionCount);
            enabled_mutations.insert(PeMutationKind::SectionHeader);
            enabled_mutations.insert(PeMutationKind::SectionBody);
        }

        if options.assembly {
            enabled_categories.insert(PeMutationCategory::Assembly);
            enabled_mutations.insert(PeMutationKind::EntryPoint);
            enabled_mutations.insert(PeMutationKind::ExecutableChunkAssembly);
        }

        if options.export_dir {
            enabled_categories.insert(PeMutationCategory::DataDirectories);
            enabled_mutations.insert(PeMutationKind::ExportDirectory);
        }

        if options.resource_dir {
            enabled_categories.insert(PeMutationCategory::DataDirectories);
            enabled_mutations.insert(PeMutationKind::ResourceDirectory);
        }

        if options.data_dir {
            enabled_categories.insert(PeMutationCategory::DataDirectories);
            enabled_mutations.insert(PeMutationKind::DataDirectoryEntry);
        }
    }

    let mut config = PeMutatorConfig {
        stack: StackDepthConfig {
            min_stack_depth: options.pe_min_stack_depth,
            max_stack_depth: options.pe_max_stack_depth,
        },
        enabled_categories,
        enabled_mutations,
        ..PeMutatorConfig::default()
    };

    if options.pelock {
        config.assembly.assembly.mode = AssemblyMutationMode::Mixed;
        config.assembly.assembly.budget.max_mutations = 2;
    }

    if let Some(weight) = options.pe_asm_semantic_weight {
        config.assembly.assembly.budget.semantic_weight = weight;
    }
    if let Some(weight) = options.pe_asm_raw_weight {
        config.assembly.assembly.mode = AssemblyMutationMode::Mixed;
        config.assembly.assembly.budget.raw_weight = weight;
    }

    config
}

fn pe_mutator_from_options(options: &FuzzerOptions) -> PeMutator {
    let config = pe_mutator_config_from_options(options);
    PeMutator::with_options(
        config,
        PeMutatorOptions {
            reporting: options
                .pe_mutator_reporting
                .then(|| "/tmp/pe-report.txt".into()),
            max_size: Some(options.max_target_input_size),
        },
    )
}

fn pelock_mutator_from_options(options: &FuzzerOptions) -> PelockDeepMutator {
    PelockDeepMutator::new(
        pe_mutator_from_options(options),
        options.pe_min_stack_depth,
        options.pe_max_stack_depth,
        options.pelock_pe_only,
    )
}

fn pe_section_body_mutator_from_options(
    options: &FuzzerOptions,
) -> BytesToPeMutator<SectionBodyMutator> {
    let section_index = options
        .section_index
        .expect("--section-body-mutator requires --section-index");
    BytesToPeMutator::with_max_size(
        SectionBodyMutator::with_options(Some(options.max_target_input_size), Some(section_index)),
        options.max_target_input_size,
    )
}

#[derive(TypedBuilder)]
pub struct Instance<'a, EM> {
    options: &'a FuzzerOptions,
    qemu: &'a Qemu,
    harness: &'a dyn FuzzHarness,
    scan_profile: Option<Arc<ScanProfile>>,
    mgr: EM,
    client_description: ClientDescription,
}

impl<EM> Instance<'_, EM>
where
    EM: EventFirer<BytesInput, ClientState>
        + EventRestarter<ClientState>
        + ProgressReporter<ClientState>
        + SendExiting
        + EventReceiver<BytesInput, ClientState>,
{
    fn sync_dir_for_client(&self) -> Option<Vec<PathBuf>> {
        // One launcher client imports external corpus files. The LLMP broker distributes
        // accepted inputs to the remaining clients, avoiding duplicate recursive scans and
        // restart metadata growth on every worker.
        (self.client_description.id() == 1)
            .then(|| self.options.sync_dir())
            .flatten()
    }

    fn collect_initial_inputs(dir: &Path) -> Result<Vec<PathBuf>, Error> {
        let mut files = Vec::new();
        let mut pending = vec![dir.to_path_buf()];

        while let Some(path) = pending.pop() {
            let metadata = fs::metadata(&path).map_err(|err| {
                Error::illegal_argument(format!(
                    "failed to stat tmin input path {}: {err}",
                    path.display()
                ))
            })?;
            if metadata.is_dir() {
                let hidden = path != dir
                    && path
                        .file_name()
                        .and_then(|name| name.to_str())
                        .is_some_and(|name| name.starts_with('.'));
                if hidden {
                    continue;
                }
                for entry in fs::read_dir(&path).map_err(|err| {
                    Error::illegal_argument(format!(
                        "failed to read tmin input directory {}: {err}",
                        path.display()
                    ))
                })? {
                    pending.push(entry.map_err(|err| Error::unknown(err.to_string()))?.path());
                }
                continue;
            }
            if !metadata.is_file() {
                continue;
            }
            let hidden = path
                .file_name()
                .and_then(|name| name.to_str())
                .is_some_and(|name| name.starts_with('.') || name.ends_with(".metadata"));
            if !hidden {
                files.push(path);
            }
        }

        files.sort();
        Ok(files)
    }

    fn run_tmin<ET>(&mut self, modules: ET, state: Option<ClientState>) -> Result<(), Error>
    where
        ET: EmulatorModuleTuple<BytesInput, ClientState> + Debug,
    {
        let tmin_observer = tmin_pc_observer();
        let factory = ObserverEqualityFactory::new(&tmin_observer);
        let mut feedback = ();
        let mut objective = ();
        let mut state = match state {
            Some(state) => state,
            None => StdState::new(
                StdRand::new(),
                InMemoryOnDiskCorpus::no_meta(self.options.queue_dir().unwrap())?,
                OnDiskCorpus::new(self.options.output_dir().unwrap())?,
                &mut feedback,
                &mut objective,
            )?,
        };

        let scheduler = QueueScheduler::new();
        let mut fuzzer = StdFuzzer::new(scheduler, feedback, objective);
        let observers = tuple_list!(tmin_observer);
        let harness = self.harness;
        let scan_profile = self.scan_profile.clone();
        let watchdog = ExecutionWatchdog::new(self.options.timeout)?;
        let mut harness_fn = move |_emulator: &mut Emulator<_, _, _, _, _, _, _>,
                                   _state: &mut _,
                                   input: &BytesInput| {
            watchdog.run(|| harness.run(input, scan_profile.as_deref()))
        };

        self.qemu.flush_jit();
        let emulator = Emulator::empty()
            .modules(modules)
            .build_with_qemu(*self.qemu)?;
        let mut executor = QemuExecutor::new(
            emulator,
            &mut harness_fn,
            observers,
            &mut fuzzer,
            &mut state,
            &mut self.mgr,
            self.options.timeout,
        )?;

        let mut qualifying = Vec::new();
        if state.must_load_initial_inputs() {
            let files = Self::collect_initial_inputs(&self.options.input_dir().unwrap())?;
            if files.is_empty() {
                return Err(Error::illegal_argument("tmin input directory is empty"));
            }

            for path in files {
                let bytes = fs::read(&path).map_err(|err| {
                    Error::illegal_argument(format!(
                        "failed to read tmin input {}: {err}",
                        path.display()
                    ))
                })?;
                let before = bytes.len();
                let input = BytesInput::new(bytes);
                let exit_kind =
                    fuzzer.execute_input(&mut state, &mut executor, &mut self.mgr, &input)?;
                if !tmin_pc_was_hit() || !matches!(exit_kind, libafl::executors::ExitKind::Ok) {
                    log::warn!(
                        "Rejecting tmin seed {}: target_hit={} exit={exit_kind:?}",
                        path.display(),
                        tmin_pc_was_hit(),
                    );
                    continue;
                }

                let filename = path
                    .file_name()
                    .and_then(|name| name.to_str())
                    .unwrap_or("tmin-input")
                    .to_string();
                let id = state
                    .corpus_mut()
                    .add(Testcase::with_filename(input, filename.clone()))?;
                qualifying.push((id, filename, before));
            }
        } else {
            for id in state.corpus().ids().collect::<Vec<_>>() {
                let testcase = state.corpus().get(id)?.borrow();
                let filename = testcase
                    .filename()
                    .clone()
                    .unwrap_or_else(|| format!("corpus-{id}"));
                let before = testcase
                    .file_path()
                    .as_ref()
                    .and_then(|path| fs::metadata(path).ok())
                    .map_or(0, |metadata| metadata.len() as usize);
                qualifying.push((id, filename, before));
            }
        }

        if qualifying.is_empty() {
            return Err(Error::illegal_argument(
                "no input reached the requested tmin target PC",
            ));
        }

        log::info!(
            "Starting exact-PC testcase minimization for {} qualifying inputs",
            qualifying.len()
        );
        let minimizer = PeSectionReducer::default();
        let mut stages = tuple_list!(StdTMinMutationalStage::new(
            minimizer,
            factory,
            self.options.tmin_iterations,
        ));

        for (id, filename, before) in qualifying {
            state.set_corpus_id(id)?;
            stages.perform_all(&mut fuzzer, &mut executor, &mut state, &mut self.mgr)?;

            let minimized = state.current_input_cloned()?;
            let exit_kind =
                fuzzer.execute_input(&mut state, &mut executor, &mut self.mgr, &minimized)?;
            if !tmin_pc_was_hit() || !matches!(exit_kind, libafl::executors::ExitKind::Ok) {
                return Err(Error::illegal_state(format!(
                    "minimized testcase {filename} failed verification: target_hit={} exit={exit_kind:?}",
                    tmin_pc_was_hit(),
                )));
            }
            log::info!(
                "TMin verified {filename}: {before} -> {} bytes",
                minimized.as_ref().len()
            );
        }

        log::info!("TMin complete: {} verified outputs", state.corpus().count());
        self.mgr.send_exiting()?;
        Ok(())
    }

    fn log_corpus_path_diagnostics(&self, label: &str) {
        let cwd = std::env::current_dir().ok();
        let queue_dir = self.options.queue_dir();
        let output_dir = self.options.output_dir();

        let probe_dir = |kind: &str, path: &std::path::PathBuf| {
            let exists = path.exists();
            let is_dir = path.is_dir();
            let canonical = fs::canonicalize(path).ok();
            let probe_path = path.join(format!(".qemu_bdclient_probe_{}", process::id()));
            let probe_result = fs::write(&probe_path, b"probe")
                .and_then(|_| fs::remove_file(&probe_path))
                .map(|_| "ok".to_string())
                .unwrap_or_else(|err| format!("err: {err}"));

            log::info!(
                "[{label}] {kind}: path={:?} exists={} is_dir={} canonical={:?} probe={}",
                path,
                exists,
                is_dir,
                canonical,
                probe_result
            );
        };

        log::info!("[{label}] cwd={cwd:?}");
        if let Some(path) = &queue_dir {
            probe_dir("queue_dir", path);
        }
        if let Some(path) = &output_dir {
            probe_dir("output_dir", path);
        }
    }

    fn tag_current_corpus_as_seed(state: &mut ClientState) -> Result<(), Error> {
        let ids = state.corpus().ids().collect::<Vec<_>>();
        for id in ids {
            let mut testcase = state.corpus().get(id)?.borrow_mut();
            if !testcase.has_metadata::<SeedCorpusEntryMetadata>() {
                testcase.add_metadata(SeedCorpusEntryMetadata);
            }
        }
        Ok(())
    }

    fn manifest_matches_fingerprint(
        manifest: &PeInputManifest,
        fingerprint: &PeInputFingerprint,
    ) -> bool {
        manifest.version == PeInputManifest::MANIFEST_VERSION
            && manifest.pe_fingerprint == *fingerprint
    }

    fn collect_pe_manifest_files(
        root: &Path,
        explicit_manifest_dir: bool,
    ) -> Result<Vec<PathBuf>, Error> {
        let mut files = Vec::new();
        if !root.exists() {
            return Ok(files);
        }

        let mut stack = vec![root.to_path_buf()];
        while let Some(path) = stack.pop() {
            let metadata = match fs::metadata(&path) {
                Ok(metadata) => metadata,
                Err(err) => {
                    return Err(Error::illegal_argument(format!(
                        "failed to stat PE manifest path {}: {err}",
                        path.display()
                    )));
                }
            };

            if metadata.is_dir() {
                for entry in fs::read_dir(&path).map_err(|err| {
                    Error::illegal_argument(format!(
                        "failed to read PE manifest directory {}: {err}",
                        path.display()
                    ))
                })? {
                    let entry = entry.map_err(|err| {
                        Error::illegal_argument(format!(
                            "failed to read PE manifest directory entry under {}: {err}",
                            path.display()
                        ))
                    })?;
                    stack.push(entry.path());
                }
                continue;
            }

            if !metadata.is_file() {
                continue;
            }

            let Some(name) = path.file_name().and_then(|name| name.to_str()) else {
                continue;
            };
            let is_manifest = if explicit_manifest_dir {
                name.ends_with(".json")
            } else {
                name.ends_with(".pemutator.json") || name.ends_with(".manifest.json")
            };
            if is_manifest {
                files.push(path);
            }
        }

        Ok(files)
    }

    fn load_pe_manifests_from_roots(
        roots: &[(PathBuf, bool)],
    ) -> Result<HashMap<[u8; 32], PeInputManifest>, Error> {
        let mut manifests = HashMap::new();

        for (root, explicit_manifest_dir) in roots {
            for path in Self::collect_pe_manifest_files(root, *explicit_manifest_dir)? {
                let bytes = fs::read(&path).map_err(|err| {
                    Error::illegal_argument(format!(
                        "failed to read PE manifest {}: {err}",
                        path.display()
                    ))
                })?;
                let manifest =
                    serde_json::from_slice::<PeInputManifest>(&bytes).map_err(|err| {
                        Error::illegal_argument(format!(
                            "failed to parse PE manifest {}: {err}",
                            path.display()
                        ))
                    })?;
                manifests.insert(manifest.pe_fingerprint.content_hash, manifest);
            }
        }

        Ok(manifests)
    }

    fn pe_manifest_roots(&self) -> Vec<(PathBuf, bool)> {
        let mut roots = Vec::new();
        if let Some(input_dir) = self.options.input_dir() {
            roots.push((input_dir.join(".pemutator"), true));
            roots.push((input_dir, false));
        }
        if let Some(manifest_dir) = self.options.pe_manifest_dir() {
            roots.push((manifest_dir, true));
        }
        roots
    }

    fn attach_pe_manifests_to_corpus(&self, state: &mut ClientState) -> Result<(), Error> {
        let roots = self.pe_manifest_roots();
        let manifests = Self::load_pe_manifests_from_roots(&roots)?;
        if manifests.is_empty() {
            println!("No PE mutator manifests found for imported seeds.");
            return Ok(());
        }

        let mut attached = 0usize;
        let mut stale = 0usize;
        let ids = state.corpus().ids().collect::<Vec<_>>();

        for id in ids {
            let (bytes, file_path, already_has_manifest) = {
                let testcase = state.corpus().get(id)?.borrow();
                let bytes = if let Some(input) = testcase.input() {
                    input.as_ref().to_vec()
                } else if let Some(path) = testcase.file_path() {
                    fs::read(path).map_err(|err| {
                        Error::illegal_argument(format!(
                            "failed to read corpus testcase {}: {err}",
                            path.display()
                        ))
                    })?
                } else {
                    continue;
                };
                (
                    bytes,
                    testcase.file_path().clone(),
                    testcase.has_metadata::<PeInputManifestMetadata>(),
                )
            };

            if already_has_manifest {
                continue;
            }

            let Ok(file) = PeFile::parse(&bytes) else {
                continue;
            };
            let fingerprint = PeInputFingerprint::from_bytes_and_pe(&bytes, &file);
            let Some(manifest) = manifests.get(&fingerprint.content_hash) else {
                continue;
            };

            if !Self::manifest_matches_fingerprint(manifest, &fingerprint) {
                stale += 1;
                eprintln!(
                    "Skipping stale PE manifest for corpus entry hash {}",
                    pe_manifest_hash_hex(&fingerprint)
                );
                continue;
            }

            let mut testcase = state.corpus().get(id)?.borrow_mut();
            testcase.add_metadata(PeInputManifestMetadata {
                manifest: manifest.clone(),
            });
            if let Some(path) = file_path.as_deref() {
                write_pe_manifest_sidecar(path, manifest)?;
            }
            attached += 1;
        }

        println!(
            "Attached PE mutator manifests to {attached} imported corpus entries ({stale} stale manifests skipped)."
        );
        Ok(())
    }

    fn collect_drcov_bulk_inputs(dir: &Path) -> Vec<PathBuf> {
        let mut files = fs::read_dir(dir)
            .unwrap_or_else(|err| panic!("Could not read DrCov bulk directory {dir:?}: {err}"))
            .filter_map(|entry| match entry {
                Ok(entry) => Some(entry.path()),
                Err(err) => {
                    log::warn!("Skipping unreadable DrCov bulk directory entry: {err}");
                    None
                }
            })
            .filter(|path| {
                let is_regular_file = path.is_file();
                let is_hidden_metadata = path
                    .file_name()
                    .and_then(|name| name.to_str())
                    .map_or(false, |name| {
                        name.starts_with('.') || name.ends_with(".metadata")
                    });
                is_regular_file && !is_hidden_metadata
            })
            .collect::<Vec<_>>();
        files.sort();
        files
    }

    pub fn run<ET>(&mut self, mut modules: ET, state: Option<ClientState>) -> Result<(), Error>
    where
        ET: EmulatorModuleTuple<BytesInput, ClientState> + Debug,
    {
        let snapshot_module: &mut SnapshotModule =
            modules.match_first_type_mut::<SnapshotModule>().unwrap();
        let snapshot_started_at = Instant::now();
        snapshot_module.snapshot(*self.qemu);
        if let Some(scan_profile) = &self.scan_profile {
            scan_profile.record_snapshot_capture(snapshot_started_at.elapsed());
        }

        if self.options.tmin {
            return self.run_tmin(modules, state);
        }

        // Create an observation channel using the coverage map
        let mut edges_observer = unsafe {
            HitcountsMapObserver::new(VariableMapObserver::from_mut_slice(
                "edges",
                OwnedMutSlice::from_raw_parts_mut(edges_map_mut_ptr(), EDGES_MAP_DEFAULT_SIZE),
                addr_of_mut!(MAX_EDGES_FOUND),
            ))
            .track_indices()
        };

        let mut edge_cov_address_filter = StdAddressFilter::default();
        match self.harness.bd_engine().coverage_filter() {
            Some(cov_address_range) => {
                edge_cov_address_filter = StdAddressFilter::allow_list(cov_address_range);
            }
            None => {
                log::warn!("No coverage filter set, instrumenting all modules");
            }
        }

        let edge_coverage_module = StdEdgeCoverageModule::builder()
            .map_observer(edges_observer.as_mut())
            .address_filter(edge_cov_address_filter)
            .build()?;

        let modules = modules.prepend(edge_coverage_module);

        // Create an observation channel to keep track of the execution time
        let time_observer = TimeObserver::new("time");

        let map_feedback = MaxMapFeedback::new(&edges_observer);

        let calibration = CalibrationStage::new(&map_feedback);

        // Feedback to rate the interestingness of an input
        // This one is composed by two Feedbacks in OR
        let mut feedback = feedback_and_fast!(
            // A crash-only campaign is not a hang campaign. Reject timed-out executions before
            // edge or time feedback can retain them in the evolution corpus.
            feedback_or_fast!(
                ConstFeedback::new(!self.options.crashes_only),
                feedback_not!(TimeoutFeedback::new())
            ),
            feedback_or!(
                // New maximization map feedback linked to the edges observer and feedback state.
                map_feedback,
                // Time feedback does not need a feedback state.
                TimeFeedback::new(&time_observer)
            )
        );

        // A feedback to choose if an input is a solution or not
        let mut objective = feedback_or_fast!(
            CrashFeedback::new(),
            feedback_and_fast!(
                ConstFeedback::new(!self.options.crashes_only),
                TimeoutFeedback::new()
            )
        );

        // If not restarting, create a State from scratch
        let mut state = match state {
            Some(x) => x,
            None => {
                StdState::new(
                    // RNG
                    StdRand::new(),
                    // Corpus that will be evolved, we keep it in memory for performance
                    InMemoryOnDiskCorpus::no_meta(self.options.queue_dir().unwrap())?,
                    // Corpus in which we store solutions (crashes in this example),
                    // on disk so the user can get them after stopping the fuzzer
                    OnDiskCorpus::new(self.options.output_dir().unwrap())?,
                    // States of the feedbacks.
                    // The feedbacks can report the data that should persist in the State.
                    &mut feedback,
                    // Same for objective feedbacks
                    &mut objective,
                )?
            }
        };

        self.log_corpus_path_diagnostics("post-state-init");

        // A minimization+queue policy to get testcasess from the corpus
        let power_scheduler =
            PowerQueueScheduler::new(&mut state, &edges_observer, PowerSchedule::fast());
        let scheduler = if self.options.disable_minimizer_scheduler {
            CampaignScheduler::Direct(power_scheduler)
        } else {
            CampaignScheduler::Minimized(IndexesLenTimeMinimizerScheduler::new(
                &edges_observer,
                power_scheduler,
            ))
        };
        let scheduler = SeedOnlyScheduler::new(scheduler, self.options.only_seeds);

        let observers = tuple_list!(edges_observer, time_observer);

        let harness = self.harness;
        let scan_profile = self.scan_profile.clone();
        let watchdog = ExecutionWatchdog::new(self.options.timeout)?;
        let mut harness_fn = move |_emulator: &mut Emulator<_, _, _, _, _, _, _>,
                                   _state: &mut _,
                                   input: &BytesInput| {
            watchdog.run(|| harness.run(input, scan_profile.as_deref()))
        };

        // A fuzzer with feedbacks and a corpus scheduler
        let mut fuzzer = StdFuzzer::new(scheduler, feedback, objective);

        self.qemu.flush_jit();
        let emulator = Emulator::empty()
            .modules(modules)
            .build_with_qemu(*self.qemu)?;

        if let Some(rerun_input) = &self.options.rerun_input {
            let mut executor = QemuExecutor::new(
                emulator,
                &mut harness_fn,
                observers,
                &mut fuzzer,
                &mut state,
                &mut self.mgr,
                self.options.timeout,
            )?;

            let rerun_inputs = if self.options.drcov_bulk {
                let files = Self::collect_drcov_bulk_inputs(rerun_input);
                if files.is_empty() {
                    return Err(Error::illegal_argument(format!(
                        "DrCov bulk directory has no regular input files: {rerun_input:?}"
                    )));
                }
                log::info!(
                    "Running DrCov bulk mode over {} files from {:?}",
                    files.len(),
                    rerun_input
                );
                files
            } else {
                vec![rerun_input.clone()]
            };

            for (idx, rerun_input) in rerun_inputs.iter().enumerate() {
                if self.options.drcov_bulk && (idx % 25 == 0 || idx + 1 == rerun_inputs.len()) {
                    println!(
                        "DrCov bulk progress: starting {}/{} {:?}",
                        idx + 1,
                        rerun_inputs.len(),
                        rerun_input
                    );
                }

                // TODO: We might want to support non-bytes inputs at some point?
                let bytes = fs::read(rerun_input)
                    .unwrap_or_else(|_| panic!("Could not load file {rerun_input:?}"));
                let input = BytesInput::new(bytes);

                log::debug!(
                    "Rerunning input with DrCov ({}/{}) {:?}",
                    idx + 1,
                    rerun_inputs.len(),
                    rerun_input
                );
                executor
                    .run_target(&mut fuzzer, &mut state, &mut self.mgr, &input)
                    .expect("Error running target");

                if self.options.drcov_bulk && ((idx + 1) % 25 == 0 || idx + 1 == rerun_inputs.len())
                {
                    println!(
                        "DrCov bulk progress: completed {}/{}",
                        idx + 1,
                        rerun_inputs.len()
                    );
                }
            }
            drop(executor);

            if let Some(output_file_path) = self.options.drcov.as_ref().cloned() {
                if self.options.drcov_bulk {
                    log::info!(
                        "Bulk DrCov file generated at {:?}. We're done! :).",
                        output_file_path
                    );
                    self.mgr.send_exiting()?;
                    return Ok(());
                } else {
                    log::debug!("Coverage file generated correctly. Compressing...");
                    if let Err(e) = utils::compress_and_replace(&output_file_path) {
                        return Err(Error::unknown(format!("Compression error: {e}")));
                    } else {
                        log::info!("Output file successfully compressed. We're done! :).");
                        self.mgr.send_exiting()?;
                        return Ok(());
                    }
                }
            } else {
                log::info!("Single rerun completed. We're done! :).");
                self.mgr.send_exiting()?;
                return Ok(());
            }
        }

        // use cmplog
        if self
            .options
            .is_cmplog_core(self.client_description.core_id())
        {
            // Create a QEMU in-process executor
            let executor = QemuExecutor::new(
                emulator,
                &mut harness_fn,
                observers,
                &mut fuzzer,
                &mut state,
                &mut self.mgr,
                self.options.timeout,
            )?;

            // Create an observation channel using cmplog map
            let cmplog_observer = CmpLogObserver::new("cmplog", true);

            let mut executor = ShadowExecutor::new(executor, tuple_list!(cmplog_observer));

            let tracing = ShadowTracingStage::new();

            // Setup a randomic Input2State stage
            let i2s = StdMutationalStage::new(HavocScheduledMutator::new(tuple_list!(
                I2SRandReplace::new()
            )));

            if self.options.uses_full_pe_mutator() {
                if self.options.pelock {
                    let pe_stage = StdMutationalStage::<
                        _, _, PeLibAflInput, BytesInput, _, _, _,
                    >::transforming(pelock_mutator_from_options(self.options));

                    match self.sync_dir_for_client() {
                        Some(sync_dir) => {
                            let sync_stage =
                                SyncFromDiskStage::with_from_file(sync_dir, Duration::from_secs(5));
                            let mut stages =
                                tuple_list!(calibration, tracing, i2s, pe_stage, sync_stage);
                            self.fuzz(&mut state, &mut fuzzer, &mut executor, &mut stages)
                        }
                        None => {
                            let mut stages = tuple_list!(calibration, tracing, i2s, pe_stage);
                            self.fuzz(&mut state, &mut fuzzer, &mut executor, &mut stages)
                        }
                    }
                } else {
                    let pe_stage = StdMutationalStage::<
                        _,
                        _,
                        PeLibAflInput,
                        BytesInput,
                        _,
                        _,
                        _,
                    >::transforming(pe_mutator_from_options(self.options));

                    match self.sync_dir_for_client() {
                        Some(sync_dir) => {
                            let sync_stage =
                                SyncFromDiskStage::with_from_file(sync_dir, Duration::from_secs(5));
                            let mut stages =
                                tuple_list!(calibration, tracing, i2s, pe_stage, sync_stage);
                            self.fuzz(&mut state, &mut fuzzer, &mut executor, &mut stages)
                        }
                        None => {
                            let mut stages = tuple_list!(calibration, tracing, i2s, pe_stage);
                            self.fuzz(&mut state, &mut fuzzer, &mut executor, &mut stages)
                        }
                    }
                }
            } else {
                let power_mutator = if self.options.fsg_postdecode {
                    BDCoreMutator::Fsg(FsgPostdecodeMutator)
                } else if self.options.pec3_peviewer {
                    BDCoreMutator::Pec3Stream(Pec3StreamWindowMutator::new(
                        self.options.pec3_peviewer_control_only,
                        self.options.pec3_peviewer_main_only,
                        self.options.pec3_peviewer_heap_poison,
                    ))
                } else if self.options.pec3_operation11 {
                    BDCoreMutator::Pec3Operation11(Pec3Operation11Mutator)
                } else if self.options.pec3_operation11_mode2 {
                    BDCoreMutator::Pec3Operation11Mode2(Pec3Operation11Mode2Mutator)
                } else if self.options.pec3_postdecode {
                    BDCoreMutator::Pec3(Pec3PostdecodeMutator)
                } else if self.options.fixed_size_mutations {
                    BDCoreMutator::MoptFixed(StdMOptMutator::new(
                        &mut state,
                        havoc_fixed_size_mutations(),
                        7,
                        5,
                    )?)
                } else {
                    BDCoreMutator::Mopt(StdMOptMutator::new(
                        &mut state,
                        libafl::mutators::havoc_mutations(),
                        7,
                        5,
                    )?)
                };

                let power: StdPowerMutationalStage<_, _, BytesInput, _, _, _> =
                    StdPowerMutationalStage::new(power_mutator);

                // The order of the stages matter!

                match self.sync_dir_for_client() {
                    Some(sync_dir) => {
                        let sync_stage =
                            SyncFromDiskStage::with_from_file(sync_dir, Duration::from_secs(5));
                        let mut stages = tuple_list!(calibration, tracing, i2s, power, sync_stage);
                        self.fuzz(&mut state, &mut fuzzer, &mut executor, &mut stages)
                    }
                    None => {
                        let mut stages = tuple_list!(calibration, tracing, i2s, power);
                        self.fuzz(&mut state, &mut fuzzer, &mut executor, &mut stages)
                    }
                }
            }
        } else {
            // Create a QEMU in-process executor
            let mut executor = QemuExecutor::new(
                emulator,
                &mut harness_fn,
                observers,
                &mut fuzzer,
                &mut state,
                &mut self.mgr,
                self.options.timeout,
            )?;
            if self.options.section_body_mutator {
                let mutator = pe_section_body_mutator_from_options(self.options);
                let mutation_stage = StdMutationalStage::new(mutator);
                match self.sync_dir_for_client() {
                    Some(sync_dir) => {
                        let sync_stage =
                            SyncFromDiskStage::with_from_file(sync_dir, Duration::from_secs(5));
                        if self.options.only_seeds {
                            let mut stages =
                                tuple_list!(SeedOnlyRestartStage::new(mutation_stage), sync_stage);
                            Ok(self.fuzz(&mut state, &mut fuzzer, &mut executor, &mut stages)?)
                        } else {
                            let mut stages = tuple_list!(mutation_stage, sync_stage);
                            Ok(self.fuzz(&mut state, &mut fuzzer, &mut executor, &mut stages)?)
                        }
                    }
                    None => {
                        if self.options.only_seeds {
                            let mut stages = tuple_list!(SeedOnlyRestartStage::new(mutation_stage));
                            Ok(self.fuzz(&mut state, &mut fuzzer, &mut executor, &mut stages)?)
                        } else {
                            let mut stages = tuple_list!(mutation_stage);
                            Ok(self.fuzz(&mut state, &mut fuzzer, &mut executor, &mut stages)?)
                        }
                    }
                }
            } else if self.options.uses_full_pe_mutator() {
                if self.options.pelock {
                    let mutator = pelock_mutator_from_options(self.options);
                    match self.sync_dir_for_client() {
                        Some(sync_dir) => {
                            let sync_stage =
                                SyncFromDiskStage::with_from_file(sync_dir, Duration::from_secs(5));
                            let pe_stage = StdMutationalStage::<
                                _,
                                _,
                                PeLibAflInput,
                                BytesInput,
                                _,
                                _,
                                _,
                            >::transforming(mutator);
                            let mut stages = tuple_list!(pe_stage, sync_stage);
                            return Ok(self.fuzz(
                                &mut state,
                                &mut fuzzer,
                                &mut executor,
                                &mut stages,
                            )?);
                        }
                        None => {
                            let pe_stage = StdMutationalStage::<
                                _,
                                _,
                                PeLibAflInput,
                                BytesInput,
                                _,
                                _,
                                _,
                            >::transforming(mutator);
                            let mut stages = tuple_list!(pe_stage);
                            return Ok(self.fuzz(
                                &mut state,
                                &mut fuzzer,
                                &mut executor,
                                &mut stages,
                            )?);
                        }
                    }
                }
                let mutator = pe_mutator_from_options(self.options);
                match self.sync_dir_for_client() {
                    Some(sync_dir) => {
                        let sync_stage =
                            SyncFromDiskStage::with_from_file(sync_dir, Duration::from_secs(5));
                        let pe_stage = StdMutationalStage::<
                            _,
                            _,
                            PeLibAflInput,
                            BytesInput,
                            _,
                            _,
                            _,
                        >::transforming(mutator);
                        let mut stages = tuple_list!(pe_stage, sync_stage);
                        Ok(self.fuzz(&mut state, &mut fuzzer, &mut executor, &mut stages)?)
                    }
                    None => {
                        let pe_stage = StdMutationalStage::<
                            _,
                            _,
                            PeLibAflInput,
                            BytesInput,
                            _,
                            _,
                            _,
                        >::transforming(mutator);
                        let mut stages = tuple_list!(pe_stage);
                        Ok(self.fuzz(&mut state, &mut fuzzer, &mut executor, &mut stages)?)
                    }
                }
            } else {
                let mutator = if self.options.fsg_postdecode {
                    BDCoreMutator::Fsg(FsgPostdecodeMutator)
                } else if self.options.pec3_peviewer {
                    BDCoreMutator::Pec3Stream(Pec3StreamWindowMutator::new(
                        self.options.pec3_peviewer_control_only,
                        self.options.pec3_peviewer_main_only,
                        self.options.pec3_peviewer_heap_poison,
                    ))
                } else if self.options.pec3_operation11 {
                    BDCoreMutator::Pec3Operation11(Pec3Operation11Mutator)
                } else if self.options.pec3_operation11_mode2 {
                    BDCoreMutator::Pec3Operation11Mode2(Pec3Operation11Mode2Mutator)
                } else if self.options.pec3_postdecode {
                    BDCoreMutator::Pec3(Pec3PostdecodeMutator)
                } else if self.options.fixed_size_mutations {
                    BDCoreMutator::MoptFixed(StdMOptMutator::new(
                        &mut state,
                        havoc_fixed_size_mutations(),
                        7,
                        5,
                    )?)
                } else {
                    BDCoreMutator::Mopt(StdMOptMutator::new(
                        &mut state,
                        libafl::mutators::havoc_mutations(),
                        7,
                        5,
                    )?)
                };
                let mutation_stage = StdMutationalStage::new(mutator);
                match self.sync_dir_for_client() {
                    Some(sync_dir) => {
                        let sync_stage =
                            SyncFromDiskStage::with_from_file(sync_dir, Duration::from_secs(5));
                        if self.options.only_seeds {
                            let mut stages =
                                tuple_list!(SeedOnlyRestartStage::new(mutation_stage), sync_stage);
                            Ok(self.fuzz(&mut state, &mut fuzzer, &mut executor, &mut stages)?)
                        } else {
                            let mut stages = tuple_list!(mutation_stage, sync_stage);
                            Ok(self.fuzz(&mut state, &mut fuzzer, &mut executor, &mut stages)?)
                        }
                    }
                    None => {
                        if self.options.only_seeds {
                            let mut stages = tuple_list!(SeedOnlyRestartStage::new(mutation_stage));
                            Ok(self.fuzz(&mut state, &mut fuzzer, &mut executor, &mut stages)?)
                        } else {
                            let mut stages = tuple_list!(mutation_stage);
                            Ok(self.fuzz(&mut state, &mut fuzzer, &mut executor, &mut stages)?)
                        }
                    }
                }
            }
        }
    }

    fn fuzz<Z, E, ST>(
        &mut self,
        state: &mut ClientState,
        fuzzer: &mut Z,
        executor: &mut E,
        stages: &mut ST,
    ) -> Result<(), Error>
    where
        Z: Fuzzer<E, EM, BytesInput, ClientState, ST>
            + Evaluator<E, EM, BytesInput, ClientState>
            + ExecutesInput<E, EM, BytesInput, ClientState>,
        ST: StagesTuple<E, EM, ClientState, Z>,
    {
        let corpus_dirs = [self.options.input_dir().unwrap()];
        println!("Loading initial corpus from disk at {:?}...", &corpus_dirs);
        self.log_corpus_path_diagnostics("pre-initial-load");
        if self.options.filter_completing_corpus {
            let files = Self::collect_initial_inputs(&self.options.input_dir().unwrap())?;
            if files.is_empty() {
                return Err(Error::illegal_argument(
                    "corpus filter input directory is empty",
                ));
            }

            let queue_dir = self.options.queue_dir().unwrap();
            let outcomes_path = queue_dir
                .parent()
                .unwrap_or_else(|| Path::new("."))
                .join("filter_outcomes.tsv");
            let mut outcomes = fs::OpenOptions::new()
                .create(true)
                .truncate(true)
                .write(true)
                .open(&outcomes_path)?;
            writeln!(outcomes, "path\texit_kind")?;

            let mut completed = 0usize;
            for (index, path) in files.iter().enumerate() {
                let input = BytesInput::new(fs::read(path)?);
                let exit_kind = fuzzer.execute_input(state, executor, &mut self.mgr, &input)?;
                writeln!(outcomes, "{}\t{exit_kind:?}", path.display())?;
                outcomes.flush()?;

                if exit_kind == libafl::executors::ExitKind::Ok {
                    let Some(file_name) = path.file_name() else {
                        continue;
                    };
                    fs::copy(path, queue_dir.join(file_name))?;
                    completed += 1;
                }

                if (index + 1) % 100 == 0 || index + 1 == files.len() {
                    println!(
                        "Corpus filter progress: {}/{} processed, {} completing",
                        index + 1,
                        files.len(),
                        completed
                    );
                }
            }

            println!(
                "Corpus filter complete: {}/{} inputs retained in {:?}",
                completed,
                files.len(),
                queue_dir
            );
            self.mgr.send_exiting()?;
            return Ok(());
        }
        if state.must_load_initial_inputs() {
            let files = Self::collect_initial_inputs(&self.options.input_dir().unwrap())?;
            let load_result = if self.options.only_seeds {
                state.load_initial_inputs_by_filenames_forced(
                    fuzzer,
                    executor,
                    &mut self.mgr,
                    &files,
                )
            } else {
                state.load_initial_inputs_by_filenames(fuzzer, executor, &mut self.mgr, &files)
            };
            if let Err(err) = load_result {
                self.log_corpus_path_diagnostics("initial-load-error");
                eprintln!(
                    "Failed to load initial corpus at {:?}: {:?}",
                    &corpus_dirs, err
                );
                return Err(err);
            }
            if self.options.only_seeds {
                Self::tag_current_corpus_as_seed(state)?;
            }
            if self.options.uses_full_pe_mutator() {
                self.attach_pe_manifests_to_corpus(state)?;
            }
            println!("We imported {} inputs from disk.", state.corpus().count());
        }

        fuzzer
            //.fuzz_loop_for(&mut stages, &mut executor, &mut state, &mut mgr, 1000)
            .fuzz_loop(stages, executor, state, &mut self.mgr)
    }
}
