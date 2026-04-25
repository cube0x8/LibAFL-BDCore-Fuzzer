use core::{fmt::Debug, ptr::addr_of_mut};
use std::{
    fs, process,
    sync::Arc,
    time::{Duration, Instant},
};

use libafl::{
    corpus::{Corpus, CorpusId, InMemoryCorpus, InMemoryOnDiskCorpus, OnDiskCorpus},
    events::{
        ClientDescription, EventFirer, EventReceiver, EventRestarter, NopEventManager,
        ProgressReporter, SendExiting,
    },
    executors::{Executor, ShadowExecutor},
    feedback_or, feedback_or_fast,
    feedbacks::{CrashFeedback, MaxMapFeedback, TimeFeedback, TimeoutFeedback},
    fuzzer::{Evaluator, Fuzzer, StdFuzzer},
    inputs::{BytesInput, Input},
    mutators::{
        token_mutations::I2SRandReplace, HavocScheduledMutator, StdMOptMutator,
        TuneableScheduledMutator,
    },
    observers::{CanTrack, HitcountsMapObserver, TimeObserver, VariableMapObserver},
    schedulers::{
        powersched::PowerSchedule, IndexesLenTimeMinimizerScheduler, PowerQueueScheduler,
        QueueScheduler,
    },
    stages::{
        calibrate::CalibrationStage, power::StdPowerMutationalStage, ShadowTracingStage,
        StagesTuple, StdMutationalStage, SyncFromDiskStage, TuneableMutationalStage,
    },
    state::{HasCorpus, StdState},
    Error, HasMetadata, NopFuzzer,
};
use libafl_bolts::{
    ownedref::OwnedMutSlice,
    rands::StdRand,
    tuples::{tuple_list, MatchFirstType, Merge, Prepend},
};
use libafl_qemu::{
    modules::{
        cmplog::{CmpLogModule, CmpLogObserver},
        edges::EdgeCoverageModule,
        snapshot::SnapshotModule,
        utils::filters::{HasAddressFilter, NopPageFilter, StdAddressFilter},
        DrCovModule, EmulatorModuleTuple, StdEdgeCoverageModule,
    },
    Emulator, Qemu, QemuExecutor,
};

use libafl_pe_mutator::{
    core::{
        PeMutationCategory, PeMutationCategorySet, PeMutationKind, PeMutationSet, PeMutatorConfig,
    },
    PeMutator, PeMutatorOptions,
};
use libafl_targets::{edges_map_mut_ptr, EDGES_MAP_DEFAULT_SIZE, MAX_EDGES_FOUND};
use serde::{Deserialize, Serialize};

use typed_builder::TypedBuilder;

pub type ClientState =
    StdState<InMemoryOnDiskCorpus<BytesInput>, BytesInput, StdRand, OnDiskCorpus<BytesInput>>;

#[derive(Debug, Clone, Serialize, Deserialize)]
struct SeedCorpusEntryMetadata;

libafl_bolts::impl_serdeany!(SeedCorpusEntryMetadata);

#[derive(Debug)]
struct SeedOnlyScheduler<CS> {
    inner: CS,
    enabled: bool,
}

impl<CS> SeedOnlyScheduler<CS> {
    fn new(inner: CS, enabled: bool) -> Self {
        Self { inner, enabled }
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
        self.inner.on_remove(state, id, testcase)
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

        let enabled_entries = state.corpus().count();
        if enabled_entries == 0 {
            return self.inner.next(state);
        }

        for _ in 0..enabled_entries {
            let id = self.inner.next(state)?;
            if Self::is_seed(state, id)? {
                return Ok(id);
            }
        }

        Err(Error::empty(
            "No seed-tagged entries are available for mutation scheduling.",
        ))
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
    harness::{FuzzHarness, MAX_TARGET_INPUT_SIZE},
    mutator::{havoc_fixed_size_mutations, BDCoreMutator},
    options::FuzzerOptions,
    scan_profile::ScanProfile,
    utils,
};

fn pe_mutator_config_from_options(options: &FuzzerOptions) -> PeMutatorConfig {
    let mut enabled_categories = PeMutationCategorySet::ALL;
    let mut enabled_mutations = PeMutationSet::ALL;

    if options.pe_header
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

    PeMutatorConfig {
        min_stack_depth: options.pe_min_stack_depth,
        max_stack_depth: options.pe_max_stack_depth,
        enabled_categories,
        enabled_mutations,
        ..PeMutatorConfig::default()
    }
}

fn pe_mutator_from_options(options: &FuzzerOptions) -> PeMutator {
    let config = pe_mutator_config_from_options(options);
    PeMutator::with_options(
        config,
        PeMutatorOptions {
            reporting: options
                .pe_mutator_reporting
                .then(|| "/tmp/pe-report.txt".into()),
            max_size: Some(MAX_TARGET_INPUT_SIZE),
        },
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

    pub fn run<ET>(&mut self, mut modules: ET, state: Option<ClientState>) -> Result<(), Error>
    where
        ET: EmulatorModuleTuple<BytesInput, ClientState> + Debug,
    {
        if let None = self.options.rerun_input {
            let snapshot_module: &mut SnapshotModule =
                modules.match_first_type_mut::<SnapshotModule>().unwrap();
            let snapshot_started_at = Instant::now();
            snapshot_module.snapshot(*self.qemu);
            if let Some(scan_profile) = &self.scan_profile {
                scan_profile.record_snapshot_capture(snapshot_started_at.elapsed());
            }
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

        let mut modules = modules.prepend(edge_coverage_module);

        // Create an observation channel to keep track of the execution time
        let time_observer = TimeObserver::new("time");

        let map_feedback = MaxMapFeedback::new(&edges_observer);

        let calibration = CalibrationStage::new(&map_feedback);

        // Feedback to rate the interestingness of an input
        // This one is composed by two Feedbacks in OR
        let mut feedback = feedback_or!(
            // New maximization map feedback linked to the edges observer and the feedback state
            map_feedback,
            // Time feedback, this one does not need a feedback state
            TimeFeedback::new(&time_observer)
        );

        // A feedback to choose if an input is a solution or not
        let mut objective = feedback_or_fast!(CrashFeedback::new(), TimeoutFeedback::new());

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
        let scheduler = SeedOnlyScheduler::new(
            IndexesLenTimeMinimizerScheduler::new(
                &edges_observer,
                PowerQueueScheduler::new(&mut state, &edges_observer, PowerSchedule::fast()),
            ),
            self.options.only_seeds,
        );

        let observers = tuple_list!(edges_observer, time_observer);

        let harness = self.harness;
        let scan_profile = self.scan_profile.clone();
        let mut harness_fn =
            move |_emulator: &mut Emulator<_, _, _, _, _, _, _>,
                  _state: &mut _,
                  input: &BytesInput| { harness.run(input, scan_profile.as_deref()) };

        // A fuzzer with feedbacks and a corpus scheduler
        let mut fuzzer = StdFuzzer::new(scheduler, feedback, objective);

        self.qemu.flush_jit();
        let emulator = Emulator::empty()
            .modules(modules)
            .build_with_qemu(*self.qemu)?;

        if let Some(rerun_input) = &self.options.rerun_input {
            // TODO: We might want to support non-bytes inputs at some point?
            let bytes = fs::read(rerun_input)
                .unwrap_or_else(|_| panic!("Could not load file {rerun_input:?}"));
            let input = BytesInput::new(bytes);

            let mut executor = QemuExecutor::new(
                emulator,
                &mut harness_fn,
                observers,
                &mut fuzzer,
                &mut state,
                &mut self.mgr,
                self.options.timeout,
            )?;

            log::debug!("Rerunning input with DrCov");
            executor
                .run_target(&mut fuzzer, &mut state, &mut self.mgr, &input)
                .expect("Error running target");

            log::debug!("Coverage file generate correctly. Compressing...");

            // TEMP: gzip compress the output file
            let output_file_path = self.options.drcov.as_ref().clone();
            if let Err(e) = utils::compress_and_replace(output_file_path.unwrap()) {
                log::error!("Compression error: {}", e);
                process::exit(-1);
            } else {
                log::info!("Output file successfully compressed. We're done! :).");
                process::exit(0);
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

            let power_mutator = if self.options.pe_mutator {
                BDCoreMutator::Pe(pe_mutator_from_options(self.options))
            } else {
                if self.options.fixed_size_mutations {
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
                }
            };
            let power: StdPowerMutationalStage<_, _, BytesInput, _, _, _> =
                StdPowerMutationalStage::new(power_mutator);

            // The order of the stages matter!

            match self.options.sync_dir() {
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
            if self.options.pe_mutator {
                let mutator = pe_mutator_from_options(self.options);
                match self.options.sync_dir() {
                    Some(sync_dir) => {
                        let sync_stage =
                            SyncFromDiskStage::with_from_file(sync_dir, Duration::from_secs(5));
                        let mut stages = tuple_list!(StdMutationalStage::new(mutator), sync_stage);
                        Ok(self.fuzz(&mut state, &mut fuzzer, &mut executor, &mut stages)?)
                    }
                    None => {
                        let mut stages = tuple_list!(StdMutationalStage::new(mutator));
                        Ok(self.fuzz(&mut state, &mut fuzzer, &mut executor, &mut stages)?)
                    }
                }
            } else {
                let mutator = if self.options.fixed_size_mutations {
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
                match self.options.sync_dir() {
                    Some(sync_dir) => {
                        let sync_stage =
                            SyncFromDiskStage::with_from_file(sync_dir, Duration::from_secs(5));
                        let mut stages = tuple_list!(StdMutationalStage::new(mutator), sync_stage);
                        Ok(self.fuzz(&mut state, &mut fuzzer, &mut executor, &mut stages)?)
                    }
                    None => {
                        let mut stages = tuple_list!(StdMutationalStage::new(mutator));
                        Ok(self.fuzz(&mut state, &mut fuzzer, &mut executor, &mut stages)?)
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
        Z: Fuzzer<E, EM, BytesInput, ClientState, ST> + Evaluator<E, EM, BytesInput, ClientState>,
        ST: StagesTuple<E, EM, ClientState, Z>,
    {
        let corpus_dirs = [self.options.input_dir().unwrap()];
        println!("Loading initial corpus from disk at {:?}...", &corpus_dirs);
        self.log_corpus_path_diagnostics("pre-initial-load");
        if state.must_load_initial_inputs() {
            let load_result = if self.options.only_seeds {
                state.load_initial_inputs_forced(fuzzer, executor, &mut self.mgr, &corpus_dirs)
            } else {
                state.load_initial_inputs(fuzzer, executor, &mut self.mgr, &corpus_dirs)
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
            println!("We imported {} inputs from disk.", state.corpus().count());
        }

        fuzzer
            //.fuzz_loop_for(&mut stages, &mut executor, &mut state, &mut mgr, 1000)
            .fuzz_loop(stages, executor, state, &mut self.mgr)
    }
}

#[cfg(test)]
mod tests {
    use super::pe_mutator_config_from_options;
    use crate::options::FuzzerOptions;
    use clap::Parser;
    use libafl_pe_mutator::core::{PeMutationCategory, PeMutationKind};

    fn base_options() -> FuzzerOptions {
        FuzzerOptions {
            pe_mutator: true,
            ..FuzzerOptions::parse_from([
                "qemu_bdclient",
                "--input",
                "in",
                "--output",
                "out",
                "--queue",
                "queue",
                "--",
                "target",
            ])
        }
    }

    #[test]
    fn pe_mutator_without_group_flags_enables_everything() {
        let config = pe_mutator_config_from_options(&base_options());

        for kind in PeMutationKind::ALL {
            assert!(
                config.is_mutation_enabled(kind),
                "expected {kind:?} to be enabled when only --pe-mutator is used"
            );
        }

        for category in PeMutationCategory::ALL {
            assert!(
                config.is_category_enabled(category),
                "expected {category:?} to be enabled when only --pe-mutator is used"
            );
        }
    }

    #[test]
    fn pe_mutator_with_selected_groups_only_enables_requested_mutations() {
        let mut options = base_options();
        options.sections = true;
        options.export_dir = true;

        let config = pe_mutator_config_from_options(&options);

        for kind in [
            PeMutationKind::SectionCount,
            PeMutationKind::SectionHeader,
            PeMutationKind::SectionBody,
            PeMutationKind::ExportDirectory,
        ] {
            assert!(config.is_mutation_enabled(kind));
        }

        for kind in [
            PeMutationKind::Architecture,
            PeMutationKind::EntryPoint,
            PeMutationKind::ExecutableChunkAssembly,
            PeMutationKind::Overlay,
            PeMutationKind::DataDirectoryEntry,
            PeMutationKind::ResourceDirectory,
        ] {
            assert!(
                !config.is_mutation_enabled(kind),
                "did not expect {kind:?} to be enabled"
            );
        }

        assert!(config.is_category_enabled(PeMutationCategory::Headers));
        assert!(config.is_category_enabled(PeMutationCategory::Sections));
        assert!(config.is_category_enabled(PeMutationCategory::DataDirectories));
        assert!(!config.is_category_enabled(PeMutationCategory::Architecture));
        assert!(!config.is_category_enabled(PeMutationCategory::Assembly));
        assert!(!config.is_category_enabled(PeMutationCategory::Overlay));
    }

    #[test]
    fn pe_mutator_uses_stack_depth_range_from_options() {
        let mut options = base_options();
        options.pe_min_stack_depth = 3;
        options.pe_max_stack_depth = 6;

        let config = pe_mutator_config_from_options(&options);

        assert_eq!(config.min_stack_depth, 3);
        assert_eq!(config.max_stack_depth, 6);
    }

    #[test]
    fn pe_mutator_reporting_is_disabled_by_default() {
        let mutator = super::pe_mutator_from_options(&base_options());
        assert!(mutator.reporting_path().is_none());
    }

    #[test]
    fn pe_mutator_reporting_can_be_enabled_explicitly() {
        let mut options = base_options();
        options.pe_mutator_reporting = true;

        let mutator = super::pe_mutator_from_options(&options);
        assert_eq!(
            mutator.reporting_path().map(|path| path.to_string_lossy()),
            Some("/tmp/pe-report.txt".into())
        );
    }
}
