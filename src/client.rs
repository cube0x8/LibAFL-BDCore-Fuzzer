use std::sync::Arc;

use libafl::{
    corpus::{InMemoryOnDiskCorpus, OnDiskCorpus},
    events::{
        ClientDescription, EventFirer, EventReceiver, EventRestarter, ProgressReporter, SendExiting,
    },
    inputs::BytesInput,
    state::StdState,
    Error,
};
use libafl_bolts::os::unix_signals::Signal;
use libafl_bolts::{rands::StdRand, tuples::tuple_list};
use libafl_qemu::{
    modules::{
        asan_host::AsanError,
        asan_host::{AsanErrorCallback, AsanTargetCrash},
        cmplog::CmpLogModule,
        snapshot::{IntervalSnapshotFilter, IntervalSnapshotFilters, SnapshotModule},
        utils::filters::StdAddressFilter,
        AsanHostModule, DrCovModule,
    },
    Qemu,
};

use crate::{
    harness::FuzzHarness,
    instance::Instance,
    options::FuzzerOptions,
    scan_profile::{ScanProfile, ScanRestoreEndModule, ScanRestoreStartModule},
    utils,
};
use typed_builder::TypedBuilder;

#[allow(clippy::module_name_repetitions)]
pub type ClientState =
    StdState<InMemoryOnDiskCorpus<BytesInput>, BytesInput, StdRand, OnDiskCorpus<BytesInput>>;

#[derive(TypedBuilder)]
pub struct Client<'a> {
    options: &'a FuzzerOptions,
    qemu: &'a Qemu,
    harness: &'a dyn FuzzHarness,
    scan_profile: Option<Arc<ScanProfile>>,
}

impl<'a> Client<'a> {
    fn coverage_address_filter(&self) -> StdAddressFilter {
        self.harness
            .bd_engine()
            .coverage_filter()
            .map_or_else(StdAddressFilter::default, StdAddressFilter::allow_list)
    }

    fn asan_skip_pcs(&self) -> Result<Vec<u64>, Error> {
        self.options
            .pcs_to_skip
            .as_ref()
            .map(|pcs| {
                pcs.iter()
                    .map(|pc| {
                        self.harness
                            .bd_engine()
                            .resolve_module_address(pc, "ASAN skip PC")
                            .map(|addr| addr as u64)
                    })
                    .collect()
            })
            .unwrap_or_else(|| Ok(Vec::new()))
    }

    fn asan_module(&self) -> Result<AsanHostModule, Error> {
        let skip_pcs = self.asan_skip_pcs()?;
        let crash_log = self.options.crash_log_file.clone();
        let address_filter = self.coverage_address_filter();

        Ok(AsanHostModule::builder()
            .filter(address_filter)
            .target_crash(AsanTargetCrash::Never)
            .error_callback(AsanErrorCallback::new(Box::new(move |_rt, qemu, pc, err| {
                if skip_pcs.contains(&(pc as u64)) {
                    log::debug!("Skipping ASAN report for configured PC {pc:#x}: {err}");
                    return;
                }

                match &err {
                    AsanError::Read(addr, size) => {
                        utils::log_asan_error_msg(
                            format!("kind=read pc={pc:#x} addr={addr:#x} size={size}"),
                            &crash_log,
                        );
                    }
                    AsanError::Write(addr, size) => {
                        utils::log_asan_error_msg(
                            format!("kind=write pc={pc:#x} addr={addr:#x} size={size}"),
                            &crash_log,
                        );
                    }
                    AsanError::BadFree(addr, interval) => {
                        let msg = match interval {
                            Some(interval) => format!(
                                "kind=bad-free pc={pc:#x} addr={addr:#x} interval_start={:#x} interval_end={:#x}",
                                interval.start, interval.end
                            ),
                            None => {
                                format!("kind=bad-free pc={pc:#x} addr={addr:#x} interval=none")
                            }
                        };
                        utils::log_asan_error_msg(msg, &crash_log);
                    }
                    AsanError::MemLeak(interval) => {
                        utils::log_asan_error_msg(
                            format!(
                                "kind=memleak pc={pc:#x} interval_start={:#x} interval_end={:#x}",
                                interval.start, interval.end
                            ),
                            &crash_log,
                        );
                    }
                    AsanError::Signal(sig) => {
                        log::debug!(
                            "Target signal observed while ASAN was enabled: signal={} pc={:#x}",
                            sig,
                            pc
                        );
                        return;
                    }
                }

                unsafe {
                    qemu.target_signal(Signal::SigSegmentationFault);
                }
            })))
            .build())
    }

    pub fn run<EM>(
        &mut self,
        state: Option<ClientState>,
        mgr: EM,
        client_description: ClientDescription,
    ) -> Result<(), Error>
    where
        EM: EventFirer<BytesInput, ClientState>
            + EventRestarter<ClientState>
            + ProgressReporter<ClientState>
            + SendExiting
            + EventReceiver<BytesInput, ClientState>,
    {
        let is_cmplog = self.options.is_cmplog_core(client_description.core_id());
        let is_asan =
            self.options.use_asan_module() && self.options.is_asan_core(client_description.core_id());

        let interval_snapshot_filters: IntervalSnapshotFilters =
            IntervalSnapshotFilters::from(vec![IntervalSnapshotFilter::ZeroList(
                self.harness.snapshot_excludes(),
            )]);

        let snapshot_module = SnapshotModule::with_filters(interval_snapshot_filters);
        let asan_module = if is_asan {
            Some(self.asan_module()?)
        } else {
            None
        };
        let edge_filter = self.coverage_address_filter();

        let instance = Instance::builder()
            .options(self.options)
            .qemu(&self.qemu)
            .harness(self.harness)
            .scan_profile(self.scan_profile.clone())
            .mgr(mgr)
            .client_description(client_description);

        if is_cmplog {
            let cmplog: CmpLogModule = CmpLogModule::new(edge_filter);
            if let Some(asan_module) = asan_module {
                if let Some(scan_profile) = self.scan_profile.clone() {
                    instance.build().run(
                        tuple_list!(
                            ScanRestoreStartModule::new(scan_profile.clone()),
                            snapshot_module,
                            ScanRestoreEndModule::new(scan_profile),
                            asan_module,
                            cmplog,
                        ),
                        state,
                    )
                } else {
                    instance
                        .build()
                        .run(tuple_list!(snapshot_module, asan_module, cmplog,), state)
                }
            } else {
                if let Some(scan_profile) = self.scan_profile.clone() {
                    instance.build().run(
                        tuple_list!(
                            ScanRestoreStartModule::new(scan_profile.clone()),
                            snapshot_module,
                            ScanRestoreEndModule::new(scan_profile),
                            cmplog,
                        ),
                        state,
                    )
                } else {
                    instance.build().run(tuple_list!(snapshot_module, cmplog,), state)
                }
            }
        } else if self.options.rerun_input.is_some() && self.options.drcov.is_some() {
            log::debug!(
                "Running with DrCov. Output coverage file: {:?}",
                self.options.drcov.as_ref().unwrap()
            );
            let drcov_output = self.options.drcov.as_ref().unwrap();

            let drcov = if let Some(coverage_modules_map) =
                self.harness.bd_engine().modules_to_instrument.clone()
            {
                DrCovModule::builder()
                    .filter(StdAddressFilter::allow_list(
                        self.harness.bd_engine().coverage_filter().unwrap(),
                    ))
                    .module_mapping(coverage_modules_map.clone())
                    .path(drcov_output.clone())
                    .full_trace(false)
                    .build()
            } else {
                DrCovModule::builder()
                    .filter(StdAddressFilter::allow_list(
                        self.harness.bd_engine().coverage_filter().unwrap(),
                    ))
                    .path(drcov_output.clone())
                    .full_trace(false)
                    .build()
            };

            if let Some(asan_module) = asan_module {
                instance.build().run(tuple_list!(asan_module, drcov), state)
            } else {
                instance.build().run(tuple_list!(drcov), state)
            }
        } else {
            if let Some(asan_module) = asan_module {
                if let Some(scan_profile) = self.scan_profile.clone() {
                    instance.build().run(
                        tuple_list!(
                            ScanRestoreStartModule::new(scan_profile.clone()),
                            snapshot_module,
                            ScanRestoreEndModule::new(scan_profile),
                            asan_module,
                        ),
                        state,
                    )
                } else {
                    instance
                        .build()
                        .run(tuple_list!(snapshot_module, asan_module,), state)
                }
            } else {
                if let Some(scan_profile) = self.scan_profile.clone() {
                    instance.build().run(
                        tuple_list!(
                            ScanRestoreStartModule::new(scan_profile.clone()),
                            snapshot_module,
                            ScanRestoreEndModule::new(scan_profile),
                        ),
                        state,
                    )
                } else {
                    instance.build().run(tuple_list!(snapshot_module,), state)
                }
            }
        }
    }
}
