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
use libafl_bolts::{rands::StdRand, tuples::tuple_list};
use libafl_qemu::{
    modules::{
        cmplog::CmpLogModule,
        snapshot::{IntervalSnapshotFilter, IntervalSnapshotFilters, SnapshotModule},
        utils::filters::StdAddressFilter,
        DrCovModule,
    },
    Qemu,
};

use crate::{
    harness::Harness,
    instance::Instance,
    options::FuzzerOptions,
    scan_profile::{ScanProfile, ScanRestoreEndModule, ScanRestoreStartModule},
};
use typed_builder::TypedBuilder;

#[allow(clippy::module_name_repetitions)]
pub type ClientState =
    StdState<InMemoryOnDiskCorpus<BytesInput>, BytesInput, StdRand, OnDiskCorpus<BytesInput>>;

#[derive(TypedBuilder)]
pub struct Client<'a> {
    options: &'a FuzzerOptions,
    qemu: &'a Qemu,
    harness: &'a Harness<'a>,
    scan_profile: Option<Arc<ScanProfile>>,
}

impl<'a> Client<'a> {
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

        let interval_snapshot_filters: IntervalSnapshotFilters =
            IntervalSnapshotFilters::from(vec![IntervalSnapshotFilter::ZeroList(
                self.harness.snapshot_excludes(),
            )]);

        let snapshot_module = SnapshotModule::with_filters(interval_snapshot_filters);

        let instance = Instance::builder()
            .options(self.options)
            .qemu(&self.qemu)
            .harness(&self.harness)
            .scan_profile(self.scan_profile.clone())
            .mgr(mgr)
            .client_description(client_description);

        if is_cmplog {
            if let Some(scan_profile) = self.scan_profile.clone() {
                instance.build().run(
                    tuple_list!(
                        ScanRestoreStartModule::new(scan_profile.clone()),
                        snapshot_module,
                        ScanRestoreEndModule::new(scan_profile),
                        CmpLogModule::new(StdAddressFilter::allow_list(
                            self.harness.bd_engine.coverage_filter().unwrap()
                        ),),
                    ),
                    state,
                )
            } else {
                instance.build().run(
                    tuple_list!(
                        snapshot_module,
                        CmpLogModule::new(StdAddressFilter::allow_list(
                            self.harness.bd_engine.coverage_filter().unwrap()
                        ),),
                    ),
                    state,
                )
            }
        } else if self.options.rerun_input.is_some() && self.options.drcov.is_some() {
            log::debug!(
                "Running with DrCov. Output coverage file: {:?}",
                self.options.drcov.as_ref().unwrap()
            );
            let drcov_output = self.options.drcov.as_ref().unwrap();

            let drcov = if let Some(coverage_modules_map) =
                self.harness.bd_engine.modules_to_instrument.clone()
            {
                DrCovModule::builder()
                    .filter(StdAddressFilter::allow_list(
                        self.harness.bd_engine.coverage_filter().unwrap(),
                    ))
                    .module_mapping(coverage_modules_map.clone())
                    .path(drcov_output.clone())
                    .full_trace(false)
                    .build()
            } else {
                DrCovModule::builder()
                    .filter(StdAddressFilter::allow_list(
                        self.harness.bd_engine.coverage_filter().unwrap(),
                    ))
                    .path(drcov_output.clone())
                    .full_trace(false)
                    .build()
            };

            instance.build().run(tuple_list!(drcov), state)
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
