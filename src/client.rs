use std::sync::{Arc, Mutex};

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
    bitdefender::{module_for_addr, BDModule},
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
    #[builder(default)]
    preinitialized_asan_module: Option<AsanHostModule>,
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
                        let pc = pc.trim();
                        if let Some(hex) = pc.strip_prefix("0x").or_else(|| pc.strip_prefix("0X"))
                        {
                            return u64::from_str_radix(hex, 16).map_err(|err| {
                                Error::unknown(format!(
                                    "Failed to parse ASAN skip PC '{pc}' as hexadecimal address: {err}"
                                ))
                            });
                        }

                        if pc.bytes().all(|byte| byte.is_ascii_digit()) {
                            return pc.parse::<u64>().map_err(|err| {
                                Error::unknown(format!(
                                    "Failed to parse ASAN skip PC '{pc}' as decimal address: {err}"
                                ))
                            });
                        }

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
        let bd_modules = self.harness.bd_engine().modules.clone();

        Ok(AsanHostModule::builder()
            .filter(address_filter)
            .target_crash(AsanTargetCrash::OnTargetStop)
            .error_callback(AsanErrorCallback::new(Box::new(move |_rt, _qemu, pc, err| {
                if skip_pcs.contains(&(pc as u64)) {
                    log::debug!("Skipping ASAN report for configured PC {pc:#x}: {err}");
                    return;
                }

                let pc_module = crate::bitdefender::module_for_addr(&bd_modules, pc as u64);
                let module_name = pc_module
                    .as_ref()
                    .map_or_else(|| "unknown".to_string(), |module| module.name.clone());
                let module_base = pc_module
                    .as_ref()
                    .map_or_else(|| "unknown".to_string(), |module| format!("{:#x}", module.start_addr));
                let module_offset = pc_module
                    .as_ref()
                    .map_or_else(|| "unknown".to_string(), |module| format!("{:#x}", module.offset));

                match &err {
                    AsanError::Read(addr, size) => {
                        utils::log_asan_error_msg(
                            format!(
                                "kind=read\npc={pc:#x}\npc_module={module_name}\npc_module_base={module_base}\npc_module_offset={module_offset}\naddr={addr:#x}\nsize={size}"
                            ),
                            &crash_log,
                        );
                    }
                    AsanError::Write(addr, size) => {
                        utils::log_asan_error_msg(
                            format!(
                                "kind=write\npc={pc:#x}\npc_module={module_name}\npc_module_base={module_base}\npc_module_offset={module_offset}\naddr={addr:#x}\nsize={size}"
                            ),
                            &crash_log,
                        );
                    }
                    AsanError::BadFree(addr, interval) => {
                        let msg = match interval {
                            Some(interval) => format!(
                                "kind=bad-free\npc={pc:#x}\npc_module={module_name}\npc_module_base={module_base}\npc_module_offset={module_offset}\naddr={addr:#x}\ninterval_start={:#x}\ninterval_end={:#x}",
                                interval.start, interval.end
                            ),
                            None => {
                                format!(
                                    "kind=bad-free\npc={pc:#x}\npc_module={module_name}\npc_module_base={module_base}\npc_module_offset={module_offset}\naddr={addr:#x}\ninterval=none"
                                )
                            }
                        };
                        utils::log_asan_error_msg(msg, &crash_log);
                    }
                    AsanError::MemLeak(interval) => {
                        utils::log_asan_error_msg(
                            format!(
                                "kind=memleak\npc={pc:#x}\npc_module={module_name}\npc_module_base={module_base}\npc_module_offset={module_offset}\ninterval_start={:#x}\ninterval_end={:#x}",
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
            })))
            .build())
    }

    fn parse_asan_skip_pc_specs(
        options: &FuzzerOptions,
    ) -> Result<(Vec<u64>, Vec<String>), Error> {
        let mut literal_pcs = Vec::new();
        let mut module_specs = Vec::new();

        if let Some(pcs) = &options.pcs_to_skip {
            for pc in pcs {
                let pc = pc.trim();
                if let Some(hex) = pc.strip_prefix("0x").or_else(|| pc.strip_prefix("0X")) {
                    literal_pcs.push(u64::from_str_radix(hex, 16).map_err(|err| {
                        Error::unknown(format!(
                            "Failed to parse ASAN skip PC '{pc}' as hexadecimal address: {err}"
                        ))
                    })?);
                    continue;
                }

                if pc.bytes().all(|byte| byte.is_ascii_digit()) {
                    literal_pcs.push(pc.parse::<u64>().map_err(|err| {
                        Error::unknown(format!(
                            "Failed to parse ASAN skip PC '{pc}' as decimal address: {err}"
                        ))
                    })?);
                    continue;
                }

                module_specs.push(pc.to_string());
            }
        }

        Ok((literal_pcs, module_specs))
    }

    fn resolve_module_relative_address(modules: &[BDModule], spec: &str) -> Option<u64> {
        let (module_name, offset_str) = spec.split_once(":+")?;
        let module_name = module_name.trim();
        let offset_str = offset_str.trim();
        if module_name.is_empty() || offset_str.is_empty() {
            return None;
        }

        let offset = if let Some(hex) = offset_str
            .strip_prefix("0x")
            .or_else(|| offset_str.strip_prefix("0X"))
        {
            u64::from_str_radix(hex, 16).ok()?
        } else {
            offset_str.parse::<u64>().ok()?
        };

        let module = modules.iter().find(|module| module.name == module_name)?;
        module.start_addr.checked_add(offset)
    }

    fn should_skip_asan_pc(
        pc: u64,
        literal_pcs: &[u64],
        module_specs: &[String],
        modules: &[BDModule],
    ) -> bool {
        literal_pcs.contains(&pc)
            || module_specs.iter().any(|spec| {
                Self::resolve_module_relative_address(modules, spec).is_some_and(|addr| addr == pc)
            })
    }

    pub fn build_preinitialized_asan_module(
        options: &FuzzerOptions,
        known_modules: Arc<Mutex<Vec<BDModule>>>,
    ) -> Result<AsanHostModule, Error> {
        let (skip_pc_literals, skip_pc_specs) = Self::parse_asan_skip_pc_specs(options)?;
        let crash_log = options.crash_log_file.clone();

        Ok(AsanHostModule::builder()
            .target_crash(AsanTargetCrash::OnTargetStop)
            .error_callback(AsanErrorCallback::new(Box::new(move |_rt, _qemu, pc, err| {
                let modules = known_modules
                    .lock()
                    .expect("ASAN module list mutex poisoned")
                    .clone();

                if Self::should_skip_asan_pc(pc as u64, &skip_pc_literals, &skip_pc_specs, &modules)
                {
                    log::debug!("Skipping ASAN report for configured PC {pc:#x}: {err}");
                    return;
                }

                let pc_module = module_for_addr(&modules, pc as u64);
                let module_name = pc_module
                    .as_ref()
                    .map_or_else(|| "unknown".to_string(), |module| module.name.clone());
                let module_base = pc_module.as_ref().map_or_else(
                    || "unknown".to_string(),
                    |module| format!("{:#x}", module.start_addr),
                );
                let module_offset = pc_module
                    .as_ref()
                    .map_or_else(|| "unknown".to_string(), |module| format!("{:#x}", module.offset));

                match &err {
                    AsanError::Read(addr, size) => {
                        utils::log_asan_error_msg(
                            format!(
                                "kind=read\npc={pc:#x}\npc_module={module_name}\npc_module_base={module_base}\npc_module_offset={module_offset}\naddr={addr:#x}\nsize={size}"
                            ),
                            &crash_log,
                        );
                    }
                    AsanError::Write(addr, size) => {
                        utils::log_asan_error_msg(
                            format!(
                                "kind=write\npc={pc:#x}\npc_module={module_name}\npc_module_base={module_base}\npc_module_offset={module_offset}\naddr={addr:#x}\nsize={size}"
                            ),
                            &crash_log,
                        );
                    }
                    AsanError::BadFree(addr, interval) => {
                        let msg = match interval {
                            Some(interval) => format!(
                                "kind=bad-free\npc={pc:#x}\npc_module={module_name}\npc_module_base={module_base}\npc_module_offset={module_offset}\naddr={addr:#x}\ninterval_start={:#x}\ninterval_end={:#x}",
                                interval.start, interval.end
                            ),
                            None => {
                                format!(
                                    "kind=bad-free\npc={pc:#x}\npc_module={module_name}\npc_module_base={module_base}\npc_module_offset={module_offset}\naddr={addr:#x}\ninterval=none"
                                )
                            }
                        };
                        utils::log_asan_error_msg(msg, &crash_log);
                    }
                    AsanError::MemLeak(interval) => {
                        utils::log_asan_error_msg(
                            format!(
                                "kind=memleak\npc={pc:#x}\npc_module={module_name}\npc_module_base={module_base}\npc_module_offset={module_offset}\ninterval_start={:#x}\ninterval_end={:#x}",
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
                    }
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
        let is_asan = self.options.use_asan_module()
            && self.options.is_asan_core(client_description.core_id());

        let interval_snapshot_filters: IntervalSnapshotFilters =
            IntervalSnapshotFilters::from(vec![IntervalSnapshotFilter::ZeroList(
                self.harness.snapshot_excludes(),
            )]);

        let snapshot_module = SnapshotModule::with_filters(interval_snapshot_filters);
        let asan_module = if is_asan {
            match self.preinitialized_asan_module.take() {
                Some(asan_module) => Some(asan_module),
                None => Some(self.asan_module()?),
            }
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
                    instance
                        .build()
                        .run(tuple_list!(snapshot_module, cmplog,), state)
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
