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
    ArchExtras, Qemu, Regs,
};

use crate::{
    bitdefender::{module_for_addr, BDModule},
    harness::{
        FuzzHarness, PcSignal, PcSignalModule, Pelock07d60RetModule,
        Pelock07d60WindowCaptureModule, PelockStage0CaptureModule,
    },
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
    fn diagnostic_asan_callback() -> AsanErrorCallback {
        AsanErrorCallback::new(Box::new(|_rt, qemu, pc, err| {
            let rsp = qemu
                .read_reg(Regs::Sp)
                .ok()
                .and_then(|value| value.try_into().ok());
            let mut stack = [0u8; 16 * 8];
            let stack_words = rsp.and_then(|rsp| {
                qemu.read_mem(rsp, &mut stack).ok()?;
                Some(
                    stack
                        .chunks_exact(8)
                        .map(|word| u64::from_le_bytes(word.try_into().unwrap()))
                        .collect::<Vec<_>>(),
                )
            });
            eprintln!(
                "BDCORE_ASAN_DIAG pc={pc:#x} error={err} rsp={rsp:?} stack={stack_words:x?}"
            );
        }))
    }

    fn unpacker_progress_module(&self) -> Result<PcSignalModule, Error> {
        if !self.options.ceva_health_signals {
            return Ok(PcSignalModule::disabled());
        }

        const ASPACK_SIGNAL_SPECS: &[(&str, &str)] = &[
            ("generic_ver_write", "aspack.xmd:+0x58a"),
            ("special_v10", "aspack.xmd:+0x634"),
            ("ver_10804_a", "aspack.xmd:+0x665"),
            ("ver_10804_b", "aspack.xmd:+0x686"),
            ("ver_10803", "aspack.xmd:+0x6a7"),
            ("builder_setup", "aspack.xmd:+0x7ae"),
            ("entry_loop", "aspack.xmd:+0x820"),
            ("commit_call", "aspack.xmd:+0x8b9"),
            ("name_write", "aspack.xmd:+0x8f8"),
        ];

        const MORPHINEP_SIGNAL_SPECS: &[(&str, &str)] = &[
            ("a870", "morphinep.xmd:+0x870"),
            ("a8d0", "morphinep.xmd:+0x8d0"),
            ("a970", "morphinep.xmd:+0x970"),
        ];

        const PELOCK_SIGNAL_SPECS: &[(&str, &str)] = &[
            ("ep_off_in_last_section", "pelock.xmd:+0x4fa6"),
            ("pelock_parse_stub", "pelock.xmd:+0x5004"),
            ("after_memset", "pelock.xmd:+0x50d6"),
            ("after_first_seek_read", "pelock.xmd:+0x5131"),
            ("returned_06b80", "pelock.xmd:+0x516c"),
            ("passed_06b80", "pelock.xmd:+0x5174"),
            ("second_parse_ep_stub_call", "pelock.xmd:+0x51be"),
            ("second_parse_ep_stub_return", "pelock.xmd:+0x51c3"),
            ("second_parse_ep_stub_nonnegative", "pelock.xmd:+0x51ce"),
            ("stage_0_parsing_done", "pelock.xmd:+0x51de"),
            ("before_07d60", "pelock.xmd:+0x520e"),
            ("after_07d60", "pelock.xmd:+0x2158"),
            ("after_0cbb0", "pelock.xmd:+0x5257"),
            ("decoder_call", "pelock.xmd:+0x5294"),
            ("after_06ad0", "pelock.xmd:+0x529d"),
            ("after_073f0", "pelock.xmd:+0x52b9"),
            ("after_06e40", "pelock.xmd:+0x5564"),
            ("dispatch_c3b0", "pelock.xmd:+0x603f"),
            ("dispatch_c5b0", "pelock.xmd:+0x60db"),
            ("dispatch_c740", "pelock.xmd:+0x61ab"),
            ("dispatch_c930", "pelock.xmd:+0x634a"),
            ("worker_fail", "pelock.xmd:+0x574c"),
        ];

        const UPACK_SIGNAL_SPECS: &[(&str, &str)] = &[
            ("worker_entry", "upack.xmd:+0x840"),
            ("first_rva_to_fileoff", "upack.xmd:+0x8c3"),
            ("first_seek", "upack.xmd:+0x8da"),
            ("first_read", "upack.xmd:+0x903"),
            ("stub_scan_done", "upack.xmd:+0xb37"),
            ("metadata_parse_done", "upack.xmd:+0x1031"),
            ("ctx_init", "upack.xmd:+0x1397"),
            ("success_marker", "upack.xmd:+0x13ea"),
            ("ret_setup", "upack.xmd:+0x1409"),
            ("epilogue", "upack.xmd:+0x141b"),
        ];

        let (target_name, signal_specs): (&'static str, &[(&str, &str)]) =
            if self.options.aspack_worker {
                ("AspackProgress", ASPACK_SIGNAL_SPECS)
            } else if self.options.morphinep {
                ("MorphinepProgress", MORPHINEP_SIGNAL_SPECS)
            } else if self.options.pelock {
                ("PelockProgress", PELOCK_SIGNAL_SPECS)
            } else if self.options.upack {
                ("UpackProgress", UPACK_SIGNAL_SPECS)
            } else {
                return Ok(PcSignalModule::disabled());
            };

        let mut signals = Vec::with_capacity(signal_specs.len());
        let modules = &self.harness.bd_engine().modules;
        for (name, spec) in signal_specs {
            let pc = Self::resolve_module_relative_address(modules, spec).ok_or_else(|| {
                Error::unknown(format!(
                    "Failed to resolve unpacker progress PC spec '{spec}'"
                ))
            })?;
            signals.push(PcSignal { name, pc });
        }

        Ok(PcSignalModule::new(
            target_name,
            self.options.ceva_health_log_every,
            signals,
        ))
    }

    fn pelock_ret_module(&self) -> Result<Pelock07d60RetModule, Error> {
        if !(self.options.ceva_health_signals && self.options.pelock) {
            return Ok(Pelock07d60RetModule::disabled());
        }

        let modules = &self.harness.bd_engine().modules;
        let pc = Self::resolve_module_relative_address(modules, "pelock.xmd:+0x2158").ok_or_else(
            || Error::unknown("Failed to resolve Pelock 07D60 return PC".to_string()),
        )?;

        Ok(Pelock07d60RetModule::new(
            pc,
            self.options.ceva_health_log_every,
        ))
    }

    fn pelock_stage0_capture_module(&self) -> Result<PelockStage0CaptureModule, Error> {
        if !(self.options.ceva_health_signals && self.options.pelock) {
            return Ok(PelockStage0CaptureModule::disabled());
        }

        let modules = &self.harness.bd_engine().modules;
        let pc = Self::resolve_module_relative_address(modules, "pelock.xmd:+0x51de").ok_or_else(
            || Error::unknown("Failed to resolve Pelock stage0 capture PC".to_string()),
        )?;
        let output_dir = self
            .options
            .output_dir()
            .and_then(|path| path.parent().map(|parent| parent.join("stage0_hits")))
            .unwrap_or_else(|| std::path::PathBuf::from("./stage0_hits"));

        Ok(PelockStage0CaptureModule::new(
            pc,
            output_dir,
            self.options.ceva_health_log_every,
        ))
    }

    fn pelock_07d60_window_capture_module(&self) -> Result<Pelock07d60WindowCaptureModule, Error> {
        if !(self.options.ceva_health_signals && self.options.pelock) {
            return Ok(Pelock07d60WindowCaptureModule::disabled());
        }

        let modules = &self.harness.bd_engine().modules;
        let call_pc = Self::resolve_module_relative_address(modules, "pelock.xmd:+0x520e")
            .ok_or_else(|| {
                Error::unknown("Failed to resolve Pelock 07D60 callsite PC".to_string())
            })?;
        let ret_pc = Self::resolve_module_relative_address(modules, "pelock.xmd:+0x2158")
            .ok_or_else(|| {
                Error::unknown("Failed to resolve Pelock 07D60 return PC".to_string())
            })?;
        let output_dir = self
            .options
            .output_dir()
            .and_then(|path| path.parent().map(|parent| parent.join("07d60_windows")))
            .unwrap_or_else(|| std::path::PathBuf::from("./07d60_windows"));

        Ok(Pelock07d60WindowCaptureModule::new(
            call_pc,
            ret_pc,
            output_dir,
            self.options.ceva_health_log_every,
        ))
    }

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
        let address_filter = self.coverage_address_filter();
        let _ = self.asan_skip_pcs()?;

        Ok(AsanHostModule::builder()
            .filter(address_filter)
            .target_crash(AsanTargetCrash::Never)
            .error_callback(Self::diagnostic_asan_callback())
            .build())
    }

    fn parse_asan_skip_pc_specs(options: &FuzzerOptions) -> Result<(Vec<u64>, Vec<String>), Error> {
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
        let _ = Self::parse_asan_skip_pc_specs(options)?;
        drop(known_modules);

        Ok(AsanHostModule::builder()
            .target_crash(AsanTargetCrash::Never)
            .error_callback(Self::diagnostic_asan_callback())
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

        let unpacker_progress_module = self.unpacker_progress_module()?;
        let pelock_ret_module = self.pelock_ret_module()?;
        let pelock_stage0_capture_module = self.pelock_stage0_capture_module()?;
        let pelock_07d60_window_capture_module = self.pelock_07d60_window_capture_module()?;
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
                            unpacker_progress_module,
                            pelock_ret_module,
                            pelock_stage0_capture_module,
                            pelock_07d60_window_capture_module,
                            cmplog,
                        ),
                        state,
                    )
                } else {
                    instance.build().run(
                        tuple_list!(
                            snapshot_module,
                            asan_module,
                            unpacker_progress_module,
                            pelock_ret_module,
                            pelock_stage0_capture_module,
                            pelock_07d60_window_capture_module,
                            cmplog,
                        ),
                        state,
                    )
                }
            } else {
                if let Some(scan_profile) = self.scan_profile.clone() {
                    instance.build().run(
                        tuple_list!(
                            ScanRestoreStartModule::new(scan_profile.clone()),
                            snapshot_module,
                            ScanRestoreEndModule::new(scan_profile),
                            unpacker_progress_module,
                            pelock_ret_module,
                            pelock_stage0_capture_module,
                            pelock_07d60_window_capture_module,
                            cmplog,
                        ),
                        state,
                    )
                } else {
                    instance.build().run(
                        tuple_list!(
                            snapshot_module,
                            unpacker_progress_module,
                            pelock_ret_module,
                            pelock_stage0_capture_module,
                            pelock_07d60_window_capture_module,
                            cmplog,
                        ),
                        state,
                    )
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
                instance.build().run(
                    tuple_list!(
                        asan_module,
                        unpacker_progress_module,
                        pelock_ret_module,
                        pelock_stage0_capture_module,
                        pelock_07d60_window_capture_module,
                        drcov
                    ),
                    state,
                )
            } else {
                instance.build().run(
                    tuple_list!(
                        unpacker_progress_module,
                        pelock_ret_module,
                        pelock_stage0_capture_module,
                        pelock_07d60_window_capture_module,
                        drcov
                    ),
                    state,
                )
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
                            unpacker_progress_module,
                            pelock_ret_module,
                            pelock_stage0_capture_module,
                            pelock_07d60_window_capture_module,
                        ),
                        state,
                    )
                } else {
                    instance.build().run(
                        tuple_list!(
                            snapshot_module,
                            asan_module,
                            unpacker_progress_module,
                            pelock_ret_module,
                            pelock_stage0_capture_module,
                            pelock_07d60_window_capture_module,
                        ),
                        state,
                    )
                }
            } else {
                if let Some(scan_profile) = self.scan_profile.clone() {
                    instance.build().run(
                        tuple_list!(
                            ScanRestoreStartModule::new(scan_profile.clone()),
                            snapshot_module,
                            ScanRestoreEndModule::new(scan_profile),
                            unpacker_progress_module,
                            pelock_ret_module,
                            pelock_stage0_capture_module,
                            pelock_07d60_window_capture_module,
                        ),
                        state,
                    )
                } else {
                    instance.build().run(
                        tuple_list!(
                            snapshot_module,
                            unpacker_progress_module,
                            pelock_ret_module,
                            pelock_stage0_capture_module,
                            pelock_07d60_window_capture_module,
                        ),
                        state,
                    )
                }
            }
        }
    }
}
