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
use libafl_bolts::{os::unix_signals::Signal, rands::StdRand, tuples::tuple_list};
use libafl_qemu::{
    modules::{
        asan_host::AsanError,
        asan_host::{AsanErrorCallback, AsanTargetCrash},
        cmplog::CmpLogModule,
        snapshot::{IntervalSnapshotFilter, IntervalSnapshotFilters, SnapshotModule},
        utils::filters::StdAddressFilter,
        AsanHostModule, DrCovModule,
    },
    Qemu, Regs,
};

use crate::{
    bitdefender::{module_for_addr, BDModule},
    harness::{
        CrashContextModule, FuzzHarness, PcSignal, PcSignalModule, Pelock07d60RetModule,
        Pelock07d60WindowCaptureModule, PelockStage0CaptureModule, TMinPcHitModule,
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
}

impl<'a> Client<'a> {
    fn diagnostic_asan_callback(
        crash_log_file: Option<String>,
        literal_skip_pcs: Vec<u64>,
        module_skip_specs: Vec<String>,
        known_modules: Arc<Mutex<Vec<BDModule>>>,
        ignore_untracked_bad_frees: bool,
    ) -> AsanErrorCallback {
        let ceva_oob_context_enabled = std::env::var_os("BDCORE_CEVA_OOB_CONTEXT").is_some();
        AsanErrorCallback::new(Box::new(move |rt, qemu, pc, err: AsanError| {
            let pc = pc as u64;
            let modules = known_modules
                .lock()
                .map(|modules| modules.clone())
                .unwrap_or_default();
            if Self::should_skip_asan_pc(pc, &literal_skip_pcs, &module_skip_specs, &modules) {
                return;
            }
            if ignore_untracked_bad_frees && matches!(&err, AsanError::BadFree(_, None)) {
                return;
            }

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
            let module_hit = module_for_addr(&modules, pc);
            let module = module_hit
                .as_ref()
                .map(|module| format!("{}:+0x{:x}", module.name, module.offset))
                .unwrap_or_else(|| "unknown".to_string());
            let ceva_oob_allocation = ceva_oob_context_enabled
                .then(|| {
                    let address = match &err {
                        AsanError::Read(address, _)
                        | AsanError::Write(address, _)
                        | AsanError::BadFree(address, _) => *address,
                        AsanError::MemLeak(_) | AsanError::Signal(_) => return None,
                    };
                    let interval = rt.alloc_get_interval(address).or_else(|| {
                        address
                            .checked_sub(1)
                            .and_then(|addr| rt.alloc_get_interval(addr))
                    })?;
                    let allocation_size = interval.end - interval.start;
                    let mut bytes = vec![0_u8; allocation_size.min(64)];
                    let bytes = qemu
                        .read_mem(interval.start, &mut bytes)
                        .ok()
                        .map(|()| bytes);
                    Some(format!(
                        "start={:#x} end={:#x} size={allocation_size:#x} bytes={bytes:x?}",
                        interval.start, interval.end
                    ))
                })
                .flatten();
            let ceva_oob_context = ceva_oob_context_enabled
                .then(|| {
                    let module = module_hit.as_ref()?;
                    if module.name != "ceva_emu.cvd" {
                        return None;
                    }

                    let (context_register_name, context_register) = match module.offset {
                        0xD1E5 => ("rcx", Regs::Rcx),
                        0x3D583 => ("rbx", Regs::Rbx),
                        _ => return None,
                    };
                    let context: usize = qemu.read_reg(context_register).ok()?.try_into().ok()?;
                    let registers = [
                        ("rax", Regs::Rax),
                        ("rbx", Regs::Rbx),
                        ("rcx", Regs::Rcx),
                        ("rdx", Regs::Rdx),
                        ("rsi", Regs::Rsi),
                        ("rdi", Regs::Rdi),
                        ("r8", Regs::R8),
                        ("r9", Regs::R9),
                        ("r10", Regs::R10),
                        ("r11", Regs::R11),
                    ]
                    .into_iter()
                    .map(|(name, register)| {
                        let value: Option<u64> = qemu
                            .read_reg(register)
                            .ok()
                            .and_then(|value| value.try_into().ok());
                        (name, value)
                    })
                    .collect::<Vec<_>>();
                    let fields = (0x200_usize..=0x278)
                        .step_by(8)
                        .map(|offset| {
                            let mut bytes = [0_u8; 8];
                            let value = qemu
                                .read_mem(context + offset, &mut bytes)
                                .ok()
                                .map(|()| u64::from_le_bytes(bytes));
                            (offset, value)
                        })
                        .collect::<Vec<_>>();
                    let read_u64 = |address| {
                        let mut bytes = [0_u8; 8];
                        qemu.read_mem(address, &mut bytes)
                            .ok()
                            .map(|()| u64::from_le_bytes(bytes))
                    };
                    let read_u32 = |address| {
                        let mut bytes = [0_u8; 4];
                        qemu.read_mem(address, &mut bytes)
                            .ok()
                            .map(|()| u32::from_le_bytes(bytes))
                    };
                    let node = read_u64(context + 0x468);
                    let node_fields = node.map(|node| {
                        (
                            node,
                            read_u64(node as usize),
                            read_u64(node as usize + 0x08),
                            read_u64(node as usize + 0x28),
                            read_u32(node as usize + 0x30),
                        )
                    });
                    let dispatch_count = read_u32(context + 0x47C);
                    let dispatch_table = read_u64(context + 0x498);

                    Some(format!(
                        "context_register={context_register_name} context={context:#x} registers={registers:x?} context_fields={fields:x?} node_fields={node_fields:x?} dispatch_count={dispatch_count:x?} dispatch_table={dispatch_table:x?}"
                    ))
                })
                .flatten();
            let runtime_stack = stack_words.as_ref().map(|words| {
                words
                    .iter()
                    .map(|addr| {
                        qemu.mappings()
                            .find(|mapping| mapping.start() <= *addr && *addr < mapping.end())
                            .map(|mapping| {
                                let path = mapping.path().map_or("[anonymous]", String::as_str);
                                format!("{addr:#x}={path}+{:#x}", addr - mapping.start())
                            })
                            .unwrap_or_else(|| format!("{addr:#x}=unmapped"))
                    })
                    .collect::<Vec<_>>()
            });
            let message = format!(
                "BDCORE_ASAN pc={pc:#x} module={module} error={err:?} ceva_oob_allocation={ceva_oob_allocation:?} ceva_oob_context={ceva_oob_context:?} rsp={rsp:?} stack={stack_words:x?} runtime_stack={runtime_stack:?}",
            );
            utils::log_asan_error_msg(message, &crash_log_file);
            unsafe {
                qemu.target_signal(Signal::SigSegmentationFault);
            }
        }))
    }

    fn unpacker_progress_module(&self) -> Result<PcSignalModule, Error> {
        if !self.options.ceva_health_signals {
            return Ok(PcSignalModule::disabled());
        }

        const FSG_SIGNAL_SPECS: &[(&str, &str)] = &[
            ("callback_entry", "fsg.xmd:+0x6e0"),
            ("mode_dispatch", "fsg.xmd:+0x727"),
            ("mode20_parser", "fsg.xmd:+0x97a"),
            ("table_allocation", "fsg.xmd:+0xac2"),
            ("record_construction", "fsg.xmd:+0xada"),
            ("copyback", "fsg.xmd:+0xb5a"),
            ("copyback_done", "fsg.xmd:+0xb9e"),
        ];

        const PELOCK_SIGNAL_SPECS: &[(&str, &str)] = &[
            ("ep_off_in_last_section", "pelock.xmd:+0x4fa7"),
            ("pelock_parse_stub", "pelock.xmd:+0x5009"),
            ("pelock_parse_stub_return", "pelock.xmd:+0x500e"),
            ("pelock_parse_stub_passed", "pelock.xmd:+0x5019"),
            ("after_memset", "pelock.xmd:+0x50da"),
            ("after_first_seek_read", "pelock.xmd:+0x5151"),
            ("returned_06b80", "pelock.xmd:+0x516c"),
            ("passed_06b80", "pelock.xmd:+0x5174"),
            ("second_parse_ep_stub_call", "pelock.xmd:+0x51be"),
            ("second_parse_ep_stub_return", "pelock.xmd:+0x51c3"),
            ("second_parse_ep_stub_nonnegative", "pelock.xmd:+0x51ce"),
            ("stage_0_parsing_done", "pelock.xmd:+0x51de"),
            ("before_07d60", "pelock.xmd:+0x520e"),
            ("after_07d60", "pelock.xmd:+0x5213"),
            ("after_0cbb0", "pelock.xmd:+0x5257"),
            ("decoder_call", "pelock.xmd:+0x5294"),
            ("after_06ad0", "pelock.xmd:+0x529d"),
            ("after_073f0", "pelock.xmd:+0x52b9"),
            ("after_06e40", "pelock.xmd:+0x5564"),
            ("mode5_06e40_call", "pelock.xmd:+0x58bb"),
            ("mode5_06e40_return", "pelock.xmd:+0x58ea"),
            ("mode5_reparse_call", "pelock.xmd:+0x5a4d"),
            ("mode5_reparse_return", "pelock.xmd:+0x5a52"),
            ("mode5_reparse_passed", "pelock.xmd:+0x5a5d"),
            ("dispatch_c3b0", "pelock.xmd:+0x603f"),
            ("dispatch_c5b0", "pelock.xmd:+0x60db"),
            ("dispatch_c740", "pelock.xmd:+0x61ab"),
            ("late_range_parser_return", "pelock.xmd:+0x5fff"),
            ("late_range_parser_passed", "pelock.xmd:+0x6007"),
            ("late_dispatch_return", "pelock.xmd:+0x6021"),
            ("dispatch_06c50_return", "pelock.xmd:+0x6055"),
            ("dispatch_076f0_return", "pelock.xmd:+0x60b3"),
            ("dispatch_handler_return", "pelock.xmd:+0x6200"),
            ("state_parser_mode7_return", "pelock.xmd:+0x615e"),
            ("before_c7a0", "pelock.xmd:+0x61fb"),
            ("c7a0_wrapping_bounds_check", "pelock.xmd:+0x67cd"),
            ("c7a0_record_read", "pelock.xmd:+0x6812"),
            ("c7a0_record_branch", "pelock.xmd:+0x685b"),
            ("dispatch_c930", "pelock.xmd:+0x634a"),
            ("worker_fail", "pelock.xmd:+0x574c"),
        ];

        let (target_name, signal_specs): (&'static str, &[(&str, &str)]) =
            if self.options.fsg_postdecode {
                ("FsgProgress", FSG_SIGNAL_SPECS)
            } else if self.options.pelock {
                ("PelockProgress", PELOCK_SIGNAL_SPECS)
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

    fn asan_address_filter(&self) -> Result<StdAddressFilter, Error> {
        Ok(self.coverage_address_filter())
    }

    fn asan_module(&self) -> Result<AsanHostModule, Error> {
        let address_filter = self.asan_address_filter()?;
        let (literal_skip_pcs, module_skip_specs) = Self::parse_asan_skip_pc_specs(self.options)?;
        let known_modules = Arc::new(Mutex::new(self.harness.bd_engine().modules.clone()));

        Ok(AsanHostModule::builder()
            .filter(address_filter)
            .target_crash(AsanTargetCrash::Never)
            .error_callback(Self::diagnostic_asan_callback(
                self.options.crash_log_file.clone(),
                literal_skip_pcs,
                module_skip_specs,
                known_modules,
                self.options.fsg_postdecode || self.options.asan_ignore_untracked_bad_frees,
            ))
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
        let crash_context_module = CrashContextModule::from_env();
        let tmin_pc_module = if self.options.tmin {
            let spec = self
                .options
                .tmin_target_pc
                .as_deref()
                .ok_or_else(|| Error::illegal_argument("--tmin requires --tmin-target-pc"))?;
            let pc = self
                .harness
                .bd_engine()
                .resolve_module_address(spec, "tmin target PC")?;
            log::info!("TMin exact-hit target {spec} resolved to {pc:#x}");
            Some(TMinPcHitModule::new(pc as u64))
        } else {
            None
        };
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

        if let Some(tmin_pc_module) = tmin_pc_module {
            return instance
                .build()
                .run(tuple_list!(snapshot_module, tmin_pc_module), state);
        }

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
                    .unique_trace(self.options.drcov_bulk)
                    .build()
            } else {
                DrCovModule::builder()
                    .filter(StdAddressFilter::allow_list(
                        self.harness.bd_engine().coverage_filter().unwrap(),
                    ))
                    .path(drcov_output.clone())
                    .full_trace(false)
                    .unique_trace(self.options.drcov_bulk)
                    .build()
            };

            if let Some(asan_module) = asan_module {
                instance.build().run(
                    tuple_list!(
                        snapshot_module,
                        asan_module,
                        unpacker_progress_module,
                        pelock_ret_module,
                        pelock_stage0_capture_module,
                        pelock_07d60_window_capture_module,
                        crash_context_module,
                        drcov
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
                        crash_context_module,
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
                            crash_context_module,
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
                            crash_context_module,
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
                            crash_context_module,
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
                            crash_context_module,
                        ),
                        state,
                    )
                }
            }
        }
    }
}
