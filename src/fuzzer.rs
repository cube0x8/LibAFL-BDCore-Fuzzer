use libafl_bolts::{os::dup2, os::dup_and_mute_outputs};
use libafl_qemu::Qemu;
use std::{
    cell::RefCell,
    env,
    fs::{File, OpenOptions},
    io::{self, Write},
    sync::Arc,
};

use clap::Parser;
#[cfg(not(feature = "simplemgr"))]
use libafl::{
    events::{EventConfig, Launcher},
    monitors::{Monitor, MultiMonitor, PrometheusMonitor},
    Error,
};
#[cfg(feature = "simplemgr")]
use libafl::{
    events::{ClientDescription, SimpleEventManager},
    monitors::{Monitor, MultiMonitor, PrometheusMonitor},
    Error,
};
#[cfg(feature = "simplemgr")]
use libafl_bolts::core_affinity::CoreId;

use libafl_bolts::current_time;

#[cfg(not(feature = "simplemgr"))]
use libafl_bolts::shmem::{ShMemProvider, StdShMemProvider};
#[cfg(unix)]
use std::os::unix::io::{AsRawFd, FromRawFd};

use crate::{
    client::Client,
    harness::{AnyHarness, CevaEmuHarness, CevaTargetKind, FuzzHarness, Harness},
    options::FuzzerOptions,
    scan_profile::ScanProfile,
};

pub struct Fuzzer {
    options: FuzzerOptions,
}

impl Fuzzer {
    pub fn new() -> Fuzzer {
        let options = FuzzerOptions::parse();
        options.validate();
        Fuzzer { options }
    }

    pub fn fuzz(&self) -> Result<(), Error> {
        let log = self.options.log.as_ref().and_then(|l| {
            OpenOptions::new()
                .append(true)
                .create(true)
                .open(l)
                .ok()
                .map(RefCell::new)
        });

        #[cfg(unix)]
        let wrapped_stdout = if self.options.verbose {
            None
        } else {
            // We forward all outputs to dev/null, but keep a copy around for the fuzzer output.
            //
            // # Safety
            // stdout and stderr should still be open at this point in time.
            let (new_stdout, new_stderr) = unsafe { dup_and_mute_outputs()? };

            // If we are debugging, re-enable target stderror.
            if std::env::var("LIBAFL_FUZZBENCH_DEBUG").is_ok() {
                // # Safety
                // Nobody else uses the new stderror here.
                unsafe {
                    dup2(new_stderr, io::stderr().as_raw_fd())?;
                }
            }

            // # Safety
            // The new stdout is open at this point, and we will don't use it anywhere else.
            #[cfg(unix)]
            Some(unsafe { File::from_raw_fd(new_stdout) })
        };

        let stdout_cpy = wrapped_stdout.map(RefCell::new);

        // The stats reporter for the broker
        match &self.options.prometheus_addr {
            Some(prometheus_addr) => {
                let listener = prometheus_addr.to_string();
                let monitor = PrometheusMonitor::new(listener, |s| println!("{s}"));
                self.launch(monitor)
            }
            None => {
                let monitor = MultiMonitor::new(|s| {
                    #[cfg(unix)]
                    if let Some(stdout_cpy) = &stdout_cpy {
                        writeln!(stdout_cpy.borrow_mut(), "{s}").unwrap();
                    } else {
                        println!("{s}");
                    }
                    #[cfg(windows)]
                    println!("{s}");

                    if let Some(log) = &log {
                        writeln!(log.borrow_mut(), "{:?} {}", current_time(), s).unwrap();
                    }
                });
                self.launch(monitor)
            }
        }
    }

    fn args(&self) -> Result<Vec<String>, Error> {
        let program = env::args()
            .next()
            .ok_or_else(|| Error::empty_optional("Failed to read program name"))?;

        let mut args = self.options.args.clone();
        args.insert(0, program);
        Ok(args)
    }

    #[allow(clippy::unused_self)] // Api should look the same as args above
    fn env(&self) -> Vec<(String, String)> {
        env::vars()
            .filter(|(k, _v)| k != "LD_LIBRARY_PATH")
            .collect::<Vec<(String, String)>>()
    }

    fn launch<M>(&self, monitor: M) -> Result<(), Error>
    where
        M: Monitor + Clone,
    {
        // The shared memory allocator
        #[cfg(not(feature = "simplemgr"))]
        let shmem_provider = StdShMemProvider::new()?;

        /* If we are running in verbose, don't provide a replacement stdout, otherwise, use /dev/null */
        #[cfg(not(feature = "simplemgr"))]
        let stdout = if self.options.verbose {
            None
        } else {
            Some("/dev/null")
        };

        let args = self.args()?;
        log::debug!("ARGS: {:#?}", args);

        let env = self.env();
        log::debug!("ENV: {:#?}", env);

        let qemu = Qemu::init(&args)?;
        let scan_profile = self
            .options
            .scan_profile_every()
            .map(|report_every| Arc::new(ScanProfile::new(report_every)));

        let harness = if self.options.translate_node_link {
            let entry_point = self.options.entry_point.clone().unwrap();
            let mut harness = CevaEmuHarness::new(
                &qemu,
                entry_point,
                CevaTargetKind::TranslateNodeLink.build(),
            )?;
            harness.init(self.options.bitdefender_modules.clone())?;
            AnyHarness::CevaEmu(harness)
        } else {
            let mut harness = Harness::new(&qemu)?;
            harness.init(
                self.options.bitdefender_modules.clone(),
                self.options.exit_points.clone(),
            )?;
            AnyHarness::Standard(harness)
        };

        qemu.flush_jit();

        let mut client = Client::builder()
            .options(&self.options)
            .qemu(&qemu)
            .harness(&harness as &dyn FuzzHarness)
            .scan_profile(scan_profile)
            .build();

        let broker_port = self
            .options
            .broker_port()
            .expect("No ports available for the broker.");
        log::info!("Broker port selected: {:?}", broker_port);
        #[cfg(feature = "simplemgr")]
        return client.run(
            None,
            SimpleEventManager::new(monitor),
            ClientDescription::new(0, 0, CoreId(0)),
        );

        // Build and run a Launcher
        #[cfg(not(feature = "simplemgr"))]
        // Build and run a Launcher that connects to an existing, remote, broker (B2B)
        match Launcher::builder()
            .shmem_provider(shmem_provider)
            .broker_port(broker_port)
            .configuration(EventConfig::from_build_id())
            .monitor(monitor)
            .run_client(|s, m, c| client.run(s, m, c))
            .cores(&self.options.cores)
            .stdout_file(stdout)
            .spawn_broker(!self.options.attach)
            .remote_broker_addr(self.options.remote_broker())
            .build()
            .launch()
        {
            Ok(()) => Ok(()),
            Err(Error::ShuttingDown) => {
                println!("Fuzzing stopped by user. Good bye.");
                Ok(())
            }
            Err(err) => Err(err),
        }
    }
}
