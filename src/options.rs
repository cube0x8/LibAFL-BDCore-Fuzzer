use clap::{builder::Str, error::ErrorKind, CommandFactory, Parser};
use core::time::Duration;
use libafl::Error;
use libafl_bolts::core_affinity::{CoreId, Cores};
use std::{
    env,
    net::{IpAddr, SocketAddr, TcpListener},
    path::PathBuf,
};

#[derive(Default)]
pub struct Version;

impl From<Version> for Str {
    fn from(_: Version) -> Str {
        let version = [
            ("Architecture:", env!("CPU_TARGET")),
            ("Build Timestamp:", env!("VERGEN_BUILD_TIMESTAMP")),
            ("Describe:", env!("VERGEN_GIT_DESCRIBE")),
            ("Commit SHA:", env!("VERGEN_GIT_SHA")),
            ("Commit Date:", env!("VERGEN_RUSTC_COMMIT_DATE")),
            ("Commit Branch:", env!("VERGEN_GIT_BRANCH")),
            ("Rustc Version:", env!("VERGEN_RUSTC_SEMVER")),
            ("Rustc Channel:", env!("VERGEN_RUSTC_CHANNEL")),
            ("Rustc Host Triple:", env!("VERGEN_RUSTC_HOST_TRIPLE")),
            ("Rustc Commit SHA:", env!("VERGEN_RUSTC_COMMIT_HASH")),
            ("Cargo Target Triple", env!("VERGEN_CARGO_TARGET_TRIPLE")),
        ]
        .iter()
        .map(|(k, v)| format!("{k:25}: {v}\n"))
        .collect::<String>();

        format!("\n{version:}").into()
    }
}

#[derive(Parser, Debug)]
#[clap(author, version, about, long_about = None)]
#[command(
    name = format!("qemu_bdclient"),
    version = Version::default(),
    about,
    long_about = "Fuzz the BitDefender engine"
)]
#[clap(author, version, about, long_about = None)]
pub struct FuzzerOptions {
    #[arg(long, help = "IP:PORT for prometheus metrics")]
    pub prometheus_addr: Option<String>,

    #[arg(long, help = "Input directory", required_unless_present("rerun_input"))]
    pub input: Option<String>,

    #[arg(
        long,
        help = "Output directory",
        required_unless_present("rerun_input")
    )]
    pub output: Option<String>,

    #[arg(long, help = "Queue directory", required_unless_present("rerun_input"))]
    pub queue: Option<String>,

    #[arg(long, help = "All the clients have ASAN")]
    pub asan: bool,

    #[arg(
        long,
        help = "Use the PE format-aware mutator instead of the default havoc mutator"
    )]
    pub pe_mutator: bool,

    #[arg(
        long,
        help = "Enable PE mutator reporting to /tmp/pe-report.txt. Requires --pe-mutator"
    )]
    pub pe_mutator_reporting: bool,

    #[arg(
        long,
        default_value_t = 2,
        value_parser = FuzzerOptions::parse_positive_usize,
        help = "Minimum number of stacked PE mutations per pass. Requires --pe-mutator"
    )]
    pub pe_min_stack_depth: usize,

    #[arg(
        long,
        default_value_t = 2,
        value_parser = FuzzerOptions::parse_positive_usize,
        help = "Maximum number of stacked PE mutations per pass. Requires --pe-mutator"
    )]
    pub pe_max_stack_depth: usize,

    #[arg(long, help = "Enable only PE header mutations. Requires --pe-mutator")]
    pub pe_header: bool,

    #[arg(long, help = "Enable only section mutations. Requires --pe-mutator")]
    pub sections: bool,

    #[arg(long, help = "Enable only assembly mutations. Requires --pe-mutator")]
    pub assembly: bool,

    #[arg(
        long,
        help = "Enable only export directory mutations. Requires --pe-mutator"
    )]
    pub export_dir: bool,

    #[arg(
        long,
        help = "Enable only resource directory mutations. Requires --pe-mutator"
    )]
    pub resource_dir: bool,

    #[arg(
        long,
        help = "Enable only data directory entry mutations. Requires --pe-mutator"
    )]
    pub data_dir: bool,

    #[arg(
        long,
        help = "Only mutate initial seed inputs; keep later corpus discoveries but do not schedule them for mutation"
    )]
    pub only_seeds: bool,

    #[arg(
        long,
        help = "Restrict havoc mutations to size-preserving operations that keep the input length unchanged"
    )]
    pub fixed_size_mutations: bool,

    #[arg(long, help = "Cpu cores to use for CmpLog", value_parser = Cores::from_cmdline)]
    pub cmplog_cores: Option<Cores>,

    #[arg(
        short = 'd',
        help = "Write a DrCov Trace for the current input. Requires -r and --modules.",
        requires = "rerun_input",
        requires = "bitdefender_modules"
    )]
    pub drcov: Option<PathBuf>,

    #[arg(short = 'r', help = "Rerun an input to gather drcov coverage")]
    pub rerun_input: Option<PathBuf>,

    #[arg(long, help = "Sync directory for new corpus files")]
    pub sync_dir: Option<String>,

    #[arg(long, help = "Crash log file")]
    pub crash_log_file: Option<String>,

    #[arg(long, help = "Profile the ScanFile hot path and log aggregate timings")]
    pub profile_scanfile: bool,

    #[arg(
        long,
        help = "Emit ScanFile timing reports every N iterations",
        default_value = "1000",
        value_parser = clap::value_parser!(u64).range(1..)
    )]
    pub profile_scanfile_every: u64,

    #[arg(long, help = "Timeout in milli-seconds", default_value = "1000", value_parser = FuzzerOptions::parse_timeout)]
    pub timeout: Duration,

    #[arg(long, help = "Log file")]
    pub log: Option<String>,

    #[arg(
        long = "port",
        help = "Broker port. Select one or a free one will be picked up randomly (starting from 1024)"
    )]
    pub port: Option<u16>,

    #[arg(
        long = "attach",
        help = "Do not spawn a broker (attach to a local one)",
        conflicts_with = "remote_broker",
        requires = "port"
    )]
    pub attach: bool,

    #[arg(
        long = "remote-broker",
        help = "IP:PORT of remote broker to connect to"
    )]
    pub remote_broker: Option<String>,

    #[arg(long, help = "Cpu cores to use", default_value = "all", value_parser = Cores::from_cmdline)]
    pub cores: Cores,

    #[clap(short, long, help = "Enable output from the fuzzer clients")]
    pub verbose: bool,

    #[arg(
        long = "modules",
        help = "Modules to instrument",
        value_delimiter = ','
    )]
    pub bitdefender_modules: Option<Vec<String>>,

    #[arg(
        long = "exit-point",
        help = "Comma separated exit points in format module:+offset",
        value_delimiter = ','
    )]
    pub exit_points: Option<Vec<String>>,

    #[arg(long, help = "Target the ceva_emu TranslateNodeLink function")]
    pub translate_node_link: bool,

    #[arg(
        long,
        help = "Entry point for ceva_emu targeted mutations in format module:+offset"
    )]
    pub entry_point: Option<String>,

    #[arg(
        long,
        long,
        help = "Comma separated PCs to skip in ASAN callback",
        value_delimiter = ','
    )]
    pub pcs_to_skip: Option<Vec<String>>,

    #[arg(last = true, help = "Arguments passed to the target")]
    pub args: Vec<String>,
}

impl FuzzerOptions {
    fn any_pe_mutation_group_selected(&self) -> bool {
        self.pe_header
            || self.sections
            || self.assembly
            || self.export_dir
            || self.resource_dir
            || self.data_dir
    }

    fn absolutize_path(path: PathBuf) -> PathBuf {
        if path.is_absolute() {
            path
        } else {
            env::current_dir()
                .map(|cwd| cwd.join(&path))
                .unwrap_or(path)
        }
    }

    fn parse_timeout(src: &str) -> Result<Duration, Error> {
        Ok(Duration::from_millis(src.parse()?))
    }

    fn parse_positive_usize(src: &str) -> Result<usize, Error> {
        let value: usize = src.parse()?;
        if value == 0 {
            return Err(Error::illegal_argument("value must be greater than 0"));
        }
        Ok(value)
    }

    fn find_free_port() -> Option<u16> {
        for port in 1024..65535 {
            let addr = SocketAddr::from(([0, 0, 0, 0], port));
            if TcpListener::bind(addr).is_ok() {
                return Some(port);
            }
        }
        None
    }

    pub fn broker_port(&self) -> Option<u16> {
        match self.port {
            Some(port) => Some(port as u16),
            None => FuzzerOptions::find_free_port(),
        }
    }

    /*
    fn parse_modules(modules_to_instrument: &str) -> Result<Vec<String>, Error> {
        if modules_to_instrument == "all" {
            return Ok(Vec::new());
        }

        let vec_of_modules: Vec<String> = modules_to_instrument.split(',').map(|x| x.to_string()).collect();
        if vec_of_modules.is_empty() {
            return Err(Error::empty_optional("--modules must be a comma-separated list or 'all'"));
        }

        Ok(vec_of_modules)
    }
    */

    pub fn is_asan(&self) -> bool {
        self.asan
    }

    pub fn is_cmplog_core(&self, core_id: CoreId) -> bool {
        self.cmplog_cores
            .as_ref()
            .map_or(false, |c| c.contains(core_id))
    }

    pub fn scan_profile_every(&self) -> Option<u64> {
        self.profile_scanfile.then_some(self.profile_scanfile_every)
    }

    pub fn input_dir(&self) -> Option<PathBuf> {
        match &self.input {
            Some(input) => Some(Self::absolutize_path(PathBuf::from(input))),
            None => None,
        }
    }

    pub fn output_dir(&self) -> Option<PathBuf> {
        if let Some(_) = &self.rerun_input {
            return Some(Self::absolutize_path(PathBuf::from("./drcov_output")));
        }
        match &self.output {
            Some(output) => Some(Self::absolutize_path(PathBuf::from(output))),
            None => None,
        }
    }

    pub fn queue_dir(&self) -> Option<PathBuf> {
        if let Some(_) = &self.rerun_input {
            return Some(Self::absolutize_path(PathBuf::from("./drcov_queue")));
        }
        match &self.queue {
            Some(queue) => Some(Self::absolutize_path(PathBuf::from(queue))),
            None => None,
        }
    }

    pub fn sync_dir(&self) -> Option<Vec<PathBuf>> {
        match &self.sync_dir {
            Some(sync_dir) => Some(
                sync_dir
                    .split(',')
                    .map(PathBuf::from)
                    .map(Self::absolutize_path)
                    .collect(),
            ),
            None => None,
        }
    }

    pub fn remote_broker(&self) -> Option<SocketAddr> {
        match &self.remote_broker {
            None => return None,
            Some(remote_broker) => {
                let parts: Vec<&str> = remote_broker.split(':').collect(); // Extracting IP and Port
                let ip_str = parts[0];
                let port_str = parts[1];

                // Parsing IP address
                let ip: IpAddr = ip_str.parse().expect("Failed to parse IP address");

                // Parsing Port
                let port: u16 = port_str.parse().expect("Failed to parse port");
                Some(SocketAddr::new(ip, port))
            }
        }
    }

    pub fn validate(&self) {
        if (self.pe_min_stack_depth != 2 || self.pe_max_stack_depth != 2) && !self.pe_mutator {
            let mut cmd = FuzzerOptions::command();
            cmd.error(
                ErrorKind::ArgumentConflict,
                "Using --pe-min-stack-depth/--pe-max-stack-depth requires --pe-mutator",
            )
            .exit();
        }

        if self.pe_mutator_reporting && !self.pe_mutator {
            let mut cmd = FuzzerOptions::command();
            cmd.error(
                ErrorKind::ArgumentConflict,
                "Using --pe-mutator-reporting requires --pe-mutator",
            )
            .exit();
        }

        if self.any_pe_mutation_group_selected() && !self.pe_mutator {
            let mut cmd = FuzzerOptions::command();
            cmd.error(
                ErrorKind::ArgumentConflict,
                "Using --pe-header/--sections/--assembly/--export-dir/--resource-dir/--data-dir requires --pe-mutator",
            )
            .exit();
        }

        if self.pe_min_stack_depth > self.pe_max_stack_depth {
            let mut cmd = FuzzerOptions::command();
            cmd.error(
                ErrorKind::ValueValidation,
                "--pe-min-stack-depth must be less than or equal to --pe-max-stack-depth",
            )
            .exit();
        }

        if self.drcov.is_some() {
            let modules_missing = self
                .bitdefender_modules
                .as_ref()
                .map_or(true, |mods| mods.iter().all(|m| m.trim().is_empty()));

            if modules_missing {
                let mut cmd = FuzzerOptions::command();
                cmd.error(
                    ErrorKind::MissingRequiredArgument,
                    "Using -d/--drcov requires --modules <module[,module...]>",
                )
                .exit();
            }
        }

        if let Some(cmplog_cores) = &self.cmplog_cores {
            for id in &cmplog_cores.ids {
                if !self.cores.contains(*id) {
                    let mut cmd = FuzzerOptions::command();
                    cmd.error(
                        ErrorKind::ValueValidation,
                        format!(
                            "Cmplog cores ({}) must be a subset of total cores ({})",
                            cmplog_cores.cmdline, self.cores.cmdline
                        ),
                    )
                    .exit();
                }
            }
        }

        if self.translate_node_link && self.entry_point.is_none() {
            let mut cmd = FuzzerOptions::command();
            cmd.error(
                ErrorKind::MissingRequiredArgument,
                "Using --translate-node-link requires --entry-point <module:+offset>",
            )
            .exit();
        }

        if !self.translate_node_link && self.entry_point.is_some() {
            let mut cmd = FuzzerOptions::command();
            cmd.error(
                ErrorKind::ArgumentConflict,
                "Using --entry-point currently requires a ceva_emu target such as --translate-node-link",
            )
            .exit();
        }

        if self.translate_node_link && self.exit_points.is_some() {
            let mut cmd = FuzzerOptions::command();
            cmd.error(
                ErrorKind::ArgumentConflict,
                "Custom --exit-point values are not supported for ceva_emu targeted mutations",
            )
            .exit();
        }
    }
}
