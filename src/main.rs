mod bitdefender;
mod client;
mod fuzzer;
mod harness;
mod inputs;
mod instance;
mod mutators;
mod options;
mod scan_profile;
mod utils;

#[cfg(target_os = "linux")]
pub fn main() {
    if let Some(path) = std::env::var_os("BDCORE_PANIC_DIAG_FILE") {
        let previous = std::panic::take_hook();
        std::panic::set_hook(Box::new(move |info| {
            if let Ok(mut file) = std::fs::OpenOptions::new()
                .create(true)
                .append(true)
                .open(&path)
            {
                use std::io::Write;
                let _ = writeln!(file, "{info}");
            }
            previous(info);
        }));
    }
    env_logger::init();
    let _fuzzer = fuzzer::Fuzzer::new().fuzz().unwrap();
}

#[cfg(not(target_os = "linux"))]
pub fn main() {
    panic!("qemu-user and libafl_qemu is only supported on linux!");
}
