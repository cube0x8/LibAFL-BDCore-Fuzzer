mod fuzzer;
mod options;
//mod reproduce;
mod bitdefender;
mod client;
mod harness;
mod instance;
mod mutator;
mod scan_profile;
mod utils;

#[cfg(target_os = "linux")]
pub fn main() {
    env_logger::init();
    let _fuzzer = fuzzer::Fuzzer::new().fuzz().unwrap();
}

#[cfg(not(target_os = "linux"))]
pub fn main() {
    panic!("qemu-user and libafl_qemu is only supported on linux!");
}
