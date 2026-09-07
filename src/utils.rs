use flate2::{write::GzEncoder, Compression};
use libafl::Error;
use libafl_qemu::{GuestAddr, Qemu};
use std::fs::{rename, File, OpenOptions};
use std::io::{BufReader, BufWriter, Read, Write};
use std::path::PathBuf;

pub fn read_guest_u32_labeled(qemu: &Qemu, address: GuestAddr, label: &str) -> Result<u32, Error> {
    let mut bytes = [0_u8; 4];
    qemu.read_mem(address, &mut bytes)
        .map_err(|error| Error::unknown(format!("Failed to read {label}: {error:?}")))?;
    Ok(u32::from_le_bytes(bytes))
}

pub fn read_guest_u32_opt(qemu: &Qemu, address: GuestAddr) -> Option<u32> {
    let mut bytes = [0_u8; 4];
    qemu.read_mem(address, &mut bytes).ok()?;
    Some(u32::from_le_bytes(bytes))
}

pub fn read_guest_u16_opt(qemu: &Qemu, address: GuestAddr) -> Option<u16> {
    let mut bytes = [0_u8; 2];
    qemu.read_mem(address, &mut bytes).ok()?;
    Some(u16::from_le_bytes(bytes))
}

pub fn read_guest_u64_labeled(qemu: &Qemu, address: GuestAddr, label: &str) -> Result<u64, Error> {
    let mut bytes = [0_u8; 8];
    qemu.read_mem(address, &mut bytes)
        .map_err(|error| Error::unknown(format!("Failed to read {label}: {error:?}")))?;
    Ok(u64::from_le_bytes(bytes))
}

pub fn read_guest_u64_opt(qemu: &Qemu, address: GuestAddr) -> Option<u64> {
    let mut bytes = [0_u8; 8];
    qemu.read_mem(address, &mut bytes).ok()?;
    Some(u64::from_le_bytes(bytes))
}

pub fn write_guest_u32_labeled(
    qemu: &Qemu,
    address: GuestAddr,
    value: u32,
    label: &str,
) -> Result<(), Error> {
    qemu.write_mem(address, &value.to_le_bytes())
        .map_err(|error| Error::unknown(format!("Failed to write {label}: {error:?}")))
}

fn write_to_asan_log_file(error_msg: &str, crash_log: &str) {
    if let Ok(mut file) = OpenOptions::new()
        .create(true)
        .append(true)
        .open(PathBuf::from(crash_log))
    {
        let pid = std::process::id();
        let new_error_msg = format!("PID {} - {}\n", pid, error_msg);
        if let Err(e) = file.write_all(new_error_msg.as_bytes()) {
            eprintln!("Error writing to file: {}", e);
        }
    }
}

pub fn log_asan_error_msg(error_msg: String, crash_log: &Option<String>) {
    match crash_log {
        Some(log) => {
            log::warn!("[ASAN] {}", error_msg);
            write_to_asan_log_file(&error_msg, &log);
        }
        None => {
            println!("ASAN_ERROR:\n{}", error_msg);
        }
    }
}

const BUFFER_SIZE: usize = 8 * 1024;

pub fn compress_and_replace(file_path: &PathBuf) -> std::io::Result<()> {
    let input_file = File::open(file_path)?;
    let mut reader = BufReader::new(input_file);

    let temp_file_path = file_path.with_extension("tmp");
    let temp_file = File::create(&temp_file_path)?;
    let mut writer = BufWriter::new(GzEncoder::new(temp_file, Compression::default()));

    let mut buffer = [0u8; BUFFER_SIZE];

    while let Ok(bytes_read) = reader.read(&mut buffer) {
        if bytes_read == 0 {
            break;
        }
        writer.write_all(&buffer[..bytes_read])?;
    }

    writer.flush()?;

    rename(temp_file_path, file_path)?;

    Ok(())
}
