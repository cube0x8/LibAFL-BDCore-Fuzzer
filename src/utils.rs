use flate2::{write::GzEncoder, Compression};
use std::fs::{rename, File, OpenOptions};
use std::io::{BufReader, BufWriter, Read, Write};
use std::path::PathBuf;

/*
pub fn print_memory<QT, S, E>(emu: &Emulator<QT, S, E>, addr: u64, size: u32) {
    unsafe {
        let mut buf: Vec<u8> = vec![0; size as usize];
        emu.read_mem(addr as u64, buf.as_mut_slice());

        // Iterate through the Vec<u8> and format each element as a hexadecimal string
        let hex_str: Vec<String> = buf.iter().map(|byte| format!("{:02X}", byte)).collect();
        let result = hex_str.join(" ");

        println!("{addr:#x?}: {result}");
    }
}

pub fn generate_random_string(length: usize) -> String {
    let s: String = rand::thread_rng()
        .sample_iter(&Alphanumeric)
        .take(length)
        .map(char::from)
        .collect();

    s
}
*/

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
