use crate::bitdefender::{BDEngine, DUMMY_PATH};

use libafl::{
    executors::ExitKind,
    inputs::{BytesInput, HasTargetBytes, Input},
    Error,
};
use libafl_bolts::AsSlice;
use libafl_qemu::{
    elf::EasyElf,
    //helper::QemuHelperTuple,
    ArchExtras,
    GuestAddr,
    GuestReg,
    MmapPerms,
    Qemu,
    Regs,
};
use std::{
    ops::Range,
    thread,
    time::{Duration, Instant},
};

use crate::scan_profile::ScanProfile;

pub struct Harness<'a> {
    qemu: &'a Qemu,
    pub input_addr: GuestAddr,
    pub file_path: GuestAddr,
    pub g_mmap_file_addr: GuestAddr,
    pub pc: GuestAddr,
    pub stack_ptr: GuestAddr,
    pub ret_addr: GuestAddr,
    pub exit_points: Vec<GuestAddr>,
    pub scan_file_ptr: GuestAddr,
    pub scan_file_core_set_call_pc: GuestAddr,
    pub scan_file_after_core_set_pc: GuestAddr,
    pub rdi: GuestAddr,
    pub bd_engine: BDEngine,
}

pub const MAX_INPUT_SIZE: usize = 1_048_576; // 1MB
pub const MAX_TARGET_INPUT_SIZE: usize = 307_200;
pub const FILE_PATH_SIZE: usize = 1024;
pub const G_MMAP_FILE_SIZE: usize = 280;
const SCAN_FILE_CORE_SET_CALL_OFFSET: GuestAddr = 0x7c;
const SCAN_FILE_AFTER_CORE_SET_OFFSET: GuestAddr = 0x7e;

impl<'a> Harness<'a> {
    pub fn new(qemu: &Qemu) -> Result<Harness<'_>, Error> {
        let mut elf_buffer = Vec::new();
        let elf = EasyElf::from_file(qemu.binary_path(), &mut elf_buffer).unwrap();

        let scan_file_ptr = elf
            .resolve_symbol("ScanFile", qemu.load_addr())
            .expect("Symbol ScanFile not found");
        println!("ScanFile @ {scan_file_ptr:#x}");

        let g_mmap_file_ptr = elf
            .resolve_symbol("g_mmap_file", qemu.load_addr())
            .expect("Symbol g_mmap_file not found");
        println!("g_mmap_file @ {g_mmap_file_ptr:#x}");

        let input_addr = qemu
            .map_private(0, MAX_INPUT_SIZE, MmapPerms::ReadWrite)
            .map_err(|e| Error::unknown(format!("Failed to map input buffer: {e:}")))?;
        println!("Input buffer @ {input_addr:#x}");

        let module_instrumentation_callback_ptr = elf
            .resolve_symbol("ModuleInstrumentationCallback2", qemu.load_addr())
            .expect("Symbol ModuleInstrumentationCallback2 not found");
        println!("ModuleInstrumentationCallback2 @ {module_instrumentation_callback_ptr:#x}");

        let virtual_protect_ptr = elf
            .resolve_symbol("VirtualProtect", qemu.load_addr())
            .expect("Symbol VirtualProtect not found");
        println!("VirtualProtect @ {virtual_protect_ptr:#x}");

        let nt_virtual_protect_ptr = elf
            .resolve_symbol("NtProtectVirtualMemory", qemu.load_addr())
            .expect("Symbol NtProtectVirtualMemory not found");
        println!("NtProtectVirtualMemory @ {virtual_protect_ptr:#x}");

        let initialize_core_ptr = elf
            .resolve_symbol("InitializeCore", qemu.load_addr())
            .expect("Symbol InitializeCore not found");
        println!("CoreInitializeResult @ {initialize_core_ptr:#x}");

        let file_path = qemu
            .map_private(0, FILE_PATH_SIZE, MmapPerms::ReadWrite)
            .unwrap();
        println!("File path @ {file_path:#x}");

        let bd_engine = BDEngine::new(
            virtual_protect_ptr,
            nt_virtual_protect_ptr,
            initialize_core_ptr,
            module_instrumentation_callback_ptr,
        );

        unsafe {
            qemu.write_mem(file_path, DUMMY_PATH.as_bytes());
        }

        Ok(Harness {
            qemu,
            input_addr,
            file_path,
            g_mmap_file_addr: g_mmap_file_ptr,
            pc: 0,
            stack_ptr: 0,
            ret_addr: 0,
            exit_points: Vec::new(),
            scan_file_ptr,
            scan_file_core_set_call_pc: scan_file_ptr + SCAN_FILE_CORE_SET_CALL_OFFSET,
            scan_file_after_core_set_pc: scan_file_ptr + SCAN_FILE_AFTER_CORE_SET_OFFSET,
            rdi: 0,
            bd_engine,
        })
    }

    pub fn snapshot_excludes(&self) -> Vec<Range<u64>> {
        let input_addr = self.input_addr as u64;
        let file_path = self.file_path as u64;
        let g_mmap_file_addr = self.g_mmap_file_addr as u64;

        vec![
            input_addr..(input_addr + MAX_INPUT_SIZE as u64),
            file_path..(file_path + FILE_PATH_SIZE as u64),
            g_mmap_file_addr..(g_mmap_file_addr + G_MMAP_FILE_SIZE as u64),
        ]
    }

    fn current_pc(&self) -> GuestAddr {
        self.qemu.read_reg(Regs::Pc).unwrap().try_into().unwrap()
    }

    fn resolve_exit_points(&self, specs: &[String]) -> Result<Vec<GuestAddr>, Error> {
        if specs.is_empty() {
            return Err(Error::unknown(
                "At least one --exit-point value is required when the option is provided",
            ));
        }

        let mut resolved = Vec::with_capacity(specs.len());

        for spec in specs {
            let (module_name, offset_str) = spec.split_once(":+").ok_or_else(|| {
                Error::unknown(format!(
                    "Invalid exit point format '{spec}', expected module:+offset"
                ))
            })?;

            let module_name = module_name.trim();
            let offset_str = offset_str.trim();

            if module_name.is_empty() || offset_str.is_empty() {
                return Err(Error::unknown(format!(
                    "Invalid exit point format '{spec}', expected module:+offset"
                )));
            }

            let offset = if let Some(hex) = offset_str
                .strip_prefix("0x")
                .or_else(|| offset_str.strip_prefix("0X"))
            {
                GuestAddr::from_str_radix(hex, 16).map_err(|err| {
                    Error::unknown(format!(
                        "Failed to parse hexadecimal offset '{offset_str}' for exit point '{spec}': {err}"
                    ))
                })?
            } else {
                offset_str.parse::<GuestAddr>().map_err(|err| {
                    Error::unknown(format!(
                        "Failed to parse decimal offset '{offset_str}' for exit point '{spec}': {err}"
                    ))
                })?
            };

            let module = self
                .bd_engine
                .modules
                .iter()
                .find(|module| module.name == module_name)
                .ok_or_else(|| {
                    Error::unknown(format!(
                        "Exit point module '{module_name}' not found. Available modules: {:?}",
                        self.bd_engine.modules
                    ))
                })?;

            let offset = offset as u64;
            let addr = module.start_addr.checked_add(offset).ok_or_else(|| {
                Error::unknown(format!(
                    "Exit point '{spec}' overflows module base {:#x} with offset {offset:#x}",
                    module.start_addr
                ))
            })?;

            let addr = GuestAddr::try_from(addr).map_err(|_| {
                Error::unknown(format!(
                    "Resolved exit point '{spec}' address {addr:#x} does not fit GuestAddr"
                ))
            })?;

            println!("Exit point {spec} -> {addr:#x}");
            resolved.push(addr);
        }

        Ok(resolved)
    }

    fn run_with_breakdown(
        &self,
        scan_profile: &ScanProfile,
        input_len: usize,
        truncated: bool,
    ) -> ExitKind {
        self.qemu.set_breakpoint(self.scan_file_core_set_call_pc);
        self.qemu.set_breakpoint(self.scan_file_after_core_set_pc);

        let guest_exec_started_at = Instant::now();
        let setup_started_at = Instant::now();
        unsafe { self.qemu.run() };

        let setup_hit = self.current_pc() == self.scan_file_core_set_call_pc;
        if !setup_hit {
            self.qemu.remove_breakpoint(self.scan_file_core_set_call_pc);
            self.qemu
                .remove_breakpoint(self.scan_file_after_core_set_pc);
            scan_profile.record_incomplete_breakdown();
            scan_profile.record_guest_exec(guest_exec_started_at.elapsed(), input_len, truncated);
            return ExitKind::Ok;
        }

        scan_profile.record_setup(setup_started_at.elapsed());
        self.qemu.remove_breakpoint(self.scan_file_core_set_call_pc);

        let core_scan_started_at = Instant::now();
        unsafe { self.qemu.run() };

        let core_scan_hit = self.current_pc() == self.scan_file_after_core_set_pc;
        if !core_scan_hit {
            self.qemu
                .remove_breakpoint(self.scan_file_after_core_set_pc);
            scan_profile.record_incomplete_breakdown();
            scan_profile.record_guest_exec(guest_exec_started_at.elapsed(), input_len, truncated);
            return ExitKind::Ok;
        }

        scan_profile.record_core_scan(core_scan_started_at.elapsed());
        self.qemu
            .remove_breakpoint(self.scan_file_after_core_set_pc);

        let teardown_started_at = Instant::now();
        unsafe { self.qemu.run() };

        if self.exit_points.contains(&self.current_pc()) {
            scan_profile.record_teardown(teardown_started_at.elapsed());
        } else {
            scan_profile.record_incomplete_breakdown();
        }

        scan_profile.record_guest_exec(guest_exec_started_at.elapsed(), input_len, truncated);
        ExitKind::Ok
    }

    pub fn init(
        &mut self,
        modules_to_instrument: Option<Vec<String>>,
        exit_points: Option<Vec<String>>,
    ) -> Result<(), Error> {
        // Initialize the Bitdefender Engine. This runs untile the ret addr of InitializeCore
        self.bd_engine.core_initialization(self.qemu);

        // Store the ranges of the module to instrument
        self.bd_engine.instrument_modules(modules_to_instrument);

        let duration = Duration::from_secs(5);
        thread::sleep(duration);

        // Run until ScanFile()
        self.qemu.set_breakpoint(self.scan_file_ptr);
        unsafe { self.qemu.run() };

        // store the stack pointer, return address, and rdi
        let stack_ptr: GuestAddr = self.qemu.read_reg(Regs::Sp).unwrap().try_into().unwrap();
        let rdi: GuestAddr = self.qemu.read_reg(Regs::Rdi).unwrap().try_into().unwrap();
        let scan_file_ret_addr: GuestAddr =
            self.qemu.read_return_address().unwrap().try_into().unwrap();
        println!("Return address = {scan_file_ret_addr:#x}");

        let pc: GuestAddr = self.qemu.read_reg(Regs::Pc).unwrap().try_into().unwrap();
        println!("Break at {pc:#x}");

        // Remove the bp to ScanFile, set it on its return ptr
        self.qemu.remove_breakpoint(self.scan_file_ptr);

        self.exit_points = match exit_points {
            Some(specs) => self.resolve_exit_points(&specs)?,
            None => vec![scan_file_ret_addr],
        };

        for exit_point in &self.exit_points {
            self.qemu.set_breakpoint(*exit_point);
        }

        // Store the new emu state for the restore
        self.pc = pc;
        self.stack_ptr = stack_ptr;
        self.ret_addr = scan_file_ret_addr;
        self.rdi = rdi;

        Ok(())
    }

    fn reset(&self, buf: &[u8], len: GuestReg) -> Result<(), Error> {
        unsafe {
            self.qemu.write_mem(self.input_addr, buf);

            self.qemu
                .write_reg(Regs::Rdi, GuestReg::try_from(self.rdi).unwrap())
                .unwrap();
            self.qemu
                .write_reg(Regs::Rsi, GuestReg::try_from(self.input_addr).unwrap())
                .unwrap();
            self.qemu.write_reg(Regs::Rdx, len).unwrap();
            self.qemu
                .write_reg(Regs::Rcx, GuestReg::try_from(self.file_path).unwrap())
                .unwrap();

            self.qemu
                .write_reg(Regs::Pc, GuestReg::try_from(self.pc).unwrap())
                .unwrap();
            self.qemu
                .write_reg(Regs::Sp, GuestReg::try_from(self.stack_ptr).unwrap())
                .unwrap();
        }
        Ok(())
    }

    pub fn run(&self, input: &BytesInput, scan_profile: Option<&ScanProfile>) -> ExitKind {
        //println!("HARNESS STARTS");

        let target = input.target_bytes();
        let mut buf = target.as_slice();

        let original_len = buf.len();
        let mut len = buf.len() as GuestReg;
        if len > MAX_TARGET_INPUT_SIZE as GuestReg {
            buf = &buf[0..MAX_TARGET_INPUT_SIZE];
            len = MAX_TARGET_INPUT_SIZE as GuestReg;
        }
        let truncated = original_len != buf.len();

        let reset_started_at = Instant::now();
        self.reset(buf, len).unwrap();
        if let Some(scan_profile) = scan_profile {
            scan_profile.record_input_reset(reset_started_at.elapsed());
        }

        if let Some(scan_profile) = scan_profile {
            return self.run_with_breakdown(scan_profile, buf.len(), truncated);
        }
        unsafe { self.qemu.run() };

        //println!("HARNESS ENDS");

        ExitKind::Ok
    }
}
