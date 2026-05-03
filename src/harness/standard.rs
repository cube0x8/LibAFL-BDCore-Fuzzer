use crate::{
    bitdefender::{BDEngine, DUMMY_PATH},
    scan_profile::ScanProfile,
};

use libafl::{
    executors::ExitKind,
    inputs::{BytesInput, HasTargetBytes},
    Error,
};
use libafl_bolts::AsSlice;
use libafl_qemu::{elf::EasyElf, ArchExtras, GuestAddr, GuestReg, MmapPerms, Qemu, Regs};
use std::{
    ops::Range,
    thread,
    time::{Duration, Instant},
};

use super::{FILE_PATH_SIZE, G_MMAP_FILE_SIZE};

const SCAN_FILE_CORE_SET_CALL_OFFSET: GuestAddr = 0x7c;
const SCAN_FILE_AFTER_CORE_SET_OFFSET: GuestAddr = 0x7e;

pub struct Harness<'a> {
    qemu: &'a Qemu,
    pub input_addr: GuestAddr,
    pub max_input_size: usize,
    pub max_target_input_size: usize,
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

impl<'a> Harness<'a> {
    pub fn new(
        qemu: &'a Qemu,
        max_input_size: usize,
        max_target_input_size: usize,
    ) -> Result<Harness<'a>, Error> {
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
            .map_private(0, max_input_size, MmapPerms::ReadWrite)
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

        let file_path = qemu.map_private(0, FILE_PATH_SIZE, MmapPerms::ReadWrite)?;
        println!("File path @ {file_path:#x}");

        let bd_engine = BDEngine::new(
            virtual_protect_ptr,
            nt_virtual_protect_ptr,
            initialize_core_ptr,
            module_instrumentation_callback_ptr,
        );

        let _ = qemu.write_mem(file_path, DUMMY_PATH.as_bytes());

        Ok(Harness {
            qemu,
            input_addr,
            max_input_size,
            max_target_input_size,
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
            input_addr..(input_addr + self.max_input_size as u64),
            file_path..(file_path + FILE_PATH_SIZE as u64),
            g_mmap_file_addr..(g_mmap_file_addr + G_MMAP_FILE_SIZE as u64),
        ]
    }

    fn current_pc(&self) -> GuestAddr {
        self.qemu.read_reg(Regs::Pc).unwrap().try_into().unwrap()
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
        unsafe {
            let _ = self.qemu.run();
        };

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
        unsafe {
            let _ = self.qemu.run();
        };

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
        unsafe {
            let _ = self.qemu.run();
        };

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
        self.bd_engine.core_initialization(self.qemu);
        self.bd_engine.instrument_modules(modules_to_instrument);

        thread::sleep(Duration::from_secs(5));

        self.qemu.set_breakpoint(self.scan_file_ptr);
        unsafe {
            let _ = self.qemu.run();
        };

        let stack_ptr: GuestAddr = self.qemu.read_reg(Regs::Sp).unwrap().try_into().unwrap();
        let rdi: GuestAddr = self.qemu.read_reg(Regs::Rdi).unwrap().try_into().unwrap();
        let scan_file_ret_addr: GuestAddr =
            self.qemu.read_return_address().unwrap().try_into().unwrap();
        println!("Return address = {scan_file_ret_addr:#x}");

        let pc: GuestAddr = self.qemu.read_reg(Regs::Pc).unwrap().try_into().unwrap();
        println!("Break at {pc:#x}");

        self.qemu.remove_breakpoint(self.scan_file_ptr);

        self.exit_points = match exit_points {
            Some(specs) => self.bd_engine.resolve_exit_points(&specs)?,
            None => vec![scan_file_ret_addr],
        };

        for exit_point in &self.exit_points {
            self.qemu.set_breakpoint(*exit_point);
        }

        self.pc = pc;
        self.stack_ptr = stack_ptr;
        self.ret_addr = scan_file_ret_addr;
        self.rdi = rdi;

        Ok(())
    }

    fn reset(&self, buf: &[u8], len: GuestReg) -> Result<(), Error> {
        let _ = self.qemu.write_mem(self.input_addr, buf);

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

        Ok(())
    }

    pub fn run(&self, input: &BytesInput, scan_profile: Option<&ScanProfile>) -> ExitKind {
        let target = input.target_bytes();
        let mut buf = target.as_slice();

        let original_len = buf.len();
        let mut len = buf.len() as GuestReg;
        let max_run_input_size = self.max_target_input_size.min(self.max_input_size);
        if len > max_run_input_size as GuestReg {
            buf = &buf[0..max_run_input_size];
            len = max_run_input_size as GuestReg;
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
        unsafe {
            let _ = self.qemu.run();
        };

        ExitKind::Ok
    }
}
