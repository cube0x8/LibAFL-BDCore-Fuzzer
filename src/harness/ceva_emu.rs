use crate::{
    bitdefender::{BDEngine},
    scan_profile::ScanProfile,
};

use libafl::{
    executors::ExitKind,
    inputs::{BytesInput, HasTargetBytes},
    Error,
};
use libafl_bolts::AsSlice;
use libafl_qemu::{ArchExtras, GuestAddr, GuestReg, Qemu, Regs};
use std::{
    ops::Range,
    thread,
    time::{Duration, Instant},
};

use super::{CevaTarget, MAX_TARGET_INPUT_SIZE};

pub struct CevaEmuHarness<'a> {
    qemu: &'a Qemu,
    pub pc: GuestAddr,
    pub stack_ptr: GuestAddr,
    pub rcx: GuestAddr,
    pub rdx: GuestAddr,
    pub r8: GuestAddr,
    pub ret_addr: GuestAddr,
    pub exit_point: GuestAddr,
    pub entry_point: GuestAddr,
    pub bd_engine: BDEngine,
    entry_point_spec: String,
    target: Box<dyn CevaTarget>,
}

impl<'a> CevaEmuHarness<'a> {
    pub fn new(
        qemu: &'a Qemu,
        entry_point_spec: String,
        target: Box<dyn CevaTarget>,
    ) -> Result<CevaEmuHarness<'a>, Error> {
        let mut elf_buffer = Vec::new();
        let elf = libafl_qemu::elf::EasyElf::from_file(qemu.binary_path(), &mut elf_buffer)
            .unwrap();

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
        println!("NtProtectVirtualMemory @ {nt_virtual_protect_ptr:#x}");

        let initialize_core_ptr = elf
            .resolve_symbol("InitializeCore", qemu.load_addr())
            .expect("Symbol InitializeCore not found");
        println!("InitializeCore @ {initialize_core_ptr:#x}");

        let bd_engine = BDEngine::new(
            virtual_protect_ptr,
            nt_virtual_protect_ptr,
            initialize_core_ptr,
            module_instrumentation_callback_ptr,
        );

        Ok(CevaEmuHarness {
            qemu,
            pc: 0,
            stack_ptr: 0,
            rcx: 0,
            rdx: 0,
            r8: 0,
            ret_addr: 0,
            exit_point: 0,
            entry_point: 0,
            bd_engine,
            entry_point_spec,
            target,
        })
    }

    pub fn snapshot_excludes(&self) -> Vec<Range<u64>> {
        vec![]
    }

    pub fn init(&mut self, modules_to_instrument: Option<Vec<String>>) -> Result<(), Error> {
        self.bd_engine.core_initialization(self.qemu);
        self.bd_engine.instrument_modules(modules_to_instrument);

        thread::sleep(Duration::from_secs(5));

        self.entry_point = self.bd_engine.resolve_entry_point(&self.entry_point_spec)?;
        println!(
            "Resolved {} entry point at {:#x}",
            self.target.name(),
            self.entry_point
        );

        self.qemu.set_breakpoint(self.entry_point);
        unsafe {
            let _ = self.qemu.run();
        };

        let stack_ptr: GuestAddr = self.qemu.read_reg(Regs::Sp).unwrap().try_into().unwrap();
        let entry_point_return_address: GuestAddr =
            self.qemu.read_return_address().unwrap().try_into().unwrap();
        println!("Return address = {entry_point_return_address:#x}");

        let pc: GuestAddr = self.qemu.read_reg(Regs::Pc).unwrap().try_into().unwrap();
        println!("Break at {pc:#x}");
        let rcx: GuestAddr = self.qemu.read_reg(Regs::Rcx).unwrap().try_into().unwrap();
        let rdx: GuestAddr = self.qemu.read_reg(Regs::Rdx).unwrap().try_into().unwrap();
        let r8: GuestAddr = self.qemu.read_reg(Regs::R8).unwrap().try_into().unwrap();

        self.qemu.remove_breakpoint(self.entry_point);
        self.exit_point = entry_point_return_address;
        self.qemu.set_breakpoint(self.exit_point);

        self.target
            .initialize(self.qemu, &self.bd_engine)?;

        self.pc = pc;
        self.stack_ptr = stack_ptr;
        self.rcx = rcx;
        self.rdx = rdx;
        self.r8 = r8;
        self.ret_addr = entry_point_return_address;

        Ok(())
    }

    fn reset(&self) -> Result<(), Error> {
        self.qemu.write_reg(Regs::Pc, GuestReg::try_from(self.pc).unwrap())
            .map_err(|e| Error::unknown(format!("Failed to restore PC: {e:?}")))?;
        self.qemu.write_reg(Regs::Sp, GuestReg::try_from(self.stack_ptr).unwrap())
            .map_err(|e| Error::unknown(format!("Failed to restore SP: {e:?}")))?;
        self.qemu.write_reg(Regs::Rcx, GuestReg::try_from(self.rcx).unwrap())
            .map_err(|e| Error::unknown(format!("Failed to restore RCX: {e:?}")))?;
        self.qemu.write_reg(Regs::Rdx, GuestReg::try_from(self.rdx).unwrap())
            .map_err(|e| Error::unknown(format!("Failed to restore RDX: {e:?}")))?;
        self.qemu.write_reg(Regs::R8, GuestReg::try_from(self.r8).unwrap())
            .map_err(|e| Error::unknown(format!("Failed to restore R8: {e:?}")))?;
        Ok(())
    }

    pub fn run(&self, input: &BytesInput, scan_profile: Option<&ScanProfile>) -> ExitKind {
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
        self.reset().unwrap();
        self.target
             .prepare_input(self.qemu, buf, len)
             .unwrap();

        if let Some(scan_profile) = scan_profile {
            scan_profile.record_input_reset(reset_started_at.elapsed());

            let guest_exec_started_at = Instant::now();
            unsafe {
                let _ = self.qemu.run();
            };
            scan_profile.record_guest_exec(guest_exec_started_at.elapsed(), buf.len(), truncated);
            return ExitKind::Ok;
        }

        unsafe {
            let _ = self.qemu.run();
        };
        ExitKind::Ok
    }
}
