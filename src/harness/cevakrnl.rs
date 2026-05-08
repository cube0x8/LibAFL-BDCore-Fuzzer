use crate::{bitdefender::BDEngine, scan_profile::ScanProfile};

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

use super::CevaTarget;

pub struct CevaEmuHarness<'a> {
    qemu: &'a Qemu,
    pub pc: GuestAddr,
    pub stack_ptr: GuestAddr,
    pub rcx: GuestAddr,
    pub rdx: GuestAddr,
    pub r8: GuestAddr,
    pub r9: GuestAddr,
    pub rdi: GuestAddr,
    pub rsi: GuestAddr,
    pub rbx: GuestAddr,
    pub rbp: GuestAddr,
    pub r12: GuestAddr,
    pub r13: GuestAddr,
    pub r14: GuestAddr,
    pub r15: GuestAddr,
    pub ret_addr: GuestAddr,
    pub exit_point: GuestAddr,
    pub entry_point: GuestAddr,
    pub bd_engine: BDEngine,
    entry_point_spec: String,
    target: Option<Box<dyn CevaTarget>>,
    max_target_input_size: usize,
}

impl<'a> CevaEmuHarness<'a> {
    pub fn new(
        qemu: &'a Qemu,
        entry_point_spec: String,
        target: Box<dyn CevaTarget>,
        max_target_input_size: usize,
    ) -> Result<CevaEmuHarness<'a>, Error> {
        let mut elf_buffer = Vec::new();
        let elf =
            libafl_qemu::elf::EasyElf::from_file(qemu.binary_path(), &mut elf_buffer).unwrap();

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
            r9: 0,
            rdi: 0,
            rsi: 0,
            rbx: 0,
            rbp: 0,
            r12: 0,
            r13: 0,
            r14: 0,
            r15: 0,
            ret_addr: 0,
            exit_point: 0,
            entry_point: 0,
            bd_engine,
            entry_point_spec,
            target: Some(target),
            max_target_input_size,
        })
    }

    pub fn qemu(&self) -> &Qemu {
        self.qemu
    }

    pub fn snapshot_excludes(&self) -> Vec<Range<u64>> {
        vec![]
    }

    pub fn init(
        &mut self,
        modules_to_instrument: Option<Vec<String>>,
        max_bp_hit_count: Option<u64>,
    ) -> Result<(), Error> {
        self.bd_engine.core_initialization(self.qemu);
        self.bd_engine.instrument_modules(modules_to_instrument);

        thread::sleep(Duration::from_secs(5));

        self.entry_point = self.bd_engine.resolve_entry_point(&self.entry_point_spec)?;
        println!(
            "Resolved {} entry point at {:#x}",
            self.target.as_ref().unwrap().name(),
            self.entry_point
        );

        self.qemu.set_breakpoint(self.entry_point);
        unsafe {
            let _ = self.qemu.run();
        };

        let entry_point_return_address: GuestAddr =
            self.qemu.read_return_address().unwrap().try_into().unwrap();
        println!("Return address = {entry_point_return_address:#x}");

        self.exit_point = entry_point_return_address;

        let mut target = self.target.take().unwrap();
        target.initialize(self, max_bp_hit_count)?;
        self.target = Some(target);

        self.qemu.remove_breakpoint(self.entry_point);
        self.qemu.set_breakpoint(self.exit_point);

        self.pc = self.qemu.read_reg(Regs::Pc).unwrap().try_into().unwrap();
        println!("Snapshot at {:#x}", self.pc);
        self.stack_ptr = self.qemu.read_reg(Regs::Sp).unwrap().try_into().unwrap();
        self.rcx = self.qemu.read_reg(Regs::Rcx).unwrap().try_into().unwrap();
        self.rdx = self.qemu.read_reg(Regs::Rdx).unwrap().try_into().unwrap();
        self.r8 = self.qemu.read_reg(Regs::R8).unwrap().try_into().unwrap();
        self.r9 = self.qemu.read_reg(Regs::R9).unwrap().try_into().unwrap();
        self.rbp = self.qemu.read_reg(Regs::Rbp).unwrap().try_into().unwrap();
        self.rdi = self.qemu.read_reg(Regs::Rdi).unwrap().try_into().unwrap();
        self.rsi = self.qemu.read_reg(Regs::Rsi).unwrap().try_into().unwrap();
        self.rbx = self.qemu.read_reg(Regs::Rbx).unwrap().try_into().unwrap();
        self.r12 = self.qemu.read_reg(Regs::R12).unwrap().try_into().unwrap();
        self.r13 = self.qemu.read_reg(Regs::R13).unwrap().try_into().unwrap();
        self.r14 = self.qemu.read_reg(Regs::R14).unwrap().try_into().unwrap();
        self.r15 = self.qemu.read_reg(Regs::R15).unwrap().try_into().unwrap();
        self.ret_addr = entry_point_return_address;

        Ok(())
    }

    fn reset(&self) -> Result<(), Error> {
        // here we reset only abi registers
        self.qemu
            .write_reg(Regs::Pc, GuestReg::try_from(self.pc).unwrap())
            .map_err(|e| Error::unknown(format!("Failed to restore PC: {e:?}")))?;
        self.qemu
            .write_reg(Regs::Sp, GuestReg::try_from(self.stack_ptr).unwrap())
            .map_err(|e| Error::unknown(format!("Failed to restore SP: {e:?}")))?;
        self.qemu
            .write_reg(Regs::Rcx, GuestReg::try_from(self.rcx).unwrap())
            .map_err(|e| Error::unknown(format!("Failed to restore RCX: {e:?}")))?;
        self.qemu
            .write_reg(Regs::Rdx, GuestReg::try_from(self.rdx).unwrap())
            .map_err(|e| Error::unknown(format!("Failed to restore RDX: {e:?}")))?;
        self.qemu
            .write_reg(Regs::R8, GuestReg::try_from(self.r8).unwrap())
            .map_err(|e| Error::unknown(format!("Failed to restore R8: {e:?}")))?;
        self.qemu
            .write_reg(Regs::R9, GuestReg::try_from(self.r9).unwrap())
            .map_err(|e| Error::unknown(format!("Failed to restore R9: {e:?}")))?;
        self.qemu
            .write_reg(Regs::Rbp, GuestReg::try_from(self.rbp).unwrap())
            .map_err(|e| Error::unknown(format!("Failed to restore RBP: {e:?}")))?;
        self.qemu
            .write_reg(Regs::R12, GuestReg::try_from(self.r12).unwrap())
            .map_err(|e| Error::unknown(format!("Failed to restore R12: {e:?}")))?;
        self.qemu
            .write_reg(Regs::R13, GuestReg::try_from(self.r13).unwrap())
            .map_err(|e| Error::unknown(format!("Failed to restore R13: {e:?}")))?;
        self.qemu
            .write_reg(Regs::R14, GuestReg::try_from(self.r14).unwrap())
            .map_err(|e| Error::unknown(format!("Failed to restore R14: {e:?}")))?;
        self.qemu
            .write_reg(Regs::R15, GuestReg::try_from(self.r15).unwrap())
            .map_err(|e| Error::unknown(format!("Failed to restore R15: {e:?}")))?;

        // reset additional registers/memory based on the target
        self.target.as_ref().unwrap().reset(self)?;

        Ok(())
    }

    fn run_until_exit(&self) -> Result<(), Error> {
        loop {
            unsafe {
                let _ = self.qemu.run();
            };

            let pc: GuestAddr = self.qemu.read_reg(Regs::Pc).unwrap().try_into().unwrap();
            if pc == self.exit_point {
                return Ok(());
            }

            if self.target.as_ref().unwrap().handle_breakpoint(self)? {
                continue;
            }

            log::debug!(
                "CevaEmu stopped at unexpected breakpoint pc={pc:#x} expected_exit={:#x}",
                self.exit_point,
            );
            return Ok(());
        }
    }

    pub fn run(&self, input: &BytesInput, scan_profile: Option<&ScanProfile>) -> ExitKind {
        let target = input.target_bytes();
        let mut buf = target.as_slice();

        let original_len = buf.len();
        let mut len = buf.len() as GuestReg;
        if len > self.max_target_input_size as GuestReg {
            buf = &buf[0..self.max_target_input_size];
            len = self.max_target_input_size as GuestReg;
        }
        let truncated = original_len != buf.len();

        let reset_started_at = Instant::now();
        self.reset().unwrap();
        self.target
            .as_ref()
            .unwrap()
            .prepare_input(self.qemu, buf, len)
            .unwrap();

        if let Some(scan_profile) = scan_profile {
            scan_profile.record_input_reset(reset_started_at.elapsed());

            log::debug!(
                "CevaEmu pre-run regs: pc={:#x} sp={:#x} rcx={:#x} rdx={:#x} r8={:#x} ret={:#x} exit={:#x}",
                self.qemu.read_reg(Regs::Pc).unwrap(),
                self.qemu.read_reg(Regs::Sp).unwrap(),
                self.qemu.read_reg(Regs::Rcx).unwrap(),
                self.qemu.read_reg(Regs::Rdx).unwrap(),
                self.qemu.read_reg(Regs::R8).unwrap(),
                self.ret_addr,
                self.exit_point,
            );
            let guest_exec_started_at = Instant::now();
            self.run_until_exit().unwrap();
            let post_pc: GuestAddr = self.qemu.read_reg(Regs::Pc).unwrap().try_into().unwrap();
            let post_sp: GuestAddr = self.qemu.read_reg(Regs::Sp).unwrap().try_into().unwrap();
            log::debug!(
                "CevaEmu post-run regs: pc={post_pc:#x} sp={post_sp:#x} expected_exit={:#x} matched_exit={}",
                self.exit_point,
                post_pc == self.exit_point,
            );
            scan_profile.record_guest_exec(guest_exec_started_at.elapsed(), buf.len(), truncated);
            return ExitKind::Ok;
        }

        log::debug!(
            "CevaEmu pre-run regs: pc={:#x} sp={:#x} rcx={:#x} rdx={:#x} r8={:#x} ret={:#x} exit={:#x}",
            self.qemu.read_reg(Regs::Pc).unwrap(),
            self.qemu.read_reg(Regs::Sp).unwrap(),
            self.qemu.read_reg(Regs::Rcx).unwrap(),
            self.qemu.read_reg(Regs::Rdx).unwrap(),
            self.qemu.read_reg(Regs::R8).unwrap(),
            self.ret_addr,
            self.exit_point,
        );
        self.run_until_exit().unwrap();
        let post_pc: GuestAddr = self.qemu.read_reg(Regs::Pc).unwrap().try_into().unwrap();
        let post_sp: GuestAddr = self.qemu.read_reg(Regs::Sp).unwrap().try_into().unwrap();
        log::debug!(
            "CevaEmu post-run regs: pc={post_pc:#x} sp={post_sp:#x} expected_exit={:#x} matched_exit={}",
            self.exit_point,
            post_pc == self.exit_point,
        );
        ExitKind::Ok
    }
}
