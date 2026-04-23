use libafl_qemu::{ArchExtras, GuestAddr, GuestReg, Qemu, Regs};
use rangemap::RangeMap;
use std::{fmt, ops::Range, str::FromStr};

pub const DUMMY_PATH: &str = "./dummy/input_file";

#[derive(Clone, Debug)]
pub struct BDModule {
    pub name: String,
    pub start_addr: u64,
    pub size: u64,
}

pub struct BDEngine {
    pub modules: Vec<BDModule>,
    pub modules_to_instrument: Option<RangeMap<u64, (u16, String)>>,
    pub virtual_protect_ptr: GuestAddr,
    pub nt_virtual_protect_ptr: GuestAddr,
    pub initialize_core_ptr: GuestAddr,
    pub module_instrumentation_callback_ptr: GuestAddr,
}

impl fmt::Display for BDModule {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(
            f,
            "{}: {:X} - {:X}",
            self.name,
            self.start_addr,
            self.start_addr + self.size
        )
    }
}

impl BDEngine {
    pub fn new(
        virtual_protect_ptr: GuestAddr,
        nt_virtual_protect: GuestAddr,
        initialize_core_ptr: GuestAddr,
        module_instrumentation_callback_ptr: GuestAddr,
    ) -> Self {
        BDEngine {
            modules: Vec::new(),
            modules_to_instrument: Some(RangeMap::new()),
            virtual_protect_ptr: virtual_protect_ptr,
            nt_virtual_protect_ptr: nt_virtual_protect,
            initialize_core_ptr: initialize_core_ptr,
            module_instrumentation_callback_ptr: module_instrumentation_callback_ptr,
        }
    }

    fn add_module(&mut self, name: String, start_addr: u64, size: u64) {
        //log::debug!("Adding module: {} - {:X} - {:X}", name, start_addr, start_addr + size);
        self.modules.push(BDModule {
            name,
            start_addr,
            size,
        });
    }

    pub fn get_module_by_addr(&self, addr: u64) -> Option<&BDModule> {
        for module in &self.modules {
            if addr >= module.start_addr && addr < module.start_addr + module.size {
                return Some(module);
            }
        }
        None
    }

    pub fn core_initialization(&mut self, qemu: &Qemu) {
        // Set a bp on core initialization function and its return address
        // so we know when initialization start and when it ends. When it ends
        // we know we saved all the modules
        qemu.set_breakpoint(self.initialize_core_ptr);
        //emu.set_breakpoint(main_ptr);

        unsafe { qemu.run() };
        //println!("Core initializing started");
        log::debug!("Core initializing started");
        let initialize_core_ret_addr: GuestAddr =
            qemu.read_return_address().unwrap().try_into().unwrap();
        log::debug!(
            "Core initializing return address: {:X}",
            initialize_core_ret_addr
        );
        qemu.remove_breakpoint(self.initialize_core_ptr);
        //emu.remove_breakpoint(main_ptr);
        qemu.set_breakpoint(initialize_core_ret_addr);

        // This loops over VirtualProtect and ModuleInstrumentationCallback2, and we store all modules
        // names/base addresses/sizes

        loop {
            qemu.set_breakpoint(self.virtual_protect_ptr);
            qemu.set_breakpoint(self.nt_virtual_protect_ptr);
            unsafe { qemu.run() };

            // Check if the core initialization hash finished
            let pc: GuestAddr = qemu.read_reg(Regs::Pc).unwrap().try_into().unwrap();
            if pc == initialize_core_ret_addr {
                log::debug!("Core initializing finished");
                break;
            }

            qemu.remove_breakpoint(self.virtual_protect_ptr);
            qemu.remove_breakpoint(self.nt_virtual_protect_ptr);
            qemu.set_breakpoint(self.module_instrumentation_callback_ptr);
            unsafe { qemu.run() };

            // I'm not very sure if there are VirtualProtect which are not on modules
            // during initialization, but just in case...
            let pc: GuestAddr = qemu.read_reg(Regs::Pc).unwrap().try_into().unwrap();
            if pc == initialize_core_ret_addr {
                log::debug!("Core initializing finished");
                break;
            }

            // Here we are on ModuleInstrumentationCallback2 prologue, so we store
            // all modules information
            let module_name_ptr: GuestAddr = qemu.read_reg(Regs::Rdi).unwrap().try_into().unwrap();
            let module_name_len: GuestReg = qemu.read_reg(Regs::Rsi).unwrap();
            let module_base_addr: GuestReg = qemu.read_reg(Regs::Rdx).unwrap();
            let module_size: GuestReg = qemu.read_reg(Regs::Rcx).unwrap();

            let mut module_name_buf: Vec<u8> = vec![0; module_name_len as usize];
            unsafe { qemu.read_mem(module_name_ptr, &mut module_name_buf) };

            let module_name_str = match std::str::from_utf8(&module_name_buf) {
                Ok(s) => s,
                Err(e) => {
                    eprintln!("Error converting module_name_buf to UTF-8: {}", e);
                    return;
                }
            };

            self.add_module(String::from(module_name_str), module_base_addr, module_size);

            qemu.remove_breakpoint(self.module_instrumentation_callback_ptr);
        }

        qemu.remove_breakpoint(self.virtual_protect_ptr);
        qemu.remove_breakpoint(self.nt_virtual_protect_ptr);
        qemu.remove_breakpoint(self.module_instrumentation_callback_ptr);
        qemu.remove_breakpoint(initialize_core_ret_addr);
    }

    fn check_modules(&self, selected_modules_to_instrument: Vec<String>) -> Result<(), String> {
        for module_name in &selected_modules_to_instrument {
            log::debug!("Checking module: {}", module_name);
            // Check if any BDModule has the same name
            if !self
                .modules
                .iter()
                .any(|module| module.name == *module_name)
            {
                return Err(format!(
                    "Module '{}' not found in bd_modules_list. These are the available modules: {:?}",
                    module_name,
                    self.modules
                ));
            }
            log::info!("Module {} found", module_name);
        }
        Ok(())
    }

    pub fn instrument_modules(&mut self, selected_modules_to_instrument: Option<Vec<String>>) {
        match selected_modules_to_instrument {
            // check if there are wrong typed modules
            Some(modules) => {
                match self.check_modules(modules.clone()) {
                    Ok(()) => {
                        println!("All modules exist! Proceeding...");
                    }
                    Err(err) => {
                        eprintln!("Error: {}", err);
                        std::process::abort();
                    }
                }

                let mut mod_id = 0;
                for bd_module in self.modules.clone().iter() {
                    if modules.contains(&String::from_str(bd_module.name.as_str()).unwrap()) {
                        let end_addr = bd_module.start_addr + bd_module.size;
                        if let Some(ref mut map) = self.modules_to_instrument {
                            map.insert(
                                bd_module.start_addr..end_addr,
                                (mod_id, bd_module.name.clone()),
                            );
                        }
                        mod_id += 1;

                        println!("Module {} added to range", bd_module);
                    }
                }
            }
            None => self.modules_to_instrument = None,
        }
    }

    pub fn coverage_filter(&self) -> Option<Vec<Range<GuestAddr>>> {
        if let Some(ref range_map) = self.modules_to_instrument {
            #[cfg_attr(target_pointer_width = "64", allow(clippy::useless_conversion))]
            let rules = range_map
                .iter()
                .map(|(range, _)| Range {
                    start: range.start.try_into().unwrap(),
                    end: range.end.try_into().unwrap(),
                })
                .collect::<Vec<Range<GuestAddr>>>();
            Some(rules)
        } else {
            None
        }
    }
}
