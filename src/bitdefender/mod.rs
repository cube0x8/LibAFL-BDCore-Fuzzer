use libafl::Error;
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

#[derive(Clone, Debug)]
pub struct BDModuleHit {
    pub name: String,
    pub start_addr: u64,
    pub size: u64,
    pub offset: u64,
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

impl fmt::Display for BDModuleHit {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(
            f,
            "{}:+{:#x} ({:#x}-{:#x})",
            self.name,
            self.offset,
            self.start_addr,
            self.start_addr + self.size
        )
    }
}

pub fn module_for_addr(modules: &[BDModule], addr: u64) -> Option<BDModuleHit> {
    modules
        .iter()
        .find(|module| addr >= module.start_addr && addr < module.start_addr + module.size)
        .map(|module| BDModuleHit {
            name: module.name.clone(),
            start_addr: module.start_addr,
            size: module.size,
            offset: addr - module.start_addr,
        })
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
            virtual_protect_ptr,
            nt_virtual_protect_ptr: nt_virtual_protect,
            initialize_core_ptr,
            module_instrumentation_callback_ptr,
        }
    }

    fn add_module(&mut self, name: String, start_addr: u64, size: u64) {
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

    pub fn module_for_addr(&self, addr: u64) -> Option<BDModuleHit> {
        module_for_addr(&self.modules, addr)
    }

    pub fn core_initialization(&mut self, qemu: &Qemu) {
        qemu.set_breakpoint(self.initialize_core_ptr);

        unsafe {
            let _ = qemu.run();
        };
        log::debug!("Core initializing started");
        let initialize_core_ret_addr: GuestAddr =
            qemu.read_return_address().unwrap().try_into().unwrap();
        log::debug!(
            "Core initializing return address: {:X}",
            initialize_core_ret_addr
        );
        qemu.remove_breakpoint(self.initialize_core_ptr);
        qemu.set_breakpoint(initialize_core_ret_addr);

        loop {
            qemu.set_breakpoint(self.virtual_protect_ptr);
            qemu.set_breakpoint(self.nt_virtual_protect_ptr);
            unsafe {
                let _ = qemu.run();
            };

            let pc: GuestAddr = qemu.read_reg(Regs::Pc).unwrap().try_into().unwrap();
            if pc == initialize_core_ret_addr {
                log::debug!("Core initializing finished");
                break;
            }

            qemu.remove_breakpoint(self.virtual_protect_ptr);
            qemu.remove_breakpoint(self.nt_virtual_protect_ptr);
            qemu.set_breakpoint(self.module_instrumentation_callback_ptr);
            unsafe {
                let _ = qemu.run();
            };

            let pc: GuestAddr = qemu.read_reg(Regs::Pc).unwrap().try_into().unwrap();
            if pc == initialize_core_ret_addr {
                log::debug!("Core initializing finished");
                break;
            }

            let module_name_ptr: GuestAddr = qemu.read_reg(Regs::Rdi).unwrap().try_into().unwrap();
            let module_name_len: GuestReg = qemu.read_reg(Regs::Rsi).unwrap();
            let module_base_addr: GuestReg = qemu.read_reg(Regs::Rdx).unwrap();
            let module_size: GuestReg = qemu.read_reg(Regs::Rcx).unwrap();

            let mut module_name_buf: Vec<u8> = vec![0; module_name_len as usize];
            let _ = qemu.read_mem(module_name_ptr, &mut module_name_buf);

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

    pub fn resolve_entry_point(&self, spec: &str) -> Result<GuestAddr, Error> {
        self.resolve_module_address(spec, "entry point")
    }

    pub fn resolve_exit_points(&self, specs: &[String]) -> Result<Vec<GuestAddr>, Error> {
        if specs.is_empty() {
            return Err(Error::unknown(
                "At least one --exit-point value is required when the option is provided",
            ));
        }

        let mut resolved = Vec::with_capacity(specs.len());
        for spec in specs {
            resolved.push(self.resolve_module_address(spec, "exit point")?);
        }
        Ok(resolved)
    }

    pub fn resolve_module_address(&self, spec: &str, kind: &str) -> Result<GuestAddr, Error> {
        let (module_name, offset_str) = spec.split_once(":+").ok_or_else(|| {
            Error::unknown(format!(
                "Invalid {kind} format '{spec}', expected module:+offset"
            ))
        })?;

        let module_name = module_name.trim();
        let offset_str = offset_str.trim();

        if module_name.is_empty() || offset_str.is_empty() {
            return Err(Error::unknown(format!(
                "Invalid {kind} format '{spec}', expected module:+offset"
            )));
        }

        let offset = if let Some(hex) = offset_str
            .strip_prefix("0x")
            .or_else(|| offset_str.strip_prefix("0X"))
        {
            GuestAddr::from_str_radix(hex, 16).map_err(|err| {
                Error::unknown(format!(
                    "Failed to parse hexadecimal offset '{offset_str}' for {kind} '{spec}': {err}"
                ))
            })?
        } else {
            offset_str.parse::<GuestAddr>().map_err(|err| {
                Error::unknown(format!(
                    "Failed to parse decimal offset '{offset_str}' for {kind} '{spec}': {err}"
                ))
            })?
        };

        let module = self
            .modules
            .iter()
            .find(|module| module.name == module_name)
            .ok_or_else(|| {
                Error::unknown(format!(
                    "{kind} module '{module_name}' not found. Available modules: {:?}",
                    self.modules
                ))
            })?;

        let offset = offset as u64;
        let addr = module.start_addr.checked_add(offset).ok_or_else(|| {
            Error::unknown(format!(
                "{kind} '{spec}' overflows module base {:#x} with offset {offset:#x}",
                module.start_addr
            ))
        })?;

        let addr = GuestAddr::try_from(addr).map_err(|_| {
            Error::unknown(format!(
                "Resolved {kind} '{spec}' address {addr:#x} does not fit GuestAddr"
            ))
        })?;

        println!("{} {spec} -> {addr:#x}", kind.to_ascii_uppercase());
        Ok(addr)
    }
}
