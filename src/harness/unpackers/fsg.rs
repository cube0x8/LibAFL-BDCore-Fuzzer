use std::cell::Cell;

use libafl::Error;
use libafl_qemu::{GuestAddr, GuestReg, Qemu, Regs};

use crate::harness::{CevaEmuHarness, CevaTarget};
use crate::inputs::fsg::parse_fsg_input;
use crate::utils::{read_guest_u32_labeled, read_guest_u64_labeled, write_guest_u32_labeled};

const FSG_IMAGE_PTR_OFFSET: GuestAddr = 0x18;
const FSG_IMAGE_SIZE_OFFSET: GuestAddr = 0x20;
const FSG_CALLBACK_CONFIG_PTR_OFFSET: GuestAddr = 0x38;
const FSG_CONFIG_START_OFFSET: GuestAddr = 0x08;
const FSG_CONFIG_BASE_OFFSET: GuestAddr = 0x0c;
const FSG_CONFIG_MODE_OFFSET: GuestAddr = 0x10;
const FSG_CALLBACK_OFFSET: GuestAddr = 0x6e0;
const FSG_OPERATION_THUNK_OFFSET: GuestAddr = 0x3288;

fn restore_nonvolatile_regs(harness: &CevaEmuHarness<'_>) -> Result<(), Error> {
    let qemu = harness.qemu();
    for (reg, value, name) in [
        (Regs::Rbx, harness.rbx, "RBX"),
        (Regs::Rbp, harness.rbp, "RBP"),
        (Regs::Rdi, harness.rdi, "RDI"),
        (Regs::Rsi, harness.rsi, "RSI"),
        (Regs::R12, harness.r12, "R12"),
        (Regs::R13, harness.r13, "R13"),
        (Regs::R14, harness.r14, "R14"),
        (Regs::R15, harness.r15, "R15"),
    ] {
        qemu.write_reg(reg, GuestReg::try_from(value).unwrap())
            .map_err(|e| Error::unknown(format!("Failed to restore FSG {name}: {e:?}")))?;
    }
    Ok(())
}

#[derive(Default)]
pub struct FsgPostdecodeTarget {
    image: Cell<GuestAddr>,
    image_size: Cell<usize>,
    config: Cell<GuestAddr>,
    operation_thunk: Cell<GuestAddr>,
}

impl CevaTarget for FsgPostdecodeTarget {
    fn name(&self) -> &'static str {
        "FSG post-decode callback"
    }

    fn initialize(
        &mut self,
        harness: &mut CevaEmuHarness<'_>,
        _max_bp_hit_count: Option<u64>,
    ) -> Result<(), Error> {
        let qemu = harness.qemu();
        let ctx: GuestAddr = qemu
            .read_reg(Regs::Rcx)
            .map_err(|e| Error::unknown(format!("Failed to read FSG context: {e:?}")))?
            .try_into()
            .unwrap();
        let callback: GuestAddr = qemu
            .read_reg(Regs::Rdx)
            .map_err(|e| Error::unknown(format!("Failed to read FSG callback: {e:?}")))?
            .try_into()
            .unwrap();
        let image = read_guest_u64_labeled(qemu, ctx + FSG_IMAGE_PTR_OFFSET, "FSG image pointer")?
            .try_into()
            .unwrap();
        let image_size =
            read_guest_u32_labeled(qemu, ctx + FSG_IMAGE_SIZE_OFFSET, "FSG image size")? as usize;
        let config = read_guest_u64_labeled(
            qemu,
            callback + FSG_CALLBACK_CONFIG_PTR_OFFSET,
            "FSG callback config pointer",
        )?
        .try_into()
        .unwrap();
        if image == 0 || image_size == 0 || config == 0 {
            return Err(Error::unknown(format!(
                "Invalid FSG callback state image={image:#x} size={image_size:#x} config={config:#x}"
            )));
        }

        self.image.set(image);
        self.image_size.set(image_size);
        self.config.set(config);
        let module_base = harness.entry_point - FSG_CALLBACK_OFFSET;
        let operation_thunk_pc = module_base + FSG_OPERATION_THUNK_OFFSET;
        self.operation_thunk.set(operation_thunk_pc);
        qemu.set_breakpoint(operation_thunk_pc);
        log::info!(
            "FSG post-decode init: image={image:#x}:{image_size:#x} config={config:#x} terminal_operation={operation_thunk_pc:#x} callback_return={:#x}",
            harness.exit_point,
        );
        Ok(())
    }

    fn prepare_input(&self, qemu: &Qemu, input: &[u8], input_len: GuestReg) -> Result<(), Error> {
        let input = &input[..(input_len as usize).min(input.len())];
        let Some(parsed) = parse_fsg_input(input) else {
            return Ok(());
        };
        if parsed.image.len() != self.image_size.get() {
            return Ok(());
        }

        qemu.write_mem(self.image.get(), parsed.image)
            .map_err(|e| Error::unknown(format!("Failed to inject FSG decoded image: {e:?}")))?;
        let config = self.config.get();
        write_guest_u32_labeled(
            qemu,
            config + FSG_CONFIG_START_OFFSET,
            parsed.start,
            "FSG start",
        )?;
        write_guest_u32_labeled(
            qemu,
            config + FSG_CONFIG_BASE_OFFSET,
            parsed.base,
            "FSG base",
        )?;
        write_guest_u32_labeled(
            qemu,
            config + FSG_CONFIG_MODE_OFFSET,
            parsed.mode,
            "FSG mode",
        )?;
        Ok(())
    }

    fn reset(&self, harness: &CevaEmuHarness<'_>) -> Result<(), Error> {
        restore_nonvolatile_regs(harness)
    }

    fn handle_breakpoint(&self, harness: &CevaEmuHarness<'_>) -> Result<bool, Error> {
        let pc: GuestAddr = harness
            .qemu()
            .read_reg(Regs::Pc)
            .map_err(|e| Error::unknown(format!("Failed to read FSG breakpoint PC: {e:?}")))?
            .try_into()
            .unwrap();

        // Stop after the parser and copyback, before operation 8 reallocates the
        // decoded image that predates the QASAN snapshot.
        if pc == self.operation_thunk.get() {
            return Ok(false);
        }

        Ok(false)
    }
}
