use libafl::Error;
use libafl_qemu::{GuestAddr, GuestReg, Qemu, Regs};
use rand::Rng;

use crate::harness::{CevaEmuHarness, CevaTarget};

#[derive(Default)]
pub struct DecodeExecuteColdPath;

const DEBUG_CODE_BYTES_LEN: usize = 16;
const DEBUG_INPUT_BYTES_LEN: usize = 32;

fn format_bytes(bytes: &[u8]) -> String {
    bytes
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect::<Vec<_>>()
        .join(" ")
}

impl CevaTarget for DecodeExecuteColdPath {
    fn name(&self) -> &'static str {
        "DecodeExecuteColdPath"
    }

    fn initialize(
        &mut self,
        harness: &mut CevaEmuHarness<'_>,
        max_bp_hit_count: Option<u64>,
    ) -> Result<(), Error> {
        let entry_point = harness.entry_point;
        let exit_point = harness.exit_point;

        harness.qemu().remove_breakpoint(entry_point);

        let max_bp_hit_count = max_bp_hit_count.ok_or_else(|| {
            Error::illegal_argument("DecodeExecuteColdPath requires a max breakpoint hit count")
        })?;
        let target_bp_hit_count = rand::thread_rng().gen_range(1..max_bp_hit_count);
        let mut bp_hit_count = 1_u64;

        let initial_pc: GuestAddr = harness
            .qemu()
            .read_reg(Regs::Pc)
            .unwrap()
            .try_into()
            .unwrap();
        let initial_sp: GuestAddr = harness
            .qemu()
            .read_reg(Regs::Sp)
            .unwrap()
            .try_into()
            .unwrap();
        let initial_rbx: GuestAddr = harness
            .qemu()
            .read_reg(Regs::Rbx)
            .unwrap()
            .try_into()
            .unwrap();
        let initial_rdi: GuestAddr = harness
            .qemu()
            .read_reg(Regs::Rdi)
            .unwrap()
            .try_into()
            .unwrap();
        let initial_rsi: GuestAddr = harness
            .qemu()
            .read_reg(Regs::Rsi)
            .unwrap()
            .try_into()
            .unwrap();
        let mut initial_bytes = [0_u8; DEBUG_CODE_BYTES_LEN];
        let _ = harness.qemu().read_mem(entry_point, &mut initial_bytes);

        log::debug!(
            "DecodeExecuteColdPath init: entry={entry_point:#x} exit={exit_point:#x} initial_pc={initial_pc:#x} sp={initial_sp:#x} rbx={initial_rbx:#x} rdi={initial_rdi:#x} rsi={initial_rsi:#x}"
        );
        log::debug!(
            "DecodeExecuteColdPath init: generated target_bp_hit_count={} (range 1..{}) entry_bytes=[{}]",
            target_bp_hit_count,
            max_bp_hit_count,
            format_bytes(&initial_bytes),
        );

        while bp_hit_count < target_bp_hit_count {
            log::debug!(
                "DecodeExecuteColdPath init loop: current_hit={} target_hit={} stepping to exit_point={:#x}",
                bp_hit_count,
                target_bp_hit_count,
                exit_point,
            );
            harness.qemu().set_breakpoint(exit_point);
            unsafe {
                let _ = harness.qemu().run();
            };
            harness.qemu().remove_breakpoint(exit_point);

            let exit_pc: GuestAddr = harness
                .qemu()
                .read_reg(Regs::Pc)
                .unwrap()
                .try_into()
                .unwrap();
            log::debug!(
                "DecodeExecuteColdPath init loop: reached exit_point breakpoint at pc={exit_pc:#x}, rearming entry_point={entry_point:#x}"
            );

            harness.qemu().set_breakpoint(entry_point);
            unsafe {
                let _ = harness.qemu().run();
            };

            harness.qemu().remove_breakpoint(entry_point);

            let loop_pc: GuestAddr = harness
                .qemu()
                .read_reg(Regs::Pc)
                .unwrap()
                .try_into()
                .unwrap();
            let loop_sp: GuestAddr = harness
                .qemu()
                .read_reg(Regs::Sp)
                .unwrap()
                .try_into()
                .unwrap();
            let loop_rbx: GuestAddr = harness
                .qemu()
                .read_reg(Regs::Rbx)
                .unwrap()
                .try_into()
                .unwrap();
            let loop_rdi: GuestAddr = harness
                .qemu()
                .read_reg(Regs::Rdi)
                .unwrap()
                .try_into()
                .unwrap();
            let loop_rsi: GuestAddr = harness
                .qemu()
                .read_reg(Regs::Rsi)
                .unwrap()
                .try_into()
                .unwrap();
            let mut loop_bytes = [0_u8; DEBUG_CODE_BYTES_LEN];
            let _ = harness.qemu().read_mem(entry_point, &mut loop_bytes);

            bp_hit_count += 1;

            log::debug!(
                "DecodeExecuteColdPath init loop: incremented hit count to {} and broke again at pc={loop_pc:#x} sp={loop_sp:#x} rbx={loop_rbx:#x} rdi={loop_rdi:#x} rsi={loop_rsi:#x} entry_bytes=[{}]",
                bp_hit_count,
                format_bytes(&loop_bytes),
            );
        }

        let current_pc: GuestAddr = harness
            .qemu()
            .read_reg(Regs::Pc)
            .unwrap()
            .try_into()
            .unwrap();
        let after_fetch_span_inited = current_pc + 0x4c;
        log::debug!(
            "DecodeExecuteColdPath init: loop finished at hit_count={} pc={current_pc:#x}; setting after_fetch_span_inited breakpoint at {after_fetch_span_inited:#x}",
            bp_hit_count,
        );
        harness.qemu().set_breakpoint(after_fetch_span_inited);

        unsafe {
            let _ = harness.qemu().run();
        };

        let final_pc: GuestAddr = harness
            .qemu()
            .read_reg(Regs::Pc)
            .unwrap()
            .try_into()
            .unwrap();
        let final_sp: GuestAddr = harness
            .qemu()
            .read_reg(Regs::Sp)
            .unwrap()
            .try_into()
            .unwrap();
        let final_rbx: GuestAddr = harness
            .qemu()
            .read_reg(Regs::Rbx)
            .unwrap()
            .try_into()
            .unwrap();
        let final_rdi: GuestAddr = harness
            .qemu()
            .read_reg(Regs::Rdi)
            .unwrap()
            .try_into()
            .unwrap();
        let final_rsi: GuestAddr = harness
            .qemu()
            .read_reg(Regs::Rsi)
            .unwrap()
            .try_into()
            .unwrap();
        let mut final_bytes = [0_u8; DEBUG_CODE_BYTES_LEN];
        let _ = harness.qemu().read_mem(final_pc, &mut final_bytes);
        log::debug!(
            "DecodeExecuteColdPath init: hit after_fetch_span_inited at pc={final_pc:#x} sp={final_sp:#x} rbx={final_rbx:#x} rdi={final_rdi:#x} rsi={final_rsi:#x} code_bytes=[{}]",
            format_bytes(&final_bytes),
        );

        harness.qemu().remove_breakpoint(after_fetch_span_inited);

        Ok(())
    }

    fn prepare_input(&self, qemu: &Qemu, input: &[u8], input_len: GuestReg) -> Result<(), Error> {
        let emulator_obj: GuestAddr = qemu.read_reg(Regs::Rbx).unwrap().try_into().unwrap();

        // get the host_start pointer of the fetchSpan obj
        let mut host_start_addr = [0u8; 8];
        let _ = qemu.read_mem(emulator_obj + 0x1E8, &mut host_start_addr);
        let host_start: GuestAddr = u64::from_le_bytes(host_start_addr.try_into().unwrap())
            .try_into()
            .unwrap();

        // get the host_end pointer
        let mut host_end_addr = [0u8; 8];
        let _ = qemu.read_mem(emulator_obj + 0x1F0, &mut host_end_addr);
        let host_end: GuestAddr = u64::from_le_bytes(host_end_addr.try_into().unwrap())
            .try_into()
            .unwrap();

        let assembly_block_size: GuestAddr = host_end - host_start;

        let mut input_buf = input;
        let final_input_len: usize = assembly_block_size.min(input_len.try_into().unwrap());
        if input_len > assembly_block_size.try_into().unwrap() {
            input_buf = &input[0..final_input_len];
        }

        let mut before_write = vec![0_u8; final_input_len];
        let _ = qemu.read_mem(host_start, &mut before_write);
        log::debug!(
            "DecodeExecuteColdPath prepare_input: host_start={host_start:#x} host_end={host_end:#x} block_size={} input_len={} final_input_len={}",
            assembly_block_size,
            input.len(),
            final_input_len,
        );
        log::debug!(
            "DecodeExecuteColdPath prepare_input: input_before_write=[{}] guest_before_write=[{}]",
            format_bytes(&input_buf[..input_buf.len().min(DEBUG_INPUT_BYTES_LEN)]),
            format_bytes(&before_write[..before_write.len().min(DEBUG_INPUT_BYTES_LEN)]),
        );

        qemu.write_mem(host_start, input_buf).unwrap();

        let mut after_write = vec![0_u8; final_input_len];
        let _ = qemu.read_mem(host_start, &mut after_write);
        log::debug!(
            "DecodeExecuteColdPath prepare_input: guest_after_write=[{}]",
            format_bytes(&after_write[..after_write.len().min(DEBUG_INPUT_BYTES_LEN)]),
        );
        Ok(())
    }

    fn reset(&self, harness: &CevaEmuHarness<'_>) -> Result<(), Error> {
        let qemu = harness.qemu();

        qemu.write_reg(Regs::Rdi, GuestReg::try_from(harness.rdi).unwrap())
            .map_err(|e| Error::unknown(format!("Failed to restore RDI: {e:?}")))?;
        qemu.write_reg(Regs::Rsi, GuestReg::try_from(harness.rsi).unwrap())
            .map_err(|e| Error::unknown(format!("Failed to restore RSI: {e:?}")))?;
        qemu.write_reg(Regs::Rbx, GuestReg::try_from(harness.rbx).unwrap())
            .map_err(|e| Error::unknown(format!("Failed to restore RBX: {e:?}")))?;

        Ok(())
    }
}
