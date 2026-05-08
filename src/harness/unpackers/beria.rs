use libafl::Error;
use libafl_qemu::{GuestAddr, GuestReg, Qemu, Regs};

use crate::harness::{CevaEmuHarness, CevaTarget};

const DEBUG_INPUT_BYTES_LEN: usize = 32;
const BERIA_AOEP_ANCHOR_OFF: usize = 0x181248;
const BERIA_PATCH_ANCHOR_OFF: usize = 0x00;
const BERIA_PATCH_V7_OFF: usize = 0x04;
const BERIA_PATCH_V7_LEN: usize = 0x1C;
const BERIA_PATCH_V12_OFF: usize = BERIA_PATCH_V7_OFF + BERIA_PATCH_V7_LEN;
const BERIA_PATCH_V8_OFF: usize = BERIA_PATCH_V12_OFF + 4;
const BERIA_PATCH_V8_LEN: usize = 0x110;
const BERIA_PATCH_INPUT_SIZE: usize = BERIA_PATCH_V8_OFF + BERIA_PATCH_V8_LEN;

/*
fn format_bytes(bytes: &[u8]) -> String {
    bytes
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect::<Vec<_>>()
        .join(" ")
}
*/

fn restore_nonvolatile_regs(_harness: &CevaEmuHarness<'_>) -> Result<(), Error> {
    Ok(())
}

#[derive(Default)]
pub struct BeriaVmTarget;

impl CevaTarget for BeriaVmTarget {
    fn name(&self) -> &'static str {
        "BeriaVMParser"
    }

    fn prepare_input(&self, qemu: &Qemu, input: &[u8], input_len: GuestReg) -> Result<(), Error> {
        let exec_ctx: GuestAddr = qemu.read_reg(Regs::Rcx).unwrap().try_into().unwrap();

        let mut ptr_buf = [0u8; 8];
        let mut len_buf = [0u8; 4];

        qemu.read_mem(exec_ctx + 0x18, &mut ptr_buf).map_err(|e| {
            Error::unknown(format!(
                "Failed to read Beria exec_ctx->work_buf at {:#x}: {e:?}",
                exec_ctx + 0x18
            ))
        })?;
        qemu.read_mem(exec_ctx + 0x20, &mut len_buf).map_err(|e| {
            Error::unknown(format!(
                "Failed to read Beria exec_ctx->work_size at {:#x}: {e:?}",
                exec_ctx + 0x20
            ))
        })?;

        let work_buf: GuestAddr = u64::from_le_bytes(ptr_buf).try_into().unwrap();
        let work_size = u32::from_le_bytes(len_buf) as usize;
        let final_input_len = BERIA_PATCH_INPUT_SIZE.min(input_len as usize);

        let mut unpack_state_ptr_buf = [0u8; 8];
        qemu.read_mem(exec_ctx + 0x10, &mut unpack_state_ptr_buf)
            .map_err(|e| {
                Error::unknown(format!(
                    "Failed to read Beria exec_ctx->unpack_state at {:#x}: {e:?}",
                    exec_ctx + 0x10
                ))
            })?;
        let unpack_state: GuestAddr = u64::from_le_bytes(unpack_state_ptr_buf).try_into().unwrap();

        let input_buf = &input[..final_input_len];

        let mut before_write = vec![0u8; DEBUG_INPUT_BYTES_LEN.min(work_size)];
        let _ = qemu.read_mem(work_buf, &mut before_write);

        let read_u32 = |qemu: &Qemu, addr: GuestAddr, label: &str| -> Result<u32, Error> {
            let mut tmp = [0u8; 4];
            qemu.read_mem(addr, &mut tmp).map_err(|e| {
                Error::unknown(format!("Failed to read {label} at {addr:#x}: {e:?}"))
            })?;
            Ok(u32::from_le_bytes(tmp))
        };

        let write_u32 =
            |qemu: &Qemu, addr: GuestAddr, value: u32, label: &str| -> Result<(), Error> {
                qemu.write_mem(addr, &value.to_le_bytes()).map_err(|e| {
                    Error::unknown(format!("Failed to write {label} at {addr:#x}: {e:?}"))
                })
            };

        let image_base = read_u32(qemu, unpack_state + 0x74, "unpack_state->image_base")?;

        if input_buf.len() < BERIA_PATCH_INPUT_SIZE {
            return Err(Error::unknown(format!(
                "Beria compact input too small: got 0x{:x}, expected at least 0x{:x}",
                input_buf.len(),
                BERIA_PATCH_INPUT_SIZE
            )));
        }

        let anchor_dword = u32::from_le_bytes(
            input_buf[BERIA_PATCH_ANCHOR_OFF..BERIA_PATCH_ANCHOR_OFF + 4]
                .try_into()
                .unwrap(),
        );
        let v7 = anchor_dword.wrapping_sub(image_base) as usize;

        let v7_window = &input_buf[BERIA_PATCH_V7_OFF..BERIA_PATCH_V7_OFF + BERIA_PATCH_V7_LEN];
        let v8_va = u32::from_le_bytes(v7_window[0x00..0x04].try_into().unwrap());
        let v12_va = u32::from_le_bytes(v7_window[0x04..0x08].try_into().unwrap());
        let v65 = u32::from_le_bytes(v7_window[0x0c..0x10].try_into().unwrap());

        let v8 = v8_va.wrapping_sub(image_base) as usize;
        let v12 = v12_va.wrapping_sub(v65) as usize;

        if v7 + BERIA_PATCH_V7_LEN > work_size
            || v8 + BERIA_PATCH_V8_LEN > work_size
            || v12 + 4 > work_size
            || BERIA_AOEP_ANCHOR_OFF + 4 > work_size
        {
            return Ok(());
        }

        write_u32(
            qemu,
            work_buf + BERIA_AOEP_ANCHOR_OFF as GuestAddr,
            anchor_dword,
            "work_buf[anchor]",
        )?;
        qemu.write_mem(work_buf + v7 as GuestAddr, v7_window)
            .map_err(|e| {
                Error::unknown(format!(
                    "Failed to write Beria v7 window at {:#x}: {e:?}",
                    work_buf + v7 as GuestAddr
                ))
            })?;
        write_u32(
            qemu,
            work_buf + v12 as GuestAddr,
            u32::from_le_bytes(
                input_buf[BERIA_PATCH_V12_OFF..BERIA_PATCH_V12_OFF + 4]
                    .try_into()
                    .unwrap(),
            ),
            "work_buf[v12]",
        )?;
        qemu.write_mem(
            work_buf + v8 as GuestAddr,
            &input_buf[BERIA_PATCH_V8_OFF..BERIA_PATCH_V8_OFF + BERIA_PATCH_V8_LEN],
        )
        .map_err(|e| {
            Error::unknown(format!(
                "Failed to write Beria v8 window at {:#x}: {e:?}",
                work_buf + v8 as GuestAddr
            ))
        })?;

        let mut after_write = vec![0u8; DEBUG_INPUT_BYTES_LEN.min(work_size)];
        let _ = qemu.read_mem(work_buf, &mut after_write);

        Ok(())
    }

    fn reset(&self, harness: &CevaEmuHarness<'_>) -> Result<(), Error> {
        restore_nonvolatile_regs(harness)
    }
}
