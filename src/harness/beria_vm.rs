use libafl::Error;
use libafl_qemu::{GuestAddr, GuestReg, Qemu, Regs};

use super::{ceva_emu::CevaEmuHarness, ceva_target::CevaTarget};

const DEBUG_INPUT_BYTES_LEN: usize = 32;
const BERIA_AOEP_ANCHOR_OFF: usize = 0x181248;
const BERIA_PATCH_ANCHOR_OFF: usize = 0x00;
const BERIA_PATCH_V7_OFF: usize = 0x04;
const BERIA_PATCH_V7_LEN: usize = 0x1C;
const BERIA_PATCH_V12_OFF: usize = BERIA_PATCH_V7_OFF + BERIA_PATCH_V7_LEN;
const BERIA_PATCH_V8_OFF: usize = BERIA_PATCH_V12_OFF + 4;
const BERIA_PATCH_V8_LEN: usize = 0x110;
const BERIA_PATCH_INPUT_SIZE: usize = BERIA_PATCH_V8_OFF + BERIA_PATCH_V8_LEN;

fn format_bytes(bytes: &[u8]) -> String {
    bytes
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect::<Vec<_>>()
        .join(" ")
}

fn restore_nonvolatile_regs(harness: &CevaEmuHarness<'_>) -> Result<(), Error> {
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

        log::debug!(
            "BeriaVMParser prepare_input: exec_ctx={exec_ctx:#x} work_buf={work_buf:#x} work_size={work_size:#x} input_len={} final_input_len={}",
            input.len(),
            final_input_len,
        );
        log::debug!(
            "BeriaVMParser prepare_input: input_before_write=[{}] guest_before_write=[{}]",
            format_bytes(&input_buf[..input_buf.len().min(DEBUG_INPUT_BYTES_LEN)]),
            format_bytes(&before_write[..before_write.len().min(DEBUG_INPUT_BYTES_LEN)]),
        );

        let read_u32 = |qemu: &Qemu, addr: GuestAddr, label: &str| -> Result<u32, Error> {
            let mut tmp = [0u8; 4];
            qemu.read_mem(addr, &mut tmp).map_err(|e| {
                Error::unknown(format!("Failed to read {label} at {addr:#x}: {e:?}"))
            })?;
            Ok(u32::from_le_bytes(tmp))
        };

        let write_u32 = |qemu: &Qemu, addr: GuestAddr, value: u32, label: &str| -> Result<(), Error> {
            qemu.write_mem(addr, &value.to_le_bytes()).map_err(|e| {
                Error::unknown(format!("Failed to write {label} at {addr:#x}: {e:?}"))
            })
        };

        let aoep = read_u32(qemu, unpack_state + 0x68, "unpack_state->aoep")?;
        let image_base = read_u32(qemu, unpack_state + 0x74, "unpack_state->image_base")?;
        let e_lfanew = read_u32(qemu, unpack_state + 0x3c, "unpack_state->e_lfanew")?;

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
            log::debug!(
                "BeriaVMParser prepare_input: invalid compact input derived offsets anchor={anchor_dword:#x} v7={v7:#x} v8={v8:#x} v12={v12:#x} work_size={work_size:#x}, leaving snapshot state untouched"
            );
            return Ok(());
        }

        write_u32(
            qemu,
            work_buf + BERIA_AOEP_ANCHOR_OFF as GuestAddr,
            anchor_dword,
            "work_buf[anchor]",
        )?;
        qemu.write_mem(work_buf + v7 as GuestAddr, v7_window)
            .map_err(|e| Error::unknown(format!("Failed to write Beria v7 window at {:#x}: {e:?}", work_buf + v7 as GuestAddr)))?;
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

        let anchor_off =
            aoep.checked_add(0x13d)
                .ok_or_else(|| Error::unknown("aoep + 0x13d overflow"))? as GuestAddr;
        let anchor_dword = read_u32(qemu, work_buf + anchor_off, "work_buf[aoep+0x13d]")?;
        let v7 = anchor_dword.wrapping_sub(image_base);

        let dword_at_v7: Option<u32> = if (v7 as usize) + 4 <= work_size {
            Some(read_u32(qemu, work_buf + v7 as GuestAddr, "work_buf[v7]")?)
        } else {
            None
        };
        let dword_at_v7_plus_4 = if (v7 as usize) + 8 <= work_size {
            Some(read_u32(
                qemu,
                work_buf + v7 as GuestAddr + 4,
                "work_buf[v7+4]",
            )?)
        } else {
            None
        };
        let dword_at_v7_plus_c = if (v7 as usize) + 0x10 <= work_size {
            Some(read_u32(
                qemu,
                work_buf + v7 as GuestAddr + 0xc,
                "work_buf[v7+0xc]",
            )?)
        } else {
            None
        };
        let v8 = dword_at_v7.map(|x| x.wrapping_sub(image_base)).unwrap_or(0);
        let v12 = match (dword_at_v7_plus_4, dword_at_v7_plus_c) {
            (Some(a), Some(b)) => a.wrapping_sub(b),
            _ => 0,
        };

        let dword_at_v8 = if (v8 as usize) + 4 <= work_size {
            Some(read_u32(qemu, work_buf + v8 as GuestAddr, "work_buf[v8]")?)
        } else {
            None
        };
        let dword_at_v8_plus_4 = if (v8 as usize) + 8 <= work_size {
            Some(read_u32(
                qemu,
                work_buf + v8 as GuestAddr + 4,
                "work_buf[v8+4]",
            )?)
        } else {
            None
        };
        let dword_at_v8_plus_8 = if (v8 as usize) + 12 <= work_size {
            Some(read_u32(
                qemu,
                work_buf + v8 as GuestAddr + 8,
                "work_buf[v8+8]",
            )?)
        } else {
            None
        };
        let dword_at_v8_plus_c = if (v8 as usize) + 16 <= work_size {
            Some(read_u32(
                qemu,
                work_buf + v8 as GuestAddr + 0xc,
                "work_buf[v8+0xc]",
            )?)
        } else {
            None
        };
        let dword_at_v12 = if (v12 as usize) + 4 <= work_size {
            Some(read_u32(
                qemu,
                work_buf + v12 as GuestAddr,
                "work_buf[v12]",
            )?)
        } else {
            None
        };
        log::debug!(
              "BeriaVMParser state: exec_ctx={exec_ctx:#x} unpack_state={unpack_state:#x} work_buf={work_buf:#x} work_size={work_size:#x} aoep={aoep:#x} image_base={image_base:#x} e_lfanew={e_lfanew:#x}"
          );
        log::debug!(
              "BeriaVMParser walk: anchor_off={anchor_off:#x} anchor_dword={anchor_dword:#x} v7={v7:#x} dword_at_v7={:#x?} dword_at_v7_plus_4={:#x?} dword_at_v7_plus_c={:#x?}",
              dword_at_v7,
              dword_at_v7_plus_4,
              dword_at_v7_plus_c,
          );
        log::debug!(
            "BeriaVMParser dynamic: v8={v8:#x} v12={v12:#x} [v8]={:#x?} [v8+4]={:#x?} [v8+8]={:#x?} [v8+0xc]={:#x?} [v12]={:#x?}",
            dword_at_v8,
            dword_at_v8_plus_4,
            dword_at_v8_plus_8,
            dword_at_v8_plus_c,
            dword_at_v12,
        );

        let mut after_write = vec![0u8; DEBUG_INPUT_BYTES_LEN.min(work_size)];
        let _ = qemu.read_mem(work_buf, &mut after_write);
        log::debug!(
            "BeriaVMParser prepare_input: guest_after_write=[{}]",
            format_bytes(&after_write[..after_write.len().min(DEBUG_INPUT_BYTES_LEN)]),
        );

        Ok(())
    }

    fn reset(&self, harness: &CevaEmuHarness<'_>) -> Result<(), Error> {
        restore_nonvolatile_regs(harness)
    }
}
