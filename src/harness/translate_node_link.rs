use libafl::Error;
use libafl_qemu::{GuestAddr, GuestReg, Qemu, Regs};

use super::ceva_target::CevaTarget;

#[derive(Default)]
pub struct TranslateNodeLinkTarget;

impl CevaTarget for TranslateNodeLinkTarget {
    fn name(&self) -> &'static str {
        "TranslateNodeLink"
    }

    fn prepare_input(&self, qemu: &Qemu, input: &[u8], _input_len: GuestReg) -> Result<(), Error> {
        // get the guest_bytes buffer from the emulator node
        // the buffer contains the assembly code that is going to be parsed and threw into the specific opcode-based handlers
        let emulator_node: GuestAddr = qemu.read_reg(Regs::Rdx).unwrap().try_into().unwrap();

        let mut guest_bytes = [0u8; 8];
        qemu.read_mem(emulator_node + 0x28, &mut guest_bytes)
            .unwrap();
        let guest_bytes_ptr: GuestAddr = u64::from_le_bytes(guest_bytes.try_into().unwrap())
            .try_into()
            .unwrap();

        let mut guest_bytes_start_addr = [0u8; 8];
        let mut guest_bytes_end_addr = [0u8; 8];
        qemu.read_mem(emulator_node + 0x0, &mut guest_bytes_start_addr)
            .unwrap();
        qemu.read_mem(emulator_node + 0x8, &mut guest_bytes_end_addr)
            .unwrap();

        let guest_bytes_len = u64::from_le_bytes(guest_bytes_end_addr.try_into().unwrap())
            - u64::from_le_bytes(guest_bytes_start_addr.try_into().unwrap());

        // the mutator should have generated an input of the size declared in the user manifest, but just in case...
        // println!("Guest bytes buffer at {guest_bytes_ptr:#x} with size {guest_bytes_len}");
        // println!("Input size: {}", input.len());
        assert!(guest_bytes_len == input.len() as u64);

        qemu.write_mem(guest_bytes_ptr, input).unwrap();
        Ok(())
    }
}
