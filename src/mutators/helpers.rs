use libafl::{
    inputs::{BytesInput, ResizableMutator},
    state::HasRand,
};
use libafl_bolts::{rands::Rand, HasLen};

pub fn in_bounds(buf: &[u8], off: usize, len: usize) -> bool {
    off <= buf.len() && len <= buf.len().saturating_sub(off)
}

pub fn read_u32_le(buf: &[u8], off: usize) -> Option<u32> {
    if !in_bounds(buf, off, 4) {
        return None;
    }
    Some(u32::from_le_bytes(buf[off..off + 4].try_into().ok()?))
}

pub fn write_u32_le(buf: &mut [u8], off: usize, value: u32) -> bool {
    if !in_bounds(buf, off, 4) {
        return false;
    }
    buf[off..off + 4].copy_from_slice(&value.to_le_bytes());
    true
}

pub fn choose_u32<S: HasRand>(state: &mut S, values: &[u32]) -> u32 {
    let idx = (state.rand_mut().next() as usize) % values.len();
    values[idx]
}

pub fn choose_usize<S: HasRand>(state: &mut S, values: &[usize]) -> usize {
    let idx = (state.rand_mut().next() as usize) % values.len();
    values[idx]
}

pub fn ensure_input_len(input: &mut BytesInput, len: usize) {
    if input.len() < len {
        input.resize(len, 0);
    }
}
