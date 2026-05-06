use std::borrow::Cow;

use libafl::{
    corpus::CorpusId,
    inputs::{BytesInput, HasMutatorBytes},
    mutators::{
        havoc_mutations::HavocMutationsType,
        mutations::{
            BitFlipMutator, ByteAddMutator, ByteDecMutator, ByteFlipMutator, ByteIncMutator,
            ByteInterestingMutator, ByteNegMutator, ByteRandMutator, BytesCopyMutator,
            BytesRandSetMutator, BytesSetMutator, BytesSwapMutator, CrossoverReplaceMutator,
            DwordAddMutator, DwordInterestingMutator, QwordAddMutator, WordAddMutator,
            WordInterestingMutator,
        },
        MutationResult, Mutator, StdMOptMutator,
    },
    state::{HasCorpus, HasMaxSize, HasRand, HasSolutions},
    Error, HasMetadata,
};
use libafl_bolts::{
    rands::Rand,
    tuples::{tuple_list, tuple_list_type},
    Named,
};
use libafl_pe_mutator::PeMutator;

pub type FixedSizeHavocMutationsType = tuple_list_type!(
    BitFlipMutator,
    ByteFlipMutator,
    ByteIncMutator,
    ByteDecMutator,
    ByteNegMutator,
    ByteRandMutator,
    ByteAddMutator,
    WordAddMutator,
    DwordAddMutator,
    QwordAddMutator,
    ByteInterestingMutator,
    WordInterestingMutator,
    DwordInterestingMutator,
    BytesSetMutator,
    BytesRandSetMutator,
    BytesCopyMutator,
    BytesSwapMutator,
    CrossoverReplaceMutator
);

#[must_use]
pub fn havoc_fixed_size_mutations() -> FixedSizeHavocMutationsType {
    tuple_list!(
        BitFlipMutator::new(),
        ByteFlipMutator::new(),
        ByteIncMutator::new(),
        ByteDecMutator::new(),
        ByteNegMutator::new(),
        ByteRandMutator::new(),
        ByteAddMutator::new(),
        WordAddMutator::new(),
        DwordAddMutator::new(),
        QwordAddMutator::new(),
        ByteInterestingMutator::new(),
        WordInterestingMutator::new(),
        DwordInterestingMutator::new(),
        BytesSetMutator::new(),
        BytesRandSetMutator::new(),
        BytesCopyMutator::new(),
        BytesSwapMutator::new(),
        CrossoverReplaceMutator::new(),
    )
}

const BERIA_IMAGE_BASE: u32 = 0x400000;
const BERIA_PATCH_ANCHOR_OFF: usize = 0x00;
const BERIA_PATCH_V7_OFF: usize = 0x04;
const BERIA_PATCH_V7_LEN: usize = 0x1C;
const BERIA_PATCH_V12_OFF: usize = BERIA_PATCH_V7_OFF + BERIA_PATCH_V7_LEN;
const BERIA_PATCH_V8_OFF: usize = BERIA_PATCH_V12_OFF + 4;
const BERIA_PATCH_V8_LEN: usize = 0x110;
const BERIA_PATCH_INPUT_SIZE: usize = BERIA_PATCH_V8_OFF + BERIA_PATCH_V8_LEN;

#[derive(Default)]
pub struct BeriaWorkbufMutator;

fn in_bounds(buf: &[u8], off: usize, len: usize) -> bool {
    off <= buf.len() && len <= buf.len().saturating_sub(off)
}

fn read_u32_le(buf: &[u8], off: usize) -> Option<u32> {
    if !in_bounds(buf, off, 4) {
        return None;
    }
    Some(u32::from_le_bytes(buf[off..off + 4].try_into().ok()?))
}

fn write_u32_le(buf: &mut [u8], off: usize, value: u32) -> bool {
    if !in_bounds(buf, off, 4) {
        return false;
    }
    buf[off..off + 4].copy_from_slice(&value.to_le_bytes());
    true
}

fn choose_u32<S: HasRand>(state: &mut S, values: &[u32]) -> u32 {
    let idx = (state.rand_mut().next() as usize) % values.len();
    values[idx]
}

fn choose_usize<S: HasRand>(state: &mut S, values: &[usize]) -> usize {
    let idx = (state.rand_mut().next() as usize) % values.len();
    values[idx]
}

impl BeriaWorkbufMutator {
    fn mutate_payload<S: HasRand>(
        &self,
        state: &mut S,
        bytes: &mut [u8],
        payload_off: usize,
        payload_len: usize,
    ) {
        if payload_len == 0 || !in_bounds(bytes, payload_off, payload_len) {
            return;
        }

        let rounds = 1 + ((state.rand_mut().next() as usize) % 8);
        for _ in 0..rounds {
            let rel = (state.rand_mut().next() as usize) % payload_len;
            let off = payload_off + rel;
            bytes[off] ^= (state.rand_mut().next() & 0xff) as u8;
        }
    }

    fn mutate_dword<S: HasRand>(
        &self,
        state: &mut S,
        bytes: &mut [u8],
        off: usize,
        interesting: &[u32],
    ) -> bool {
        if !in_bounds(bytes, off, 4) {
            return false;
        }

        let mode = (state.rand_mut().next() % 4) as u32;
        let cur = read_u32_le(bytes, off).unwrap();

        let new_val = match mode {
            0 => choose_u32(state, interesting),
            1 => cur.wrapping_add(choose_u32(state, &[1, 2, 4, 8, 0x10, 0x100])),
            2 => cur.wrapping_sub(choose_u32(state, &[1, 2, 4, 8, 0x10, 0x100])),
            _ => cur ^ choose_u32(state, &[0xff, 0xffff, 0xffffffff, 0x1000, 0x10000]),
        };

        write_u32_le(bytes, off, new_val)
    }
}

impl Named for BeriaWorkbufMutator {
    fn name(&self) -> &Cow<'static, str> {
        static NAME: Cow<'static, str> = Cow::Borrowed("BeriaWorkbufMutator");
        &NAME
    }
}

impl<S> Mutator<BytesInput, S> for BeriaWorkbufMutator
where
    S: HasRand + HasMetadata + HasCorpus<BytesInput> + HasSolutions<BytesInput> + HasMaxSize,
{
    fn mutate(&mut self, state: &mut S, input: &mut BytesInput) -> Result<MutationResult, Error> {
        let bytes = input.mutator_bytes_mut();

        if bytes.len() != BERIA_PATCH_INPUT_SIZE || !in_bounds(bytes, BERIA_PATCH_ANCHOR_OFF, 4) {
            return Ok(MutationResult::Skipped);
        }

        if !in_bounds(bytes, BERIA_PATCH_V7_OFF + 0x18, 4) {
            return Ok(MutationResult::Skipped);
        }

        if read_u32_le(bytes, BERIA_PATCH_ANCHOR_OFF).is_none() {
            return Ok(MutationResult::Skipped);
        }

        if !in_bounds(bytes, BERIA_PATCH_V8_OFF + 0x10, 1)
            || !in_bounds(bytes, BERIA_PATCH_V12_OFF, 4)
        {
            return Ok(MutationResult::Skipped);
        }

        let op = (state.rand_mut().next() % 11) as u32;

        match op {
            // Coherent family rewrite: keeps the parser on a structurally valid path.
            0 => {
                let new_v7 = choose_usize(
                    state,
                    &[
                        0x80000, 0x81000, 0x82000, 0x83000, 0x84000, 0x85000, 0x86000, 0x87000,
                        0x88000, 0x89000,
                    ],
                );
                let new_v8 = new_v7 + 0x10000;
                let new_v12 = new_v8 + 0x200;

                write_u32_le(
                    bytes,
                    BERIA_PATCH_ANCHOR_OFF,
                    BERIA_IMAGE_BASE.wrapping_add(new_v7 as u32),
                );
                write_u32_le(
                    bytes,
                    BERIA_PATCH_V7_OFF + 0x00,
                    BERIA_IMAGE_BASE.wrapping_add(new_v8 as u32),
                );
                write_u32_le(
                    bytes,
                    BERIA_PATCH_V7_OFF + 0x04,
                    BERIA_IMAGE_BASE.wrapping_add(new_v12 as u32),
                );
                write_u32_le(bytes, BERIA_PATCH_V7_OFF + 0x0c, BERIA_IMAGE_BASE);
                write_u32_le(
                    bytes,
                    BERIA_PATCH_V7_OFF + 0x10,
                    BERIA_IMAGE_BASE.wrapping_add(choose_u32(state, &[0, 0x20, 0x40, 0x80, 0x120])),
                );
                write_u32_le(
                    bytes,
                    BERIA_PATCH_V7_OFF + 0x18,
                    BERIA_IMAGE_BASE
                        .wrapping_add(choose_u32(state, &[0, 0x40, 0x80, 0x120, 0x200])),
                );
                write_u32_le(
                    bytes,
                    BERIA_PATCH_V12_OFF,
                    choose_u32(state, &[0, 0, 0, 1, 2, 4]),
                );
                write_u32_le(
                    bytes,
                    BERIA_PATCH_V8_OFF + 0x00,
                    choose_u32(state, &[1, 1, 1, 2, 3]),
                );
            }

            // Anchor dword -> v7
            1 => {
                self.mutate_dword(
                    state,
                    bytes,
                    BERIA_PATCH_ANCHOR_OFF,
                    &[
                        0x480000, 0x481000, 0x482000, 0x483000, 0x484000, 0x485000, 0x486000,
                        0x487000, 0x488000, 0x489000,
                    ],
                );
            }

            // v7 + 0x00 -> v8 VA
            2 => {
                self.mutate_dword(
                    state,
                    bytes,
                    BERIA_PATCH_V7_OFF + 0x00,
                    &[
                        0x490000, 0x491000, 0x492000, 0x493000, 0x494000, 0x495000, 0x496000,
                        0x497000, 0x498000, 0x499000,
                    ],
                );
            }

            // v7 + 0x04 -> v12 VA
            3 => {
                self.mutate_dword(
                    state,
                    bytes,
                    BERIA_PATCH_V7_OFF + 0x04,
                    &[
                        0x490200, 0x491200, 0x492200, 0x493200, 0x494200, 0x495200, 0x496200,
                        0x497200, 0x498200, 0x499200,
                    ],
                );
            }

            // v7 + 0x0c / v7 + 0x10 / v7 + 0x18
            4 => {
                let which = choose_usize(state, &[0usize, 1, 2]);
                let off = match which {
                    0 => BERIA_PATCH_V7_OFF + 0x0c,
                    1 => BERIA_PATCH_V7_OFF + 0x10,
                    _ => BERIA_PATCH_V7_OFF + 0x18,
                };
                self.mutate_dword(
                    state,
                    bytes,
                    off,
                    &[
                        0x400000, 0x400020, 0x400040, 0x400080, 0x400100, 0x401000, 0x410000,
                    ],
                );
            }

            // Phase-1 count at v12
            5 => {
                self.mutate_dword(
                    state,
                    bytes,
                    BERIA_PATCH_V12_OFF,
                    &[0, 0, 0, 1, 2, 4, 8, 0x10, 0x20],
                );
            }

            // Second-phase count
            6 => {
                self.mutate_dword(
                    state,
                    bytes,
                    BERIA_PATCH_V8_OFF + 0x00,
                    &[0, 1, 1, 1, 2, 3, 4, 0x10, 0x2710],
                );
            }

            // data_len
            7 => {
                self.mutate_dword(
                    state,
                    bytes,
                    BERIA_PATCH_V8_OFF + 0x04,
                    &[
                        0xfffffff4, 0xfffffff5, 0xfffffff6, 0xfffffff8, 0xffffffff, 0, 1, 2, 4, 8,
                        0x20, 0x100, 0x1000,
                    ],
                );
            }

            // out_len
            8 => {
                self.mutate_dword(
                    state,
                    bytes,
                    BERIA_PATCH_V8_OFF + 0x08,
                    &[0, 1, 2, 4, 8, 0x20, 0x40, 0x100, 0x200, 0x1000, 0x4000],
                );
            }

            // flags
            9 => {
                self.mutate_dword(
                    state,
                    bytes,
                    BERIA_PATCH_V8_OFF + 0x0c,
                    &[0, 1, 2, 0xff, 0xffffffff],
                );
            }

            // payload bytes at v8 + 0x10
            _ => {
                self.mutate_payload(state, bytes, BERIA_PATCH_V8_OFF + 0x10, 0x100);
            }
        }

        Ok(MutationResult::Mutated)
    }

    fn post_exec(&mut self, _state: &mut S, _new_corpus_id: Option<CorpusId>) -> Result<(), Error> {
        Ok(())
    }
}

pub enum BDCoreMutator {
    Pe(PeMutator),
    Beria(BeriaWorkbufMutator),
    Mopt(StdMOptMutator<HavocMutationsType>),
    MoptFixed(StdMOptMutator<FixedSizeHavocMutationsType>),
}

impl Named for BDCoreMutator {
    fn name(&self) -> &Cow<'static, str> {
        match self {
            Self::Pe(m) => m.name(),
            Self::Beria(m) => m.name(),
            Self::Mopt(m) => m.name(),
            Self::MoptFixed(m) => m.name(),
        }
    }
}

impl<S> Mutator<BytesInput, S> for BDCoreMutator
where
    S: HasRand + HasMetadata + HasCorpus<BytesInput> + HasSolutions<BytesInput> + HasMaxSize,
{
    fn mutate(&mut self, state: &mut S, input: &mut BytesInput) -> Result<MutationResult, Error> {
        match self {
            Self::Pe(m) => m.mutate(state, input),
            Self::Beria(m) => m.mutate(state, input),
            Self::Mopt(m) => m.mutate(state, input),
            Self::MoptFixed(m) => m.mutate(state, input),
        }
    }

    fn post_exec(&mut self, state: &mut S, new_corpus_id: Option<CorpusId>) -> Result<(), Error> {
        match self {
            Self::Pe(m) => m.post_exec(state, new_corpus_id),
            Self::Beria(m) => m.post_exec(state, new_corpus_id),
            Self::Mopt(m) => m.post_exec(state, new_corpus_id),
            Self::MoptFixed(m) => m.post_exec(state, new_corpus_id),
        }
    }
}
