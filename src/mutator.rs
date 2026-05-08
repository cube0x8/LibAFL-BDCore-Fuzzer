use std::borrow::Cow;

use libafl::{
    corpus::CorpusId,
    inputs::{BytesInput, HasMutatorBytes, ResizableMutator},
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
    HasLen, Named,
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
const MORPHINEP_STAGE0_MAX: usize = 0x4000;
const MORPHINEP_STAGE1_MAX: usize = 0x100;
const MORPHINEP_INPUT_MAX: usize = MORPHINEP_STAGE0_MAX + MORPHINEP_STAGE1_MAX;
const MORPHINEP_STAGE0_MIN: usize = 5;
const MORPHINEP_PHASE1_OFF: usize = 0x3045;
const MORPHINEP_PHASE1_GUARD_LEN: usize = 0x20;
const MORPHINEP_PHASE2_OFF: usize = 0x200;
const MORPHINEP_PHASE2_R14_OFF: usize = MORPHINEP_PHASE2_OFF + 0x0b;
const MORPHINEP_PHASE2_SIZE_OFF: usize = MORPHINEP_PHASE2_OFF + 0x0c;
const MORPHINEP_PHASE2_MARKER2_OFF: usize = MORPHINEP_PHASE2_OFF + 0x10;

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

/*
fn choose_u8<S: HasRand>(state: &mut S, values: &[u8]) -> u8 {
    let idx = (state.rand_mut().next() as usize) % values.len();
    values[idx]
}
*/

fn ensure_input_len(input: &mut BytesInput, len: usize) {
    if input.len() < len {
        input.resize(len, 0);
    }
}

fn split_morphinep_layout(total_len: usize) -> (usize, usize) {
    if total_len > MORPHINEP_STAGE0_MAX {
        (
            MORPHINEP_STAGE0_MAX,
            (total_len - MORPHINEP_STAGE0_MAX).min(MORPHINEP_STAGE1_MAX),
        )
    } else {
        (total_len.max(MORPHINEP_STAGE0_MIN), 0)
    }
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

#[derive(Default)]
pub struct MorphinepStreamMutator;

impl MorphinepStreamMutator {
    fn mutate_stage0_payload<S: HasRand>(&self, state: &mut S, input: &mut BytesInput) {
        ensure_input_len(input, MORPHINEP_STAGE0_MIN);

        let stage0_len = input
            .len()
            .min(MORPHINEP_STAGE0_MAX)
            .max(MORPHINEP_STAGE0_MIN);
        let bytes = input.mutator_bytes_mut();
        let rounds = 1 + ((state.rand_mut().next() as usize) % 16);
        for _ in 0..rounds {
            let rel = (state.rand_mut().next() as usize) % stage0_len;
            bytes[rel] ^= (state.rand_mut().next() & 0xff) as u8;
        }
    }

    fn repair_phase1<S: HasRand>(&self, state: &mut S, input: &mut BytesInput) {
        ensure_input_len(input, MORPHINEP_PHASE1_OFF + MORPHINEP_PHASE1_GUARD_LEN);
        let bytes = input.mutator_bytes_mut();
        bytes[MORPHINEP_PHASE1_OFF] = 0xff;
        bytes[MORPHINEP_PHASE1_OFF + 1] = 0x75;
        bytes[MORPHINEP_PHASE1_OFF + 2] = 0x08;

        let rounds = 1 + ((state.rand_mut().next() as usize) % 6);
        for _ in 0..rounds {
            let rel = 3 + ((state.rand_mut().next() as usize) % 0x1d);
            let off = MORPHINEP_PHASE1_OFF + rel;
            bytes[off] ^= (state.rand_mut().next() & 0xff) as u8;
        }
    }

    fn break_phase1_guard(&self, input: &mut BytesInput) {
        ensure_input_len(input, MORPHINEP_PHASE1_OFF + 3);
        let bytes = input.mutator_bytes_mut();
        bytes[MORPHINEP_PHASE1_OFF] = 0x90;
    }

    fn repair_phase2_template(&self, input: &mut BytesInput) {
        ensure_input_len(input, MORPHINEP_PHASE2_MARKER2_OFF + 4);
        let bytes = input.mutator_bytes_mut();

        bytes[MORPHINEP_PHASE2_OFF..MORPHINEP_PHASE2_OFF + 4]
            .copy_from_slice(&[0xde, 0xc0, 0xde, 0x00]);
        bytes[MORPHINEP_PHASE2_OFF + 4] = 0x00;
        bytes[MORPHINEP_PHASE2_OFF + 5] = 0x52;
        bytes[MORPHINEP_PHASE2_OFF + 6] = 0x52;
        bytes[MORPHINEP_PHASE2_OFF + 7] = 0xff;
        bytes[MORPHINEP_PHASE2_OFF + 8] = 0x35;
        bytes[MORPHINEP_PHASE2_OFF + 9] = 0x38;
        bytes[MORPHINEP_PHASE2_OFF + 10] = 0x35;

        bytes[MORPHINEP_PHASE2_R14_OFF..MORPHINEP_PHASE2_R14_OFF + 4]
            .copy_from_slice(&0x200u32.to_le_bytes());
        bytes[MORPHINEP_PHASE2_SIZE_OFF..MORPHINEP_PHASE2_SIZE_OFF + 4]
            .copy_from_slice(&0x100u32.to_le_bytes());
        bytes[MORPHINEP_PHASE2_MARKER2_OFF..MORPHINEP_PHASE2_MARKER2_OFF + 4]
            .copy_from_slice(&0xc0dec0deu32.to_le_bytes());
    }

    fn mutate_phase2_fields<S: HasRand>(&self, state: &mut S, input: &mut BytesInput) {
        self.repair_phase2_template(input);
        let bytes = input.mutator_bytes_mut();

        let r14 = choose_u32(state, &[0, 1, 2, 4, 8, 0x20, 0x80, 0x100, 0x200, 0x400]);
        let size = choose_u32(state, &[0, 1, 2, 4, 8, 0x10, 0x20, 0x40, 0x80, 0x100]);

        write_u32_le(bytes, MORPHINEP_PHASE2_R14_OFF, r14);
        write_u32_le(bytes, MORPHINEP_PHASE2_SIZE_OFF, size);
    }

    fn mutate_stage1_length<S: HasRand>(&self, state: &mut S, input: &mut BytesInput) {
        let size = read_u32_le(input.mutator_bytes(), MORPHINEP_PHASE2_SIZE_OFF)
            .unwrap_or(MORPHINEP_STAGE1_MAX as u32)
            .min(MORPHINEP_STAGE1_MAX as u32) as usize;
        let match_size = (state.rand_mut().next() & 1) == 0;
        let stage1_len = if match_size {
            size
        } else {
            choose_usize(state, &[0, 1, 2, 4, 8, 0x10, 0x20, 0x40, 0x80, 0x100])
        };

        let wanted = MORPHINEP_STAGE0_MAX + stage1_len.min(MORPHINEP_STAGE1_MAX);
        input.resize(wanted.max(MORPHINEP_STAGE0_MIN), 0);
    }

    fn mutate_stage1_payload<S: HasRand>(&self, state: &mut S, input: &mut BytesInput) {
        if input.len() <= MORPHINEP_STAGE0_MAX {
            input.resize(MORPHINEP_INPUT_MAX, 0);
        }

        let (_, stage1_len) = split_morphinep_layout(input.len());
        if stage1_len == 0 {
            return;
        }

        let stage1_off = MORPHINEP_STAGE0_MAX;
        let bytes = input.mutator_bytes_mut();
        let rounds = 1 + ((state.rand_mut().next() as usize) % 8);
        for _ in 0..rounds {
            let rel = (state.rand_mut().next() as usize) % stage1_len;
            let off = stage1_off + rel;
            bytes[off] ^= (state.rand_mut().next() & 0xff) as u8;
        }
    }

    fn mutate_stage0_length<S: HasRand>(&self, state: &mut S, input: &mut BytesInput) {
        let keep_stage1 = input.len() > MORPHINEP_STAGE0_MAX && (state.rand_mut().next() & 1) == 0;
        let requested_stage0_len = choose_usize(
            state,
            &[
                5, 0x20, 0x80, 0x100, 0x200, 0x600, 0x1000, 0x2000, 0x3fff, 0x4000,
            ],
        )
        .min(MORPHINEP_STAGE0_MAX)
        .max(MORPHINEP_STAGE0_MIN);

        let stage1_len = if keep_stage1 {
            input
                .len()
                .saturating_sub(MORPHINEP_STAGE0_MAX)
                .min(MORPHINEP_STAGE1_MAX)
        } else {
            0
        };

        let new_total_len = if stage1_len > 0 {
            MORPHINEP_STAGE0_MAX + stage1_len
        } else {
            requested_stage0_len
        };

        input.resize(new_total_len, 0);
    }
}

impl Named for MorphinepStreamMutator {
    fn name(&self) -> &Cow<'static, str> {
        static NAME: Cow<'static, str> = Cow::Borrowed("MorphinepStreamMutator");
        &NAME
    }
}

impl<S> Mutator<BytesInput, S> for MorphinepStreamMutator
where
    S: HasRand + HasMetadata + HasCorpus<BytesInput> + HasSolutions<BytesInput> + HasMaxSize,
{
    fn mutate(&mut self, state: &mut S, input: &mut BytesInput) -> Result<MutationResult, Error> {
        if input.len() == 0 {
            input.resize(MORPHINEP_STAGE0_MIN, 0);
        }

        let op = (state.rand_mut().next() % 9) as u32;
        match op {
            0 => self.mutate_stage0_length(state, input),
            1 => self.mutate_stage0_payload(state, input),
            2 => self.repair_phase1(state, input),
            3 => self.break_phase1_guard(input),
            4 => self.repair_phase2_template(input),
            5 => self.mutate_phase2_fields(state, input),
            6 => self.mutate_stage1_length(state, input),
            7 => self.mutate_stage1_payload(state, input),
            _ => {
                self.repair_phase1(state, input);
                self.repair_phase2_template(input);
                self.mutate_phase2_fields(state, input);
            }
        }

        if input.len() > MORPHINEP_INPUT_MAX {
            input.resize(MORPHINEP_INPUT_MAX, 0);
        }

        if input.len() < MORPHINEP_STAGE0_MIN {
            input.resize(MORPHINEP_STAGE0_MIN, 0);
        }

        Ok(MutationResult::Mutated)
    }

    fn post_exec(&mut self, _state: &mut S, _new_corpus_id: Option<CorpusId>) -> Result<(), Error> {
        Ok(())
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
    Morphinep(MorphinepStreamMutator),
    Mopt(StdMOptMutator<HavocMutationsType>),
    MoptFixed(StdMOptMutator<FixedSizeHavocMutationsType>),
}

impl Named for BDCoreMutator {
    fn name(&self) -> &Cow<'static, str> {
        match self {
            Self::Pe(m) => m.name(),
            Self::Beria(m) => m.name(),
            Self::Morphinep(m) => m.name(),
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
            Self::Morphinep(m) => m.mutate(state, input),
            Self::Mopt(m) => m.mutate(state, input),
            Self::MoptFixed(m) => m.mutate(state, input),
        }
    }

    fn post_exec(&mut self, state: &mut S, new_corpus_id: Option<CorpusId>) -> Result<(), Error> {
        match self {
            Self::Pe(m) => m.post_exec(state, new_corpus_id),
            Self::Beria(m) => m.post_exec(state, new_corpus_id),
            Self::Morphinep(m) => m.post_exec(state, new_corpus_id),
            Self::Mopt(m) => m.post_exec(state, new_corpus_id),
            Self::MoptFixed(m) => m.post_exec(state, new_corpus_id),
        }
    }
}
