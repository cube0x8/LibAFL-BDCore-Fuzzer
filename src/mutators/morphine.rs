use std::borrow::Cow;

use libafl::{
    corpus::CorpusId,
    inputs::{BytesInput, HasMutatorBytes, ResizableMutator},
    mutators::{MutationResult, Mutator},
    state::{HasCorpus, HasMaxSize, HasRand, HasSolutions},
    Error, HasMetadata,
};
use libafl_bolts::{rands::Rand, HasLen, Named};

use super::helpers::{choose_u32, choose_usize, ensure_input_len, read_u32_le, write_u32_le};

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
