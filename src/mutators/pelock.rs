use std::borrow::Cow;

use libafl::{
    corpus::CorpusId,
    inputs::{BytesInput, HasMutatorBytes, ResizableMutator},
    mutators::{MutationResult, Mutator},
    state::{HasCorpus, HasMaxSize, HasRand, HasSolutions},
    Error, HasMetadata,
};
use libafl_bolts::{rands::Rand, HasLen, Named};

use super::helpers::{choose_u32, write_u32_le};

const PELOCK_STREAM_LEN: usize = 0x3a00;
const PELOCK_STUB_PREFIX_LEN: usize = 10;
const PELOCK_07D60_WINDOW_LEN: usize = 0xab;
const PELOCK_TOTAL_LEN: usize =
    PELOCK_STUB_PREFIX_LEN + PELOCK_STREAM_LEN + PELOCK_07D60_WINDOW_LEN;
const PELOCK_STUB_IMM1_OFF: usize = 1;
const PELOCK_STUB_IMM2_OFF: usize = 6;
const PELOCK_DEFAULT_OEP_VA: u32 = 0x409000;
const PELOCK_07D60_TEMPLATE_LEN: usize = 0xab;
const PELOCK_07D60_CURSOR_IN_WINDOW: usize = 0x10;
const PELOCK_DEFAULT_PREFIX: [u8; PELOCK_STUB_PREFIX_LEN] =
    [0xB8, 0x00, 0x91, 0x40, 0x00, 0xB9, 0x00, 0x02, 0x00, 0x00];
const PELOCK_07D60_WINDOW_TEMPLATE: [u8; PELOCK_07D60_TEMPLATE_LEN] = [
    0x44, 0x33, 0x22, 0x11, 0x49, 0x0f, 0xb6, 0x10, 0x02, 0xd1, 0x8b, 0xca, 0x88, 0x08, 0x75, 0xf5,
    0x85, 0x4c, 0x72, 0x01, 0x20, 0xb0, 0x00, 0x86, 0x85, 0x9e, 0xde, 0x6a, 0x88, 0xa3, 0x67, 0x74,
    0xe9, 0x41, 0x64, 0x61, 0x60, 0xea, 0xe3, 0xa9, 0xce, 0x5c, 0x7a, 0x84, 0xdd, 0xaf, 0xc8, 0x56,
    0x74, 0xde, 0x52, 0xda, 0xd5, 0x39, 0xc1, 0x4e, 0x6c, 0xd6, 0xcf, 0x95, 0xba, 0x48, 0x66, 0x70,
    0xc9, 0x9f, 0xb4, 0x42, 0x60, 0xca, 0x3e, 0xc6, 0xc1, 0x2d, 0xad, 0x3a, 0x58, 0xba, 0xf3, 0x27,
    0xa7, 0x34, 0x52, 0x31, 0x3f, 0xb3, 0xd7, 0x2f, 0x2c, 0x2b, 0xad, 0xe6, 0x12, 0x9a, 0x27, 0x45,
    0x24, 0x32, 0xa6, 0xbd, 0x22, 0x1f, 0x1e, 0xaa, 0xa1, 0xa8, 0x8e, 0x1a, 0x38, 0x67, 0x15, 0xaa,
    0xfe, 0x86, 0x13, 0x31, 0x93, 0x07, 0x0e, 0x1c, 0x90, 0x91, 0x0c, 0x09, 0x08, 0x90, 0x8b, 0xeb,
    0x77, 0x04, 0x22, 0x8e, 0x85, 0x15, 0x72, 0xfe, 0x1c, 0x4b, 0xf9, 0xae, 0xde, 0x6a, 0xf7, 0x15,
    0xf3, 0x88, 0xe4, 0x64, 0xf1, 0x0f, 0x71, 0xe5, 0xec, 0xfa, 0x6e, 0x41, 0xea, 0xe7, 0xe6, 0x6e,
    0x69, 0xd1, 0x55, 0xe2, 0x00, 0x6c, 0x63, 0xff, 0x50, 0xdc, 0xfa,
];

#[derive(Default)]
pub struct PelockStubMutator;

impl PelockStubMutator {
    fn ensure_prefixed_layout(&self, input: &mut BytesInput) {
        if input.len() == PELOCK_TOTAL_LEN {
            return;
        }

        let old = input.mutator_bytes().to_vec();
        let mut rebuilt = vec![0u8; PELOCK_TOTAL_LEN];
        rebuilt[..PELOCK_STUB_PREFIX_LEN].copy_from_slice(&PELOCK_DEFAULT_PREFIX);
        rebuilt[PELOCK_STUB_PREFIX_LEN + PELOCK_STREAM_LEN..]
            .copy_from_slice(&PELOCK_07D60_WINDOW_TEMPLATE);

        if old.len() >= PELOCK_STUB_PREFIX_LEN + PELOCK_STREAM_LEN {
            rebuilt[..PELOCK_STUB_PREFIX_LEN]
                .copy_from_slice(&old[..PELOCK_STUB_PREFIX_LEN.min(old.len())]);
            rebuilt[PELOCK_STUB_PREFIX_LEN..PELOCK_STUB_PREFIX_LEN + PELOCK_STREAM_LEN]
                .copy_from_slice(
                    &old[PELOCK_STUB_PREFIX_LEN..PELOCK_STUB_PREFIX_LEN + PELOCK_STREAM_LEN],
                );
            if old.len() >= PELOCK_TOTAL_LEN {
                rebuilt[PELOCK_STUB_PREFIX_LEN + PELOCK_STREAM_LEN..].copy_from_slice(
                    &old[PELOCK_STUB_PREFIX_LEN + PELOCK_STREAM_LEN..PELOCK_TOTAL_LEN],
                );
            }
        } else {
            let stream_src = if old.len() > PELOCK_STREAM_LEN {
                &old[PELOCK_STUB_PREFIX_LEN.min(old.len())..]
            } else {
                &old[..]
            };
            let copy_len = stream_src.len().min(PELOCK_STREAM_LEN);
            rebuilt[PELOCK_STUB_PREFIX_LEN..PELOCK_STUB_PREFIX_LEN + copy_len]
                .copy_from_slice(&stream_src[..copy_len]);
        }
        input.resize(PELOCK_TOTAL_LEN, 0);
        input.mutator_bytes_mut().copy_from_slice(&rebuilt);
    }

    fn mutate_stub_immediates<S: HasRand>(&self, state: &mut S, input: &mut BytesInput) {
        self.ensure_prefixed_layout(input);
        let bytes = input.mutator_bytes_mut();

        let out_delta = choose_u32(
            state,
            &[
                0x100, 0x100, 0x180, 0x200, 0x200, 0x400, 0x500, 0x800, 0x1000, 0x1800, 0x1e00,
                0x2800, 0x2c00, 0x16, 0x18, 0x20, 0x40, 0x80,
            ],
        );
        let out_va = PELOCK_DEFAULT_OEP_VA.wrapping_add(out_delta);
        let out_aux = choose_u32(
            state,
            &[
                0x10, 0x20, 0x40, 0x80, 0x100, 0x180, 0x200, 0x200, 0x400, 1, 2, 4, 8,
            ],
        );

        let _ = write_u32_le(bytes, PELOCK_STUB_IMM1_OFF, out_va);
        let _ = write_u32_le(bytes, PELOCK_STUB_IMM2_OFF, out_aux);
        bytes[0] = 0xB8;
        bytes[5] = 0xB9;
    }

    fn build_07d60_template<S: HasRand>(&self, state: &mut S) -> [u8; PELOCK_07D60_TEMPLATE_LEN] {
        let mut template = PELOCK_07D60_WINDOW_TEMPLATE;
        let cursor = PELOCK_07D60_CURSOR_IN_WINDOW;
        let rel32 = choose_u32(state, &[0, 1, 2, 4, 8, 0x10, 0x20, 0x40]);
        let slot48 = [0x48, 0x66, 0x70, 0xC9, 0x9F];
        let slot49 = [0x49, 0x0F, 0xB6, 0x10, 0x02];
        let variant = (state.rand_mut().next() % 4) as u8;

        // 07D60 only records the tracked slots when the instruction decoder
        // sees a valid 5-byte instruction whose first byte is 0x48..0x4f.
        // These two 5-byte sequences are copied from the stable runtime
        // window. The useful search space here is:
        //   - order of the two tracked entries
        //   - whether the E2 back-edge lands on the first or second entry
        //
        // Layout from `cursor`:
        //   slot_a[5]
        //   slot_b[5]
        //   filler
        //   E2 disp8
        //   E8 rel32
        let (slot_a, slot_b, disp8) = match variant {
            0 => (slot48, slot49, 0xF8), // back-edge to second entry
            1 => (slot49, slot48, 0xF8), // back-edge to second entry
            2 => (slot48, slot49, 0xF3), // back-edge to first entry
            _ => (slot49, slot48, 0xF3), // back-edge to first entry
        };
        template[cursor..cursor + 5].copy_from_slice(&slot_a);
        template[cursor + 5..cursor + 10].copy_from_slice(&slot_b);
        template[cursor + 10] = 0x90;
        template[cursor + 11] = 0xE2;
        template[cursor + 12] = disp8;
        template[cursor + 13] = 0xE8;
        template[cursor + 14..cursor + 18].copy_from_slice(&rel32.to_le_bytes());

        let protected_start = cursor;
        let protected_end = cursor + 18;
        let rounds = 1 + ((state.rand_mut().next() as usize) % 8);
        for _ in 0..rounds {
            let idx = (state.rand_mut().next() as usize) % template.len();
            if (protected_start..protected_end).contains(&idx) {
                continue;
            }
            template[idx] ^= (state.rand_mut().next() & 0xff) as u8;
        }
        template
    }

    fn overwrite_07d60_window<S: HasRand>(&self, state: &mut S, input: &mut BytesInput) {
        self.ensure_prefixed_layout(input);
        let template = self.build_07d60_template(state);
        let base = PELOCK_STUB_PREFIX_LEN + PELOCK_STREAM_LEN;
        let bytes = input.mutator_bytes_mut();
        bytes[base..base + PELOCK_07D60_TEMPLATE_LEN].copy_from_slice(&template);
    }

    fn mutate_early_stream<S: HasRand>(&self, state: &mut S, input: &mut BytesInput) {
        self.ensure_prefixed_layout(input);
        let bytes = input.mutator_bytes_mut();
        let base = PELOCK_STUB_PREFIX_LEN;
        let window = 0x2000usize.min(PELOCK_STREAM_LEN);
        let rounds = 1 + ((state.rand_mut().next() as usize) % 16);
        for _ in 0..rounds {
            let off = base + ((state.rand_mut().next() as usize) % window);
            bytes[off] ^= (state.rand_mut().next() & 0xff) as u8;
        }
    }

    fn mutate_07d60_window<S: HasRand>(&self, state: &mut S, input: &mut BytesInput) {
        self.ensure_prefixed_layout(input);
        let base = PELOCK_STUB_PREFIX_LEN + PELOCK_STREAM_LEN;
        let bytes = input.mutator_bytes_mut();
        let protected_start = PELOCK_07D60_CURSOR_IN_WINDOW;
        let protected_end = protected_start + 18;
        let rounds = 1 + ((state.rand_mut().next() as usize) % 12);
        for _ in 0..rounds {
            let idx = (state.rand_mut().next() as usize) % PELOCK_07D60_WINDOW_LEN;
            if (protected_start..protected_end).contains(&idx) {
                continue;
            }
            bytes[base + idx] ^= (state.rand_mut().next() & 0xff) as u8;
        }
    }
}

impl Named for PelockStubMutator {
    fn name(&self) -> &Cow<'static, str> {
        static NAME: Cow<'static, str> = Cow::Borrowed("PelockStubMutator");
        &NAME
    }
}

impl<S> Mutator<BytesInput, S> for PelockStubMutator
where
    S: HasRand + HasMetadata + HasCorpus<BytesInput> + HasSolutions<BytesInput> + HasMaxSize,
{
    fn mutate(&mut self, state: &mut S, input: &mut BytesInput) -> Result<MutationResult, Error> {
        self.ensure_prefixed_layout(input);

        self.mutate_stub_immediates(state, input);
        self.overwrite_07d60_window(state, input);
        self.mutate_early_stream(state, input);
        self.mutate_07d60_window(state, input);

        if input.len() != PELOCK_TOTAL_LEN {
            input.resize(PELOCK_TOTAL_LEN, 0);
        }

        Ok(MutationResult::Mutated)
    }

    fn post_exec(&mut self, _state: &mut S, _new_corpus_id: Option<CorpusId>) -> Result<(), Error> {
        Ok(())
    }
}
