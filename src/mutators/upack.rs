use std::borrow::Cow;

use libafl::{
    corpus::CorpusId,
    inputs::{BytesInput, HasMutatorBytes, ResizableMutator},
    mutators::{HavocScheduledMutator, MutationResult, Mutator},
    state::{HasCorpus, HasMaxSize, HasRand, HasSolutions},
    Error, HasMetadata,
};
use libafl_bolts::{rands::Rand, HasLen, Named};

use super::havoc_fixed_size_mutations;

use crate::harness::{
    seed_bootstrap_windows, snapshot_windows, UPACK_ENTRY_STUB_LEN, UPACK_MAX_STREAM_LEN,
};

#[derive(Clone, Copy, Debug)]
struct InputWindow {
    start: usize,
    len: usize,
}

#[derive(Default)]
pub struct UpackWindowMutator;

impl UpackWindowMutator {
    const MAX_TOTAL_LEN: usize = UPACK_ENTRY_STUB_LEN + UPACK_MAX_STREAM_LEN;

    fn is_prefixed_layout(input: &[u8]) -> bool {
        input.len() > UPACK_ENTRY_STUB_LEN && !input.starts_with(b"MZ")
    }

    fn normalize_len(&self, input: &mut BytesInput) {
        if input.len() == 0 {
            input.resize(0x200, 0);
            return;
        }

        if input.len() > Self::MAX_TOTAL_LEN {
            input.resize(Self::MAX_TOTAL_LEN, 0);
        }
    }

    fn current_windows(&self, input: &[u8]) -> Vec<InputWindow> {
        seed_bootstrap_windows();

        let input_len = input.len();
        let is_prefixed = Self::is_prefixed_layout(input);
        let stream_base = if is_prefixed { UPACK_ENTRY_STUB_LEN } else { 0 };
        let mut windows = Vec::with_capacity(32);

        if is_prefixed {
            windows.push(InputWindow {
                start: 0,
                len: UPACK_ENTRY_STUB_LEN,
            });
        }

        for observed in snapshot_windows() {
            let start = stream_base.saturating_add(observed.stream_offset);
            if start >= input_len {
                continue;
            }
            let len = observed.size.min(input_len - start);
            if len != 0 {
                windows.push(InputWindow { start, len });
            }
        }

        windows
    }

    fn mutate_window<S>(
        &self,
        state: &mut S,
        input: &mut BytesInput,
        window: InputWindow,
    ) -> Result<MutationResult, Error>
    where
        S: HasRand + HasMetadata + HasCorpus<BytesInput> + HasSolutions<BytesInput> + HasMaxSize,
    {
        let bytes = input.mutator_bytes_mut();
        let end = window.start.saturating_add(window.len).min(bytes.len());
        if window.start >= end {
            return Ok(MutationResult::Skipped);
        }

        let original_len = end - window.start;
        let mut window_input = BytesInput::new(bytes[window.start..end].to_vec());
        let mut havoc = HavocScheduledMutator::new(havoc_fixed_size_mutations());
        let result = havoc.mutate(state, &mut window_input)?;

        if result == MutationResult::Mutated && window_input.len() == original_len {
            bytes[window.start..end].copy_from_slice(window_input.mutator_bytes());
        }

        Ok(result)
    }
}

impl Named for UpackWindowMutator {
    fn name(&self) -> &Cow<'static, str> {
        static NAME: Cow<'static, str> = Cow::Borrowed("UpackWindowMutator");
        &NAME
    }
}

impl<S> Mutator<BytesInput, S> for UpackWindowMutator
where
    S: HasRand + HasMetadata + HasCorpus<BytesInput> + HasSolutions<BytesInput> + HasMaxSize,
{
    fn mutate(&mut self, state: &mut S, input: &mut BytesInput) -> Result<MutationResult, Error> {
        self.normalize_len(input);
        let windows = self.current_windows(input.mutator_bytes());
        if windows.is_empty() {
            return Ok(MutationResult::Skipped);
        }

        let window_rounds = 1 + ((state.rand_mut().next() as usize) % 4);
        let mut mutated = false;
        for _ in 0..window_rounds {
            let idx = (state.rand_mut().next() as usize) % windows.len();
            mutated |= self.mutate_window(state, input, windows[idx])? == MutationResult::Mutated;
        }

        if input.len() > Self::MAX_TOTAL_LEN {
            input.resize(Self::MAX_TOTAL_LEN, 0);
        }

        Ok(if mutated {
            MutationResult::Mutated
        } else {
            MutationResult::Skipped
        })
    }

    fn post_exec(&mut self, _state: &mut S, _new_corpus_id: Option<CorpusId>) -> Result<(), Error> {
        Ok(())
    }
}
