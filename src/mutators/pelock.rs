use std::borrow::Cow;

use libafl::{
    corpus::CorpusId,
    inputs::{BytesInput, HasMutatorBytes, HasTargetBytes},
    mutators::{HavocScheduledMutator, MutationResult, Mutator},
    state::{HasCorpus, HasMaxSize, HasRand, HasSolutions},
    Error, HasMetadata,
};
use libafl_bolts::{rands::Rand, AsSlice, Named};
use libafl_pe_mutator::{PeLibAflInput, PeMutator};
use pe_mutator_core::{pe::PeFile, PeInputFingerprint};

use super::havoc_fixed_size_mutations;

const DECODED_STAGE_RAW_OFFSET: usize = 0x11000;
const RECORD_TABLE_OFFSET: usize = DECODED_STAGE_RAW_OFFSET + 0x220;
const RECORD_TABLE_END: usize = DECODED_STAGE_RAW_OFFSET + 0x280;
const RECORD_COUNT_IMMEDIATE: usize = DECODED_STAGE_RAW_OFFSET + 0x1ac;
const TRACKED_ESI_IMMEDIATE: usize = DECODED_STAGE_RAW_OFFSET + 0x1bb;

const RECORD_COUNTS: &[u32] = &[
    0,
    1,
    2,
    0x10,
    0x100,
    0x1fff_ffff,
    0x2000_0000,
    0x3fff_ffff,
    0x4000_0000,
    0x7fff_ffff,
    0x8000_0000,
    u32::MAX,
];

const RECORD_OFFSETS: &[u32] = &[
    0,
    4,
    0x21c,
    0x220,
    0x224,
    0x240,
    0x27c,
    0x280,
    0x2fc,
    0x3fc,
    0x7fff_fffc,
    0x8000_0000,
    0xffff_fffc,
];

fn mutate_record_table<S>(state: &mut S, input: &mut PeLibAflInput) -> Result<bool, Error>
where
    S: HasRand + HasMetadata + HasCorpus<BytesInput> + HasSolutions<BytesInput> + HasMaxSize,
{
    let bytes = input.bytes.mutator_bytes_mut();
    let Some(window) = bytes.get_mut(RECORD_TABLE_OFFSET..RECORD_TABLE_END) else {
        return Ok(false);
    };
    let mutation_len = 4 * (1 + state.rand_mut().next() as usize % 4);
    let slot_count = (window.len() - mutation_len) / 4 + 1;
    let start = 4 * (state.rand_mut().next() as usize % slot_count);
    let range = start..start + mutation_len;
    let mut staged = BytesInput::new(window[range.clone()].to_vec());
    let mut havoc = HavocScheduledMutator::with_max_stack_pow(havoc_fixed_size_mutations(), 0);
    if havoc.mutate(state, &mut staged)? != MutationResult::Mutated
        || staged.mutator_bytes().len() != mutation_len
    {
        return Ok(false);
    }
    window[range].copy_from_slice(staged.mutator_bytes());
    Ok(true)
}

fn mutate_correlated_record_bounds<S>(state: &mut S, input: &mut PeLibAflInput) -> bool
where
    S: HasRand,
{
    let bytes = input.bytes.mutator_bytes_mut();
    if TRACKED_ESI_IMMEDIATE + 4 > bytes.len() {
        return false;
    }

    let count = RECORD_COUNTS[state.rand_mut().next() as usize % RECORD_COUNTS.len()];
    let records_offset = RECORD_OFFSETS[state.rand_mut().next() as usize % RECORD_OFFSETS.len()];
    // Caller invariant: records_offset = tracked_esi - 4 * count + 4 (mod 2^32).
    let tracked_esi = records_offset
        .wrapping_add(count.wrapping_mul(4))
        .wrapping_sub(4);
    bytes[RECORD_COUNT_IMMEDIATE..RECORD_COUNT_IMMEDIATE + 4].copy_from_slice(&count.to_le_bytes());
    bytes[TRACKED_ESI_IMMEDIATE..TRACKED_ESI_IMMEDIATE + 4]
        .copy_from_slice(&tracked_esi.to_le_bytes());
    true
}

pub struct PelockDeepMutator {
    pe: PeMutator,
    min_stack_depth: usize,
    max_stack_depth: usize,
    pe_only: bool,
}

impl PelockDeepMutator {
    pub fn new(
        pe: PeMutator,
        min_stack_depth: usize,
        max_stack_depth: usize,
        pe_only: bool,
    ) -> Self {
        Self {
            pe,
            min_stack_depth,
            max_stack_depth,
            pe_only,
        }
    }
}

impl Named for PelockDeepMutator {
    fn name(&self) -> &Cow<'static, str> {
        static NAME: Cow<'static, str> = Cow::Borrowed("PelockDeepMutator");
        &NAME
    }
}

impl<S> Mutator<PeLibAflInput, S> for PelockDeepMutator
where
    S: HasRand + HasMetadata + HasCorpus<BytesInput> + HasSolutions<BytesInput> + HasMaxSize,
{
    fn mutate(
        &mut self,
        state: &mut S,
        input: &mut PeLibAflInput,
    ) -> Result<MutationResult, Error> {
        let span = self.max_stack_depth - self.min_stack_depth + 1;
        let depth = self.min_stack_depth + state.rand_mut().next() as usize % span;
        let mut mutated = false;
        for _ in 0..depth {
            if self.pe_only {
                mutated |= self.pe.mutate(state, input)? == MutationResult::Mutated;
                continue;
            }
            match state.rand_mut().next() % 10 {
                0..=2 => mutated |= self.pe.mutate(state, input)? == MutationResult::Mutated,
                3..=7 => mutated |= mutate_record_table(state, input)?,
                _ => mutated |= mutate_correlated_record_bounds(state, input),
            }
        }
        if !mutated {
            return Ok(MutationResult::Skipped);
        }

        let bytes = input.bytes.target_bytes();
        let pe = PeFile::parse(bytes.as_slice()).map_err(|e| {
            Error::illegal_argument(format!("Invalid PELock PE after mutation: {e}"))
        })?;
        input.manifest.pe_fingerprint =
            PeInputFingerprint::from_bytes_and_pe(bytes.as_slice(), &pe);
        Ok(MutationResult::Mutated)
    }

    fn post_exec(&mut self, _state: &mut S, _new_corpus_id: Option<CorpusId>) -> Result<(), Error> {
        Ok(())
    }
}
