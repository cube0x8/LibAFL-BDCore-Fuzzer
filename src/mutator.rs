use std::borrow::Cow;

use libafl::{
    corpus::CorpusId,
    inputs::BytesInput,
    mutators::{
        havoc_mutations::HavocMutationsType,
        mutations::{
            BitFlipMutator, ByteAddMutator, ByteDecMutator, ByteFlipMutator,
            ByteInterestingMutator, ByteIncMutator, ByteNegMutator, ByteRandMutator,
            BytesCopyMutator, BytesRandSetMutator, BytesSetMutator, BytesSwapMutator,
            CrossoverReplaceMutator, DwordAddMutator, DwordInterestingMutator, QwordAddMutator,
            WordAddMutator, WordInterestingMutator,
        },
        MutationResult, Mutator, StdMOptMutator,
    },
    state::{HasCorpus, HasMaxSize, HasRand, HasSolutions},
    Error, HasMetadata,
};
use libafl_bolts::{
    Named,
    tuples::{tuple_list, tuple_list_type},
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

pub enum BDCoreMutator {
    Pe(PeMutator),
    Mopt(StdMOptMutator<HavocMutationsType>),
    MoptFixed(StdMOptMutator<FixedSizeHavocMutationsType>),
}

impl Named for BDCoreMutator {
    fn name(&self) -> &Cow<'static, str> {
        match self {
            Self::Pe(m) => m.name(),
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
            Self::Mopt(m) => m.mutate(state, input),
            Self::MoptFixed(m) => m.mutate(state, input),
        }
    }

    fn post_exec(&mut self, state: &mut S, new_corpus_id: Option<CorpusId>) -> Result<(), Error> {
        match self {
            Self::Pe(m) => m.post_exec(state, new_corpus_id),
            Self::Mopt(m) => m.post_exec(state, new_corpus_id),
            Self::MoptFixed(m) => m.post_exec(state, new_corpus_id),
        }
    }
}
