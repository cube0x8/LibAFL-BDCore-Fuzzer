use std::borrow::Cow;

use libafl::{
    corpus::CorpusId,
    inputs::BytesInput,
    mutators::{havoc_mutations::HavocMutationsType, MutationResult, Mutator, StdMOptMutator},
    state::{HasCorpus, HasMaxSize, HasRand, HasSolutions},
    Error, HasMetadata,
};
use libafl_bolts::Named;

use super::{
    BeriaWorkbufMutator, FixedSizeHavocMutationsType, MorphinepStreamMutator, UpackWindowMutator,
};

pub enum BDCoreMutator {
    Beria(BeriaWorkbufMutator),
    Morphinep(MorphinepStreamMutator),
    Upack(UpackWindowMutator),
    Mopt(StdMOptMutator<HavocMutationsType>),
    MoptFixed(StdMOptMutator<FixedSizeHavocMutationsType>),
}

impl Named for BDCoreMutator {
    fn name(&self) -> &Cow<'static, str> {
        match self {
            Self::Beria(m) => m.name(),
            Self::Morphinep(m) => m.name(),
            Self::Upack(m) => m.name(),
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
            Self::Beria(m) => m.mutate(state, input),
            Self::Morphinep(m) => m.mutate(state, input),
            Self::Upack(m) => m.mutate(state, input),
            Self::Mopt(m) => m.mutate(state, input),
            Self::MoptFixed(m) => m.mutate(state, input),
        }
    }

    fn post_exec(&mut self, state: &mut S, new_corpus_id: Option<CorpusId>) -> Result<(), Error> {
        match self {
            Self::Beria(m) => m.post_exec(state, new_corpus_id),
            Self::Morphinep(m) => m.post_exec(state, new_corpus_id),
            Self::Upack(m) => m.post_exec(state, new_corpus_id),
            Self::Mopt(m) => m.post_exec(state, new_corpus_id),
            Self::MoptFixed(m) => m.post_exec(state, new_corpus_id),
        }
    }
}
