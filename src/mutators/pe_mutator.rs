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
    FixedSizeHavocMutationsType, FsgPostdecodeMutator, Pec3Operation11Mode2Mutator,
    Pec3Operation11Mutator, Pec3PostdecodeMutator, Pec3StreamWindowMutator,
};

pub enum BDCoreMutator {
    Fsg(FsgPostdecodeMutator),
    Pec3(Pec3PostdecodeMutator),
    Pec3Operation11(Pec3Operation11Mutator),
    Pec3Operation11Mode2(Pec3Operation11Mode2Mutator),
    Pec3Stream(Pec3StreamWindowMutator),
    Mopt(StdMOptMutator<HavocMutationsType>),
    MoptFixed(StdMOptMutator<FixedSizeHavocMutationsType>),
}

impl Named for BDCoreMutator {
    fn name(&self) -> &Cow<'static, str> {
        match self {
            Self::Fsg(m) => m.name(),
            Self::Pec3(m) => m.name(),
            Self::Pec3Operation11(m) => m.name(),
            Self::Pec3Operation11Mode2(m) => m.name(),
            Self::Pec3Stream(m) => m.name(),
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
            Self::Fsg(m) => m.mutate(state, input),
            Self::Pec3(m) => m.mutate(state, input),
            Self::Pec3Operation11(m) => m.mutate(state, input),
            Self::Pec3Operation11Mode2(m) => m.mutate(state, input),
            Self::Pec3Stream(m) => m.mutate(state, input),
            Self::Mopt(m) => m.mutate(state, input),
            Self::MoptFixed(m) => m.mutate(state, input),
        }
    }

    fn post_exec(&mut self, state: &mut S, new_corpus_id: Option<CorpusId>) -> Result<(), Error> {
        match self {
            Self::Fsg(m) => m.post_exec(state, new_corpus_id),
            Self::Pec3(m) => m.post_exec(state, new_corpus_id),
            Self::Pec3Operation11(m) => m.post_exec(state, new_corpus_id),
            Self::Pec3Operation11Mode2(m) => m.post_exec(state, new_corpus_id),
            Self::Pec3Stream(m) => m.post_exec(state, new_corpus_id),
            Self::Mopt(m) => m.post_exec(state, new_corpus_id),
            Self::MoptFixed(m) => m.post_exec(state, new_corpus_id),
        }
    }
}
