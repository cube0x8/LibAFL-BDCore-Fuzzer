use std::borrow::Cow;

use libafl::{
    corpus::{Corpus, CorpusId},
    inputs::BytesInput,
    mutators::{MutationResult, Mutator, MutatorsTuple, StdMOptMutator},
    state::{HasCorpus, HasRand, HasSolutions},
    Error, HasMetadata,
};
use libafl_bolts::Named;
use libafl_pe_mutator::PeMutator;

pub enum BDCoreMutator<MT> {
    Pe(PeMutator),
    Mopt(StdMOptMutator<MT>),
}

impl<MT> Named for BDCoreMutator<MT>
where
    StdMOptMutator<MT>: Named,
{
    fn name(&self) -> &Cow<'static, str> {
        match self {
            Self::Pe(m) => m.name(),
            Self::Mopt(m) => m.name(),
        }
    }
}

impl<S, MT> Mutator<BytesInput, S> for BDCoreMutator<MT>
where
    S: HasRand + HasMetadata + HasCorpus<BytesInput> + HasSolutions<BytesInput>,
    MT: MutatorsTuple<BytesInput, S>,
    StdMOptMutator<MT>: Named,
{
    fn mutate(&mut self, state: &mut S, input: &mut BytesInput) -> Result<MutationResult, Error> {
        match self {
            Self::Pe(m) => m.mutate(state, input),
            Self::Mopt(m) => m.mutate(state, input),
        }
    }

    fn post_exec(&mut self, state: &mut S, new_corpus_id: Option<CorpusId>) -> Result<(), Error> {
        match self {
            Self::Pe(m) => m.post_exec(state, new_corpus_id),
            Self::Mopt(m) => m.post_exec(state, new_corpus_id),
        }
    }
}
