use std::borrow::Cow;

use libafl::{
    corpus::CorpusId,
    inputs::{BytesInput, HasMutatorBytes},
    mutators::{HavocScheduledMutator, MutationResult, Mutator},
    state::{HasCorpus, HasMaxSize, HasRand, HasSolutions},
    Error, HasMetadata,
};
use libafl_bolts::{rands::Rand, HasLen, Named};

use crate::inputs::fsg::{parse_fsg_input, FSG_INPUT_HEADER_LEN, FSG_INPUT_MAGIC};

use super::havoc_fixed_size_mutations;

const MODE20: u32 = 20;
const VALID_MODES: &[u32] = &[20, 100, 131, 133];

#[derive(Default)]
pub struct FsgPostdecodeMutator;

fn write_u32(bytes: &mut [u8], offset: usize, value: u32) -> bool {
    let Some(dst) = bytes.get_mut(offset..offset.saturating_add(4)) else {
        return false;
    };
    dst.copy_from_slice(&value.to_le_bytes());
    true
}

fn choose_u32<S: HasRand>(state: &mut S, values: &[u32]) -> u32 {
    values[state.rand_mut().next() as usize % values.len()]
}

fn havoc_image_window<S>(state: &mut S, input: &mut BytesInput) -> Result<bool, Error>
where
    S: HasRand + HasMetadata + HasCorpus<BytesInput> + HasSolutions<BytesInput> + HasMaxSize,
{
    let image_len = input.len().saturating_sub(FSG_INPUT_HEADER_LEN);
    if image_len == 0 {
        return Ok(false);
    }
    let mutation_len = 1 + state.rand_mut().next() as usize % image_len.min(64);
    let relative = state.rand_mut().next() as usize % (image_len - mutation_len + 1);
    let start = FSG_INPUT_HEADER_LEN + relative;
    let mut staged = BytesInput::new(input.mutator_bytes()[start..start + mutation_len].to_vec());
    let mut havoc = HavocScheduledMutator::with_max_stack_pow(havoc_fixed_size_mutations(), 1);
    if havoc.mutate(state, &mut staged)? != MutationResult::Mutated
        || staged.mutator_bytes().len() != mutation_len
    {
        return Ok(false);
    }
    input.mutator_bytes_mut()[start..start + mutation_len].copy_from_slice(staged.mutator_bytes());
    Ok(true)
}

fn synthesize_mode20<S: HasRand>(state: &mut S, input: &mut BytesInput) -> bool {
    let Some(parsed) = parse_fsg_input(input.mutator_bytes()) else {
        return false;
    };
    let image_len = parsed.image.len();
    if image_len < 0x100 {
        return false;
    }

    let requested = 1 + state.rand_mut().next() as usize % 32;
    let record_bytes = 20usize.saturating_mul(requested + 1);
    let max_start = image_len
        .saturating_sub(record_bytes)
        .saturating_sub(8 * requested);
    if max_start < 0x40 {
        return false;
    }
    let start = if state.rand_mut().coinflip(0.6) && (parsed.start as usize) <= max_start {
        parsed.start as usize
    } else {
        0x40 + state.rand_mut().next() as usize % (max_start - 0x40 + 1)
    };
    let pair_end = start + requested * 8;
    let target_base = pair_end.max(image_len / 2).min(image_len.saturating_sub(8));
    let target_span = image_len.saturating_sub(target_base);
    let string_base = target_base.saturating_add(requested.saturating_mul(4));
    if target_span < requested.saturating_mul(6).saturating_add(8) {
        return false;
    }

    let base = choose_u32(state, &[0, 0x400000, 0x10000000, 0x7fff0000]);
    let bytes = input.mutator_bytes_mut();
    bytes[..4].copy_from_slice(FSG_INPUT_MAGIC);
    write_u32(bytes, 4, start as u32);
    write_u32(bytes, 8, base);
    write_u32(bytes, 12, MODE20);

    for index in 0..requested {
        let pair = FSG_INPUT_HEADER_LEN + start + index * 8;
        let marker_off = target_base + index * 4;
        let string_off = string_base + index * 2;
        let marker = if index + 1 == requested {
            0xffff_ffff
        } else {
            0x7fff_ffff
        };
        write_u32(bytes, pair, base.wrapping_add(marker_off as u32));
        write_u32(
            bytes,
            pair + 4,
            if index + 1 == requested {
                choose_u32(state, &[0, 1, 0x7fff_ffff, 0x8000_0000, 0xffff_ffff])
            } else {
                base.wrapping_add(string_off as u32)
            },
        );
        write_u32(bytes, FSG_INPUT_HEADER_LEN + marker_off, marker);
        if index + 1 != requested {
            let string = FSG_INPUT_HEADER_LEN + string_off;
            bytes[string] = b'A'.wrapping_add((index % 26) as u8);
            bytes[string + 1] = 0;
        }
    }
    true
}

fn mutate_config<S: HasRand>(state: &mut S, input: &mut BytesInput) -> bool {
    let Some(parsed) = parse_fsg_input(input.mutator_bytes()) else {
        return false;
    };
    let image_len = parsed.image.len() as u32;
    let field = state.rand_mut().next() % 3;
    let bytes = input.mutator_bytes_mut();
    match field {
        0 => write_u32(
            bytes,
            4,
            choose_u32(
                state,
                &[0, 1, 4, 8, 0x6b76, image_len.saturating_sub(1), image_len],
            ),
        ),
        1 => write_u32(
            bytes,
            8,
            choose_u32(state, &[0, 1, 0x400000, 0x7fff_ffff, 0x8000_0000, u32::MAX]),
        ),
        _ => write_u32(bytes, 12, choose_u32(state, VALID_MODES)),
    }
}

impl Named for FsgPostdecodeMutator {
    fn name(&self) -> &Cow<'static, str> {
        static NAME: Cow<'static, str> = Cow::Borrowed("FsgPostdecodeMutator");
        &NAME
    }
}

impl<S> Mutator<BytesInput, S> for FsgPostdecodeMutator
where
    S: HasRand + HasMetadata + HasCorpus<BytesInput> + HasSolutions<BytesInput> + HasMaxSize,
{
    fn mutate(&mut self, state: &mut S, input: &mut BytesInput) -> Result<MutationResult, Error> {
        if parse_fsg_input(input.mutator_bytes()).is_none() {
            return Ok(MutationResult::Skipped);
        }

        let depth = 1 + state.rand_mut().next() as usize % 4;
        let mut mutated = false;
        for _ in 0..depth {
            mutated |= match state.rand_mut().next() % 100 {
                0..=44 => synthesize_mode20(state, input),
                45..=64 => mutate_config(state, input),
                _ => havoc_image_window(state, input)?,
            };
        }
        input.mutator_bytes_mut()[..4].copy_from_slice(FSG_INPUT_MAGIC);
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
