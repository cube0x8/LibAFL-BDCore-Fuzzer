use std::{borrow::Cow, ops::Range};

use libafl::{
    corpus::CorpusId,
    inputs::{BytesInput, HasMutatorBytes},
    mutators::{HavocScheduledMutator, MutationResult, Mutator},
    state::{HasCorpus, HasMaxSize, HasRand, HasSolutions},
    Error, HasMetadata,
};
use libafl_bolts::{rands::Rand, Named};

use crate::inputs::pec3_operation11::{
    parse_pec3_operation11_input, parse_pec3_operation11_mode2_input, PEC3_OPERATION11_HEADER_LEN,
    PEC3_OPERATION11_MAGIC, PEC3_OPERATION11_MODE2_ENTRY_LEN, PEC3_OPERATION11_MODE2_HEADER_LEN,
    PEC3_OPERATION11_MODE2_MAGIC,
};

use super::havoc_fixed_size_mutations;

const HEADER_SIZE: usize = 12;
const MAGIC: &[u8; 4] = b"P3PD";
const DECODED_SIZE: usize = 0x1730;
const VARIANT_OFFSET: usize = 0xA34;
const VARIANT_SIGNATURE_SIZE: usize = 12;
const FORMAT_HEADER: usize = 0x900;
const RECORD_SIZE: usize = 0x1C;
const ORIGINAL_RECORDS: usize = 0x950;
const OPERATION11_TRANSFORMS: &[u32] = &[
    0x0574_2D02,
    0x0AD6_5946,
    0x2DDC_8355,
    0xA858_1CF6,
    0xDC72_A75E,
    0xE31E_B186,
];
const OPERATION11_MODE2_TRANSFORMS: &[u32] = &[
    0x0574_2D02,
    0x0A8F_34C6,
    0x0E1A_9A6D,
    0x2206_D540,
    0x27AE_6619,
    0x2A5C_D85C,
    0x3222_ACEF,
    0x3D96_1CCE,
    0x4BF6_9E5E,
    0x4D81_71FF,
    0x50E5_7DBC,
    0x6592_C532,
    0x6963_B234,
    0x6DF6_E3E1,
    0x71BD_3A21,
    0x7C3F_93AD,
    0x8DA2_D1C1,
    0x98BF_66DD,
    0xA5AF_6041,
    0xA6F6_790B,
    0xB0F1_5000,
    0xB139_9FFB,
    0xC2E8_ADE6,
    0xC8A9_C60C,
    0xDF49_9370,
    0xE34F_2D74,
    0xF02A_6472,
    0xF59F_D30B,
    0xF629_B04F,
];
const OPERATION11_MODE2_VALID_ENTRIES: &[(u32, u32, Option<[u8; 8]>)] = &[
    (0x0574_2D02, 0x32CC_55DF, None),
    (0x0A8F_34C6, 0x6511_E0D3, None),
    (0x0E1A_9A6D, 0x6511_E0D3, None),
    (0x2206_D540, 0x6511_E0D3, None),
    (0x27AE_6619, 0x6511_E0D3, None),
    (0x2A5C_D85C, 0x6511_E0D3, None),
    (0x3222_ACEF, 0, None),
    (0x3D96_1CCE, 0, None),
    (0x4BF6_9E5E, 0x6511_E0D3, None),
    (0x4D81_71FF, 0x6511_E0D3, None),
    (0x50E5_7DBC, 0x6511_E0D3, None),
    (0x6592_C532, 0x6511_E0D3, None),
    (0x6963_B234, 0x6511_E0D3, None),
    (
        0x6DF6_E3E1,
        0x73EA_A31A,
        Some([0xD4, 0x1D, 0x8C, 0xD9, 0x8F, 0x00, 0xB2, 0x5B]),
    ),
    (0x71BD_3A21, 0, None),
    (0x7C3F_93AD, 0x6511_E0D3, None),
    (0x8DA2_D1C1, 0x6511_E0D3, None),
    (0x98BF_66DD, 0, None),
    (0xA5AF_6041, 0x6511_E0D3, None),
    (0xA6F6_790B, 0x7FFF_FFFF, None),
    (0xB0F1_5000, 0x7FFF_FFFF, None),
    (0xB139_9FFB, 0x6511_E0D3, None),
    (0xC2E8_ADE6, 4, None),
    (0xC8A9_C60C, 0, None),
    (0xDF49_9370, 0, None),
    (0xE34F_2D74, 1, None),
    (0xF02A_6472, 0, None),
    (0xF59F_D30B, 0x6511_E0D3, None),
    (0xF629_B04F, 0x6511_E0D3, None),
];

#[derive(Default)]
pub struct Pec3PostdecodeMutator;

#[derive(Default)]
pub struct Pec3Operation11Mutator;

#[derive(Default)]
pub struct Pec3Operation11Mode2Mutator;

#[derive(Default)]
pub struct Pec3StreamWindowMutator {
    control_only: bool,
    main_only: bool,
    heap_poison: bool,
}

const PEVIEWER_MAIN_READ: Range<usize> = 0x6D620..0x6E199;
const PEVIEWER_STAGE28_READ: Range<usize> = 0x6E199..0x6E1C1;
const PEVIEWER_STAGE10_READ: Range<usize> = 0x6E244..0x6E254;
const PEVIEWER_STAGE40_READ: Range<usize> = 0x6E268..0x6E2A8;
const PEVIEWER_FILE_SIZE: usize = 0x6E400;

const PEVIEWER_READ_WINDOWS: [Range<usize>; 4] = [
    PEVIEWER_MAIN_READ,
    PEVIEWER_STAGE28_READ,
    PEVIEWER_STAGE10_READ,
    PEVIEWER_STAGE40_READ,
];

// Keep the high-volume decoded body dominant while still perturbing the three
// records that select offsets, sizes, and transform behavior.
const PEVIEWER_WEIGHTED_WINDOWS: [usize; 10] = [0, 0, 0, 0, 0, 0, 1, 1, 2, 3];
const PEVIEWER_CONTROL_WINDOWS: [usize; 4] = [1, 1, 2, 3];

impl Pec3StreamWindowMutator {
    pub fn new(control_only: bool, main_only: bool, heap_poison: bool) -> Self {
        Self {
            control_only,
            main_only,
            heap_poison,
        }
    }
}

fn decoded_offset(offset: usize) -> usize {
    HEADER_SIZE + offset
}

fn write_u16(bytes: &mut [u8], offset: usize, value: u16) -> bool {
    let Some(destination) = bytes.get_mut(offset..offset.saturating_add(2)) else {
        return false;
    };
    destination.copy_from_slice(&value.to_le_bytes());
    true
}

fn write_u32(bytes: &mut [u8], offset: usize, value: u32) -> bool {
    let Some(destination) = bytes.get_mut(offset..offset.saturating_add(4)) else {
        return false;
    };
    destination.copy_from_slice(&value.to_le_bytes());
    true
}

fn read_u32(bytes: &[u8], offset: usize) -> Option<u32> {
    Some(u32::from_le_bytes(
        bytes.get(offset..offset.checked_add(4)?)?.try_into().ok()?,
    ))
}

fn choose_u16<S: HasRand>(state: &mut S, values: &[u16]) -> u16 {
    values[state.rand_mut().next() as usize % values.len()]
}

fn choose_u32<S: HasRand>(state: &mut S, values: &[u32]) -> u32 {
    values[state.rand_mut().next() as usize % values.len()]
}

fn mutate_window<S>(
    state: &mut S,
    input: &mut BytesInput,
    range: Range<usize>,
    max_stack_pow: usize,
) -> Result<bool, Error>
where
    S: HasRand + HasMetadata + HasCorpus<BytesInput> + HasSolutions<BytesInput> + HasMaxSize,
{
    let Some(window) = input.mutator_bytes().get(range.clone()) else {
        return Ok(false);
    };
    if window.is_empty() {
        return Ok(false);
    }

    let mut staged = BytesInput::new(window.to_vec());
    let mut havoc =
        HavocScheduledMutator::with_max_stack_pow(havoc_fixed_size_mutations(), max_stack_pow);
    if havoc.mutate(state, &mut staged)? != MutationResult::Mutated
        || staged.mutator_bytes().len() != range.len()
    {
        return Ok(false);
    }
    input.mutator_bytes_mut()[range].copy_from_slice(staged.mutator_bytes());
    Ok(true)
}

fn mutate_format_header<S: HasRand>(state: &mut S, input: &mut BytesInput) -> bool {
    let field = [0usize, 0x0C, 0x30, 0x34, 0x3C, 0x40, 0x44, 0x48, 0x4C]
        [state.rand_mut().next() as usize % 9];
    let bytes = input.mutator_bytes_mut();
    let base = decoded_offset(FORMAT_HEADER);

    if field == 0 {
        return write_u16(
            bytes,
            base,
            choose_u16(state, &[0, 4, 0x1C, 0x4C, 0x50, 0x54, 0x7C, 0x130, 0xFFFF]),
        );
    }

    let values: &[u32] = if field == 0x3C {
        &[0, 1, 2, 7, 8, 9, 19, 20, 21, u32::MAX]
    } else {
        &[
            0,
            1,
            4,
            0x14,
            0x1C,
            0x50,
            0x8FC,
            0x900,
            0x950,
            0xA30,
            0xA34,
            0x172C,
            0x1730,
            0x7FFF_FFFF,
            0x8000_0000,
            u32::MAX,
        ]
    };
    write_u32(bytes, base + field, choose_u32(state, values))
}

fn mutate_record_field<S: HasRand>(state: &mut S, input: &mut BytesInput) -> bool {
    let record_index = state.rand_mut().next() as usize % 20;
    let record = ORIGINAL_RECORDS + record_index * RECORD_SIZE;
    if record + RECORD_SIZE > DECODED_SIZE {
        return false;
    }
    let field = [0usize, 4, 8, 0x0C, 0x10, 0x14, 0x18, 0x1A][state.rand_mut().next() as usize % 8];
    let bytes = input.mutator_bytes_mut();
    let absolute = decoded_offset(record + field);

    match field {
        0x10 => write_u32(
            bytes,
            absolute,
            choose_u32(state, &[0, 1, 2, 4, 0x10, 0x12, 0xFFFF_FFFF]),
        ),
        0x18 | 0x1A => write_u16(
            bytes,
            absolute,
            choose_u16(state, &[0, 1, 2, 7, 8, 0x13, 0x14, 0xFFFF]),
        ),
        _ => write_u32(
            bytes,
            absolute,
            choose_u32(
                state,
                &[
                    0,
                    1,
                    4,
                    0x14,
                    0x1C,
                    0x100,
                    0x8FC,
                    0x900,
                    0x950,
                    0xA30,
                    0x172C,
                    0x1730,
                    0x7FFF_FFFF,
                    0x8000_0000,
                    u32::MAX,
                ],
            ),
        ),
    }
}

fn havoc_record<S>(state: &mut S, input: &mut BytesInput) -> Result<bool, Error>
where
    S: HasRand + HasMetadata + HasCorpus<BytesInput> + HasSolutions<BytesInput> + HasMaxSize,
{
    let record_index = state.rand_mut().next() as usize % 20;
    let record = ORIGINAL_RECORDS + record_index * RECORD_SIZE;
    mutate_window(
        state,
        input,
        decoded_offset(record)..decoded_offset(record + RECORD_SIZE),
        1,
    )
}

fn havoc_payload<S>(state: &mut S, input: &mut BytesInput) -> Result<bool, Error>
where
    S: HasRand + HasMetadata + HasCorpus<BytesInput> + HasSolutions<BytesInput> + HasMaxSize,
{
    let anchors = [
        0usize,
        FORMAT_HEADER,
        ORIGINAL_RECORDS,
        0xA30,
        0xB00,
        0x1000,
        0x1504,
        DECODED_SIZE - 4,
    ];
    let anchor = anchors[state.rand_mut().next() as usize % anchors.len()];
    let width = [4usize, 8, 16, 20, 28, 32, 64, 128][state.rand_mut().next() as usize % 8]
        .min(DECODED_SIZE);
    let jitter = state.rand_mut().next() as usize % 0x41;
    let start = anchor.saturating_sub(jitter).min(DECODED_SIZE - width);
    mutate_window(
        state,
        input,
        decoded_offset(start)..decoded_offset(start + width),
        1,
    )
}

fn restore_contract(input: &mut BytesInput, variant_signature: &[u8; VARIANT_SIGNATURE_SIZE]) {
    let bytes = input.mutator_bytes_mut();
    bytes[..4].copy_from_slice(MAGIC);
    bytes[4..8].copy_from_slice(&(DECODED_SIZE as u32).to_le_bytes());
    bytes[8..12].copy_from_slice(&(VARIANT_OFFSET as u32).to_le_bytes());
    let signature = decoded_offset(VARIANT_OFFSET);
    bytes[signature..signature + VARIANT_SIGNATURE_SIZE].copy_from_slice(variant_signature);
}

fn operation11_offset_values(image_size: u32) -> [u32; 14] {
    [
        0,
        1,
        2,
        4,
        0xFFC,
        0x1000,
        0x1001,
        image_size.saturating_sub(0x1000),
        image_size.saturating_sub(4),
        image_size.saturating_sub(2),
        image_size.saturating_sub(1),
        image_size,
        image_size.saturating_add(1),
        u32::MAX,
    ]
}

fn mutate_operation11_range<S: HasRand>(
    state: &mut S,
    input: &mut BytesInput,
    image_size: u32,
    payload_length: u32,
) -> bool {
    let offsets = operation11_offset_values(image_size);
    let source_offset = choose_u32(state, &offsets);
    let remaining = image_size.saturating_sub(source_offset);
    let source_sizes = [
        0,
        1,
        2,
        4,
        0x10,
        0x100,
        0x1000,
        payload_length.saturating_sub(1),
        payload_length,
        payload_length.saturating_add(1),
        remaining.saturating_sub(1),
        remaining,
        remaining.saturating_add(1),
        u32::MAX,
    ];
    let source_size = choose_u32(state, &source_sizes);
    let wrote_offset = write_u32(input.mutator_bytes_mut(), 8, source_offset);
    let wrote_size = write_u32(input.mutator_bytes_mut(), 0x10, source_size);
    wrote_offset && wrote_size
}

fn mutate_operation11_field<S: HasRand>(
    state: &mut S,
    input: &mut BytesInput,
    image_size: u32,
    payload_length: u32,
) -> bool {
    match state.rand_mut().next() % 5 {
        0 => mutate_operation11_range(state, input, image_size, payload_length),
        1 => write_u32(
            input.mutator_bytes_mut(),
            0xC,
            choose_u32(state, &operation11_offset_values(image_size)),
        ),
        2 => write_u32(
            input.mutator_bytes_mut(),
            0x14,
            choose_u32(
                state,
                &[
                    0,
                    1,
                    2,
                    4,
                    0xFF,
                    0x100,
                    0xFFF,
                    0x1000,
                    0x15FBB5,
                    0x7FFF_FFFF,
                    0x8000_0000,
                    u32::MAX,
                ],
            ),
        ),
        3 => write_u32(
            input.mutator_bytes_mut(),
            0x18,
            choose_u32(state, OPERATION11_TRANSFORMS),
        ),
        _ => {
            let source_offset = read_u32(input.mutator_bytes(), 8).unwrap_or(0);
            let available = image_size.saturating_sub(source_offset);
            let bounded = available.min(payload_length);
            let values = [
                0,
                1.min(bounded),
                4.min(bounded),
                0x10.min(bounded),
                0x100.min(bounded),
                bounded / 2,
                bounded.saturating_sub(1),
                bounded,
            ];
            write_u32(input.mutator_bytes_mut(), 0x1C, choose_u32(state, &values))
        }
    }
}

fn havoc_operation11_payload<S>(state: &mut S, input: &mut BytesInput) -> Result<bool, Error>
where
    S: HasRand + HasMetadata + HasCorpus<BytesInput> + HasSolutions<BytesInput> + HasMaxSize,
{
    let payload_length = input
        .mutator_bytes()
        .len()
        .saturating_sub(PEC3_OPERATION11_HEADER_LEN);
    if payload_length == 0 {
        return Ok(false);
    }
    let width = 1 + state.rand_mut().next() as usize % payload_length.min(256);
    let relative = state.rand_mut().next() as usize % (payload_length - width + 1);
    let start = PEC3_OPERATION11_HEADER_LEN + relative;
    mutate_window(state, input, start..start + width, 1)
}

fn restore_operation11_contract(input: &mut BytesInput, image_size: u32, payload_length: u32) {
    let bytes = input.mutator_bytes_mut();
    bytes[..4].copy_from_slice(PEC3_OPERATION11_MAGIC);
    let _ = write_u32(bytes, 4, image_size);
    let _ = write_u32(bytes, 0x20, payload_length);
}

fn mode2_payload_offset(entry_capacity: u32) -> Option<usize> {
    PEC3_OPERATION11_MODE2_HEADER_LEN
        .checked_add((entry_capacity as usize).checked_mul(PEC3_OPERATION11_MODE2_ENTRY_LEN)?)
}

fn mutate_operation11_mode2_range<S: HasRand>(
    state: &mut S,
    input: &mut BytesInput,
    image_size: u32,
    payload_length: u32,
) -> bool {
    let current_source = read_u32(input.mutator_bytes(), 8).unwrap_or(0);
    let mut offsets = operation11_offset_values(image_size).to_vec();
    offsets.push(current_source);
    let source_offset = choose_u32(state, &offsets);
    let available = image_size.saturating_sub(source_offset).min(payload_length);
    let length_values = [
        0,
        1.min(available),
        4.min(available),
        0x10.min(available),
        0x100.min(available),
        0x1000.min(available),
        available / 2,
        available.saturating_sub(1),
        available,
    ];
    let prefix_length = choose_u32(state, &length_values);
    let source_length = choose_u32(state, &length_values);
    let total_length = prefix_length.saturating_add(source_length);
    write_u32(input.mutator_bytes_mut(), 8, source_offset)
        & write_u32(input.mutator_bytes_mut(), 0x10, prefix_length)
        & write_u32(input.mutator_bytes_mut(), 0x14, total_length)
}

fn mutate_operation11_mode2_entry<S: HasRand>(
    state: &mut S,
    input: &mut BytesInput,
    entry_capacity: u32,
    record_count: u32,
) -> bool {
    if entry_capacity == 0 {
        return false;
    }
    let active_count = record_count.clamp(1, entry_capacity) as usize;
    let index_limit = if state.rand_mut().next() % 4 == 0 {
        entry_capacity as usize
    } else {
        active_count
    };
    let index = state.rand_mut().next() as usize % index_limit;
    let offset = PEC3_OPERATION11_MODE2_HEADER_LEN + index * PEC3_OPERATION11_MODE2_ENTRY_LEN;
    match state.rand_mut().next() % 6 {
        0..=2 => {
            let tuple_index =
                state.rand_mut().next() as usize % OPERATION11_MODE2_VALID_ENTRIES.len();
            let (selector, auxiliary, implicit_key) = OPERATION11_MODE2_VALID_ENTRIES[tuple_index];
            let mut changed = write_u32(input.mutator_bytes_mut(), offset, selector);
            changed |= write_u32(input.mutator_bytes_mut(), offset + 4, auxiliary);
            changed |= write_u32(
                input.mutator_bytes_mut(),
                offset + 8,
                u32::from(implicit_key.is_some()),
            );
            let key = implicit_key.unwrap_or_default();
            if let Some(destination) = input.mutator_bytes_mut().get_mut(offset + 12..offset + 20) {
                changed |= destination != key;
                destination.copy_from_slice(&key);
            }
            changed
        }
        3 => write_u32(
            input.mutator_bytes_mut(),
            offset,
            choose_u32(state, OPERATION11_MODE2_TRANSFORMS),
        ),
        4 => write_u32(
            input.mutator_bytes_mut(),
            offset + 4,
            choose_u32(
                state,
                &[0, 1, 4, 0x32CC_55DF, 0x7FFF_FFFF, 0x8000_0000, u32::MAX],
            ),
        ),
        5 => {
            let enabled = (state.rand_mut().next() & 1) as u32;
            let mut changed = write_u32(input.mutator_bytes_mut(), offset + 8, enabled);
            let key_offset = offset + 12 + state.rand_mut().next() as usize % 8;
            let value = state.rand_mut().next() as u8;
            let bytes = input.mutator_bytes_mut();
            let Some(current) = bytes.get_mut(key_offset) else {
                return changed;
            };
            changed |= *current != value;
            *current = value;
            changed
        }
        _ => false,
    }
}

fn havoc_operation11_mode2_payload<S>(
    state: &mut S,
    input: &mut BytesInput,
    entry_capacity: u32,
) -> Result<bool, Error>
where
    S: HasRand + HasMetadata + HasCorpus<BytesInput> + HasSolutions<BytesInput> + HasMaxSize,
{
    let Some(start) = mode2_payload_offset(entry_capacity) else {
        return Ok(false);
    };
    let payload_length = input.mutator_bytes().len().saturating_sub(start);
    if payload_length == 0 {
        return Ok(false);
    }
    let width = 1 + state.rand_mut().next() as usize % payload_length.min(256);
    let relative = state.rand_mut().next() as usize % (payload_length - width + 1);
    mutate_window(state, input, start + relative..start + relative + width, 1)
}

fn restore_operation11_mode2_contract(
    input: &mut BytesInput,
    image_size: u32,
    entry_capacity: u32,
    payload_length: u32,
) {
    let bytes = input.mutator_bytes_mut();
    bytes[..4].copy_from_slice(PEC3_OPERATION11_MODE2_MAGIC);
    let _ = write_u32(bytes, 4, image_size);
    let record_count = if entry_capacity == 0 {
        0
    } else {
        read_u32(bytes, 0x18).unwrap_or(1).clamp(1, entry_capacity)
    };
    let _ = write_u32(bytes, 0x18, record_count);
    let _ = write_u32(bytes, 0x1c, entry_capacity);
    let _ = write_u32(bytes, 0x20, payload_length);
    for index in 0..entry_capacity as usize {
        let offset =
            PEC3_OPERATION11_MODE2_HEADER_LEN + index * PEC3_OPERATION11_MODE2_ENTRY_LEN + 8;
        let enabled = read_u32(bytes, offset).unwrap_or(0) != 0;
        let _ = write_u32(bytes, offset, u32::from(enabled));
    }
    let total_length = read_u32(bytes, 0x14).unwrap_or(0);
    let prefix_length = read_u32(bytes, 0x10).unwrap_or(0).min(total_length);
    let _ = write_u32(bytes, 0x10, prefix_length);
}

impl Named for Pec3PostdecodeMutator {
    fn name(&self) -> &Cow<'static, str> {
        static NAME: Cow<'static, str> = Cow::Borrowed("Pec3PostdecodeMutator");
        &NAME
    }
}

impl Named for Pec3Operation11Mutator {
    fn name(&self) -> &Cow<'static, str> {
        static NAME: Cow<'static, str> = Cow::Borrowed("Pec3Operation11Mutator");
        &NAME
    }
}

impl Named for Pec3Operation11Mode2Mutator {
    fn name(&self) -> &Cow<'static, str> {
        static NAME: Cow<'static, str> = Cow::Borrowed("Pec3Operation11Mode2Mutator");
        &NAME
    }
}

impl Named for Pec3StreamWindowMutator {
    fn name(&self) -> &Cow<'static, str> {
        static NAME: Cow<'static, str> = Cow::Borrowed("Pec3StreamWindowMutator");
        &NAME
    }
}

impl<S> Mutator<BytesInput, S> for Pec3StreamWindowMutator
where
    S: HasRand + HasMetadata + HasCorpus<BytesInput> + HasSolutions<BytesInput> + HasMaxSize,
{
    fn mutate(&mut self, state: &mut S, input: &mut BytesInput) -> Result<MutationResult, Error> {
        if input.mutator_bytes().len() < PEVIEWER_STAGE40_READ.end {
            return Ok(MutationResult::Skipped);
        }

        if self.heap_poison {
            if input.mutator_bytes().len() <= PEVIEWER_FILE_SIZE {
                return Ok(MutationResult::Skipped);
            }
            let range = if state.rand_mut().next() % 4 == 0 {
                PEVIEWER_MAIN_READ
            } else {
                PEVIEWER_FILE_SIZE..input.mutator_bytes().len()
            };
            let mutated = mutate_window(state, input, range, 1)?;
            return Ok(if mutated {
                MutationResult::Mutated
            } else {
                MutationResult::Skipped
            });
        }

        let window = if self.main_only {
            0
        } else if self.control_only {
            let weighted_index = state.rand_mut().next() as usize % PEVIEWER_CONTROL_WINDOWS.len();
            PEVIEWER_CONTROL_WINDOWS[weighted_index]
        } else {
            let weighted_index = state.rand_mut().next() as usize % PEVIEWER_WEIGHTED_WINDOWS.len();
            PEVIEWER_WEIGHTED_WINDOWS[weighted_index]
        };
        let mutated = mutate_window(state, input, PEVIEWER_READ_WINDOWS[window].clone(), 0)?;

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

impl<S> Mutator<BytesInput, S> for Pec3PostdecodeMutator
where
    S: HasRand + HasMetadata + HasCorpus<BytesInput> + HasSolutions<BytesInput> + HasMaxSize,
{
    fn mutate(&mut self, state: &mut S, input: &mut BytesInput) -> Result<MutationResult, Error> {
        if input.mutator_bytes().len() != HEADER_SIZE + DECODED_SIZE
            || input.mutator_bytes().get(..4) != Some(MAGIC)
        {
            return Ok(MutationResult::Skipped);
        }

        let signature = decoded_offset(VARIANT_OFFSET);
        let variant_signature: [u8; VARIANT_SIGNATURE_SIZE] = input.mutator_bytes()
            [signature..signature + VARIANT_SIGNATURE_SIZE]
            .try_into()
            .unwrap();

        let depth = 1 + state.rand_mut().next() as usize % 4;
        let mut mutated = false;
        for _ in 0..depth {
            mutated |= match state.rand_mut().next() % 100 {
                0..=24 => mutate_format_header(state, input),
                25..=59 => mutate_record_field(state, input),
                60..=79 => havoc_record(state, input)?,
                _ => havoc_payload(state, input)?,
            };
        }
        restore_contract(input, &variant_signature);

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

impl<S> Mutator<BytesInput, S> for Pec3Operation11Mutator
where
    S: HasRand + HasMetadata + HasCorpus<BytesInput> + HasSolutions<BytesInput> + HasMaxSize,
{
    fn mutate(&mut self, state: &mut S, input: &mut BytesInput) -> Result<MutationResult, Error> {
        let Some(parsed) = parse_pec3_operation11_input(input.mutator_bytes()) else {
            return Ok(MutationResult::Skipped);
        };
        let image_size = parsed.image_size;
        let payload_length = parsed.payload.len() as u32;
        let depth = 1 + state.rand_mut().next() as usize % 4;
        let mut mutated = false;
        for _ in 0..depth {
            if state.rand_mut().next() % 4 == 0 {
                mutated |= havoc_operation11_payload(state, input)?;
            } else {
                mutated |= mutate_operation11_field(state, input, image_size, payload_length);
            }
        }
        restore_operation11_contract(input, image_size, payload_length);

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

impl<S> Mutator<BytesInput, S> for Pec3Operation11Mode2Mutator
where
    S: HasRand + HasMetadata + HasCorpus<BytesInput> + HasSolutions<BytesInput> + HasMaxSize,
{
    fn mutate(&mut self, state: &mut S, input: &mut BytesInput) -> Result<MutationResult, Error> {
        let Some(parsed) = parse_pec3_operation11_mode2_input(input.mutator_bytes()) else {
            return Ok(MutationResult::Skipped);
        };
        let image_size = parsed.image_size;
        let entry_capacity = parsed.entry_capacity;
        let record_count = parsed.record_count;
        let payload_length = parsed.payload.len() as u32;
        let depth = 1 + state.rand_mut().next() as usize % 4;
        let mut mutated = false;
        for _ in 0..depth {
            mutated |= match state.rand_mut().next() % 100 {
                0..=39 => havoc_operation11_mode2_payload(state, input, entry_capacity)?,
                40..=59 => mutate_operation11_mode2_range(state, input, image_size, payload_length),
                60..=74 => write_u32(
                    input.mutator_bytes_mut(),
                    0xc,
                    choose_u32(state, &operation11_offset_values(image_size)),
                ),
                75..=84 if entry_capacity != 0 => write_u32(
                    input.mutator_bytes_mut(),
                    0x18,
                    1 + state.rand_mut().next() as u32 % entry_capacity,
                ),
                _ => mutate_operation11_mode2_entry(state, input, entry_capacity, record_count),
            };
        }
        restore_operation11_mode2_contract(input, image_size, entry_capacity, payload_length);

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
