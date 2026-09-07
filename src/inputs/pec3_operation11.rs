pub const PEC3_OPERATION11_MAGIC: &[u8; 4] = b"P311";
pub const PEC3_OPERATION11_HEADER_LEN: usize = 0x24;
pub const PEC3_OPERATION11_MODE2_MAGIC: &[u8; 4] = b"P312";
pub const PEC3_OPERATION11_MODE2_HEADER_LEN: usize = 0x24;
pub const PEC3_OPERATION11_MODE2_ENTRY_LEN: usize = 0x14;

#[derive(Clone, Copy, Debug)]
pub struct Pec3Operation11Input<'a> {
    pub image_size: u32,
    pub source_offset: u32,
    pub destination_offset: u32,
    pub source_length: u32,
    pub transform_parameter: u32,
    pub transform_selector: u32,
    pub prefix_length: u32,
    pub payload: &'a [u8],
}

#[derive(Clone, Copy, Debug)]
pub struct Pec3Operation11Mode2Entry {
    pub selector: u32,
    pub auxiliary: u32,
    pub implicit_key: Option<[u8; 8]>,
}

#[derive(Clone, Copy, Debug)]
pub struct Pec3Operation11Mode2Input<'a> {
    pub image_size: u32,
    pub source_offset: u32,
    pub destination_offset: u32,
    pub prefix_length: u32,
    pub total_length: u32,
    pub record_count: u32,
    pub entry_capacity: u32,
    entries: &'a [u8],
    pub payload: &'a [u8],
}

impl Pec3Operation11Mode2Input<'_> {
    pub fn entry(&self, index: usize) -> Option<Pec3Operation11Mode2Entry> {
        if index >= self.entry_capacity as usize {
            return None;
        }
        let start = index.checked_mul(PEC3_OPERATION11_MODE2_ENTRY_LEN)?;
        let entry = self
            .entries
            .get(start..start + PEC3_OPERATION11_MODE2_ENTRY_LEN)?;
        Some(Pec3Operation11Mode2Entry {
            selector: u32::from_le_bytes(entry[0..4].try_into().ok()?),
            auxiliary: u32::from_le_bytes(entry[4..8].try_into().ok()?),
            implicit_key: if u32::from_le_bytes(entry[8..12].try_into().ok()?) != 0 {
                Some(entry[12..20].try_into().ok()?)
            } else {
                None
            },
        })
    }
}

pub fn parse_pec3_operation11_input(input: &[u8]) -> Option<Pec3Operation11Input<'_>> {
    if input.get(..4)? != PEC3_OPERATION11_MAGIC {
        return None;
    }
    let payload_length = u32::from_le_bytes(input.get(0x20..0x24)?.try_into().ok()?) as usize;
    let payload = input.get(PEC3_OPERATION11_HEADER_LEN..)?;
    if payload.len() != payload_length {
        return None;
    }

    Some(Pec3Operation11Input {
        image_size: u32::from_le_bytes(input.get(4..8)?.try_into().ok()?),
        source_offset: u32::from_le_bytes(input.get(8..0xc)?.try_into().ok()?),
        destination_offset: u32::from_le_bytes(input.get(0xc..0x10)?.try_into().ok()?),
        source_length: u32::from_le_bytes(input.get(0x10..0x14)?.try_into().ok()?),
        transform_parameter: u32::from_le_bytes(input.get(0x14..0x18)?.try_into().ok()?),
        transform_selector: u32::from_le_bytes(input.get(0x18..0x1c)?.try_into().ok()?),
        prefix_length: u32::from_le_bytes(input.get(0x1c..0x20)?.try_into().ok()?),
        payload,
    })
}

pub fn build_pec3_operation11_input(
    image_size: u32,
    source_offset: u32,
    destination_offset: u32,
    source_length: u32,
    transform_parameter: u32,
    transform_selector: u32,
    prefix_length: u32,
    payload: &[u8],
) -> Vec<u8> {
    let mut output = Vec::with_capacity(PEC3_OPERATION11_HEADER_LEN + payload.len());
    output.extend_from_slice(PEC3_OPERATION11_MAGIC);
    output.extend_from_slice(&image_size.to_le_bytes());
    output.extend_from_slice(&source_offset.to_le_bytes());
    output.extend_from_slice(&destination_offset.to_le_bytes());
    output.extend_from_slice(&source_length.to_le_bytes());
    output.extend_from_slice(&transform_parameter.to_le_bytes());
    output.extend_from_slice(&transform_selector.to_le_bytes());
    output.extend_from_slice(&prefix_length.to_le_bytes());
    output.extend_from_slice(&(payload.len() as u32).to_le_bytes());
    output.extend_from_slice(payload);
    output
}

pub fn parse_pec3_operation11_mode2_input(input: &[u8]) -> Option<Pec3Operation11Mode2Input<'_>> {
    if input.get(..4)? != PEC3_OPERATION11_MODE2_MAGIC {
        return None;
    }
    let entry_capacity = u32::from_le_bytes(input.get(0x1c..0x20)?.try_into().ok()?);
    let payload_length = u32::from_le_bytes(input.get(0x20..0x24)?.try_into().ok()?) as usize;
    let entries_length = (entry_capacity as usize).checked_mul(PEC3_OPERATION11_MODE2_ENTRY_LEN)?;
    let entries_end = PEC3_OPERATION11_MODE2_HEADER_LEN.checked_add(entries_length)?;
    let payload_end = entries_end.checked_add(payload_length)?;
    if payload_end != input.len() {
        return None;
    }

    Some(Pec3Operation11Mode2Input {
        image_size: u32::from_le_bytes(input.get(4..8)?.try_into().ok()?),
        source_offset: u32::from_le_bytes(input.get(8..0xc)?.try_into().ok()?),
        destination_offset: u32::from_le_bytes(input.get(0xc..0x10)?.try_into().ok()?),
        prefix_length: u32::from_le_bytes(input.get(0x10..0x14)?.try_into().ok()?),
        total_length: u32::from_le_bytes(input.get(0x14..0x18)?.try_into().ok()?),
        record_count: u32::from_le_bytes(input.get(0x18..0x1c)?.try_into().ok()?),
        entry_capacity,
        entries: input.get(PEC3_OPERATION11_MODE2_HEADER_LEN..entries_end)?,
        payload: input.get(entries_end..payload_end)?,
    })
}

pub fn build_pec3_operation11_mode2_input(
    image_size: u32,
    source_offset: u32,
    destination_offset: u32,
    prefix_length: u32,
    total_length: u32,
    record_count: u32,
    entries: &[Pec3Operation11Mode2Entry],
    payload: &[u8],
) -> Vec<u8> {
    let entries_length = entries.len() * PEC3_OPERATION11_MODE2_ENTRY_LEN;
    let mut output =
        Vec::with_capacity(PEC3_OPERATION11_MODE2_HEADER_LEN + entries_length + payload.len());
    output.extend_from_slice(PEC3_OPERATION11_MODE2_MAGIC);
    output.extend_from_slice(&image_size.to_le_bytes());
    output.extend_from_slice(&source_offset.to_le_bytes());
    output.extend_from_slice(&destination_offset.to_le_bytes());
    output.extend_from_slice(&prefix_length.to_le_bytes());
    output.extend_from_slice(&total_length.to_le_bytes());
    output.extend_from_slice(&record_count.to_le_bytes());
    output.extend_from_slice(&(entries.len() as u32).to_le_bytes());
    output.extend_from_slice(&(payload.len() as u32).to_le_bytes());
    for entry in entries {
        output.extend_from_slice(&entry.selector.to_le_bytes());
        output.extend_from_slice(&entry.auxiliary.to_le_bytes());
        output.extend_from_slice(&u32::from(entry.implicit_key.is_some()).to_le_bytes());
        output.extend_from_slice(&entry.implicit_key.unwrap_or_default());
    }
    output.extend_from_slice(payload);
    output
}
