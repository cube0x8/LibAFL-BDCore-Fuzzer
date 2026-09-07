pub const FSG_INPUT_MAGIC: &[u8; 4] = b"FSGP";
pub const FSG_INPUT_HEADER_LEN: usize = 0x10;

#[derive(Clone, Copy, Debug)]
pub struct FsgInput<'a> {
    pub start: u32,
    pub base: u32,
    pub mode: u32,
    pub image: &'a [u8],
}

pub fn parse_fsg_input(input: &[u8]) -> Option<FsgInput<'_>> {
    if input.get(..4)? != FSG_INPUT_MAGIC {
        return None;
    }

    Some(FsgInput {
        start: u32::from_le_bytes(input.get(4..8)?.try_into().ok()?),
        base: u32::from_le_bytes(input.get(8..12)?.try_into().ok()?),
        mode: u32::from_le_bytes(input.get(12..16)?.try_into().ok()?),
        image: input.get(FSG_INPUT_HEADER_LEN..)?,
    })
}
