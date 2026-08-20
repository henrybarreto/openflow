use crate::protocol::error::{OfError, Result};

/// Reads a fixed-width big-endian integer out of `buf` at `offset`.
///
/// `first_chunk` yields a `&[u8; N]` directly, so there is exactly one
/// fallible step -- the bounds check. Slicing and then `try_into()`ing
/// would add a second, provably unreachable error arm (the slice is
/// already exactly `N` long), which no test could ever exercise.
macro_rules! read_be {
    ($name:ident, $ty:ty, $n:literal) => {
        pub fn $name(buf: &[u8], offset: usize) -> Result<$ty> {
            let bytes = buf
                .get(offset..)
                .and_then(<[u8]>::first_chunk::<$n>)
                .ok_or(OfError::ShortBuffer)?;
            Ok(<$ty>::from_be_bytes(*bytes))
        }
    };
}

read_be!(read_u16, u16, 2);
read_be!(read_u32, u32, 4);
read_be!(read_u64, u64, 8);

/// Convert a body length into a wire `u16`, failing instead of silently
/// truncating (a truncated length desyncs the peer's framing since the full
/// body is still written after it).
pub fn checked_u16_len(len: usize) -> Result<u16> {
    u16::try_from(len).map_err(|_| OfError::InvalidLength(u16::MAX))
}
