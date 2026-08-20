//! Ethernet II header parsing for controller packet-in handling.

/// The two fields of an Ethernet II header used by the learning-switch
/// controller.
///
/// Only the 14-byte fixed header is parsed; the payload is left to the
/// caller.
#[derive(Debug, Clone)]
pub struct Frame {
    /// Destination MAC.
    pub dst: [u8; 6],
    /// Source MAC.
    pub src: [u8; 6],
}

impl Frame {
    /// Parse the Ethernet header, or `None` if `data` is under 14 bytes.
    #[must_use]
    pub fn parse(data: &[u8]) -> Option<Self> {
        if data.len() < 14 {
            return None;
        }

        let mut dst = [0u8; 6];
        let mut src = [0u8; 6];

        dst.copy_from_slice(data.get(0..6)?);
        src.copy_from_slice(data.get(6..12)?);

        Some(Self { dst, src })
    }

    /// Whether the destination is the broadcast address
    /// `ff:ff:ff:ff:ff:ff`.
    #[must_use]
    pub fn is_broadcast(&self) -> bool {
        self.dst == [0xff; 6]
    }
}
