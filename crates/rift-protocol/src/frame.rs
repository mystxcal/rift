//! Allocation-bounded native datagram framing.

use thiserror::Error;

const MAGIC: [u8; 4] = *b"RIFT";
const VERSION: u8 = 1;
/// Fixed bytes before authenticated payload.
pub const HEADER_LEN: usize = 28;

/// Packet-plane discriminator.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum PacketKind {
    /// Reliable control-plane record.
    Control,
    /// Original source symbol.
    Systematic,
    /// Coded repair symbol.
    Repair,
    /// Delivery, rank, and pressure feedback.
    Feedback,
    /// Path validation or measurement.
    Probe,
    /// Explicitly optional future packet kind.
    Optional(u8),
}

impl PacketKind {
    fn encode(self) -> Result<u8, FrameError> {
        match self {
            Self::Control => Ok(1),
            Self::Systematic => Ok(2),
            Self::Repair => Ok(3),
            Self::Feedback => Ok(4),
            Self::Probe => Ok(5),
            Self::Optional(value) if value <= 0x7f => Ok(value | 0x80),
            Self::Optional(_) => Err(FrameError::InvalidOptionalKind),
        }
    }

    fn decode(value: u8) -> Result<Self, FrameError> {
        match value {
            1 => Ok(Self::Control),
            2 => Ok(Self::Systematic),
            3 => Ok(Self::Repair),
            4 => Ok(Self::Feedback),
            5 => Ok(Self::Probe),
            value if value & 0x80 != 0 => Ok(Self::Optional(value & 0x7f)),
            value => Err(FrameError::UnknownCriticalKind(value)),
        }
    }
}

/// Native packet header authenticated with its payload.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct PacketHeader {
    /// Packet semantic plane.
    pub kind: PacketKind,
    /// Negotiated packet flags.
    pub flags: u16,
    /// Session-local path identity.
    pub path_id: u32,
    /// Key epoch.
    pub key_epoch: u32,
    /// Monotonic packet number within path and epoch.
    pub packet_number: u64,
}

/// Borrowed decoded datagram.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct DecodedFrame<'a> {
    /// Parsed header.
    pub header: PacketHeader,
    /// Payload slice borrowed from the input datagram.
    pub payload: &'a [u8],
}

/// Rejected frame.
#[derive(Clone, Debug, Error, Eq, PartialEq)]
pub enum FrameError {
    /// Datagram is shorter than its declared shape.
    #[error("truncated RIFT datagram")]
    Truncated,
    /// Magic or version is unsupported.
    #[error("unsupported RIFT packet envelope")]
    UnsupportedEnvelope,
    /// Unknown mandatory packet kind.
    #[error("unknown critical packet kind {0}")]
    UnknownCriticalKind(u8),
    /// Optional packet identifiers occupy only the low seven bits.
    #[error("optional packet kind exceeds its seven-bit namespace")]
    InvalidOptionalKind,
    /// Payload exceeds negotiated or representable bounds.
    #[error("packet payload exceeds negotiated bound")]
    PayloadTooLarge,
    /// Datagram length differs from the authenticated declared length.
    #[error("packet length mismatch")]
    LengthMismatch,
}

impl PacketHeader {
    /// Encode a complete native datagram.
    ///
    /// # Errors
    ///
    /// Returns [`FrameError`] when the payload exceeds its negotiated bound or
    /// the packet uses an invalid optional-kind identifier.
    pub fn encode(self, payload: &[u8], max_payload: usize) -> Result<Vec<u8>, FrameError> {
        if payload.len() > max_payload {
            return Err(FrameError::PayloadTooLarge);
        }
        let payload_len = u32::try_from(payload.len()).map_err(|_| FrameError::PayloadTooLarge)?;
        let mut output = Vec::with_capacity(HEADER_LEN + payload.len());
        output.extend_from_slice(&MAGIC);
        output.push(VERSION);
        output.push(self.kind.encode()?);
        output.extend_from_slice(&self.flags.to_be_bytes());
        output.extend_from_slice(&self.path_id.to_be_bytes());
        output.extend_from_slice(&self.key_epoch.to_be_bytes());
        output.extend_from_slice(&self.packet_number.to_be_bytes());
        output.extend_from_slice(&payload_len.to_be_bytes());
        output.extend_from_slice(payload);
        Ok(output)
    }
}

/// Decode one exact native datagram without allocating.
///
/// # Errors
///
/// Returns [`FrameError`] for malformed, unknown-critical, truncated,
/// oversized, or non-exact datagrams.
pub fn decode_datagram(input: &[u8], max_payload: usize) -> Result<DecodedFrame<'_>, FrameError> {
    if input.len() < HEADER_LEN {
        return Err(FrameError::Truncated);
    }
    if input[..4] != MAGIC || input[4] != VERSION {
        return Err(FrameError::UnsupportedEnvelope);
    }
    let kind = PacketKind::decode(input[5])?;
    let flags = u16::from_be_bytes(array(input, 6)?);
    let path_id = u32::from_be_bytes(array(input, 8)?);
    let key_epoch = u32::from_be_bytes(array(input, 12)?);
    let packet_number = u64::from_be_bytes(array(input, 16)?);
    let payload_len = usize::try_from(u32::from_be_bytes(array(input, 24)?))
        .map_err(|_| FrameError::PayloadTooLarge)?;
    if payload_len > max_payload {
        return Err(FrameError::PayloadTooLarge);
    }
    if input.len() != HEADER_LEN + payload_len {
        return Err(FrameError::LengthMismatch);
    }
    Ok(DecodedFrame {
        header: PacketHeader {
            kind,
            flags,
            path_id,
            key_epoch,
            packet_number,
        },
        payload: input.get(HEADER_LEN..).ok_or(FrameError::Truncated)?,
    })
}

fn array<const N: usize>(input: &[u8], offset: usize) -> Result<[u8; N], FrameError> {
    input
        .get(offset..offset + N)
        .ok_or(FrameError::Truncated)?
        .try_into()
        .map_err(|_| FrameError::Truncated)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn header() -> PacketHeader {
        PacketHeader {
            kind: PacketKind::Systematic,
            flags: 3,
            path_id: 9,
            key_epoch: 2,
            packet_number: 44,
        }
    }

    #[test]
    fn exact_round_trip_is_borrowed() {
        let encoded = header().encode(b"payload", 100).unwrap();
        let decoded = decode_datagram(&encoded, 100).unwrap();
        assert_eq!(decoded.header, header());
        assert_eq!(decoded.payload, b"payload");
    }

    #[test]
    fn rejects_trailing_truncated_and_oversized_inputs() {
        let mut encoded = header().encode(b"payload", 100).unwrap();
        assert_eq!(
            decode_datagram(&encoded[..10], 100),
            Err(FrameError::Truncated)
        );
        assert_eq!(
            decode_datagram(&encoded, 3),
            Err(FrameError::PayloadTooLarge)
        );
        encoded.push(0);
        assert_eq!(
            decode_datagram(&encoded, 100),
            Err(FrameError::LengthMismatch)
        );
    }

    #[test]
    fn unknown_kinds_must_explicitly_be_optional() {
        let mut encoded = header().encode(&[], 100).unwrap();
        encoded[5] = 42;
        assert_eq!(
            decode_datagram(&encoded, 100),
            Err(FrameError::UnknownCriticalKind(42))
        );
        encoded[5] = 0x80 | 0x2a;
        assert_eq!(
            decode_datagram(&encoded, 100).unwrap().header.kind,
            PacketKind::Optional(42)
        );
        let invalid = PacketHeader {
            kind: PacketKind::Optional(200),
            ..header()
        };
        assert_eq!(
            invalid.encode(&[], 100),
            Err(FrameError::InvalidOptionalKind)
        );
    }
}
