//! Canonical bounded datagrams for direct-path acquisition and record delivery.
//!
//! The rendezvous relay can parse registration and match envelopes, but it
//! never receives the transfer secret. Probe authentication and all payload
//! protection remain endpoint responsibilities.

use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};

use thiserror::Error;

use crate::Role;

const VERSION: u8 = 1;
const REGISTRATION_MAGIC: [u8; 4] = *b"RFDR";
const MATCH_MAGIC: [u8; 4] = *b"RFDM";
const PROBE_MAGIC: [u8; 4] = *b"RFDP";
const HANDSHAKE_MAGIC: [u8; 4] = *b"RFDH";
const CIPHERTEXT_MAGIC: [u8; 4] = *b"RIFX";

const FRAGMENT: u8 = 1;
const ACK: u8 = 2;
const RECEIPT: u8 = 3;
const CONFIRM: u8 = 4;
const TRIAL: u8 = 5;
const TRIAL_ACK: u8 = 6;
const TRIAL_RESULT: u8 = 7;
const REPAIR: u8 = 8;
const MTU_PROBE: u8 = 9;
const MTU_ACK: u8 = 10;
const MTU_RESULT: u8 = 11;

/// Fixed encoded width of a UDP rendezvous registration.
pub const DIRECT_REGISTRATION_BYTES: usize = 56;
/// Fixed encoded width of a matched peer address response.
pub const DIRECT_MATCH_BYTES: usize = 75;
/// Fixed encoded width of an authenticated connectivity probe.
pub const DIRECT_PROBE_BYTES: usize = 76;
/// Fixed prefix before a Noise handshake message.
pub const DIRECT_HANDSHAKE_HEADER_BYTES: usize = 14;
/// Largest accepted Noise handshake payload.
pub const MAX_DIRECT_HANDSHAKE_BYTES: usize = 1_024;
/// Fixed cleartext prefix before one stateless Noise ciphertext.
pub const DIRECT_CIPHERTEXT_HEADER_BYTES: usize = 22;
/// Minimum UDP payload admitted by path MTU discovery.
pub const MIN_DIRECT_DATAGRAM_BYTES: usize = 1_200;
/// Maximum IPv6-safe UDP payload under a 1,500-byte link MTU.
pub const MAX_DIRECT_DATAGRAM_BYTES: usize = 1_452;
/// Noise transport authentication tag bytes for the selected AEAD.
pub const DIRECT_AEAD_TAG_BYTES: usize = 16;
/// Largest decrypted direct packet body.
pub const MAX_DIRECT_PACKET_BYTES: usize =
    MAX_DIRECT_DATAGRAM_BYTES - DIRECT_CIPHERTEXT_HEADER_BYTES - DIRECT_AEAD_TAG_BYTES;
/// Smallest decrypted direct packet admitted by path MTU discovery.
pub const MIN_DIRECT_PACKET_BYTES: usize =
    MIN_DIRECT_DATAGRAM_BYTES - DIRECT_CIPHERTEXT_HEADER_BYTES - DIRECT_AEAD_TAG_BYTES;
/// Largest logical application record carried over either path.
pub const MAX_SEQUENCED_RECORD_PAYLOAD: usize = 60 * 1_024;
/// Fixed prefix for a globally sequenced logical record.
pub const SEQUENCED_RECORD_HEADER_BYTES: usize = 12;
/// Fixed prefix for a direct data fragment.
pub const DIRECT_FRAGMENT_HEADER_BYTES: usize = 20;
/// Fixed prefix for one direct Cauchy repair symbol.
pub const DIRECT_REPAIR_HEADER_BYTES: usize = 24;
/// Largest direct fragment body.
pub const MAX_DIRECT_FRAGMENT_BYTES: usize = MAX_DIRECT_PACKET_BYTES - DIRECT_REPAIR_HEADER_BYTES;
/// Smallest source-symbol width selected by path MTU discovery.
pub const MIN_DIRECT_FRAGMENT_BYTES: usize = MIN_DIRECT_PACKET_BYTES - DIRECT_REPAIR_HEADER_BYTES;
/// Ordered packetization-layer sizes tested by authenticated PLPMTUD.
pub const DIRECT_MTU_CANDIDATES: [u16; 5] = [1_452, 1_400, 1_280, 1_232, 1_200];
/// Maximum fragments needed for the largest sequenced record.
pub const MAX_DIRECT_FRAGMENTS: usize = (MAX_SEQUENCED_RECORD_PAYLOAD
    + SEQUENCED_RECORD_HEADER_BYTES)
    .div_ceil(MIN_DIRECT_FRAGMENT_BYTES);

/// Convert one admitted UDP payload size into the common source-symbol width.
#[must_use]
pub const fn fragment_bytes_for_datagram(datagram_bytes: usize) -> Option<usize> {
    if datagram_bytes < MIN_DIRECT_DATAGRAM_BYTES || datagram_bytes > MAX_DIRECT_DATAGRAM_BYTES {
        return None;
    }
    Some(
        datagram_bytes
            - DIRECT_CIPHERTEXT_HEADER_BYTES
            - DIRECT_AEAD_TAG_BYTES
            - DIRECT_REPAIR_HEADER_BYTES,
    )
}

/// Padding bytes needed for an exact-size authenticated MTU probe.
#[must_use]
pub const fn mtu_probe_data_bytes(datagram_bytes: usize) -> Option<usize> {
    const PROBE_HEADER: usize = 16;
    if datagram_bytes < MIN_DIRECT_DATAGRAM_BYTES || datagram_bytes > MAX_DIRECT_DATAGRAM_BYTES {
        return None;
    }
    Some(datagram_bytes - DIRECT_CIPHERTEXT_HEADER_BYTES - DIRECT_AEAD_TAG_BYTES - PROBE_HEADER)
}

/// Invalid direct-path envelope or bounded payload.
#[derive(Clone, Debug, Error, Eq, PartialEq)]
pub enum DirectProtocolError {
    /// Envelope does not have the exact expected width.
    #[error("invalid direct-path envelope length")]
    InvalidLength,
    /// Envelope is not the requested RIFT record type.
    #[error("invalid direct-path envelope magic")]
    BadMagic,
    /// Envelope belongs to an unsupported protocol generation.
    #[error("unsupported direct-path envelope version")]
    UnsupportedVersion,
    /// Endpoint role is unknown.
    #[error("unknown direct-path endpoint role")]
    UnknownRole,
    /// Reserved bits, padding, or encoded values are non-canonical.
    #[error("non-canonical direct-path envelope")]
    NonCanonical,
    /// An encoded address family is unsupported.
    #[error("unsupported direct-path address family")]
    UnsupportedAddress,
    /// A bounded payload exceeds the direct protocol ceiling.
    #[error("direct-path payload exceeds its bound")]
    PayloadTooLarge,
    /// Fragment geometry is impossible or inconsistent.
    #[error("invalid direct-path fragment geometry")]
    InvalidFragment,
    /// Encrypted packet type is unknown.
    #[error("unknown direct-path packet type {0}")]
    UnknownPacket(u8),
}

/// Cleartext registration understood by the blind UDP rendezvous service.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct DirectRegistration {
    /// Opaque session lookup shared with the stream rendezvous path.
    pub lookup_id: [u8; 16],
    /// Endpoint role.
    pub role: Role,
    /// Endpoint-generated freshness and path-binding nonce.
    pub nonce: [u8; 16],
    /// Truncated keyed authenticator opaque to the relay.
    pub authenticator: [u8; 16],
}

impl DirectRegistration {
    /// Prefix authenticated by the endpoints' transfer secret.
    #[must_use]
    pub fn authenticated_prefix(lookup_id: [u8; 16], role: Role, nonce: [u8; 16]) -> [u8; 40] {
        let mut output = [0_u8; 40];
        output[..4].copy_from_slice(&REGISTRATION_MAGIC);
        output[4] = VERSION;
        output[5] = encode_role(role);
        output[8..24].copy_from_slice(&lookup_id);
        output[24..].copy_from_slice(&nonce);
        output
    }

    /// Encode the exact registration datagram.
    #[must_use]
    pub fn encode(self) -> [u8; DIRECT_REGISTRATION_BYTES] {
        let mut output = [0_u8; DIRECT_REGISTRATION_BYTES];
        output[..40].copy_from_slice(&Self::authenticated_prefix(
            self.lookup_id,
            self.role,
            self.nonce,
        ));
        output[40..].copy_from_slice(&self.authenticator);
        output
    }

    /// Decode one exact registration datagram.
    ///
    /// # Errors
    ///
    /// Rejects bad framing, roles, versions, or reserved bytes.
    pub fn decode(input: &[u8]) -> Result<Self, DirectProtocolError> {
        exact(input, DIRECT_REGISTRATION_BYTES)?;
        envelope(input, REGISTRATION_MAGIC)?;
        if input[6..8] != [0, 0] {
            return Err(DirectProtocolError::NonCanonical);
        }
        Ok(Self {
            lookup_id: array(input, 8)?,
            role: decode_role(input[5])?,
            nonce: array(input, 24)?,
            authenticator: array(input, 40)?,
        })
    }
}

/// Relay response containing the observed address and nonce of the peer.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct DirectMatch {
    /// Opaque session lookup.
    pub lookup_id: [u8; 16],
    /// Peer registration nonce used to bind path authentication.
    pub peer_nonce: [u8; 16],
    /// Peer's registration authenticator, still opaque to the relay.
    pub peer_authenticator: [u8; 16],
    /// Peer source address observed by the relay.
    pub peer_addr: SocketAddr,
}

impl DirectMatch {
    /// Encode a canonical fixed-width response.
    #[must_use]
    pub fn encode(self) -> [u8; DIRECT_MATCH_BYTES] {
        let mut output = [0_u8; DIRECT_MATCH_BYTES];
        output[..4].copy_from_slice(&MATCH_MAGIC);
        output[4] = VERSION;
        output[8..24].copy_from_slice(&self.lookup_id);
        output[24..40].copy_from_slice(&self.peer_nonce);
        output[40..56].copy_from_slice(&self.peer_authenticator);
        encode_socket(self.peer_addr, &mut output[56..]);
        output
    }

    /// Decode a canonical fixed-width response.
    ///
    /// # Errors
    ///
    /// Rejects malformed envelopes, padding, and address families.
    pub fn decode(input: &[u8]) -> Result<Self, DirectProtocolError> {
        exact(input, DIRECT_MATCH_BYTES)?;
        envelope(input, MATCH_MAGIC)?;
        if input[5..8] != [0, 0, 0] {
            return Err(DirectProtocolError::NonCanonical);
        }
        Ok(Self {
            lookup_id: array(input, 8)?,
            peer_nonce: array(input, 24)?,
            peer_authenticator: array(input, 40)?,
            peer_addr: decode_socket(&input[56..])?,
        })
    }
}

/// Session-authenticated bidirectional connectivity check.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct DirectProbe {
    /// Opaque session lookup.
    pub lookup_id: [u8; 16],
    /// Sender or receiver role.
    pub role: Role,
    /// Deterministic identity of this candidate pair.
    pub path_id: u32,
    /// Fresh challenge generated by this endpoint.
    pub challenge: [u8; 16],
    /// Peer challenge being answered, or all-zero for an initial probe.
    pub response: [u8; 16],
    /// Truncated keyed authenticator over the preceding bytes.
    pub authenticator: [u8; 16],
}

impl DirectProbe {
    /// Prefix authenticated by the transfer secret.
    #[must_use]
    pub fn authenticated_prefix(
        lookup_id: [u8; 16],
        role: Role,
        path_id: u32,
        challenge: [u8; 16],
        response: [u8; 16],
    ) -> [u8; 60] {
        let mut output = [0_u8; 60];
        output[..4].copy_from_slice(&PROBE_MAGIC);
        output[4] = VERSION;
        output[5] = encode_role(role);
        output[8..24].copy_from_slice(&lookup_id);
        output[24..28].copy_from_slice(&path_id.to_be_bytes());
        output[28..44].copy_from_slice(&challenge);
        output[44..].copy_from_slice(&response);
        output
    }

    /// Encode one exact probe.
    #[must_use]
    pub fn encode(self) -> [u8; DIRECT_PROBE_BYTES] {
        let mut output = [0_u8; DIRECT_PROBE_BYTES];
        output[..60].copy_from_slice(&Self::authenticated_prefix(
            self.lookup_id,
            self.role,
            self.path_id,
            self.challenge,
            self.response,
        ));
        output[60..].copy_from_slice(&self.authenticator);
        output
    }

    /// Decode one exact probe.
    ///
    /// # Errors
    ///
    /// Rejects malformed envelopes and reserved bytes before authentication.
    pub fn decode(input: &[u8]) -> Result<Self, DirectProtocolError> {
        exact(input, DIRECT_PROBE_BYTES)?;
        envelope(input, PROBE_MAGIC)?;
        if input[6..8] != [0, 0] {
            return Err(DirectProtocolError::NonCanonical);
        }
        Ok(Self {
            lookup_id: array(input, 8)?,
            role: decode_role(input[5])?,
            path_id: u32::from_be_bytes(array(input, 24)?),
            challenge: array(input, 28)?,
            response: array(input, 44)?,
            authenticator: array(input, 60)?,
        })
    }
}

/// One bounded Noise handshake flight carried over UDP.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct DirectHandshake {
    /// Endpoint sending this flight.
    pub role: Role,
    /// Candidate-pair identity.
    pub path_id: u32,
    /// Noise handshake bytes.
    pub payload: Vec<u8>,
}

impl DirectHandshake {
    /// Encode a bounded handshake datagram.
    ///
    /// # Errors
    ///
    /// Returns [`DirectProtocolError::PayloadTooLarge`] above the fixed bound.
    pub fn encode(&self) -> Result<Vec<u8>, DirectProtocolError> {
        if self.payload.is_empty() || self.payload.len() > MAX_DIRECT_HANDSHAKE_BYTES {
            return Err(DirectProtocolError::PayloadTooLarge);
        }
        let payload_len =
            u16::try_from(self.payload.len()).map_err(|_| DirectProtocolError::PayloadTooLarge)?;
        let mut output = vec![0_u8; DIRECT_HANDSHAKE_HEADER_BYTES + self.payload.len()];
        output[..4].copy_from_slice(&HANDSHAKE_MAGIC);
        output[4] = VERSION;
        output[5] = encode_role(self.role);
        output[8..12].copy_from_slice(&self.path_id.to_be_bytes());
        output[12..14].copy_from_slice(&payload_len.to_be_bytes());
        output[14..].copy_from_slice(&self.payload);
        Ok(output)
    }

    /// Decode one bounded exact handshake flight.
    ///
    /// # Errors
    ///
    /// Rejects truncation, trailing data, empty messages, and oversized input.
    pub fn decode(input: &[u8]) -> Result<Self, DirectProtocolError> {
        if input.len() < DIRECT_HANDSHAKE_HEADER_BYTES {
            return Err(DirectProtocolError::InvalidLength);
        }
        envelope(input, HANDSHAKE_MAGIC)?;
        if input[6..8] != [0, 0] {
            return Err(DirectProtocolError::NonCanonical);
        }
        let payload_len = usize::from(u16::from_be_bytes(array(input, 12)?));
        if payload_len == 0 || payload_len > MAX_DIRECT_HANDSHAKE_BYTES {
            return Err(DirectProtocolError::PayloadTooLarge);
        }
        exact(input, DIRECT_HANDSHAKE_HEADER_BYTES + payload_len)?;
        Ok(Self {
            role: decode_role(input[5])?,
            path_id: u32::from_be_bytes(array(input, 8)?),
            payload: input[14..].to_vec(),
        })
    }
}

/// Globally sequenced application record shared by relay and direct paths.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct SequencedRecord {
    /// Monotonic transfer-global record identity.
    pub sequence: u64,
    /// Existing authenticated stream-oracle record bytes.
    pub payload: Vec<u8>,
}

impl SequencedRecord {
    /// Encode a bounded record.
    ///
    /// # Errors
    ///
    /// Rejects an empty or oversized application payload.
    pub fn encode(&self) -> Result<Vec<u8>, DirectProtocolError> {
        if self.payload.is_empty() || self.payload.len() > MAX_SEQUENCED_RECORD_PAYLOAD {
            return Err(DirectProtocolError::PayloadTooLarge);
        }
        let payload_len =
            u32::try_from(self.payload.len()).map_err(|_| DirectProtocolError::PayloadTooLarge)?;
        let mut output = Vec::with_capacity(SEQUENCED_RECORD_HEADER_BYTES + self.payload.len());
        output.extend_from_slice(&self.sequence.to_be_bytes());
        output.extend_from_slice(&payload_len.to_be_bytes());
        output.extend_from_slice(&self.payload);
        Ok(output)
    }

    /// Decode one exact bounded record.
    ///
    /// # Errors
    ///
    /// Rejects truncation, trailing bytes, empty payloads, and oversized input.
    pub fn decode(input: &[u8]) -> Result<Self, DirectProtocolError> {
        if input.len() < SEQUENCED_RECORD_HEADER_BYTES {
            return Err(DirectProtocolError::InvalidLength);
        }
        let payload_len = usize::try_from(u32::from_be_bytes(array(input, 8)?))
            .map_err(|_| DirectProtocolError::PayloadTooLarge)?;
        if payload_len == 0 || payload_len > MAX_SEQUENCED_RECORD_PAYLOAD {
            return Err(DirectProtocolError::PayloadTooLarge);
        }
        exact(input, SEQUENCED_RECORD_HEADER_BYTES + payload_len)?;
        Ok(Self {
            sequence: u64::from_be_bytes(array(input, 0)?),
            payload: input[SEQUENCED_RECORD_HEADER_BYTES..].to_vec(),
        })
    }
}

/// Decrypted packet protected by stateless Noise transport encryption.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum DirectPacket {
    /// One fragment of an encoded [`SequencedRecord`].
    Fragment {
        /// Global record sequence repeated for cheap routing and validation.
        sequence: u64,
        /// Zero-based fragment index.
        index: u8,
        /// Total number of fragments.
        count: u8,
        /// Total encoded record bytes.
        total_len: u32,
        /// Byte offset of this fragment in the encoded record.
        offset: u32,
        /// Fragment bytes.
        data: Vec<u8>,
    },
    /// One MDS repair equation over the record's systematic fragments.
    Repair {
        /// Global record sequence.
        sequence: u64,
        /// Cauchy repair-row identity, bounded below 128.
        repair_index: u8,
        /// Total number of systematic fragments.
        count: u8,
        /// Total encoded record bytes before canonical zero padding.
        total_len: u32,
        /// Systematic fragment subset participating in this equation.
        source_bitmap: u64,
        /// Coded bytes at the fixed direct source-symbol width.
        data: Vec<u8>,
    },
    /// Selective acknowledgement bitmap for a record.
    Ack {
        /// Global record sequence.
        sequence: u64,
        /// Expected fragment count.
        count: u8,
        /// Bit `n` acknowledges fragment `n`.
        bitmap: u64,
    },
    /// End-to-end verified commit receipt.
    Receipt {
        /// Committed object digest.
        digest: [u8; 32],
        /// Committed logical byte length.
        length: u64,
    },
    /// Confirms that the responder completed the direct Noise handshake.
    Confirm {
        /// Responder's connectivity challenge bound into the direct transcript.
        challenge: [u8; 16],
    },
    /// Bounded authenticated goodput-trial datagram.
    Trial {
        /// Fresh trial identity.
        token: u64,
        /// Zero-based trial datagram index.
        index: u8,
        /// Total trial datagrams.
        count: u8,
        /// Incompressible trial bytes.
        data: Vec<u8>,
    },
    /// Cumulative goodput-trial acknowledgement.
    TrialAck {
        /// Trial identity.
        token: u64,
        /// Expected trial datagram count.
        count: u8,
        /// Bit `n` acknowledges trial datagram `n`.
        bitmap: u64,
    },
    /// Conservative direct goodput floor measured by the sender.
    TrialResult {
        /// Useful payload bits per second after the trial safety margin.
        goodput_floor_bps: u64,
    },
    /// Authenticated exact-size packetization-layer probe.
    MtuProbe {
        /// Fresh probe-series identity.
        token: u64,
        /// Exact outer UDP payload bytes represented by this packet.
        datagram_bytes: u16,
        /// Canonical padding that makes the encrypted envelope exact-size.
        data: Vec<u8>,
    },
    /// Receipt for one exact-size packetization-layer probe.
    MtuAck {
        /// Probe-series identity.
        token: u64,
        /// Successfully received outer UDP payload bytes.
        datagram_bytes: u16,
    },
    /// Sender's authenticated packetization-layer selection.
    MtuResult {
        /// Probe-series identity.
        token: u64,
        /// Largest mutually observed UDP payload bytes.
        datagram_bytes: u16,
    },
}

impl DirectPacket {
    /// Encode one bounded decrypted packet.
    ///
    /// # Errors
    ///
    /// Rejects invalid fragment geometry and payloads above one datagram.
    pub fn encode(&self) -> Result<Vec<u8>, DirectProtocolError> {
        match self {
            Self::Fragment {
                sequence,
                index,
                count,
                total_len,
                offset,
                data,
            } => encode_fragment(*sequence, *index, *count, *total_len, *offset, data),
            Self::Repair {
                sequence,
                repair_index,
                count,
                total_len,
                source_bitmap,
                data,
            } => encode_repair(
                *sequence,
                *repair_index,
                *count,
                *total_len,
                *source_bitmap,
                data,
            ),
            Self::Ack {
                sequence,
                count,
                bitmap,
            } => encode_bitmap_record(ACK, *sequence, *count, *bitmap),
            Self::Receipt { digest, length } => {
                let mut output = vec![0_u8; 44];
                output[0] = RECEIPT;
                output[4..36].copy_from_slice(digest);
                output[36..44].copy_from_slice(&length.to_be_bytes());
                Ok(output)
            }
            Self::Confirm { challenge } => {
                let mut output = vec![0_u8; 20];
                output[0] = CONFIRM;
                output[4..].copy_from_slice(challenge);
                Ok(output)
            }
            Self::Trial {
                token,
                index,
                count,
                data,
            } => encode_trial(*token, *index, *count, data),
            Self::TrialAck {
                token,
                count,
                bitmap,
            } => encode_bitmap_record(TRIAL_ACK, *token, *count, *bitmap),
            Self::TrialResult { goodput_floor_bps } => {
                if *goodput_floor_bps == 0 {
                    return Err(DirectProtocolError::NonCanonical);
                }
                let mut output = vec![0_u8; 12];
                output[0] = TRIAL_RESULT;
                output[4..12].copy_from_slice(&goodput_floor_bps.to_be_bytes());
                Ok(output)
            }
            Self::MtuProbe {
                token,
                datagram_bytes,
                data,
            } => encode_mtu_probe(*token, *datagram_bytes, data),
            Self::MtuAck {
                token,
                datagram_bytes,
            }
            | Self::MtuResult {
                token,
                datagram_bytes,
            } => encode_mtu_choice(
                if matches!(self, Self::MtuAck { .. }) {
                    MTU_ACK
                } else {
                    MTU_RESULT
                },
                *token,
                *datagram_bytes,
            ),
        }
    }

    /// Decode one exact decrypted packet.
    ///
    /// # Errors
    ///
    /// Rejects unknown packet kinds, nonzero reserved bytes, and impossible
    /// fragment or acknowledgement geometry.
    pub fn decode(input: &[u8]) -> Result<Self, DirectProtocolError> {
        let kind = *input.first().ok_or(DirectProtocolError::InvalidLength)?;
        match kind {
            FRAGMENT => decode_fragment(input),
            ACK => decode_ack(input),
            RECEIPT => decode_receipt(input),
            CONFIRM => decode_confirm(input),
            TRIAL => decode_trial(input),
            TRIAL_ACK => decode_trial_ack(input),
            TRIAL_RESULT => decode_trial_result(input),
            REPAIR => decode_repair(input),
            MTU_PROBE => decode_mtu_probe(input),
            MTU_ACK => decode_mtu_choice(input, false),
            MTU_RESULT => decode_mtu_choice(input, true),
            other => Err(DirectProtocolError::UnknownPacket(other)),
        }
    }
}

fn encode_fragment(
    sequence: u64,
    index: u8,
    count: u8,
    total_len: u32,
    offset: u32,
    data: &[u8],
) -> Result<Vec<u8>, DirectProtocolError> {
    validate_fragment(index, count, total_len, offset, data)?;
    let mut output = Vec::with_capacity(DIRECT_FRAGMENT_HEADER_BYTES + data.len());
    output.extend_from_slice(&[FRAGMENT, index, count, 0]);
    output.extend_from_slice(&sequence.to_be_bytes());
    output.extend_from_slice(&total_len.to_be_bytes());
    output.extend_from_slice(&offset.to_be_bytes());
    output.extend_from_slice(data);
    Ok(output)
}

fn encode_repair(
    sequence: u64,
    repair_index: u8,
    count: u8,
    total_len: u32,
    source_bitmap: u64,
    data: &[u8],
) -> Result<Vec<u8>, DirectProtocolError> {
    validate_repair(repair_index, count, total_len, source_bitmap, data)?;
    let mut output = Vec::with_capacity(DIRECT_REPAIR_HEADER_BYTES + data.len());
    output.extend_from_slice(&[REPAIR, repair_index, count, 0]);
    output.extend_from_slice(&sequence.to_be_bytes());
    output.extend_from_slice(&total_len.to_be_bytes());
    output.extend_from_slice(&source_bitmap.to_be_bytes());
    output.extend_from_slice(data);
    Ok(output)
}

fn encode_bitmap_record(
    kind: u8,
    identity: u64,
    count: u8,
    bitmap: u64,
) -> Result<Vec<u8>, DirectProtocolError> {
    if kind == ACK {
        validate_ack(count, bitmap)?;
    } else {
        validate_trial_ack(count, bitmap)?;
    }
    let mut output = vec![0_u8; 24];
    output[0] = kind;
    output[4..12].copy_from_slice(&identity.to_be_bytes());
    output[12] = count;
    output[16..24].copy_from_slice(&bitmap.to_be_bytes());
    Ok(output)
}

fn encode_trial(
    token: u64,
    index: u8,
    count: u8,
    data: &[u8],
) -> Result<Vec<u8>, DirectProtocolError> {
    validate_trial(index, count, data)?;
    let mut output = Vec::with_capacity(12 + data.len());
    output.extend_from_slice(&[TRIAL, index, count, 0]);
    output.extend_from_slice(&token.to_be_bytes());
    output.extend_from_slice(data);
    Ok(output)
}

fn encode_mtu_probe(
    token: u64,
    datagram_bytes: u16,
    data: &[u8],
) -> Result<Vec<u8>, DirectProtocolError> {
    validate_mtu_probe(datagram_bytes, data)?;
    let mut output = Vec::with_capacity(16 + data.len());
    output.extend_from_slice(&[MTU_PROBE, 0, 0, 0]);
    output.extend_from_slice(&token.to_be_bytes());
    output.extend_from_slice(&datagram_bytes.to_be_bytes());
    output.extend_from_slice(&[0, 0]);
    output.extend_from_slice(data);
    Ok(output)
}

fn encode_mtu_choice(
    kind: u8,
    token: u64,
    datagram_bytes: u16,
) -> Result<Vec<u8>, DirectProtocolError> {
    validate_mtu_bytes(datagram_bytes)?;
    let mut output = vec![0_u8; 16];
    output[0] = kind;
    output[4..12].copy_from_slice(&token.to_be_bytes());
    output[12..14].copy_from_slice(&datagram_bytes.to_be_bytes());
    Ok(output)
}

fn decode_fragment(input: &[u8]) -> Result<DirectPacket, DirectProtocolError> {
    if input.len() <= DIRECT_FRAGMENT_HEADER_BYTES {
        return Err(DirectProtocolError::InvalidLength);
    }
    if input[3] != 0 {
        return Err(DirectProtocolError::NonCanonical);
    }
    let packet = DirectPacket::Fragment {
        sequence: u64::from_be_bytes(array(input, 4)?),
        index: input[1],
        count: input[2],
        total_len: u32::from_be_bytes(array(input, 12)?),
        offset: u32::from_be_bytes(array(input, 16)?),
        data: input[20..].to_vec(),
    };
    let DirectPacket::Fragment {
        index,
        count,
        total_len,
        offset,
        data,
        ..
    } = &packet
    else {
        unreachable!();
    };
    validate_fragment(*index, *count, *total_len, *offset, data)?;
    Ok(packet)
}

fn decode_repair(input: &[u8]) -> Result<DirectPacket, DirectProtocolError> {
    if input.len() <= DIRECT_REPAIR_HEADER_BYTES {
        return Err(DirectProtocolError::InvalidLength);
    }
    if input[3] != 0 {
        return Err(DirectProtocolError::NonCanonical);
    }
    let packet = DirectPacket::Repair {
        sequence: u64::from_be_bytes(array(input, 4)?),
        repair_index: input[1],
        count: input[2],
        total_len: u32::from_be_bytes(array(input, 12)?),
        source_bitmap: u64::from_be_bytes(array(input, 16)?),
        data: input[24..].to_vec(),
    };
    let DirectPacket::Repair {
        repair_index,
        count,
        total_len,
        source_bitmap,
        data,
        ..
    } = &packet
    else {
        unreachable!();
    };
    validate_repair(*repair_index, *count, *total_len, *source_bitmap, data)?;
    Ok(packet)
}

fn decode_ack(input: &[u8]) -> Result<DirectPacket, DirectProtocolError> {
    exact(input, 24)?;
    if input[1..4] != [0, 0, 0] || input[13..16] != [0, 0, 0] {
        return Err(DirectProtocolError::NonCanonical);
    }
    let count = input[12];
    let bitmap = u64::from_be_bytes(array(input, 16)?);
    validate_ack(count, bitmap)?;
    Ok(DirectPacket::Ack {
        sequence: u64::from_be_bytes(array(input, 4)?),
        count,
        bitmap,
    })
}

fn decode_receipt(input: &[u8]) -> Result<DirectPacket, DirectProtocolError> {
    exact(input, 44)?;
    if input[1..4] != [0, 0, 0] {
        return Err(DirectProtocolError::NonCanonical);
    }
    Ok(DirectPacket::Receipt {
        digest: array(input, 4)?,
        length: u64::from_be_bytes(array(input, 36)?),
    })
}

fn decode_confirm(input: &[u8]) -> Result<DirectPacket, DirectProtocolError> {
    exact(input, 20)?;
    if input[1..4] != [0, 0, 0] {
        return Err(DirectProtocolError::NonCanonical);
    }
    Ok(DirectPacket::Confirm {
        challenge: array(input, 4)?,
    })
}

fn decode_trial(input: &[u8]) -> Result<DirectPacket, DirectProtocolError> {
    if input.len() <= 12 || input[3] != 0 {
        return Err(DirectProtocolError::InvalidLength);
    }
    let packet = DirectPacket::Trial {
        token: u64::from_be_bytes(array(input, 4)?),
        index: input[1],
        count: input[2],
        data: input[12..].to_vec(),
    };
    let DirectPacket::Trial {
        index, count, data, ..
    } = &packet
    else {
        unreachable!();
    };
    validate_trial(*index, *count, data)?;
    Ok(packet)
}

fn decode_trial_ack(input: &[u8]) -> Result<DirectPacket, DirectProtocolError> {
    exact(input, 24)?;
    if input[1..4] != [0, 0, 0] || input[13..16] != [0, 0, 0] {
        return Err(DirectProtocolError::NonCanonical);
    }
    let count = input[12];
    let bitmap = u64::from_be_bytes(array(input, 16)?);
    validate_trial_ack(count, bitmap)?;
    Ok(DirectPacket::TrialAck {
        token: u64::from_be_bytes(array(input, 4)?),
        count,
        bitmap,
    })
}

fn decode_trial_result(input: &[u8]) -> Result<DirectPacket, DirectProtocolError> {
    exact(input, 12)?;
    if input[1..4] != [0, 0, 0] {
        return Err(DirectProtocolError::NonCanonical);
    }
    let goodput_floor_bps = u64::from_be_bytes(array(input, 4)?);
    if goodput_floor_bps == 0 {
        return Err(DirectProtocolError::NonCanonical);
    }
    Ok(DirectPacket::TrialResult { goodput_floor_bps })
}

fn decode_mtu_probe(input: &[u8]) -> Result<DirectPacket, DirectProtocolError> {
    if input.len() <= 16 || input[1..4] != [0, 0, 0] || input[14..16] != [0, 0] {
        return Err(DirectProtocolError::InvalidLength);
    }
    let packet = DirectPacket::MtuProbe {
        token: u64::from_be_bytes(array(input, 4)?),
        datagram_bytes: u16::from_be_bytes(array(input, 12)?),
        data: input[16..].to_vec(),
    };
    let DirectPacket::MtuProbe {
        datagram_bytes,
        data,
        ..
    } = &packet
    else {
        unreachable!();
    };
    validate_mtu_probe(*datagram_bytes, data)?;
    Ok(packet)
}

fn decode_mtu_choice(input: &[u8], result: bool) -> Result<DirectPacket, DirectProtocolError> {
    exact(input, 16)?;
    if input[1..4] != [0, 0, 0] || input[14..16] != [0, 0] {
        return Err(DirectProtocolError::NonCanonical);
    }
    let token = u64::from_be_bytes(array(input, 4)?);
    let datagram_bytes = u16::from_be_bytes(array(input, 12)?);
    validate_mtu_bytes(datagram_bytes)?;
    Ok(if result {
        DirectPacket::MtuResult {
            token,
            datagram_bytes,
        }
    } else {
        DirectPacket::MtuAck {
            token,
            datagram_bytes,
        }
    })
}

/// Explicit-nonce stateless Noise ciphertext envelope.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct DirectCiphertext {
    /// Candidate-pair identity.
    pub path_id: u32,
    /// Explicit Noise nonce; never reused with one transport key.
    pub nonce: u64,
    /// Ciphertext including the Noise authentication tag.
    pub payload: Vec<u8>,
}

impl DirectCiphertext {
    /// Encode one bounded ciphertext datagram.
    ///
    /// # Errors
    ///
    /// Rejects ciphertext too small to contain a tag or above one datagram.
    pub fn encode(&self) -> Result<Vec<u8>, DirectProtocolError> {
        if self.payload.len() < DIRECT_AEAD_TAG_BYTES
            || self.payload.len() > MAX_DIRECT_DATAGRAM_BYTES - DIRECT_CIPHERTEXT_HEADER_BYTES
        {
            return Err(DirectProtocolError::PayloadTooLarge);
        }
        let payload_len =
            u16::try_from(self.payload.len()).map_err(|_| DirectProtocolError::PayloadTooLarge)?;
        let mut output = vec![0_u8; DIRECT_CIPHERTEXT_HEADER_BYTES + self.payload.len()];
        output[..4].copy_from_slice(&CIPHERTEXT_MAGIC);
        output[4] = VERSION;
        output[8..12].copy_from_slice(&self.path_id.to_be_bytes());
        output[12..20].copy_from_slice(&self.nonce.to_be_bytes());
        output[20..22].copy_from_slice(&payload_len.to_be_bytes());
        output[22..].copy_from_slice(&self.payload);
        Ok(output)
    }

    /// Decode one exact bounded ciphertext datagram.
    ///
    /// # Errors
    ///
    /// Rejects bad framing, padding, truncation, and oversized ciphertext.
    pub fn decode(input: &[u8]) -> Result<Self, DirectProtocolError> {
        if input.len() < DIRECT_CIPHERTEXT_HEADER_BYTES {
            return Err(DirectProtocolError::InvalidLength);
        }
        envelope(input, CIPHERTEXT_MAGIC)?;
        if input[5..8] != [0, 0, 0] {
            return Err(DirectProtocolError::NonCanonical);
        }
        let payload_len = usize::from(u16::from_be_bytes(array(input, 20)?));
        if !(DIRECT_AEAD_TAG_BYTES..=MAX_DIRECT_DATAGRAM_BYTES - DIRECT_CIPHERTEXT_HEADER_BYTES)
            .contains(&payload_len)
        {
            return Err(DirectProtocolError::PayloadTooLarge);
        }
        exact(input, DIRECT_CIPHERTEXT_HEADER_BYTES + payload_len)?;
        Ok(Self {
            path_id: u32::from_be_bytes(array(input, 8)?),
            nonce: u64::from_be_bytes(array(input, 12)?),
            payload: input[22..].to_vec(),
        })
    }
}

fn validate_fragment(
    index: u8,
    count: u8,
    total_len: u32,
    offset: u32,
    data: &[u8],
) -> Result<(), DirectProtocolError> {
    let total_len = usize::try_from(total_len).map_err(|_| DirectProtocolError::InvalidFragment)?;
    let offset = usize::try_from(offset).map_err(|_| DirectProtocolError::InvalidFragment)?;
    if count == 0
        || usize::from(count) > MAX_DIRECT_FRAGMENTS
        || index >= count
        || data.is_empty()
        || data.len() > MAX_DIRECT_FRAGMENT_BYTES
        || !(SEQUENCED_RECORD_HEADER_BYTES + 1
            ..=SEQUENCED_RECORD_HEADER_BYTES + MAX_SEQUENCED_RECORD_PAYLOAD)
            .contains(&total_len)
    {
        return Err(DirectProtocolError::InvalidFragment);
    }
    let symbol_bytes = if count == 1 {
        total_len
    } else if index == 0 {
        data.len()
    } else {
        let index = usize::from(index);
        if offset % index != 0 {
            return Err(DirectProtocolError::InvalidFragment);
        }
        offset / index
    };
    if (count > 1
        && !(MIN_DIRECT_FRAGMENT_BYTES..=MAX_DIRECT_FRAGMENT_BYTES).contains(&symbol_bytes))
        || offset != usize::from(index) * symbol_bytes
        || offset.checked_add(data.len()) > Some(total_len)
        || (index + 1 < count && data.len() != symbol_bytes)
        || (index + 1 == count && offset + data.len() != total_len)
        || usize::from(count) != total_len.div_ceil(symbol_bytes)
    {
        return Err(DirectProtocolError::InvalidFragment);
    }
    Ok(())
}

fn validate_repair(
    repair_index: u8,
    count: u8,
    total_len: u32,
    source_bitmap: u64,
    data: &[u8],
) -> Result<(), DirectProtocolError> {
    let total_len = usize::try_from(total_len).map_err(|_| DirectProtocolError::InvalidFragment)?;
    let allowed = if count == 64 {
        u64::MAX
    } else {
        (1_u64 << count) - 1
    };
    if repair_index >= 128
        || count == 0
        || usize::from(count) > MAX_DIRECT_FRAGMENTS
        || source_bitmap == 0
        || source_bitmap & !allowed != 0
        || !(MIN_DIRECT_FRAGMENT_BYTES..=MAX_DIRECT_FRAGMENT_BYTES).contains(&data.len())
        || !(SEQUENCED_RECORD_HEADER_BYTES + 1
            ..=SEQUENCED_RECORD_HEADER_BYTES + MAX_SEQUENCED_RECORD_PAYLOAD)
            .contains(&total_len)
        || usize::from(count) != total_len.div_ceil(data.len())
    {
        return Err(DirectProtocolError::InvalidFragment);
    }
    Ok(())
}

fn validate_ack(count: u8, bitmap: u64) -> Result<(), DirectProtocolError> {
    if count == 0 || usize::from(count) > MAX_DIRECT_FRAGMENTS {
        return Err(DirectProtocolError::InvalidFragment);
    }
    let allowed = if count == 64 {
        u64::MAX
    } else {
        (1_u64 << count) - 1
    };
    if bitmap & !allowed != 0 {
        return Err(DirectProtocolError::InvalidFragment);
    }
    Ok(())
}

fn validate_trial(index: u8, count: u8, data: &[u8]) -> Result<(), DirectProtocolError> {
    if count == 0
        || count > 32
        || index >= count
        || data.is_empty()
        || data.len() > MAX_DIRECT_PACKET_BYTES - 12
    {
        return Err(DirectProtocolError::InvalidFragment);
    }
    Ok(())
}

fn validate_trial_ack(count: u8, bitmap: u64) -> Result<(), DirectProtocolError> {
    if count == 0 || count > 32 || bitmap & !((1_u64 << count) - 1) != 0 {
        return Err(DirectProtocolError::InvalidFragment);
    }
    Ok(())
}

fn validate_mtu_probe(datagram_bytes: u16, data: &[u8]) -> Result<(), DirectProtocolError> {
    validate_mtu_bytes(datagram_bytes)?;
    if mtu_probe_data_bytes(usize::from(datagram_bytes)) != Some(data.len()) {
        return Err(DirectProtocolError::InvalidFragment);
    }
    Ok(())
}

fn validate_mtu_bytes(datagram_bytes: u16) -> Result<(), DirectProtocolError> {
    if !(MIN_DIRECT_DATAGRAM_BYTES..=MAX_DIRECT_DATAGRAM_BYTES)
        .contains(&usize::from(datagram_bytes))
    {
        return Err(DirectProtocolError::InvalidFragment);
    }
    Ok(())
}

fn encode_socket(address: SocketAddr, output: &mut [u8]) {
    debug_assert_eq!(output.len(), 19);
    match address.ip() {
        IpAddr::V4(ip) => {
            output[0] = 4;
            output[1..13].fill(0);
            output[13..17].copy_from_slice(&ip.octets());
        }
        IpAddr::V6(ip) => {
            output[0] = 6;
            output[1..17].copy_from_slice(&ip.octets());
        }
    }
    output[17..19].copy_from_slice(&address.port().to_be_bytes());
}

fn decode_socket(input: &[u8]) -> Result<SocketAddr, DirectProtocolError> {
    exact(input, 19)?;
    let port = u16::from_be_bytes(array(input, 17)?);
    let ip = match input[0] {
        4 => {
            if input[1..13] != [0; 12] {
                return Err(DirectProtocolError::NonCanonical);
            }
            IpAddr::V4(Ipv4Addr::from(array::<4>(input, 13)?))
        }
        6 => IpAddr::V6(Ipv6Addr::from(array::<16>(input, 1)?)),
        _ => return Err(DirectProtocolError::UnsupportedAddress),
    };
    Ok(SocketAddr::new(ip, port))
}

fn encode_role(role: Role) -> u8 {
    match role {
        Role::Sender => 1,
        Role::Receiver => 2,
    }
}

fn decode_role(value: u8) -> Result<Role, DirectProtocolError> {
    match value {
        1 => Ok(Role::Sender),
        2 => Ok(Role::Receiver),
        _ => Err(DirectProtocolError::UnknownRole),
    }
}

fn envelope(input: &[u8], magic: [u8; 4]) -> Result<(), DirectProtocolError> {
    if input.len() < 5 {
        return Err(DirectProtocolError::InvalidLength);
    }
    if input[..4] != magic {
        return Err(DirectProtocolError::BadMagic);
    }
    if input[4] != VERSION {
        return Err(DirectProtocolError::UnsupportedVersion);
    }
    Ok(())
}

fn exact(input: &[u8], expected: usize) -> Result<(), DirectProtocolError> {
    if input.len() == expected {
        Ok(())
    } else {
        Err(DirectProtocolError::InvalidLength)
    }
}

fn array<const N: usize>(input: &[u8], offset: usize) -> Result<[u8; N], DirectProtocolError> {
    input
        .get(offset..offset + N)
        .ok_or(DirectProtocolError::InvalidLength)?
        .try_into()
        .map_err(|_| DirectProtocolError::InvalidLength)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn registration_and_probe_round_trip_exactly() {
        let registration = DirectRegistration {
            lookup_id: [1; 16],
            role: Role::Sender,
            nonce: [2; 16],
            authenticator: [3; 16],
        };
        assert_eq!(
            DirectRegistration::decode(&registration.encode()),
            Ok(registration)
        );

        let probe = DirectProbe {
            lookup_id: [4; 16],
            role: Role::Receiver,
            path_id: 9,
            challenge: [5; 16],
            response: [6; 16],
            authenticator: [7; 16],
        };
        assert_eq!(DirectProbe::decode(&probe.encode()), Ok(probe));
    }

    #[test]
    fn matches_preserve_ipv4_and_ipv6_canonically() {
        for address in [
            "192.0.2.7:4040".parse().unwrap(),
            "[2001:db8::7]:5050".parse().unwrap(),
        ] {
            let matched = DirectMatch {
                lookup_id: [8; 16],
                peer_nonce: [9; 16],
                peer_authenticator: [10; 16],
                peer_addr: address,
            };
            assert_eq!(DirectMatch::decode(&matched.encode()), Ok(matched));
        }
    }

    #[test]
    fn variable_envelopes_reject_truncation_trailing_and_padding() {
        let handshake = DirectHandshake {
            role: Role::Sender,
            path_id: 4,
            payload: vec![1, 2, 3],
        };
        let encoded = handshake.encode().unwrap();
        assert_eq!(DirectHandshake::decode(&encoded), Ok(handshake));
        assert!(DirectHandshake::decode(&encoded[..encoded.len() - 1]).is_err());
        let mut trailing = encoded.clone();
        trailing.push(0);
        assert!(DirectHandshake::decode(&trailing).is_err());
        let mut noncanonical = encoded;
        noncanonical[7] = 1;
        assert_eq!(
            DirectHandshake::decode(&noncanonical),
            Err(DirectProtocolError::NonCanonical)
        );
    }

    #[test]
    fn maximum_record_fragments_round_trip() {
        let record = SequencedRecord {
            sequence: 42,
            payload: vec![0xA5; MAX_SEQUENCED_RECORD_PAYLOAD],
        };
        let encoded = record.encode().unwrap();
        assert_eq!(SequencedRecord::decode(&encoded), Ok(record));
        let count = u8::try_from(encoded.len().div_ceil(MAX_DIRECT_FRAGMENT_BYTES)).unwrap();
        assert!(usize::from(count) <= MAX_DIRECT_FRAGMENTS);

        for (index, chunk) in encoded.chunks(MAX_DIRECT_FRAGMENT_BYTES).enumerate() {
            let packet = DirectPacket::Fragment {
                sequence: 42,
                index: u8::try_from(index).unwrap(),
                count,
                total_len: u32::try_from(encoded.len()).unwrap(),
                offset: u32::try_from(index * MAX_DIRECT_FRAGMENT_BYTES).unwrap(),
                data: chunk.to_vec(),
            };
            let packet_bytes = packet.encode().unwrap();
            assert!(packet_bytes.len() <= MAX_DIRECT_PACKET_BYTES);
            assert_eq!(DirectPacket::decode(&packet_bytes), Ok(packet));
        }

        let minimum_count = encoded.len().div_ceil(MIN_DIRECT_FRAGMENT_BYTES);
        assert_eq!(minimum_count, MAX_DIRECT_FRAGMENTS);
        for (index, chunk) in encoded.chunks(MIN_DIRECT_FRAGMENT_BYTES).enumerate() {
            let packet = DirectPacket::Fragment {
                sequence: 42,
                index: u8::try_from(index).unwrap(),
                count: u8::try_from(minimum_count).unwrap(),
                total_len: u32::try_from(encoded.len()).unwrap(),
                offset: u32::try_from(index * MIN_DIRECT_FRAGMENT_BYTES).unwrap(),
                data: chunk.to_vec(),
            };
            assert_eq!(DirectPacket::decode(&packet.encode().unwrap()), Ok(packet));
        }
    }

    #[test]
    fn impossible_fragment_and_ack_geometry_fail_closed() {
        assert_eq!(
            DirectPacket::Fragment {
                sequence: 1,
                index: 0,
                count: 2,
                total_len: 10,
                offset: 0,
                data: vec![0; 10],
            }
            .encode(),
            Err(DirectProtocolError::InvalidFragment)
        );
        assert_eq!(
            DirectPacket::Ack {
                sequence: 1,
                count: 2,
                bitmap: 0b100,
            }
            .encode(),
            Err(DirectProtocolError::InvalidFragment)
        );
    }

    #[test]
    fn repair_symbol_round_trips_at_the_datagram_bound() {
        let total_len = MAX_SEQUENCED_RECORD_PAYLOAD + SEQUENCED_RECORD_HEADER_BYTES;
        let packet = DirectPacket::Repair {
            sequence: 44,
            repair_index: 73,
            count: u8::try_from(total_len.div_ceil(MAX_DIRECT_FRAGMENT_BYTES)).unwrap(),
            total_len: u32::try_from(total_len).unwrap(),
            source_bitmap: 0b10101,
            data: vec![0xC7; MAX_DIRECT_FRAGMENT_BYTES],
        };
        let encoded = packet.encode().unwrap();
        assert_eq!(encoded.len(), MAX_DIRECT_PACKET_BYTES);
        assert_eq!(DirectPacket::decode(&encoded), Ok(packet));
    }

    #[test]
    fn ciphertext_round_trip_is_bounded_and_exact() {
        let ciphertext = DirectCiphertext {
            path_id: 17,
            nonce: 99,
            payload: vec![0x5A; MAX_DIRECT_DATAGRAM_BYTES - DIRECT_CIPHERTEXT_HEADER_BYTES],
        };
        let encoded = ciphertext.encode().unwrap();
        assert_eq!(encoded.len(), MAX_DIRECT_DATAGRAM_BYTES);
        assert_eq!(DirectCiphertext::decode(&encoded), Ok(ciphertext));
    }

    #[test]
    fn mtu_probe_series_is_exact_sized_and_canonical() {
        for datagram_bytes in DIRECT_MTU_CANDIDATES {
            let packet = DirectPacket::MtuProbe {
                token: 0xA55A,
                datagram_bytes,
                data: vec![0xC3; mtu_probe_data_bytes(usize::from(datagram_bytes)).unwrap()],
            };
            let plaintext = packet.encode().unwrap();
            assert_eq!(
                plaintext.len() + DIRECT_CIPHERTEXT_HEADER_BYTES + DIRECT_AEAD_TAG_BYTES,
                usize::from(datagram_bytes)
            );
            assert_eq!(DirectPacket::decode(&plaintext), Ok(packet));

            for choice in [
                DirectPacket::MtuAck {
                    token: 0xA55A,
                    datagram_bytes,
                },
                DirectPacket::MtuResult {
                    token: 0xA55A,
                    datagram_bytes,
                },
            ] {
                assert_eq!(DirectPacket::decode(&choice.encode().unwrap()), Ok(choice));
            }
        }
    }

    #[test]
    fn every_reserved_field_fails_closed() {
        let mut registration = DirectRegistration {
            lookup_id: [0; 16],
            role: Role::Sender,
            nonce: [0; 16],
            authenticator: [0; 16],
        }
        .encode();
        registration[6] = 1;
        assert_eq!(
            DirectRegistration::decode(&registration),
            Err(DirectProtocolError::NonCanonical)
        );

        let mut matched = DirectMatch {
            lookup_id: [0; 16],
            peer_nonce: [0; 16],
            peer_authenticator: [0; 16],
            peer_addr: "127.0.0.1:9".parse().unwrap(),
        }
        .encode();
        matched[5] = 1;
        assert_eq!(
            DirectMatch::decode(&matched),
            Err(DirectProtocolError::NonCanonical)
        );
    }
}
