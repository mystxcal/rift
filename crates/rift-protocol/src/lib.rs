#![forbid(unsafe_code)]

//! Bounded wire types and capability handling for RIFT.

pub mod capability;
pub mod direct;
pub mod frame;
pub mod handshake;
pub mod manifest;
pub mod pairing_code;
pub mod pairing_handshake;
pub mod piece;
pub mod rendezvous;
pub mod route_bundle;
pub mod stream_record;
pub mod stun;

pub use capability::{Capability, CapabilityError};
pub use direct::{
    DIRECT_AEAD_TAG_BYTES, DIRECT_CIPHERTEXT_HEADER_BYTES, DIRECT_FRAGMENT_HEADER_BYTES,
    DIRECT_HANDSHAKE_HEADER_BYTES, DIRECT_MATCH_BYTES, DIRECT_MTU_CANDIDATES, DIRECT_PROBE_BYTES,
    DIRECT_REGISTRATION_BYTES, DirectCiphertext, DirectHandshake, DirectMatch, DirectPacket,
    DirectProbe, DirectProtocolError, DirectRegistration, MAX_DIRECT_DATAGRAM_BYTES,
    MAX_DIRECT_FRAGMENT_BYTES, MAX_DIRECT_FRAGMENTS, MAX_DIRECT_HANDSHAKE_BYTES,
    MAX_DIRECT_PACKET_BYTES, MAX_SEQUENCED_RECORD_PAYLOAD, MIN_DIRECT_DATAGRAM_BYTES,
    MIN_DIRECT_FRAGMENT_BYTES, MIN_DIRECT_PACKET_BYTES, SEQUENCED_RECORD_HEADER_BYTES,
    SequencedRecord, fragment_bytes_for_datagram, mtu_probe_data_bytes,
};
pub use frame::{DecodedFrame, FrameError, PacketHeader, PacketKind};
pub use handshake::{AlgorithmOffer, HandshakeError, HandshakePrologue, Role, SelectedAlgorithms};
pub use manifest::{EntryKind, EntryRecord, HardLimits, ManifestError, ObjectStart};
pub use pairing_code::{PairingCode, PairingCodeError};
pub use pairing_handshake::{
    PAIRING_CONFIRMATION_BYTES, PAIRING_CONFIRMATION_FRAME_BYTES, PAIRING_SHARE_BYTES,
    PAIRING_SHARE_FRAME_BYTES, PairingConfirmation, PairingFrameError, PairingShare,
};
pub use piece::{
    MAX_DURABLE_RANGES, PieceRecord, PieceRecordError, ResumeRange, decode_piece_record,
};
pub use rendezvous::{
    JOIN_ACK_BYTES, JOIN_PRELUDE_BYTES, JoinPrelude, JoinStatus, RendezvousError, RendezvousRole,
};
pub use route_bundle::{
    MAX_ROUTE_BUNDLE_BYTES, ROUTE_BUNDLE_HEADER_BYTES, RouteBundle, RouteBundleError, RouteServer,
    RouteTransport, TurnAuthorization, route_bundle_encoded_len,
};
pub use stream_record::{
    MAX_STREAM_BLOCK_BYTES, MAX_STREAM_COMPONENT_BYTES, STREAM_BLOCK_BYTES, StreamRecord,
    StreamRecordError, decode_stream_record,
};
pub use stun::{
    BINDING_REQUEST_BYTES, MAX_STUN_MESSAGE_BYTES, StunError, TransactionId,
    decode_binding_response, encode_binding_request,
};
