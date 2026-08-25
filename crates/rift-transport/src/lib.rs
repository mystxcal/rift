#![forbid(unsafe_code)]

//! Bounded transport adapters shared by RIFT endpoints and relays.

pub mod quic;
pub mod turn;
pub mod websocket;
pub mod wss;

pub use quic::{
    QuicBootstrapError, QuicDatagram, QuicEngine, QuicEngineError, QuicIdentityError,
    QuicPathStats, QuicReadError, QuicRole, QuicServerIdentity, QuicStreamFinishError,
    QuicStreamWriteError, pinned_client_config,
};
pub use quinn_proto::{
    Event as QuicEvent, StreamEvent as QuicStreamEvent, StreamId as QuicStreamId,
};
pub use turn::{
    TurnDatagram, TurnEngine, TurnEngineError, TurnEngineEvent, TurnPeerDatagram, TurnStreamEngine,
    TurnStreamWrite, TurnTime,
};

pub use websocket::{
    RIFT_WEBSOCKET_PATH, RIFT_WEBSOCKET_PROTOCOL, WebSocketByteStream, WebSocketRole,
};
pub use wss::{WssEndpoint, WssError, WssStream, accept_wss, connect_wss, connect_wss_with};
