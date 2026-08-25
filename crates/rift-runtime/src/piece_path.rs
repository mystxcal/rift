//! One authenticated reconstruction interface over QUIC or ordered WSS.

use std::time::Duration;

use rift_core::BlockId;

use crate::{
    DirectQuicLinkError, RelayStream, SecureStream, TransferTransport,
    path_pool::{PathPoolMetrics, QuicPathPool},
    stream_crypto::MAX_STREAM_PLAINTEXT,
};

const RELAY_PIECE_MAGIC: [u8; 4] = *b"RFPW";
const RELAY_PIECE_VERSION: u8 = 1;
const RELAY_PIECE_HEADER_BYTES: usize = 16;

/// Path operations needed by the sparse authenticated piece oracle.
pub(crate) trait PiecePath {
    async fn queue_control(
        &mut self,
        bytes: &[u8],
        maximum: usize,
        timeout: Duration,
    ) -> Result<(), DirectQuicLinkError>;

    async fn receive_control(
        &mut self,
        maximum: usize,
        timeout: Duration,
    ) -> Result<Vec<u8>, DirectQuicLinkError>;

    async fn queue_piece(
        &mut self,
        block: BlockId,
        bytes: &[u8],
        maximum: usize,
        timeout: Duration,
    ) -> Result<(), DirectQuicLinkError>;

    async fn receive_any(
        &mut self,
        maximum: usize,
        timeout: Duration,
    ) -> Result<Vec<u8>, DirectQuicLinkError>;

    async fn flush_all(&mut self) -> Result<(), DirectQuicLinkError>;

    fn metrics(&self) -> PathPoolMetrics;

    fn transport(&self) -> TransferTransport;
}

impl PiecePath for QuicPathPool {
    async fn queue_control(
        &mut self,
        bytes: &[u8],
        maximum: usize,
        timeout: Duration,
    ) -> Result<(), DirectQuicLinkError> {
        Self::queue_control(self, bytes, maximum, timeout).await
    }

    async fn receive_control(
        &mut self,
        maximum: usize,
        timeout: Duration,
    ) -> Result<Vec<u8>, DirectQuicLinkError> {
        Self::receive_control(self, maximum, timeout).await
    }

    async fn queue_piece(
        &mut self,
        block: BlockId,
        bytes: &[u8],
        maximum: usize,
        timeout: Duration,
    ) -> Result<(), DirectQuicLinkError> {
        Self::queue_piece(self, block, bytes, maximum, timeout).await
    }

    async fn receive_any(
        &mut self,
        maximum: usize,
        timeout: Duration,
    ) -> Result<Vec<u8>, DirectQuicLinkError> {
        Self::receive_any(self, maximum, timeout).await
    }

    async fn flush_all(&mut self) -> Result<(), DirectQuicLinkError> {
        Self::flush_all(self).await
    }

    fn metrics(&self) -> PathPoolMetrics {
        Self::metrics(self)
    }

    fn transport(&self) -> TransferTransport {
        Self::transport(self)
    }
}

/// The already-authenticated WSS stream presented as a piece path.
pub(crate) struct RelayPiecePath {
    secure: SecureStream<RelayStream>,
    sent_bytes: u64,
    received_bytes: u64,
}

impl RelayPiecePath {
    pub(crate) const fn new(secure: SecureStream<RelayStream>) -> Self {
        Self {
            secure,
            sent_bytes: 0,
            received_bytes: 0,
        }
    }

    async fn send(&mut self, bytes: &[u8], maximum: usize) -> Result<(), DirectQuicLinkError> {
        if bytes.len() > maximum {
            return Err(DirectQuicLinkError::FrameTooLarge);
        }

        let mut header = [0_u8; RELAY_PIECE_HEADER_BYTES];
        header[..4].copy_from_slice(&RELAY_PIECE_MAGIC);
        header[4] = RELAY_PIECE_VERSION;
        header[8..].copy_from_slice(&(bytes.len() as u64).to_be_bytes());
        self.secure.send(&header).await.map_err(secure_path_error)?;
        for chunk in bytes.chunks(MAX_STREAM_PLAINTEXT) {
            self.secure.send(chunk).await.map_err(secure_path_error)?;
        }
        self.sent_bytes = self.sent_bytes.saturating_add(bytes.len() as u64);
        Ok(())
    }

    async fn receive(&mut self, maximum: usize) -> Result<Vec<u8>, DirectQuicLinkError> {
        let header = self.secure.receive().await.map_err(secure_path_error)?;
        if header.len() != RELAY_PIECE_HEADER_BYTES
            || header[..4] != RELAY_PIECE_MAGIC
            || header[4] != RELAY_PIECE_VERSION
            || header[5..8] != [0, 0, 0]
        {
            return Err(invalid_relay_piece());
        }

        let length = usize::try_from(u64::from_be_bytes(
            header[8..].try_into().map_err(|_| invalid_relay_piece())?,
        ))
        .map_err(|_| DirectQuicLinkError::FrameTooLarge)?;
        if length > maximum {
            return Err(DirectQuicLinkError::FrameTooLarge);
        }

        let mut bytes = Vec::with_capacity(length);
        while bytes.len() < length {
            let chunk = self.secure.receive().await.map_err(secure_path_error)?;
            let expected = (length - bytes.len()).min(MAX_STREAM_PLAINTEXT);
            if chunk.len() != expected {
                return Err(invalid_relay_piece());
            }
            bytes.extend_from_slice(&chunk);
        }
        self.received_bytes = self.received_bytes.saturating_add(length as u64);
        Ok(bytes)
    }
}

impl PiecePath for RelayPiecePath {
    async fn queue_control(
        &mut self,
        bytes: &[u8],
        maximum: usize,
        _timeout: Duration,
    ) -> Result<(), DirectQuicLinkError> {
        self.send(bytes, maximum).await
    }

    async fn receive_control(
        &mut self,
        maximum: usize,
        _timeout: Duration,
    ) -> Result<Vec<u8>, DirectQuicLinkError> {
        self.receive(maximum).await
    }

    async fn queue_piece(
        &mut self,
        _block: BlockId,
        bytes: &[u8],
        maximum: usize,
        _timeout: Duration,
    ) -> Result<(), DirectQuicLinkError> {
        self.send(bytes, maximum).await?;
        self.secure.flush().await.map_err(secure_path_error)
    }

    async fn receive_any(
        &mut self,
        maximum: usize,
        _timeout: Duration,
    ) -> Result<Vec<u8>, DirectQuicLinkError> {
        self.receive(maximum).await
    }

    async fn flush_all(&mut self) -> Result<(), DirectQuicLinkError> {
        self.secure.flush().await.map_err(secure_path_error)
    }

    fn metrics(&self) -> PathPoolMetrics {
        PathPoolMetrics {
            paths: 1,
            payload_paths: u16::from(self.sent_bytes != 0 || self.received_bytes != 0),
            wire_sent_bytes: self.sent_bytes,
            wire_received_bytes: self.received_bytes,
            ..PathPoolMetrics::default()
        }
    }

    fn transport(&self) -> TransferTransport {
        TransferTransport::Relay
    }
}

fn secure_path_error(error: crate::SecureStreamError) -> DirectQuicLinkError {
    DirectQuicLinkError::Io(std::io::Error::other(error))
}

fn invalid_relay_piece() -> DirectQuicLinkError {
    DirectQuicLinkError::Io(std::io::Error::new(
        std::io::ErrorKind::InvalidData,
        "invalid authenticated relay piece framing",
    ))
}
