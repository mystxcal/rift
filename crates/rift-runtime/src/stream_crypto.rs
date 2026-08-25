//! PSK-authenticated ephemeral Noise session for the stream-path oracle.

use std::sync::{
    Arc,
    atomic::{AtomicU64, Ordering},
};

use snow::{Builder, HandshakeState, StatelessTransportState, TransportState, params::NoiseParams};
use thiserror::Error;

const NOISE_PATTERN: &str = "Noise_NNpsk0_25519_ChaChaPoly_BLAKE2s";
/// Largest plaintext record admitted by the stream oracle.
pub const MAX_STREAM_PLAINTEXT: usize = 60 * 1024;
/// Noise AEAD expansion for one transport record.
pub const STREAM_TAG_BYTES: usize = 16;

/// Endpoint role in the two-message Noise handshake.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum HandshakeRole {
    /// Writes the first handshake message.
    Initiator,
    /// Reads the first handshake message.
    Responder,
}

/// Noise handshake or transport failure.
#[derive(Debug, Error)]
pub enum CryptoError {
    /// Construction parameters or cryptographic processing failed.
    #[error("Noise protocol failure: {0}")]
    Noise(#[from] snow::Error),
    /// Plaintext exceeds the stream-path record contract.
    #[error("secure stream record exceeds the plaintext bound")]
    PlaintextTooLarge,
    /// Ciphertext cannot be a valid bounded stream record.
    #[error("secure stream ciphertext has an invalid length")]
    InvalidCiphertextLength,
    /// Transport conversion was requested before handshake completion.
    #[error("Noise handshake is not complete")]
    HandshakeIncomplete,
    /// Explicit datagram nonce space was exhausted.
    #[error("Noise datagram nonce space exhausted")]
    NonceExhausted,
}

/// Stateful handshake driver independent of a concrete byte path.
pub struct NoiseHandshake {
    role: HandshakeRole,
    state: HandshakeState,
}

/// Ordered confidential record state for one reliable stream path.
pub struct StreamCipher {
    state: TransportState,
}

/// Cloneable explicit-nonce Noise state for one unreliable direct path.
///
/// Clones share a single atomic egress nonce allocator while stateless Noise
/// permits concurrent ingress authentication. Replay policy remains above this
/// primitive because it depends on accepted packet semantics.
#[derive(Clone)]
pub struct DatagramCipher {
    state: Arc<StatelessTransportState>,
    next_nonce: Arc<AtomicU64>,
}

impl NoiseHandshake {
    /// Construct a fresh ephemeral handshake bound to the canonical prologue.
    ///
    /// # Errors
    ///
    /// Returns [`CryptoError`] when the fixed Noise suite cannot be initialized
    /// or secure ephemeral entropy is unavailable.
    pub fn new(
        role: HandshakeRole,
        transfer_secret: &[u8; 32],
        prologue: &[u8],
    ) -> Result<Self, CryptoError> {
        let params: NoiseParams = NOISE_PATTERN.parse()?;
        let builder = Builder::new(params)
            .prologue(prologue)?
            .psk(0, transfer_secret)?;
        let state = match role {
            HandshakeRole::Initiator => builder.build_initiator()?,
            HandshakeRole::Responder => builder.build_responder()?,
        };
        Ok(Self { role, state })
    }

    /// Role used to construct this state.
    #[must_use]
    pub fn role(&self) -> HandshakeRole {
        self.role
    }

    /// Whether the two-message pattern has completed successfully.
    #[must_use]
    pub fn is_complete(&self) -> bool {
        self.state.is_handshake_finished()
    }

    /// Produce the next handshake message.
    ///
    /// # Errors
    ///
    /// Returns [`CryptoError`] when called out of turn or the output is too
    /// small for the Noise message.
    pub fn write_message(
        &mut self,
        payload: &[u8],
        output: &mut [u8],
    ) -> Result<usize, CryptoError> {
        self.state
            .write_message(payload, output)
            .map_err(CryptoError::from)
    }

    /// Authenticate and consume the next handshake message.
    ///
    /// # Errors
    ///
    /// Returns [`CryptoError`] for an out-of-turn, malformed, unauthenticated,
    /// or incorrectly prologued message.
    pub fn read_message(
        &mut self,
        message: &[u8],
        output: &mut [u8],
    ) -> Result<usize, CryptoError> {
        self.state
            .read_message(message, output)
            .map_err(CryptoError::from)
    }

    /// Consume a completed handshake and enter ordered transport mode.
    ///
    /// # Errors
    ///
    /// Returns [`CryptoError::HandshakeIncomplete`] when called before both
    /// authenticated handshake messages have been processed.
    pub fn into_transport(self) -> Result<StreamCipher, CryptoError> {
        if !self.state.is_handshake_finished() {
            return Err(CryptoError::HandshakeIncomplete);
        }
        Ok(StreamCipher {
            state: self.state.into_transport_mode()?,
        })
    }

    /// Consume a completed handshake and enter explicit-nonce transport mode.
    ///
    /// # Errors
    ///
    /// Returns [`CryptoError::HandshakeIncomplete`] before both flights have
    /// authenticated successfully.
    pub fn into_datagram_transport(self) -> Result<DatagramCipher, CryptoError> {
        if !self.state.is_handshake_finished() {
            return Err(CryptoError::HandshakeIncomplete);
        }
        Ok(DatagramCipher {
            state: Arc::new(self.state.into_stateless_transport_mode()?),
            next_nonce: Arc::new(AtomicU64::new(0)),
        })
    }
}

impl StreamCipher {
    /// Encrypt and authenticate the next ordered plaintext record.
    ///
    /// # Errors
    ///
    /// Returns [`CryptoError`] when plaintext exceeds the fixed bound, output
    /// is too small, or the Noise nonce space is exhausted.
    pub fn seal(&mut self, plaintext: &[u8], output: &mut [u8]) -> Result<usize, CryptoError> {
        if plaintext.len() > MAX_STREAM_PLAINTEXT {
            return Err(CryptoError::PlaintextTooLarge);
        }
        self.state
            .write_message(plaintext, output)
            .map_err(CryptoError::from)
    }

    /// Authenticate and decrypt the next ordered ciphertext record.
    ///
    /// # Errors
    ///
    /// Returns [`CryptoError`] for impossible lengths, tampering, replay,
    /// reordering, insufficient output, or nonce exhaustion.
    pub fn open(&mut self, ciphertext: &[u8], output: &mut [u8]) -> Result<usize, CryptoError> {
        if !(STREAM_TAG_BYTES..=MAX_STREAM_PLAINTEXT + STREAM_TAG_BYTES).contains(&ciphertext.len())
        {
            return Err(CryptoError::InvalidCiphertextLength);
        }
        self.state
            .read_message(ciphertext, output)
            .map_err(CryptoError::from)
    }
}

impl DatagramCipher {
    /// Allocate a unique nonce and encrypt one bounded datagram plaintext.
    ///
    /// # Errors
    ///
    /// Returns for oversized plaintext, output shortage, cryptographic
    /// failure, or exhausted nonce space.
    pub fn seal(&self, plaintext: &[u8], output: &mut [u8]) -> Result<(u64, usize), CryptoError> {
        if plaintext.len() > rift_protocol::MAX_DIRECT_PACKET_BYTES {
            return Err(CryptoError::PlaintextTooLarge);
        }
        let nonce = self
            .next_nonce
            .fetch_update(Ordering::Relaxed, Ordering::Relaxed, |value| {
                value.checked_add(1)
            })
            .map_err(|_| CryptoError::NonceExhausted)?;
        let length = self.state.write_message(nonce, plaintext, output)?;
        Ok((nonce, length))
    }

    /// Authenticate and decrypt one explicit-nonce datagram ciphertext.
    ///
    /// This primitive deliberately does not remember nonces. Callers must
    /// reject replays before allowing decrypted packets to affect state.
    ///
    /// # Errors
    ///
    /// Returns for impossible lengths, tampering, output shortage, or an
    /// invalid nonce.
    pub fn open(
        &self,
        nonce: u64,
        ciphertext: &[u8],
        output: &mut [u8],
    ) -> Result<usize, CryptoError> {
        if !(STREAM_TAG_BYTES..=rift_protocol::MAX_DIRECT_PACKET_BYTES + STREAM_TAG_BYTES)
            .contains(&ciphertext.len())
        {
            return Err(CryptoError::InvalidCiphertextLength);
        }
        self.state
            .read_message(nonce, ciphertext, output)
            .map_err(CryptoError::from)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn establish(
        initiator_secret: &[u8; 32],
        responder_secret: &[u8; 32],
        initiator_prologue: &[u8],
        responder_prologue: &[u8],
    ) -> Result<(StreamCipher, StreamCipher), CryptoError> {
        let mut initiator = NoiseHandshake::new(
            HandshakeRole::Initiator,
            initiator_secret,
            initiator_prologue,
        )?;
        let mut responder = NoiseHandshake::new(
            HandshakeRole::Responder,
            responder_secret,
            responder_prologue,
        )?;
        let mut message = [0_u8; 256];
        let mut payload = [0_u8; 256];

        let length = initiator.write_message(&[], &mut message)?;
        responder.read_message(&message[..length], &mut payload)?;
        let length = responder.write_message(&[], &mut message)?;
        initiator.read_message(&message[..length], &mut payload)?;

        Ok((initiator.into_transport()?, responder.into_transport()?))
    }

    fn establish_datagram() -> (DatagramCipher, DatagramCipher) {
        let mut initiator =
            NoiseHandshake::new(HandshakeRole::Initiator, &[7; 32], b"datagram").unwrap();
        let mut responder =
            NoiseHandshake::new(HandshakeRole::Responder, &[7; 32], b"datagram").unwrap();
        let mut message = [0_u8; 256];
        let mut payload = [0_u8; 256];
        let length = initiator.write_message(&[], &mut message).unwrap();
        responder
            .read_message(&message[..length], &mut payload)
            .unwrap();
        let length = responder.write_message(&[], &mut message).unwrap();
        initiator
            .read_message(&message[..length], &mut payload)
            .unwrap();
        (
            initiator.into_datagram_transport().unwrap(),
            responder.into_datagram_transport().unwrap(),
        )
    }

    #[test]
    fn matching_capability_and_prologue_establish_confidential_transport() {
        let (mut sender, mut receiver) =
            establish(&[7; 32], &[7; 32], b"context", b"context").unwrap();
        let mut ciphertext = [0_u8; 256];
        let mut plaintext = [0_u8; 256];
        let length = sender
            .seal(b"authenticated object record", &mut ciphertext)
            .unwrap();
        let opened = receiver
            .open(&ciphertext[..length], &mut plaintext)
            .unwrap();
        assert_eq!(&plaintext[..opened], b"authenticated object record");
    }

    #[test]
    fn wrong_capability_or_transcript_fails_closed() {
        assert!(establish(&[1; 32], &[2; 32], b"context", b"context").is_err());
        assert!(establish(&[1; 32], &[1; 32], b"context-a", b"context-b").is_err());
    }

    #[test]
    fn replay_is_not_valid_at_the_next_ordered_nonce() {
        let (mut sender, mut receiver) =
            establish(&[7; 32], &[7; 32], b"context", b"context").unwrap();
        let mut ciphertext = [0_u8; 256];
        let mut plaintext = [0_u8; 256];
        let length = sender.seal(b"once", &mut ciphertext).unwrap();
        receiver
            .open(&ciphertext[..length], &mut plaintext)
            .unwrap();
        assert!(
            receiver
                .open(&ciphertext[..length], &mut plaintext)
                .is_err()
        );
    }

    #[test]
    fn cloned_datagram_senders_allocate_one_nonce_space() {
        let (sender, receiver) = establish_datagram();
        let sender_clone = sender.clone();
        let mut first = [0_u8; 128];
        let mut second = [0_u8; 128];
        let (first_nonce, first_len) = sender.seal(b"one", &mut first).unwrap();
        let (second_nonce, second_len) = sender_clone.seal(b"two", &mut second).unwrap();
        assert_eq!((first_nonce, second_nonce), (0, 1));

        let mut plaintext = [0_u8; 128];
        let length = receiver
            .open(second_nonce, &second[..second_len], &mut plaintext)
            .unwrap();
        assert_eq!(&plaintext[..length], b"two");
        let length = receiver
            .open(first_nonce, &first[..first_len], &mut plaintext)
            .unwrap();
        assert_eq!(&plaintext[..length], b"one");
    }
}
