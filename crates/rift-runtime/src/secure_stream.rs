//! Length-bounded Noise records over any ordered asupersync byte path.

use std::io;

use asupersync::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};
use thiserror::Error;

use crate::stream_crypto::{
    CryptoError, HandshakeRole, MAX_STREAM_PLAINTEXT, NoiseHandshake, STREAM_TAG_BYTES,
    StreamCipher,
};

const MAX_HANDSHAKE_MESSAGE: usize = 1_024;

/// One encrypted ordered path with strict record bounds.
pub struct SecureStream<S> {
    inner: S,
    cipher: StreamCipher,
}

/// Framing, I/O, or cryptographic failure on the stream oracle.
#[derive(Debug, Error)]
pub enum SecureStreamError {
    /// Underlying ordered path failed.
    #[error("secure stream I/O failed: {0}")]
    Io(#[from] io::Error),
    /// Noise authentication or transport processing failed.
    #[error(transparent)]
    Crypto(#[from] CryptoError),
    /// Peer declared a record larger than the fixed memory envelope.
    #[error("peer declared an oversized secure stream record")]
    OversizedRecord,
    /// Peer declared an empty or oversized handshake frame.
    #[error("peer declared an invalid Noise handshake frame")]
    InvalidHandshakeFrame,
}

impl<S> SecureStream<S>
where
    S: AsyncRead + AsyncWrite + Unpin,
{
    /// Run the two-message capability-authenticated handshake over `inner`.
    ///
    /// # Errors
    ///
    /// Returns [`SecureStreamError`] for I/O failure, malformed framing,
    /// capability mismatch, transcript mismatch, or cryptographic failure.
    pub async fn establish(
        mut inner: S,
        role: HandshakeRole,
        transfer_secret: &[u8; 32],
        prologue: &[u8],
    ) -> Result<Self, SecureStreamError> {
        let mut handshake = NoiseHandshake::new(role, transfer_secret, prologue)?;
        let mut message = [0_u8; MAX_HANDSHAKE_MESSAGE];
        let mut payload = [0_u8; MAX_HANDSHAKE_MESSAGE];

        match role {
            HandshakeRole::Initiator => {
                let length = handshake.write_message(&[], &mut message)?;
                write_handshake_frame(&mut inner, &message[..length]).await?;
                let length = read_handshake_frame(&mut inner, &mut message).await?;
                handshake.read_message(&message[..length], &mut payload)?;
            }
            HandshakeRole::Responder => {
                let length = read_handshake_frame(&mut inner, &mut message).await?;
                handshake.read_message(&message[..length], &mut payload)?;
                let length = handshake.write_message(&[], &mut message)?;
                write_handshake_frame(&mut inner, &message[..length]).await?;
            }
        }

        Ok(Self {
            inner,
            cipher: handshake.into_transport()?,
        })
    }

    /// Encrypt and send one exact application record.
    ///
    /// Cancellation after encryption poisons this ordered path because its send
    /// nonce has advanced; the path owner must close rather than reuse it.
    ///
    /// # Errors
    ///
    /// Returns [`SecureStreamError`] for oversized plaintext, cryptographic
    /// failure, nonce exhaustion, or path I/O failure.
    pub async fn send(&mut self, plaintext: &[u8]) -> Result<(), SecureStreamError> {
        let mut ciphertext = vec![0_u8; plaintext.len().saturating_add(STREAM_TAG_BYTES)];
        let length = self.cipher.seal(plaintext, &mut ciphertext)?;
        let length_prefix = u32::try_from(length)
            .map_err(|_| SecureStreamError::OversizedRecord)?
            .to_be_bytes();
        self.inner.write_all(&length_prefix).await?;
        self.inner.write_all(&ciphertext[..length]).await?;
        Ok(())
    }

    /// Make all previously sent authenticated records visible to the peer.
    ///
    /// Data paths may deliberately batch records, but every protocol boundary
    /// that writes and then waits for the peer must flush first.
    ///
    /// # Errors
    ///
    /// Returns when the ordered path cannot flush its buffered bytes.
    pub async fn flush(&mut self) -> Result<(), SecureStreamError> {
        self.inner.flush().await?;
        Ok(())
    }

    /// Receive, authenticate, and decrypt one exact application record.
    ///
    /// Cancellation after consuming any prefix or ciphertext poisons this
    /// ordered path; the path owner must close rather than reuse it.
    ///
    /// # Errors
    ///
    /// Returns [`SecureStreamError`] for invalid length, I/O failure, replay,
    /// reordering, tampering, or cryptographic failure.
    pub async fn receive(&mut self) -> Result<Vec<u8>, SecureStreamError> {
        let mut prefix = [0_u8; 4];
        self.inner.read_exact(&mut prefix).await?;
        let length = usize::try_from(u32::from_be_bytes(prefix))
            .map_err(|_| SecureStreamError::OversizedRecord)?;
        if !(STREAM_TAG_BYTES..=MAX_STREAM_PLAINTEXT + STREAM_TAG_BYTES).contains(&length) {
            return Err(SecureStreamError::OversizedRecord);
        }

        let mut ciphertext = vec![0_u8; length];
        self.inner.read_exact(&mut ciphertext).await?;
        let mut plaintext = vec![0_u8; length - STREAM_TAG_BYTES];
        let opened = self.cipher.open(&ciphertext, &mut plaintext)?;
        plaintext.truncate(opened);
        Ok(plaintext)
    }

    /// Flush protocol framing and close the authenticated byte path cleanly.
    ///
    /// # Errors
    ///
    /// Returns when the underlying transport cannot complete its shutdown.
    pub async fn shutdown(&mut self) -> Result<(), SecureStreamError> {
        self.inner.shutdown().await?;
        Ok(())
    }

    /// Consume the wrapper after a clean protocol shutdown.
    #[must_use]
    pub fn into_inner(self) -> S {
        self.inner
    }
}

async fn write_handshake_frame<S>(inner: &mut S, message: &[u8]) -> Result<(), SecureStreamError>
where
    S: AsyncWrite + Unpin,
{
    let length =
        u16::try_from(message.len()).map_err(|_| SecureStreamError::InvalidHandshakeFrame)?;
    if length == 0 || usize::from(length) > MAX_HANDSHAKE_MESSAGE {
        return Err(SecureStreamError::InvalidHandshakeFrame);
    }
    inner.write_all(&length.to_be_bytes()).await?;
    inner.write_all(message).await?;
    inner.flush().await?;
    Ok(())
}

async fn read_handshake_frame<S>(
    inner: &mut S,
    output: &mut [u8; MAX_HANDSHAKE_MESSAGE],
) -> Result<usize, SecureStreamError>
where
    S: AsyncRead + Unpin,
{
    let mut prefix = [0_u8; 2];
    inner.read_exact(&mut prefix).await?;
    let length = usize::from(u16::from_be_bytes(prefix));
    if length == 0 || length > output.len() {
        return Err(SecureStreamError::InvalidHandshakeFrame);
    }
    inner.read_exact(&mut output[..length]).await?;
    Ok(length)
}

#[cfg(test)]
mod tests {
    use std::{
        pin::Pin,
        task::{Context, Poll},
    };

    use asupersync::{io::AsyncWrite, runtime::RuntimeBuilder};

    use super::write_handshake_frame;

    #[derive(Default)]
    struct FlushRecorder {
        bytes: Vec<u8>,
        flushes: usize,
    }

    impl AsyncWrite for FlushRecorder {
        fn poll_write(
            self: Pin<&mut Self>,
            _cx: &mut Context<'_>,
            bytes: &[u8],
        ) -> Poll<std::io::Result<usize>> {
            self.get_mut().bytes.extend_from_slice(bytes);
            Poll::Ready(Ok(bytes.len()))
        }

        fn poll_flush(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<std::io::Result<()>> {
            self.get_mut().flushes += 1;
            Poll::Ready(Ok(()))
        }

        fn poll_shutdown(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<std::io::Result<()>> {
            Poll::Ready(Ok(()))
        }
    }

    #[test]
    fn handshake_flight_is_flushed_before_the_peer_must_reply() {
        let runtime = RuntimeBuilder::new().worker_threads(1).build().unwrap();
        runtime.block_on(async {
            let mut transport = FlushRecorder::default();
            write_handshake_frame(&mut transport, b"noise")
                .await
                .unwrap();
            assert_eq!(transport.bytes, b"\0\x05noise");
            assert_eq!(transport.flushes, 1);
        });
    }
}
