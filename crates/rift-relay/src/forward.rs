//! Bounded-memory, activity-timed ciphertext forwarding.

use std::{
    future::{Future, poll_fn},
    io,
    pin::Pin,
    sync::{
        Arc,
        atomic::{AtomicU64, Ordering},
    },
    task::{Context, Poll},
    time::Duration,
};

use asupersync::{
    io::{AsyncRead, AsyncWrite, AsyncWriteExt, ReadBuf, copy_bidirectional},
    time::{Sleep, wall_now},
};
use thiserror::Error;

/// Committed bytes forwarded before the live session reached peer closure.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ForwardStats {
    /// Bytes from the sender-side socket to the receiver-side socket.
    pub sender_to_receiver: u64,
    /// Bytes from the receiver-side socket to the sender-side socket.
    pub receiver_to_sender: u64,
}

/// Terminal relay-session result.
#[derive(Debug, Error)]
pub enum ForwardError {
    /// A peer or local socket failed.
    #[error("relay forwarding failed: {0}")]
    Io(#[from] io::Error),
    /// Neither direction committed bytes within the fixed idle envelope.
    #[error("relay session exceeded its idle timeout")]
    IdleTimeout,
    /// Idle timeout must be positive.
    #[error("relay idle timeout must be nonzero")]
    InvalidTimeout,
}

/// Forward a live byte stream in both directions with bounded private buffers.
///
/// The function never parses, retains, or reconstructs payload bytes. An idle
/// timeout closes the whole path; a timed-out `copy_bidirectional` is never
/// resumed, so its drop-cancellation read-ahead caveat cannot skip bytes in a
/// reused session.
///
/// # Errors
///
/// Returns [`ForwardError::IdleTimeout`] after a full interval without a
/// successful read or write, or [`ForwardError::Io`] for socket failure.
pub async fn forward_bidirectional<A, B>(
    sender: &mut A,
    receiver: &mut B,
    idle_timeout: Duration,
) -> Result<ForwardStats, ForwardError>
where
    A: AsyncRead + AsyncWrite + Unpin,
    B: AsyncRead + AsyncWrite + Unpin,
{
    forward_bidirectional_with_close(sender, receiver, idle_timeout, false).await
}

pub(crate) async fn forward_bidirectional_websocket<A, B>(
    sender: &mut A,
    receiver: &mut B,
    idle_timeout: Duration,
) -> Result<ForwardStats, ForwardError>
where
    A: AsyncRead + AsyncWrite + Unpin,
    B: AsyncRead + AsyncWrite + Unpin,
{
    forward_bidirectional_with_close(sender, receiver, idle_timeout, true).await
}

async fn forward_bidirectional_with_close<A, B>(
    sender: &mut A,
    receiver: &mut B,
    idle_timeout: Duration,
    websocket_close_is_terminal: bool,
) -> Result<ForwardStats, ForwardError>
where
    A: AsyncRead + AsyncWrite + Unpin,
    B: AsyncRead + AsyncWrite + Unpin,
{
    if idle_timeout.is_zero() {
        return Err(ForwardError::InvalidTimeout);
    }

    let activity = Arc::new(AtomicU64::new(0));
    let mut sender_io = ActivityIo::new(
        &mut *sender,
        Arc::clone(&activity),
        websocket_close_is_terminal,
    );
    let mut receiver_io = ActivityIo::new(
        &mut *receiver,
        Arc::clone(&activity),
        websocket_close_is_terminal,
    );
    let mut copy = Box::pin(copy_bidirectional(&mut sender_io, &mut receiver_io));
    // TLS may commit buffered ciphertext into the kernel while the socket's
    // readiness edge is coalesced with reads on the same full-duplex stream.
    // Windows can exhibit the same missed-wake shape for a raw full-duplex
    // loopback copy. Bounded progress probes prevent either path from staying
    // parked until the much longer idle deadline; Linux raw relays retain the
    // purely readiness-driven production path.
    let progress_probe = if websocket_close_is_terminal {
        idle_timeout.min(Duration::from_secs(1))
    } else if cfg!(windows) {
        idle_timeout.min(Duration::from_millis(100))
    } else {
        idle_timeout
    };
    let mut last_activity = wall_now();
    let idle_nanos = u64::try_from(idle_timeout.as_nanos()).unwrap_or(u64::MAX);
    let mut idle = Box::pin(Sleep::after(last_activity, progress_probe));
    let mut armed_generation = 0;

    let outcome = poll_fn(|cx| {
        if let Poll::Ready(result) = copy.as_mut().poll(cx) {
            return Poll::Ready(result.map(|(forward, reverse)| ForwardStats {
                sender_to_receiver: forward,
                receiver_to_sender: reverse,
            }));
        }

        let latest_generation = activity.load(Ordering::Acquire);
        if latest_generation != armed_generation {
            armed_generation = latest_generation;
            last_activity = wall_now();
        }
        if idle.as_mut().poll(cx).is_ready() {
            let now = wall_now();
            if now.duration_since(last_activity) >= idle_nanos {
                return Poll::Ready(Err(io::Error::new(
                    io::ErrorKind::TimedOut,
                    "relay session idle",
                )));
            }
            idle.as_mut().get_mut().reset_after(now, progress_probe);
            cx.waker().wake_by_ref();
        }
        Poll::Pending
    })
    .await;
    drop(copy);
    let committed_before_close = ForwardStats {
        sender_to_receiver: receiver_io.written,
        receiver_to_sender: sender_io.written,
    };
    drop(sender_io);
    drop(receiver_io);

    let stats = match outcome {
        Ok(stats) => stats,
        // A relay has no object-level completion authority. Once a matched
        // peer closes, writes racing that close can surface before the read
        // half reports EOF (especially when the peer's final receipt used a
        // different path). Preserve the bytes already committed and classify
        // peer-closure errors as the terminal transport event. Endpoint
        // receipts, not relay shutdown order, decide transfer success.
        Err(error) if peer_closed(error.kind()) => committed_before_close,
        Err(error) if error.kind() == io::ErrorKind::TimedOut => {
            return Err(ForwardError::IdleTimeout);
        }
        Err(error) => return Err(ForwardError::Io(error)),
    };

    // `copy_bidirectional` models byte-stream half-close by shutting down the
    // opposite writer as soon as one reader reaches EOF. A WebSocket close is
    // full-duplex, so propagating that intermediate shutdown can reject the
    // final bytes already flowing in the other direction. The wrappers defer
    // transport shutdown until both readers reached EOF and both private copy
    // buffers drained. At that point close errors cannot invalidate bytes that
    // were already counted and committed.
    let _ = sender.shutdown().await;
    let _ = receiver.shutdown().await;
    Ok(stats)
}

fn peer_closed(kind: io::ErrorKind) -> bool {
    matches!(
        kind,
        io::ErrorKind::BrokenPipe
            | io::ErrorKind::ConnectionAborted
            | io::ErrorKind::ConnectionReset
            | io::ErrorKind::NotConnected
    )
}

struct ActivityIo<S> {
    inner: S,
    activity: Arc<AtomicU64>,
    read_eof: bool,
    written: u64,
    defer_shutdown: bool,
}

impl<S> ActivityIo<S> {
    fn new(inner: S, activity: Arc<AtomicU64>, defer_shutdown: bool) -> Self {
        Self {
            inner,
            activity,
            read_eof: false,
            written: 0,
            defer_shutdown,
        }
    }

    fn touch(&self) {
        self.activity.fetch_add(1, Ordering::AcqRel);
    }
}

impl<S: AsyncRead + Unpin> AsyncRead for ActivityIo<S> {
    fn poll_read(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buffer: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        let this = self.get_mut();
        let before = buffer.filled().len();
        let result = Pin::new(&mut this.inner).poll_read(cx, buffer);
        if matches!(result, Poll::Ready(Ok(()))) && buffer.filled().len() > before {
            this.touch();
        } else if matches!(result, Poll::Ready(Ok(()))) {
            this.read_eof = true;
        }
        result
    }
}

impl<S: AsyncWrite + Unpin> AsyncWrite for ActivityIo<S> {
    fn poll_write(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buffer: &[u8],
    ) -> Poll<io::Result<usize>> {
        let this = self.get_mut();
        let result = Pin::new(&mut this.inner).poll_write(cx, buffer);
        if let Poll::Ready(Ok(written)) = result
            && written > 0
        {
            this.written = this
                .written
                .saturating_add(u64::try_from(written).unwrap_or(u64::MAX));
            this.touch();
        }
        result
    }

    fn poll_flush(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        let this = self.get_mut();
        let result = Pin::new(&mut this.inner).poll_flush(cx);
        if matches!(result, Poll::Ready(Ok(()))) {
            this.touch();
        }
        result
    }

    fn poll_shutdown(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        let this = self.get_mut();
        if this.defer_shutdown {
            Poll::Ready(Ok(()))
        } else {
            Pin::new(&mut this.inner).poll_shutdown(cx)
        }
    }
}

#[cfg(test)]
mod tests {
    use std::{
        pin::Pin,
        sync::{Arc, atomic::AtomicU64},
        task::{Context, Poll},
    };

    use asupersync::{
        io::{AsyncRead, AsyncWrite, AsyncWriteExt, ReadBuf},
        runtime::RuntimeBuilder,
    };

    use super::{ActivityIo, forward_bidirectional_with_close};

    struct ClosedPeer;

    impl AsyncRead for ClosedPeer {
        fn poll_read(
            self: Pin<&mut Self>,
            _cx: &mut Context<'_>,
            _buffer: &mut ReadBuf<'_>,
        ) -> Poll<std::io::Result<()>> {
            Poll::Ready(Ok(()))
        }
    }

    impl AsyncWrite for ClosedPeer {
        fn poll_write(
            self: Pin<&mut Self>,
            _cx: &mut Context<'_>,
            buffer: &[u8],
        ) -> Poll<std::io::Result<usize>> {
            Poll::Ready(Ok(buffer.len()))
        }

        fn poll_flush(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<std::io::Result<()>> {
            Poll::Ready(Ok(()))
        }

        fn poll_shutdown(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<std::io::Result<()>> {
            Poll::Ready(Err(std::io::Error::new(
                std::io::ErrorKind::BrokenPipe,
                "peer already closed",
            )))
        }
    }

    #[test]
    fn copy_half_shutdown_is_deferred_until_both_directions_finish() {
        let runtime = RuntimeBuilder::new().worker_threads(1).build().unwrap();
        runtime.block_on(async {
            let activity = Arc::new(AtomicU64::new(0));
            let mut path = ActivityIo::new(ClosedPeer, activity, true);
            path.shutdown().await.unwrap();
        });
    }

    struct PendingReader {
        bytes: Option<Vec<u8>>,
        reject_writes: bool,
    }

    impl AsyncRead for PendingReader {
        fn poll_read(
            self: Pin<&mut Self>,
            _cx: &mut Context<'_>,
            buffer: &mut ReadBuf<'_>,
        ) -> Poll<std::io::Result<()>> {
            let this = self.get_mut();
            if let Some(bytes) = this.bytes.take() {
                buffer.put_slice(&bytes);
                Poll::Ready(Ok(()))
            } else {
                Poll::Pending
            }
        }
    }

    impl AsyncWrite for PendingReader {
        fn poll_write(
            self: Pin<&mut Self>,
            _cx: &mut Context<'_>,
            buffer: &[u8],
        ) -> Poll<std::io::Result<usize>> {
            if self.reject_writes {
                Poll::Ready(Err(std::io::Error::new(
                    std::io::ErrorKind::BrokenPipe,
                    "peer closed before read EOF was observed",
                )))
            } else {
                Poll::Ready(Ok(buffer.len()))
            }
        }

        fn poll_flush(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<std::io::Result<()>> {
            Poll::Ready(Ok(()))
        }

        fn poll_shutdown(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<std::io::Result<()>> {
            Poll::Ready(Ok(()))
        }
    }

    #[test]
    fn write_side_peer_close_is_terminal_even_before_read_eof() {
        let runtime = RuntimeBuilder::new().worker_threads(1).build().unwrap();
        runtime.block_on(async {
            let mut closed = PendingReader {
                bytes: None,
                reject_writes: true,
            };
            let mut source = PendingReader {
                bytes: Some(vec![7; 32]),
                reject_writes: false,
            };
            let stats = forward_bidirectional_with_close(
                &mut closed,
                &mut source,
                std::time::Duration::from_secs(1),
                true,
            )
            .await
            .unwrap();
            assert_eq!(stats.sender_to_receiver, 0);
            assert_eq!(stats.receiver_to_sender, 0);
        });
    }
}
