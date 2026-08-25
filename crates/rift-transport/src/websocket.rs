//! A bounded binary WebSocket viewed as an ordered byte stream.

use std::{
    io,
    pin::Pin,
    task::{Context, Poll},
};

use asupersync::{
    bytes::{Bytes, BytesMut},
    codec::{Decoder, Encoder},
    io::{AsyncRead, AsyncWrite, ReadBuf},
    net::websocket::{Frame, FrameCodec, Opcode, WsError},
};

/// Canonical HTTP upgrade path for RIFT relay traffic.
pub const RIFT_WEBSOCKET_PATH: &str = "/rift/v1";
/// Required WebSocket subprotocol for RIFT relay traffic.
pub const RIFT_WEBSOCKET_PROTOCOL: &str = "rift.v1";

const MAX_FRAME_PAYLOAD_BYTES: usize = 256 * 1024;
const READ_SCRATCH_BYTES: usize = 16 * 1024;
const MAX_RETAINED_WIRE_BYTES: usize = MAX_FRAME_PAYLOAD_BYTES + 14 + READ_SCRATCH_BYTES;
const MAX_FRAMES_PER_POLL: usize = 32;

/// Local endpoint role, which determines RFC 6455 masking behavior.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum WebSocketRole {
    /// WebSocket client: writes are masked and reads must be unmasked.
    Client,
    /// WebSocket server: writes are unmasked and reads must be masked.
    Server,
}

/// A strict binary-only WebSocket adapter implementing ordered async byte I/O.
///
/// Application writes become final binary frames. Application reads receive
/// the concatenation of binary payloads, so higher protocol layers remain
/// independent of WebSocket message boundaries. Fragmented and text messages
/// are rejected rather than creating a second application protocol.
pub struct WebSocketByteStream<IO> {
    io: IO,
    codec: FrameCodec,
    read_wire: BytesMut,
    read_payload: Bytes,
    read_offset: usize,
    write_wire: BytesMut,
    write_offset: usize,
    pending_accepted: Option<usize>,
    peer_closed: bool,
    close_queued: bool,
}

enum DecodeProgress {
    Payload,
    NeedInput,
    Yield,
}

impl<IO> WebSocketByteStream<IO> {
    /// Wrap an already-upgraded WebSocket transport.
    #[must_use]
    pub fn new(io: IO, role: WebSocketRole) -> Self {
        Self::with_trailing(io, role, &[])
    }

    /// Wrap an upgraded transport while preserving bytes coalesced after the
    /// HTTP response or request headers.
    #[must_use]
    pub fn with_trailing(io: IO, role: WebSocketRole, trailing: &[u8]) -> Self {
        let codec = match role {
            WebSocketRole::Client => FrameCodec::client(),
            WebSocketRole::Server => FrameCodec::server(),
        }
        .max_payload_size(MAX_FRAME_PAYLOAD_BYTES);
        let mut read_wire = BytesMut::with_capacity(trailing.len().max(READ_SCRATCH_BYTES));
        read_wire.extend_from_slice(trailing);
        Self {
            io,
            codec,
            read_wire,
            read_payload: Bytes::new(),
            read_offset: 0,
            write_wire: BytesMut::new(),
            write_offset: 0,
            pending_accepted: None,
            peer_closed: false,
            close_queued: false,
        }
    }

    /// Recover the underlying upgraded I/O object.
    #[must_use]
    pub fn into_inner(self) -> IO {
        self.io
    }

    fn queue_frame(&mut self, frame: Frame) -> io::Result<()> {
        if self.write_offset == self.write_wire.len() {
            self.write_wire.clear();
            self.write_offset = 0;
        }
        self.codec
            .encode(frame, &mut self.write_wire)
            .map_err(ws_io_error)
    }

    fn poll_drain_wire(&mut self, cx: &mut Context<'_>) -> Poll<io::Result<()>>
    where
        IO: AsyncWrite + Unpin,
    {
        while self.write_offset < self.write_wire.len() {
            match Pin::new(&mut self.io).poll_write(cx, &self.write_wire[self.write_offset..]) {
                Poll::Ready(Ok(0)) => {
                    return Poll::Ready(Err(io::Error::new(
                        io::ErrorKind::WriteZero,
                        "WebSocket transport stopped accepting bytes",
                    )));
                }
                Poll::Ready(Ok(written)) => self.write_offset += written,
                Poll::Ready(Err(error)) => return Poll::Ready(Err(error)),
                Poll::Pending => return Poll::Pending,
            }
        }
        self.write_wire.clear();
        self.write_offset = 0;
        Poll::Ready(Ok(()))
    }

    fn copy_payload(&mut self, destination: &mut ReadBuf<'_>) -> bool {
        let remaining = &self.read_payload[self.read_offset..];
        let copied = remaining.len().min(destination.remaining());
        if copied == 0 {
            return false;
        }
        destination.put_slice(&remaining[..copied]);
        self.read_offset += copied;
        if self.read_offset == self.read_payload.len() {
            self.read_payload = Bytes::new();
            self.read_offset = 0;
        }
        true
    }

    fn decode_next_payload(&mut self) -> io::Result<DecodeProgress> {
        for _ in 0..MAX_FRAMES_PER_POLL {
            let Some(frame) = self
                .codec
                .decode(&mut self.read_wire)
                .map_err(ws_io_error)?
            else {
                return Ok(DecodeProgress::NeedInput);
            };
            match frame.opcode {
                Opcode::Binary if frame.fin => {
                    if !frame.payload.is_empty() {
                        self.read_payload = frame.payload;
                        self.read_offset = 0;
                        return Ok(DecodeProgress::Payload);
                    }
                }
                Opcode::Ping => self.queue_frame(Frame::pong(frame.payload))?,
                Opcode::Pong => {}
                Opcode::Close => {
                    self.peer_closed = true;
                    if !self.close_queued {
                        self.queue_frame(Frame::close(None, None))?;
                        self.close_queued = true;
                    }
                    return Ok(DecodeProgress::NeedInput);
                }
                Opcode::Binary | Opcode::Continuation | Opcode::Text => {
                    return Err(io::Error::new(
                        io::ErrorKind::InvalidData,
                        "RIFT WebSocket accepts only final binary frames",
                    ));
                }
            }
        }
        Ok(DecodeProgress::Yield)
    }
}

impl<IO: AsyncRead + AsyncWrite + Unpin> AsyncRead for WebSocketByteStream<IO> {
    fn poll_read(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        destination: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        let this = self.get_mut();
        if destination.remaining() == 0 || this.copy_payload(destination) {
            return Poll::Ready(Ok(()));
        }

        loop {
            let decode_progress = match this.decode_next_payload() {
                Ok(DecodeProgress::Payload) => {
                    let _ = this.copy_payload(destination);
                    return Poll::Ready(Ok(()));
                }
                Ok(DecodeProgress::NeedInput) if this.peer_closed => {
                    return match this.poll_drain_wire(cx) {
                        Poll::Ready(Ok(())) => Poll::Ready(Ok(())),
                        Poll::Ready(Err(error)) => Poll::Ready(Err(error)),
                        Poll::Pending => Poll::Pending,
                    };
                }
                Ok(progress) => progress,
                Err(error) => return Poll::Ready(Err(error)),
            };

            if !this.write_wire.is_empty() {
                match this.poll_drain_wire(cx) {
                    Poll::Ready(Ok(())) => {}
                    Poll::Ready(Err(error)) => return Poll::Ready(Err(error)),
                    Poll::Pending => return Poll::Pending,
                }
            }

            if matches!(decode_progress, DecodeProgress::Yield) {
                cx.waker().wake_by_ref();
                return Poll::Pending;
            }

            let remaining_budget = MAX_RETAINED_WIRE_BYTES.saturating_sub(this.read_wire.len());
            if remaining_budget == 0 {
                return Poll::Ready(Err(io::Error::new(
                    io::ErrorKind::InvalidData,
                    "WebSocket frame exceeded the retained wire budget",
                )));
            }
            let mut scratch = [0_u8; READ_SCRATCH_BYTES];
            let mut read = ReadBuf::new(&mut scratch[..remaining_budget.min(READ_SCRATCH_BYTES)]);
            match Pin::new(&mut this.io).poll_read(cx, &mut read) {
                Poll::Ready(Ok(())) if read.filled().is_empty() => {
                    if this.read_wire.is_empty() {
                        this.peer_closed = true;
                        return Poll::Ready(Ok(()));
                    }
                    return Poll::Ready(Err(io::Error::new(
                        io::ErrorKind::UnexpectedEof,
                        "WebSocket transport ended inside a frame",
                    )));
                }
                Poll::Ready(Ok(())) => this.read_wire.extend_from_slice(read.filled()),
                Poll::Ready(Err(error)) => return Poll::Ready(Err(error)),
                Poll::Pending => return Poll::Pending,
            }
        }
    }
}

impl<IO: AsyncWrite + Unpin> AsyncWrite for WebSocketByteStream<IO> {
    fn poll_write(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        source: &[u8],
    ) -> Poll<io::Result<usize>> {
        let this = self.get_mut();
        if this.peer_closed || this.close_queued {
            return Poll::Ready(Err(io::Error::new(
                io::ErrorKind::BrokenPipe,
                "WebSocket is closing",
            )));
        }
        if source.is_empty() {
            return Poll::Ready(Ok(0));
        }
        if let Some(accepted) = this.pending_accepted {
            match this.poll_drain_wire(cx) {
                Poll::Ready(Ok(())) => {
                    this.pending_accepted = None;
                    return Poll::Ready(Ok(accepted));
                }
                Poll::Ready(Err(error)) => return Poll::Ready(Err(error)),
                Poll::Pending => return Poll::Pending,
            }
        }
        let accepted = source.len().min(MAX_FRAME_PAYLOAD_BYTES);
        if let Err(error) =
            this.queue_frame(Frame::binary(Bytes::copy_from_slice(&source[..accepted])))
        {
            return Poll::Ready(Err(error));
        }
        this.pending_accepted = Some(accepted);
        match this.poll_drain_wire(cx) {
            Poll::Ready(Ok(())) => {
                this.pending_accepted = None;
                Poll::Ready(Ok(accepted))
            }
            Poll::Ready(Err(error)) => Poll::Ready(Err(error)),
            Poll::Pending => Poll::Pending,
        }
    }

    fn poll_flush(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        let this = self.get_mut();
        match this.poll_drain_wire(cx) {
            Poll::Ready(Ok(())) => Pin::new(&mut this.io).poll_flush(cx),
            other => other,
        }
    }

    fn poll_shutdown(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        let this = self.get_mut();
        if !this.close_queued {
            if let Err(error) = this.queue_frame(Frame::close(None, None)) {
                return Poll::Ready(Err(error));
            }
            this.close_queued = true;
        }
        match this.poll_drain_wire(cx) {
            Poll::Ready(Ok(())) => Pin::new(&mut this.io).poll_shutdown(cx),
            other => other,
        }
    }
}

fn ws_io_error(error: WsError) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidData, error)
}

#[cfg(test)]
mod tests {
    use asupersync::{
        bytes::BytesMut,
        codec::Encoder,
        io::{AsyncReadExt, AsyncWriteExt},
        net::{TcpListener, TcpStream},
        runtime::RuntimeBuilder,
    };

    use super::*;

    #[test]
    fn binary_frames_form_one_exact_bounded_byte_stream() {
        let runtime = RuntimeBuilder::new().worker_threads(2).build().unwrap();
        let handle = runtime.handle();
        runtime.block_on(async move {
            let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
            let address = listener.local_addr().unwrap();
            let server = handle.clone().spawn(async move {
                let (tcp, _) = listener.accept().await.unwrap();
                let mut stream = WebSocketByteStream::new(tcp, WebSocketRole::Server);
                let mut received = vec![0_u8; MAX_FRAME_PAYLOAD_BYTES * 2 + 7_919];
                stream.read_exact(&mut received).await.unwrap();
                assert!(
                    received
                        .iter()
                        .enumerate()
                        .all(|(index, byte)| *byte == u8::try_from(index % 251).unwrap())
                );
                stream.write_all(b"exact").await.unwrap();
                stream.shutdown().await.unwrap();
            });

            let tcp = TcpStream::connect(address).await.unwrap();
            let mut stream = WebSocketByteStream::new(tcp, WebSocketRole::Client);
            let sent: Vec<u8> = (0..MAX_FRAME_PAYLOAD_BYTES * 2 + 7_919)
                .map(|index| u8::try_from(index % 251).unwrap())
                .collect();
            stream.write_all(&sent).await.unwrap();
            let mut response = [0_u8; 5];
            stream.read_exact(&mut response).await.unwrap();
            assert_eq!(&response, b"exact");
            let () = server.await;
        });
    }

    #[test]
    fn text_and_oversized_frames_fail_before_application_bytes() {
        let runtime = RuntimeBuilder::new().worker_threads(2).build().unwrap();
        let handle = runtime.handle();
        runtime.block_on(async move {
            let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
            let address = listener.local_addr().unwrap();
            let text_sender = handle.clone().spawn(async move {
                let mut tcp = TcpStream::connect(address).await.unwrap();
                let mut codec = FrameCodec::client();
                let mut wire = BytesMut::new();
                codec.encode(Frame::text("not RIFT"), &mut wire).unwrap();
                tcp.write_all(&wire).await.unwrap();
                AsyncWriteExt::shutdown(&mut tcp).await.unwrap();
            });
            let (tcp, _) = listener.accept().await.unwrap();
            let mut stream = WebSocketByteStream::new(tcp, WebSocketRole::Server);
            let mut byte = [0_u8; 1];
            let error = stream.read_exact(&mut byte).await.unwrap_err();
            assert_eq!(error.kind(), io::ErrorKind::InvalidData);
            let () = text_sender.await;

            let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
            let address = listener.local_addr().unwrap();
            let oversized_sender = handle.clone().spawn(async move {
                let mut tcp = TcpStream::connect(address).await.unwrap();
                let mut header = Vec::with_capacity(14);
                header.extend_from_slice(&[0x82, 0xff]);
                header.extend_from_slice(
                    &u64::try_from(MAX_FRAME_PAYLOAD_BYTES + 1)
                        .unwrap()
                        .to_be_bytes(),
                );
                header.extend_from_slice(&[1, 2, 3, 4]);
                tcp.write_all(&header).await.unwrap();
                AsyncWriteExt::shutdown(&mut tcp).await.unwrap();
            });
            let (tcp, _) = listener.accept().await.unwrap();
            let mut stream = WebSocketByteStream::new(tcp, WebSocketRole::Server);
            let error = stream.read_exact(&mut byte).await.unwrap_err();
            assert_eq!(error.kind(), io::ErrorKind::InvalidData);
            let () = oversized_sender.await;
        });
    }
}
