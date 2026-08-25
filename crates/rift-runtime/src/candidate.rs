//! Asupersync-native server-reflexive UDP candidate discovery.

use std::{io, net::SocketAddr, time::Duration};

use asupersync::{
    net::UdpSocket,
    time::{timeout_at, wall_now},
};
use rift_protocol::{
    MAX_STUN_MESSAGE_BYTES, StunError as ProtocolStunError, TransactionId, decode_binding_response,
    encode_binding_request,
};
use thiserror::Error;

/// Bounded STUN retransmission and unrelated-datagram policy.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct StunPolicy {
    /// First response deadline; later attempts use capped exponential backoff.
    pub initial_rto: Duration,
    /// Total sends of the identical Binding transaction.
    pub max_attempts: u8,
    /// Unrelated datagrams ignored within one response deadline.
    pub max_unrelated_datagrams: u16,
}

impl Default for StunPolicy {
    fn default() -> Self {
        Self {
            initial_rto: Duration::from_millis(500),
            max_attempts: 4,
            max_unrelated_datagrams: 32,
        }
    }
}

impl StunPolicy {
    fn validate(self) -> Result<Self, CandidateError> {
        if self.initial_rto.is_zero()
            || self.initial_rto > Duration::from_secs(4)
            || self.max_attempts == 0
            || self.max_attempts > 8
            || self.max_unrelated_datagrams == 0
            || self.max_unrelated_datagrams > 1_024
        {
            return Err(CandidateError::InvalidPolicy);
        }
        Ok(self)
    }
}

/// One server-reflexive observation tied to its base socket and server.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ServerReflexiveCandidate {
    /// Local socket from which the Binding transaction was sent.
    pub base: SocketAddr,
    /// Public mapping observed by the STUN server.
    pub mapped: SocketAddr,
    /// Server that returned the authenticated transaction identity.
    pub server: SocketAddr,
    /// Round trip for the successful attempt.
    pub rtt_us: u64,
    /// One-based transmission attempt that succeeded.
    pub attempts: u8,
}

/// Candidate-gathering failure.
#[derive(Debug, Error)]
pub enum CandidateError {
    /// Policy would create an unbounded or inert transaction.
    #[error("invalid STUN candidate policy")]
    InvalidPolicy,
    /// Operating-system CSPRNG was unavailable.
    #[error("secure operating-system entropy unavailable")]
    EntropyUnavailable,
    /// UDP socket failed.
    #[error("STUN path I/O failed: {0}")]
    Io(#[from] io::Error),
    /// Expected STUN server returned a malformed or negative response.
    #[error(transparent)]
    Protocol(#[from] ProtocolStunError),
    /// All bounded retransmissions expired.
    #[error("STUN Binding transaction timed out")]
    Timeout,
    /// Datagram noise exhausted the per-attempt processing budget.
    #[error("too many unrelated datagrams during STUN discovery")]
    UnrelatedDatagramLimit,
}

/// Discover the public mapping for an already-bound UDP socket.
///
/// The same socket and transaction ID are retained across retransmissions so
/// the result describes the exact future data path. Responses from other
/// sources and other transactions are ignored within a strict packet budget.
///
/// # Errors
///
/// Returns for invalid policy, entropy or socket failure, a malformed expected
/// response, unrelated-datagram flooding, or bounded timeout.
pub async fn discover_server_reflexive(
    socket: &mut UdpSocket,
    server: SocketAddr,
    policy: StunPolicy,
) -> Result<ServerReflexiveCandidate, CandidateError> {
    let policy = policy.validate()?;
    let base = socket.local_addr()?;
    let mut identity = [0_u8; 12];
    getrandom::fill(&mut identity).map_err(|_| CandidateError::EntropyUnavailable)?;
    let transaction = TransactionId(identity);
    let request = encode_binding_request(transaction);
    let mut rto = policy.initial_rto;

    for attempt in 1..=policy.max_attempts {
        let sent_at = wall_now();
        let sent = socket.send_to(&request, server).await?;
        if sent != request.len() {
            return Err(CandidateError::Io(io::Error::new(
                io::ErrorKind::WriteZero,
                "partial UDP datagram send",
            )));
        }
        let deadline = sent_at.saturating_add_nanos(duration_nanos(rto));
        let mut unrelated = 0_u16;
        let mut response = [0_u8; MAX_STUN_MESSAGE_BYTES];
        loop {
            let received = timeout_at(deadline, socket.recv_from(&mut response)).await;
            let Ok(received) = received else {
                break;
            };
            let (length, source) = received?;
            if source == server {
                match decode_binding_response(&response[..length], transaction) {
                    Ok(mapped) => {
                        let elapsed = wall_now().duration_since(sent_at);
                        return Ok(ServerReflexiveCandidate {
                            base,
                            mapped,
                            server,
                            rtt_us: elapsed / 1_000,
                            attempts: attempt,
                        });
                    }
                    Err(ProtocolStunError::TransactionMismatch) => {
                        unrelated = unrelated.saturating_add(1);
                    }
                    Err(error) => return Err(CandidateError::Protocol(error)),
                }
            } else {
                unrelated = unrelated.saturating_add(1);
            }
            if unrelated >= policy.max_unrelated_datagrams {
                return Err(CandidateError::UnrelatedDatagramLimit);
            }
        }
        rto = rto.saturating_mul(2).min(Duration::from_secs(4));
    }
    Err(CandidateError::Timeout)
}

fn duration_nanos(duration: Duration) -> u64 {
    u64::try_from(duration.as_nanos()).unwrap_or(u64::MAX)
}

#[cfg(test)]
mod tests {
    use asupersync::{net::UdpSocket, runtime::RuntimeBuilder};

    use super::*;

    #[test]
    fn discovers_mapping_on_the_same_live_udp_socket() {
        let runtime = RuntimeBuilder::new().worker_threads(2).build().unwrap();
        let handle = runtime.handle();
        let candidate = runtime.block_on(async move {
            let mut server = UdpSocket::bind("127.0.0.1:0").await.unwrap();
            let server_address = server.local_addr().unwrap();
            let mapped: SocketAddr = "203.0.113.44:4242".parse().unwrap();
            let server_task = handle.spawn(async move {
                let mut request = [0_u8; 64];
                let (length, peer) = server.recv_from(&mut request).await.unwrap();
                assert_eq!(length, 28);
                let transaction = TransactionId(request[8..20].try_into().unwrap());
                let response = binding_response(transaction, mapped);
                server.send_to(&response, peer).await.unwrap();
            });

            let mut client = UdpSocket::bind("127.0.0.1:0").await.unwrap();
            let base = client.local_addr().unwrap();
            let candidate = discover_server_reflexive(
                &mut client,
                server_address,
                StunPolicy {
                    initial_rto: Duration::from_millis(100),
                    max_attempts: 1,
                    max_unrelated_datagrams: 4,
                },
            )
            .await
            .unwrap();
            server_task.await;
            assert_eq!(candidate.base, base);
            candidate
        });
        assert_eq!(candidate.mapped, "203.0.113.44:4242".parse().unwrap());
        assert_eq!(candidate.attempts, 1);
    }

    #[test]
    fn bounded_timeout_does_not_invent_a_candidate() {
        let runtime = RuntimeBuilder::new().worker_threads(1).build().unwrap();
        let error = runtime.block_on(async {
            let sink = UdpSocket::bind("127.0.0.1:0").await.unwrap();
            let sink_address = sink.local_addr().unwrap();
            let mut client = UdpSocket::bind("127.0.0.1:0").await.unwrap();
            discover_server_reflexive(
                &mut client,
                sink_address,
                StunPolicy {
                    initial_rto: Duration::from_millis(20),
                    max_attempts: 1,
                    max_unrelated_datagrams: 2,
                },
            )
            .await
            .unwrap_err()
        });
        assert!(matches!(error, CandidateError::Timeout));
    }

    #[test]
    fn unrelated_transaction_is_ignored_within_the_packet_budget() {
        let runtime = RuntimeBuilder::new().worker_threads(2).build().unwrap();
        let handle = runtime.handle();
        let candidate = runtime.block_on(async move {
            let mut server = UdpSocket::bind("127.0.0.1:0").await.unwrap();
            let server_address = server.local_addr().unwrap();
            let mapped: SocketAddr = "198.51.100.8:7337".parse().unwrap();
            let server_task = handle.spawn(async move {
                let mut request = [0_u8; 64];
                let (_, peer) = server.recv_from(&mut request).await.unwrap();
                let transaction = TransactionId(request[8..20].try_into().unwrap());
                server
                    .send_to(&binding_response(TransactionId([0xEE; 12]), mapped), peer)
                    .await
                    .unwrap();
                server
                    .send_to(&binding_response(transaction, mapped), peer)
                    .await
                    .unwrap();
            });
            let mut client = UdpSocket::bind("127.0.0.1:0").await.unwrap();
            let candidate = discover_server_reflexive(
                &mut client,
                server_address,
                StunPolicy {
                    initial_rto: Duration::from_millis(100),
                    max_attempts: 1,
                    max_unrelated_datagrams: 2,
                },
            )
            .await
            .unwrap();
            server_task.await;
            candidate
        });
        assert_eq!(candidate.mapped, "198.51.100.8:7337".parse().unwrap());
        assert_eq!(candidate.attempts, 1);
    }

    #[test]
    fn retransmission_keeps_socket_and_transaction_identity() {
        let runtime = RuntimeBuilder::new().worker_threads(2).build().unwrap();
        let handle = runtime.handle();
        let candidate = runtime.block_on(async move {
            let mut server = UdpSocket::bind("127.0.0.1:0").await.unwrap();
            let server_address = server.local_addr().unwrap();
            let mapped: SocketAddr = "203.0.113.19:60123".parse().unwrap();
            let server_task = handle.spawn(async move {
                let mut first = [0_u8; 64];
                let (_, first_peer) = server.recv_from(&mut first).await.unwrap();
                let mut second = [0_u8; 64];
                let (_, second_peer) = server.recv_from(&mut second).await.unwrap();
                assert_eq!(first_peer, second_peer);
                assert_eq!(&first[8..20], &second[8..20]);
                let transaction = TransactionId(second[8..20].try_into().unwrap());
                server
                    .send_to(&binding_response(transaction, mapped), second_peer)
                    .await
                    .unwrap();
            });
            let mut client = UdpSocket::bind("127.0.0.1:0").await.unwrap();
            let candidate = discover_server_reflexive(
                &mut client,
                server_address,
                StunPolicy {
                    initial_rto: Duration::from_millis(20),
                    max_attempts: 2,
                    max_unrelated_datagrams: 2,
                },
            )
            .await
            .unwrap();
            server_task.await;
            candidate
        });
        assert_eq!(candidate.mapped, "203.0.113.19:60123".parse().unwrap());
        assert_eq!(candidate.attempts, 2);
    }

    fn binding_response(transaction: TransactionId, mapped: SocketAddr) -> Vec<u8> {
        const COOKIE: u32 = 0x2112_A442;
        const XOR_MAPPED: u16 = 0x0020;
        let SocketAddr::V4(mapped) = mapped else {
            panic!("test helper expects IPv4");
        };
        let mut value = vec![0, 1];
        value.extend_from_slice(&(mapped.port() ^ 0x2112).to_be_bytes());
        for (byte, mask) in mapped.ip().octets().iter().zip(COOKIE.to_be_bytes()) {
            value.push(*byte ^ mask);
        }
        let mut response = vec![0_u8; 20];
        response[..2].copy_from_slice(&0x0101_u16.to_be_bytes());
        response[2..4].copy_from_slice(&12_u16.to_be_bytes());
        response[4..8].copy_from_slice(&COOKIE.to_be_bytes());
        response[8..20].copy_from_slice(&transaction.0);
        response.extend_from_slice(&XOR_MAPPED.to_be_bytes());
        response.extend_from_slice(&8_u16.to_be_bytes());
        response.extend_from_slice(&value);
        response
    }
}
