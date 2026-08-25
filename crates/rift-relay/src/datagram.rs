//! Blind, bounded UDP rendezvous for direct-path candidate exchange.
//!
//! The relay matches opaque lookup identifiers and returns only source
//! addresses it observed itself. It cannot authenticate registrations because
//! it deliberately lacks the transfer secret; peers authenticate the resulting
//! path before any payload migration.

use std::{collections::BTreeMap, io, net::SocketAddr, time::Duration};

use asupersync::{
    cx::Cx,
    net::UdpSocket,
    time::{timeout, wall_now},
};
use rift_protocol::{
    DIRECT_MATCH_BYTES, DirectMatch, DirectRegistration, MAX_DIRECT_DATAGRAM_BYTES, Role,
};
use thiserror::Error;

use crate::{RelayPolicy, RelayPolicyError};

/// Terminal direct-rendezvous service failure.
#[derive(Debug, Error)]
pub enum DirectRendezvousError {
    /// Resource policy is invalid.
    #[error(transparent)]
    Policy(#[from] RelayPolicyError),
    /// UDP socket operation failed.
    #[error("direct rendezvous I/O failed: {0}")]
    Io(#[from] io::Error),
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct Endpoint {
    address: SocketAddr,
    nonce: [u8; 16],
    authenticator: [u8; 16],
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum Entry {
    Waiting {
        sender: Endpoint,
        expires_at_ms: u64,
    },
    Matched {
        sender: Endpoint,
        receiver: Endpoint,
        expires_at_ms: u64,
    },
}

#[derive(Debug)]
struct DirectMatchTable {
    entries: BTreeMap<[u8; 16], Entry>,
    capacity: usize,
    ttl_ms: u64,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum RegistrationOutcome {
    Ignored,
    Waiting,
    Matched {
        sender: Endpoint,
        receiver: Endpoint,
    },
    Repeat {
        peer: Endpoint,
    },
}

impl DirectMatchTable {
    fn new(capacity: usize, ttl_ms: u64) -> Result<Self, RelayPolicyError> {
        if capacity == 0 || ttl_ms == 0 {
            return Err(RelayPolicyError::UnboundedOrPersistent);
        }
        Ok(Self {
            entries: BTreeMap::new(),
            capacity,
            ttl_ms,
        })
    }

    fn register(
        &mut self,
        now_ms: u64,
        registration: DirectRegistration,
        address: SocketAddr,
    ) -> RegistrationOutcome {
        self.expire(now_ms);
        let endpoint = Endpoint {
            address,
            nonce: registration.nonce,
            authenticator: registration.authenticator,
        };
        let existing = self.entries.get(&registration.lookup_id).copied();
        match (registration.role, existing) {
            (Role::Sender, None) if self.entries.len() >= self.capacity => {
                RegistrationOutcome::Ignored
            }
            (Role::Sender, None) => {
                self.entries.insert(
                    registration.lookup_id,
                    Entry::Waiting {
                        sender: endpoint,
                        expires_at_ms: now_ms.saturating_add(self.ttl_ms),
                    },
                );
                RegistrationOutcome::Waiting
            }
            (
                Role::Receiver,
                Some(Entry::Waiting {
                    sender,
                    expires_at_ms,
                }),
            ) => {
                self.entries.insert(
                    registration.lookup_id,
                    Entry::Matched {
                        sender,
                        receiver: endpoint,
                        expires_at_ms,
                    },
                );
                RegistrationOutcome::Matched {
                    sender,
                    receiver: endpoint,
                }
            }
            (Role::Sender, Some(Entry::Waiting { sender, .. })) if sender == endpoint => {
                RegistrationOutcome::Waiting
            }
            (
                Role::Sender,
                Some(Entry::Matched {
                    sender, receiver, ..
                }),
            ) if sender == endpoint => RegistrationOutcome::Repeat { peer: receiver },
            (
                Role::Receiver,
                Some(Entry::Matched {
                    sender, receiver, ..
                }),
            ) if receiver == endpoint => RegistrationOutcome::Repeat { peer: sender },
            _ => RegistrationOutcome::Ignored,
        }
    }

    fn expire(&mut self, now_ms: u64) {
        self.entries.retain(|_, entry| match entry {
            Entry::Waiting { expires_at_ms, .. } | Entry::Matched { expires_at_ms, .. } => {
                *expires_at_ms > now_ms
            }
        });
    }
}

/// Serve UDP candidate rendezvous until the owning runtime context is cancelled.
///
/// The service is intentionally live-only. A sender must reserve a random
/// lookup first, entries expire under the relay's existing match timeout, and
/// a short matched cache only allows either live endpoint to recover a lost UDP
/// match response.
///
/// # Errors
///
/// Returns for an invalid relay policy or terminal UDP I/O failure. Malformed,
/// duplicate, receiver-first, and capacity-exhausting datagrams are ignored.
pub async fn serve_direct_rendezvous(
    mut socket: UdpSocket,
    policy: RelayPolicy,
) -> Result<(), DirectRendezvousError> {
    let policy = policy.validate()?;
    let capacity = usize::try_from(policy.max_pending_lookups)
        .map_err(|_| RelayPolicyError::UnboundedOrPersistent)?;
    let mut table = DirectMatchTable::new(capacity, policy.match_timeout_ms)?;
    let sweep = Duration::from_millis(policy.match_timeout_ms.min(100));
    let cx = Cx::current().ok_or_else(|| io::Error::other("UDP rendezvous requires a runtime"))?;
    let mut buffer = [0_u8; MAX_DIRECT_DATAGRAM_BYTES];

    loop {
        cx.checkpoint()
            .map_err(|_| io::Error::new(io::ErrorKind::Interrupted, "UDP rendezvous cancelled"))?;
        let received = timeout(wall_now(), sweep, socket.recv_from(&mut buffer)).await;
        let Ok(received) = received else {
            table.expire(now_ms());
            continue;
        };
        let (length, source) = received?;
        let Ok(registration) = DirectRegistration::decode(&buffer[..length]) else {
            continue;
        };
        match table.register(now_ms(), registration, source) {
            RegistrationOutcome::Matched { sender, receiver } => {
                // One endpoint can disappear between registration and this
                // reply. A destination-scoped UDP error must not kill the
                // shared rendezvous service or prevent the other endpoint from
                // receiving its match. The bounded matched entry lets either
                // live endpoint retransmit its registration.
                let _ = send_match_to(
                    &mut socket,
                    registration.lookup_id,
                    sender.address,
                    receiver,
                )
                .await;
                let _ = send_match_to(
                    &mut socket,
                    registration.lookup_id,
                    receiver.address,
                    sender,
                )
                .await;
            }
            RegistrationOutcome::Repeat { peer } => {
                let _ = send_match_to(&mut socket, registration.lookup_id, source, peer).await;
            }
            RegistrationOutcome::Ignored | RegistrationOutcome::Waiting => {}
        }
    }
}

async fn send_match_to(
    socket: &mut UdpSocket,
    lookup_id: [u8; 16],
    target: SocketAddr,
    peer: Endpoint,
) -> io::Result<()> {
    let response = DirectMatch {
        lookup_id,
        peer_nonce: peer.nonce,
        peer_authenticator: peer.authenticator,
        peer_addr: peer.address,
    }
    .encode();
    let sent = socket.send_to(&response, target).await?;
    if sent == DIRECT_MATCH_BYTES {
        Ok(())
    } else {
        Err(io::Error::new(
            io::ErrorKind::WriteZero,
            "partial direct rendezvous datagram send",
        ))
    }
}

fn now_ms() -> u64 {
    wall_now().as_millis()
}

#[cfg(test)]
mod tests {
    use asupersync::{
        net::UdpSocket,
        runtime::RuntimeBuilder,
        time::{timeout, wall_now},
    };

    use super::*;

    fn registration(lookup_id: [u8; 16], role: Role, nonce: u8) -> DirectRegistration {
        DirectRegistration {
            lookup_id,
            role,
            nonce: [nonce; 16],
            authenticator: [0xA5; 16],
        }
    }

    #[test]
    fn sender_first_table_is_bounded_and_one_shot() {
        let mut table = DirectMatchTable::new(1, 100).unwrap();
        let sender_addr = "127.0.0.1:1001".parse().unwrap();
        let receiver_addr = "127.0.0.1:1002".parse().unwrap();
        assert_eq!(
            table.register(0, registration([1; 16], Role::Receiver, 2), receiver_addr),
            RegistrationOutcome::Ignored
        );
        assert_eq!(
            table.register(0, registration([1; 16], Role::Sender, 1), sender_addr),
            RegistrationOutcome::Waiting
        );
        assert_eq!(
            table.register(0, registration([2; 16], Role::Sender, 3), sender_addr),
            RegistrationOutcome::Ignored
        );
        assert!(matches!(
            table.register(1, registration([1; 16], Role::Receiver, 2), receiver_addr),
            RegistrationOutcome::Matched { .. }
        ));
        assert_eq!(
            table.register(2, registration([1; 16], Role::Sender, 1), sender_addr),
            RegistrationOutcome::Repeat {
                peer: Endpoint {
                    address: receiver_addr,
                    nonce: [2; 16],
                    authenticator: [0xA5; 16]
                }
            }
        );
        assert_eq!(
            table.register(101, registration([2; 16], Role::Sender, 3), sender_addr),
            RegistrationOutcome::Waiting
        );
    }

    #[test]
    fn live_service_matches_observed_addresses_and_recovers_response_loss() {
        let runtime = RuntimeBuilder::new().worker_threads(2).build().unwrap();
        runtime.block_on(async move {
            let relay = UdpSocket::bind("127.0.0.1:0").await.unwrap();
            let relay_addr = relay.local_addr().unwrap();
            let cx = Cx::current().unwrap();
            let mut service = cx
                .spawn(move |_cx| async move {
                    serve_direct_rendezvous(
                        relay,
                        RelayPolicy {
                            match_timeout_ms: 1_000,
                            ..RelayPolicy::default()
                        },
                    )
                    .await
                })
                .unwrap();
            let mut sender = UdpSocket::bind("127.0.0.1:0").await.unwrap();
            let mut receiver = UdpSocket::bind("127.0.0.1:0").await.unwrap();
            let sender_addr = sender.local_addr().unwrap();
            let receiver_addr = receiver.local_addr().unwrap();
            let sender_registration = registration([7; 16], Role::Sender, 1).encode();
            let receiver_registration = registration([7; 16], Role::Receiver, 2).encode();
            sender
                .send_to(&sender_registration, relay_addr)
                .await
                .unwrap();
            receiver
                .send_to(&receiver_registration, relay_addr)
                .await
                .unwrap();

            let mut buffer = [0_u8; DIRECT_MATCH_BYTES];
            let (length, source) = timeout(
                wall_now(),
                Duration::from_secs(1),
                receiver.recv_from(&mut buffer),
            )
            .await
            .unwrap()
            .unwrap();
            assert_eq!(source, relay_addr);
            assert_eq!(
                DirectMatch::decode(&buffer[..length]).unwrap(),
                DirectMatch {
                    lookup_id: [7; 16],
                    peer_nonce: [1; 16],
                    peer_authenticator: [0xA5; 16],
                    peer_addr: sender_addr,
                }
            );

            sender
                .send_to(&sender_registration, relay_addr)
                .await
                .unwrap();
            let (length, source) = timeout(
                wall_now(),
                Duration::from_secs(1),
                sender.recv_from(&mut buffer),
            )
            .await
            .unwrap()
            .unwrap();
            assert_eq!(source, relay_addr);
            assert_eq!(
                DirectMatch::decode(&buffer[..length]).unwrap(),
                DirectMatch {
                    lookup_id: [7; 16],
                    peer_nonce: [2; 16],
                    peer_authenticator: [0xA5; 16],
                    peer_addr: receiver_addr,
                }
            );

            service.abort();
            let _ = service.join(&cx).await;
        });
    }
}
