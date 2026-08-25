//! Bounded network-route bootstrap delivered by the live relay after matching.

use thiserror::Error;
use zeroize::{Zeroize, Zeroizing};

const MAGIC: [u8; 4] = *b"RFTR";
const VERSION: u8 = 1;
const HEADER_BYTES: usize = 12;
const SERVER_HEADER_BYTES: usize = 4;
const MAX_SERVERS: usize = 8;
const MAX_HOST_BYTES: usize = 253;
const MAX_SECRET_BYTES: usize = 512;

/// Maximum encoded route bootstrap accepted from a relay.
pub const MAX_ROUTE_BUNDLE_BYTES: usize = 4 * 1024;
/// Bytes needed to learn the exact route-bootstrap length.
pub const ROUTE_BUNDLE_HEADER_BYTES: usize = HEADER_BYTES;

/// One candidate-discovery or relay transport advertised to both live peers.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[repr(u8)]
pub enum RouteTransport {
    /// RFC 8489 STUN over UDP.
    StunUdp = 1,
    /// TURN allocation carrying datagrams over UDP.
    TurnUdp = 2,
    /// TURN allocation reached over TCP.
    TurnTcp = 3,
    /// TURN allocation reached over TLS.
    TurnTls = 4,
}

/// One bounded network endpoint.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct RouteServer {
    /// Transport semantics for this endpoint.
    pub transport: RouteTransport,
    /// DNS name; IP literals are also accepted.
    pub host: String,
    /// Network port.
    pub port: u16,
}

/// Short-lived TURN authorization shared only with one matched live pair.
pub struct TurnAuthorization {
    username: Zeroizing<String>,
    credential: Zeroizing<String>,
}

impl std::fmt::Debug for TurnAuthorization {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("TurnAuthorization")
            .field("username", &"[REDACTED]")
            .field("credential", &"[REDACTED]")
            .finish()
    }
}

impl TurnAuthorization {
    /// Construct bounded ephemeral authorization.
    ///
    /// # Errors
    ///
    /// Returns when either provider value is empty or exceeds the wire bound.
    pub fn new(
        username: impl Into<String>,
        credential: impl Into<String>,
    ) -> Result<Self, RouteBundleError> {
        let username = username.into();
        let credential = credential.into();
        if username.is_empty()
            || credential.is_empty()
            || username.len() > MAX_SECRET_BYTES
            || credential.len() > MAX_SECRET_BYTES
        {
            return Err(RouteBundleError::InvalidAuthorization);
        }
        Ok(Self {
            username: Zeroizing::new(username),
            credential: Zeroizing::new(credential),
        })
    }

    /// Ephemeral TURN username.
    #[must_use]
    pub fn username(&self) -> &str {
        self.username.as_str()
    }

    /// Ephemeral TURN credential.
    #[must_use]
    pub fn credential(&self) -> &str {
        self.credential.as_str()
    }
}

/// Network bootstrap generated once for one matched pair.
pub struct RouteBundle {
    servers: Vec<RouteServer>,
    turn: Option<TurnAuthorization>,
}

impl std::fmt::Debug for RouteBundle {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("RouteBundle")
            .field("servers", &self.servers)
            .field("turn", &self.turn)
            .finish()
    }
}

impl RouteBundle {
    /// Construct and validate one provider-independent bundle.
    ///
    /// # Errors
    ///
    /// Returns for duplicate, malformed, unsupported, or incoherent routes.
    pub fn new(
        servers: Vec<RouteServer>,
        turn: Option<TurnAuthorization>,
    ) -> Result<Self, RouteBundleError> {
        if servers.is_empty() || servers.len() > MAX_SERVERS {
            return Err(RouteBundleError::InvalidServers);
        }
        let mut has_turn = false;
        for (index, server) in servers.iter().enumerate() {
            if server.host.is_empty()
                || server.host.len() > MAX_HOST_BYTES
                || !server.host.is_ascii()
                || server.port == 0
                || servers[..index].contains(server)
            {
                return Err(RouteBundleError::InvalidServers);
            }
            has_turn |= server.transport != RouteTransport::StunUdp;
        }
        if has_turn != turn.is_some() {
            return Err(RouteBundleError::InvalidAuthorization);
        }
        Ok(Self { servers, turn })
    }

    /// Advertised endpoints in provider preference order.
    #[must_use]
    pub fn servers(&self) -> &[RouteServer] {
        &self.servers
    }

    /// Short-lived TURN authorization, when TURN routes are present.
    #[must_use]
    pub const fn turn(&self) -> Option<&TurnAuthorization> {
        self.turn.as_ref()
    }

    /// Encode the exact bounded bootstrap; the returned secret-bearing buffer
    /// zeroizes itself on drop.
    ///
    /// # Errors
    ///
    /// Returns if the total encoded representation exceeds its fixed envelope.
    pub fn encode(&self) -> Result<Zeroizing<Vec<u8>>, RouteBundleError> {
        let username = self.turn.as_ref().map_or("", TurnAuthorization::username);
        let credential = self.turn.as_ref().map_or("", TurnAuthorization::credential);
        let mut encoded = Zeroizing::new(Vec::with_capacity(MAX_ROUTE_BUNDLE_BYTES.min(512)));
        encoded.extend_from_slice(&MAGIC);
        encoded.push(VERSION);
        encoded.push(u8::try_from(self.servers.len()).map_err(|_| RouteBundleError::TooLarge)?);
        encoded.extend_from_slice(&[0_u8; 2]);
        encoded.extend_from_slice(
            &u16::try_from(username.len())
                .map_err(|_| RouteBundleError::TooLarge)?
                .to_be_bytes(),
        );
        encoded.extend_from_slice(
            &u16::try_from(credential.len())
                .map_err(|_| RouteBundleError::TooLarge)?
                .to_be_bytes(),
        );
        for server in &self.servers {
            encoded.push(server.transport as u8);
            encoded.push(u8::try_from(server.host.len()).map_err(|_| RouteBundleError::TooLarge)?);
            encoded.extend_from_slice(&server.port.to_be_bytes());
            encoded.extend_from_slice(server.host.as_bytes());
        }
        encoded.extend_from_slice(username.as_bytes());
        encoded.extend_from_slice(credential.as_bytes());
        if encoded.len() > MAX_ROUTE_BUNDLE_BYTES {
            return Err(RouteBundleError::TooLarge);
        }
        let total_len = u16::try_from(encoded.len()).map_err(|_| RouteBundleError::TooLarge)?;
        encoded[6..8].copy_from_slice(&total_len.to_be_bytes());
        Ok(encoded)
    }

    /// Decode one exact provider-independent bootstrap.
    ///
    /// # Errors
    ///
    /// Rejects non-canonical, truncated, oversized, or incoherent input.
    pub fn decode(mut encoded: Zeroizing<Vec<u8>>) -> Result<Self, RouteBundleError> {
        if encoded.len() < HEADER_BYTES || encoded.len() > MAX_ROUTE_BUNDLE_BYTES {
            return Err(RouteBundleError::InvalidLength);
        }
        if encoded[..4] != MAGIC || encoded[4] != VERSION {
            return Err(RouteBundleError::InvalidEnvelope);
        }
        let count = usize::from(encoded[5]);
        let declared_len = usize::from(u16::from_be_bytes([encoded[6], encoded[7]]));
        let username_len = usize::from(u16::from_be_bytes([encoded[8], encoded[9]]));
        let credential_len = usize::from(u16::from_be_bytes([encoded[10], encoded[11]]));
        if count == 0
            || count > MAX_SERVERS
            || declared_len != encoded.len()
            || username_len > MAX_SECRET_BYTES
            || credential_len > MAX_SECRET_BYTES
        {
            return Err(RouteBundleError::InvalidLength);
        }
        let mut cursor = HEADER_BYTES;
        let mut servers = Vec::with_capacity(count);
        for _ in 0..count {
            let header = encoded
                .get(cursor..cursor + SERVER_HEADER_BYTES)
                .ok_or(RouteBundleError::InvalidLength)?;
            let transport = match header[0] {
                1 => RouteTransport::StunUdp,
                2 => RouteTransport::TurnUdp,
                3 => RouteTransport::TurnTcp,
                4 => RouteTransport::TurnTls,
                _ => return Err(RouteBundleError::InvalidEnvelope),
            };
            let host_len = usize::from(header[1]);
            let port = u16::from_be_bytes([header[2], header[3]]);
            cursor += SERVER_HEADER_BYTES;
            let host = std::str::from_utf8(
                encoded
                    .get(cursor..cursor + host_len)
                    .ok_or(RouteBundleError::InvalidLength)?,
            )
            .map_err(|_| RouteBundleError::InvalidEnvelope)?
            .to_owned();
            cursor += host_len;
            servers.push(RouteServer {
                transport,
                host,
                port,
            });
        }
        let secrets_end = cursor
            .checked_add(username_len)
            .and_then(|end| end.checked_add(credential_len))
            .ok_or(RouteBundleError::InvalidLength)?;
        if secrets_end != encoded.len() {
            return Err(RouteBundleError::InvalidLength);
        }
        let username = String::from_utf8(
            encoded
                .get(cursor..cursor + username_len)
                .ok_or(RouteBundleError::InvalidLength)?
                .to_vec(),
        )
        .map_err(|_| RouteBundleError::InvalidEnvelope)?;
        cursor += username_len;
        let credential = String::from_utf8(
            encoded
                .get(cursor..cursor + credential_len)
                .ok_or(RouteBundleError::InvalidLength)?
                .to_vec(),
        )
        .map_err(|_| RouteBundleError::InvalidEnvelope)?;
        encoded.zeroize();
        let turn = if username.is_empty() && credential.is_empty() {
            None
        } else {
            Some(TurnAuthorization::new(username, credential)?)
        };
        Self::new(servers, turn)
    }
}

/// Route-bootstrap wire failure.
#[derive(Clone, Copy, Debug, Error, Eq, PartialEq)]
pub enum RouteBundleError {
    /// Server list was empty, duplicated, malformed, or too long.
    #[error("invalid route servers")]
    InvalidServers,
    /// TURN routes and short-lived authorization disagree.
    #[error("invalid TURN authorization")]
    InvalidAuthorization,
    /// Encoded representation exceeded its fixed envelope.
    #[error("route bundle exceeded its fixed envelope")]
    TooLarge,
    /// Encoded representation had a wrong or inexact length.
    #[error("invalid route bundle length")]
    InvalidLength,
    /// Magic, version, UTF-8, or route kind was invalid.
    #[error("invalid route bundle envelope")]
    InvalidEnvelope,
}

/// Return the full encoded length from one already-read fixed header.
///
/// # Errors
///
/// Rejects malformed headers and lengths outside the fixed envelope.
pub fn route_bundle_encoded_len(
    header: &[u8; ROUTE_BUNDLE_HEADER_BYTES],
) -> Result<usize, RouteBundleError> {
    if header[..4] != MAGIC || header[4] != VERSION {
        return Err(RouteBundleError::InvalidEnvelope);
    }
    let count = usize::from(header[5]);
    let encoded_len = usize::from(u16::from_be_bytes([header[6], header[7]]));
    let username_len = usize::from(u16::from_be_bytes([header[8], header[9]]));
    let credential_len = usize::from(u16::from_be_bytes([header[10], header[11]]));
    if count == 0
        || count > MAX_SERVERS
        || username_len > MAX_SECRET_BYTES
        || credential_len > MAX_SECRET_BYTES
        || !(HEADER_BYTES..=MAX_ROUTE_BUNDLE_BYTES).contains(&encoded_len)
        || encoded_len < HEADER_BYTES + username_len + credential_len
    {
        return Err(RouteBundleError::InvalidLength);
    }
    Ok(encoded_len)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn bundle() -> RouteBundle {
        RouteBundle::new(
            vec![
                RouteServer {
                    transport: RouteTransport::StunUdp,
                    host: "stun.cloudflare.com".to_owned(),
                    port: 3478,
                },
                RouteServer {
                    transport: RouteTransport::TurnUdp,
                    host: "turn.cloudflare.com".to_owned(),
                    port: 3478,
                },
            ],
            Some(TurnAuthorization::new("temporary-user", "temporary-secret").unwrap()),
        )
        .unwrap()
    }

    #[test]
    fn exact_round_trip_keeps_routes_and_redacts_authorization() {
        let expected = bundle();
        let encoded = expected.encode().unwrap();
        let actual = RouteBundle::decode(encoded).unwrap();
        assert_eq!(actual.servers(), expected.servers());
        assert_eq!(actual.turn().unwrap().username(), "temporary-user");
        let debug = format!("{actual:?}");
        assert!(!debug.contains("temporary-user"));
        assert!(!debug.contains("temporary-secret"));
    }

    #[test]
    fn rejects_turn_without_authorization() {
        assert_eq!(
            RouteBundle::new(
                vec![RouteServer {
                    transport: RouteTransport::TurnUdp,
                    host: "turn.cloudflare.com".to_owned(),
                    port: 3478,
                }],
                None,
            )
            .unwrap_err(),
            RouteBundleError::InvalidAuthorization
        );
    }
}
