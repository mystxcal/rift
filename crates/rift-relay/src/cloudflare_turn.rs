//! Server-side issuance of short-lived Cloudflare TURN credentials.

use std::{sync::Arc, time::Duration};

use asupersync::{cx::Cx, http::HttpClient};
use rift_protocol::{
    RouteBundle, RouteBundleError, RouteServer, RouteTransport, TurnAuthorization,
};
use serde::{Deserialize, Serialize};
use thiserror::Error;
use zeroize::{Zeroize, Zeroizing};

const API_ORIGIN: &str = "https://rtc.live.cloudflare.com/v1/turn/keys";
const MAX_KEY_ID_BYTES: usize = 256;
const MAX_RESPONSE_BYTES: usize = 64 * 1024;
const MIN_TTL_SECONDS: u32 = 60;
const MAX_TTL_SECONDS: u32 = 48 * 60 * 60;

/// Cheaply cloneable server-side issuer shared by matched relay workers.
#[derive(Clone)]
pub struct RelayRouteIssuer {
    config: Arc<CloudflareTurnConfig>,
    client: HttpClient,
}

impl std::fmt::Debug for RelayRouteIssuer {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("RelayRouteIssuer")
            .field("config", &self.config)
            .finish_non_exhaustive()
    }
}

impl RelayRouteIssuer {
    /// Build a pooled Cloudflare credential issuer from server-only config.
    #[must_use]
    pub fn cloudflare(config: CloudflareTurnConfig) -> Self {
        Self {
            config: Arc::new(config),
            client: HttpClient::new(),
        }
    }

    pub(crate) async fn issue(&self, cx: &Cx) -> Result<Zeroizing<Vec<u8>>, RelayRouteIssueError> {
        Ok(self
            .config
            .generate(&self.client, cx)
            .await?
            .route_bundle()?
            .encode()?)
    }
}

#[derive(Debug, Error)]
pub(crate) enum RelayRouteIssueError {
    #[error(transparent)]
    Provider(#[from] CloudflareTurnError),
    #[error(transparent)]
    Bundle(#[from] RouteBundleError),
}

/// Server-only Cloudflare TURN issuer configuration.
///
/// The long-lived API token never crosses RIFT's client protocol and is
/// redacted from debug output.
pub struct CloudflareTurnConfig {
    key_id: String,
    api_token: Zeroizing<String>,
    ttl_seconds: u32,
    request_timeout: Duration,
}

impl std::fmt::Debug for CloudflareTurnConfig {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("CloudflareTurnConfig")
            .field("key_id", &self.key_id)
            .field("api_token", &"[REDACTED]")
            .field("ttl_seconds", &self.ttl_seconds)
            .field("request_timeout", &self.request_timeout)
            .finish()
    }
}

impl Drop for CloudflareTurnConfig {
    fn drop(&mut self) {
        self.key_id.zeroize();
    }
}

impl CloudflareTurnConfig {
    /// Build a bounded issuer configuration from deployment secrets.
    ///
    /// # Errors
    ///
    /// Returns when the key identifier, API token, TTL, or timeout violates the
    /// fixed server-side envelope.
    pub fn new(
        key_id: impl Into<String>,
        api_token: impl Into<String>,
        ttl_seconds: u32,
        request_timeout: Duration,
    ) -> Result<Self, CloudflareTurnError> {
        let key_id = key_id.into();
        let api_token = api_token.into();
        if key_id.is_empty()
            || key_id.len() > MAX_KEY_ID_BYTES
            || !key_id
                .bytes()
                .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_'))
            || api_token.is_empty()
            || !(MIN_TTL_SECONDS..=MAX_TTL_SECONDS).contains(&ttl_seconds)
            || request_timeout.is_zero()
            || request_timeout > Duration::from_secs(30)
        {
            return Err(CloudflareTurnError::InvalidConfig);
        }
        Ok(Self {
            key_id,
            api_token: Zeroizing::new(api_token),
            ttl_seconds,
            request_timeout,
        })
    }

    /// Mint one credential scoped by Cloudflare's expiry TTL.
    ///
    /// # Errors
    ///
    /// Returns for cancellation, HTTPS/DNS failure, a non-201 response, an
    /// oversized response, or a malformed/unsupported credential document.
    pub async fn generate(
        &self,
        client: &HttpClient,
        cx: &Cx,
    ) -> Result<ShortLivedTurnCredentials, CloudflareTurnError> {
        let endpoint = format!(
            "{API_ORIGIN}/{}/credentials/generate-ice-servers",
            self.key_id
        );
        let request = TtlRequest {
            ttl: self.ttl_seconds,
        };
        let response = client
            .post(endpoint)
            .bearer_auth(self.api_token.as_str())
            .accept("application/json")
            .json(&request)?
            .timeout(self.request_timeout)
            .send(cx)
            .await?;
        if response.status != 201 {
            return Err(CloudflareTurnError::Status(response.status));
        }
        if response.body.len() > MAX_RESPONSE_BYTES {
            return Err(CloudflareTurnError::OversizedResponse);
        }
        parse_credentials(&response.body)
    }
}

/// One supported Cloudflare STUN or TURN endpoint.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct CloudflareTurnServer {
    /// Route semantics parsed from the provider ICE document.
    pub transport: RouteTransport,
    /// DNS host supplied by the provider.
    pub host: String,
    /// UDP port supplied by the provider.
    pub port: u16,
}

/// Short-lived client material safe to deliver only to the matched live peers.
pub struct ShortLivedTurnCredentials {
    username: Zeroizing<String>,
    credential: Zeroizing<String>,
    servers: Vec<CloudflareTurnServer>,
}

impl std::fmt::Debug for ShortLivedTurnCredentials {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("ShortLivedTurnCredentials")
            .field("username", &"[REDACTED]")
            .field("credential", &"[REDACTED]")
            .field("servers", &self.servers)
            .finish()
    }
}

impl ShortLivedTurnCredentials {
    /// Ephemeral TURN username.
    #[must_use]
    pub fn username(&self) -> &str {
        self.username.as_str()
    }

    /// Ephemeral TURN password.
    #[must_use]
    pub fn credential(&self) -> &str {
        self.credential.as_str()
    }

    /// Provider endpoints in RIFT race order: STUN, TURN/UDP, TURN/TLS, TCP.
    #[must_use]
    pub fn servers(&self) -> &[CloudflareTurnServer] {
        &self.servers
    }

    /// Convert provider output into RIFT's bounded, provider-independent wire
    /// bootstrap.
    ///
    /// # Errors
    ///
    /// Returns if the provider values violate RIFT's stricter wire envelope.
    pub fn route_bundle(&self) -> Result<RouteBundle, RouteBundleError> {
        let servers = self
            .servers
            .iter()
            .map(|server| RouteServer {
                transport: server.transport,
                host: server.host.clone(),
                port: server.port,
            })
            .collect();
        RouteBundle::new(
            servers,
            Some(TurnAuthorization::new(
                self.username.as_str(),
                self.credential.as_str(),
            )?),
        )
    }
}

/// Cloudflare credential issuance failure.
#[derive(Debug, Error)]
pub enum CloudflareTurnError {
    /// Deployment configuration violates the bounded issuer policy.
    #[error("invalid Cloudflare TURN issuer configuration")]
    InvalidConfig,
    /// HTTPS request failed.
    #[error("Cloudflare TURN credential request failed: {0}")]
    Http(#[from] asupersync::http::ClientError),
    /// JSON request or response was malformed.
    #[error("Cloudflare TURN credential JSON was invalid: {0}")]
    Json(#[from] serde_json::Error),
    /// Provider returned an unsuccessful status without exposing its body.
    #[error("Cloudflare TURN credential endpoint returned HTTP {0}")]
    Status(u16),
    /// Provider response exceeded the fixed control-plane envelope.
    #[error("Cloudflare TURN credential response exceeded its limit")]
    OversizedResponse,
    /// Provider document had no complete supported UDP TURN entry.
    #[error("Cloudflare TURN credential response contained no supported UDP server")]
    MissingUdpTurn,
}

#[derive(Serialize)]
struct TtlRequest {
    ttl: u32,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct IceResponse {
    ice_servers: Vec<IceServer>,
}

#[derive(Deserialize)]
struct IceServer {
    urls: Vec<String>,
    username: Option<String>,
    credential: Option<String>,
}

fn parse_credentials(body: &[u8]) -> Result<ShortLivedTurnCredentials, CloudflareTurnError> {
    let response: IceResponse = serde_json::from_slice(body)?;
    let mut stun_servers = response
        .ice_servers
        .iter()
        .flat_map(|server| server.urls.iter())
        .filter_map(|url| parse_stun_url(url))
        .collect::<Vec<_>>();
    stun_servers.sort_by_key(|server| match server.port {
        3478 => 0,
        53 => 1,
        _ => 2,
    });
    stun_servers.dedup();
    for mut server in response.ice_servers {
        let (Some(username), Some(credential)) = (server.username.take(), server.credential.take())
        else {
            continue;
        };
        if username.is_empty() || credential.is_empty() {
            continue;
        }
        let mut turn_servers = server
            .urls
            .iter()
            .filter_map(|url| parse_turn_url(url))
            .collect::<Vec<_>>();
        turn_servers.sort_by_key(|server| {
            let preference = match server.transport {
                RouteTransport::TurnUdp if server.port == 3478 => 0,
                RouteTransport::TurnUdp => 1,
                RouteTransport::TurnTls if server.port == 443 => 2,
                RouteTransport::TurnTls => 3,
                RouteTransport::TurnTcp => 4,
                RouteTransport::StunUdp => 5,
            };
            (preference, server.port)
        });
        turn_servers.dedup();
        if turn_servers
            .iter()
            .any(|server| server.transport == RouteTransport::TurnUdp)
        {
            let mut servers = stun_servers.clone();
            servers.extend(turn_servers);
            return Ok(ShortLivedTurnCredentials {
                username: Zeroizing::new(username),
                credential: Zeroizing::new(credential),
                servers,
            });
        }
    }
    Err(CloudflareTurnError::MissingUdpTurn)
}

fn parse_stun_url(url: &str) -> Option<CloudflareTurnServer> {
    let authority = url.strip_prefix("stun:")?;
    let (host, port) = authority.rsplit_once(':')?;
    let port = port.parse().ok()?;
    if host != "stun.cloudflare.com" || !matches!(port, 53 | 3478) {
        return None;
    }
    Some(CloudflareTurnServer {
        transport: RouteTransport::StunUdp,
        host: host.to_owned(),
        port,
    })
}

fn parse_turn_url(url: &str) -> Option<CloudflareTurnServer> {
    let (authority, transport) = if let Some(authority) = url
        .strip_prefix("turn:")
        .and_then(|url| url.strip_suffix("?transport=udp"))
    {
        (authority, RouteTransport::TurnUdp)
    } else if let Some(authority) = url
        .strip_prefix("turn:")
        .and_then(|url| url.strip_suffix("?transport=tcp"))
    {
        (authority, RouteTransport::TurnTcp)
    } else {
        (
            url.strip_prefix("turns:")?.strip_suffix("?transport=tcp")?,
            RouteTransport::TurnTls,
        )
    };
    let (host, port) = authority.rsplit_once(':')?;
    let port = port.parse().ok()?;
    let valid_port = match transport {
        RouteTransport::TurnUdp => matches!(port, 53 | 3478),
        RouteTransport::TurnTcp => matches!(port, 80 | 3478),
        RouteTransport::TurnTls => matches!(port, 443 | 5349),
        RouteTransport::StunUdp => false,
    };
    if host != "turn.cloudflare.com" || !valid_port {
        return None;
    }
    Some(CloudflareTurnServer {
        transport,
        host: host.to_owned(),
        port,
    })
}

#[cfg(test)]
mod tests {
    use asupersync::runtime::RuntimeBuilder;

    use super::*;

    const DOCUMENT: &[u8] = br#"{
      "iceServers": [
        {"urls":[
          "stun:stun.cloudflare.com:53",
          "stun:stun.cloudflare.com:3478"
        ]},
        {
          "urls":[
            "turns:turn.cloudflare.com:443?transport=tcp",
            "turns:turn.cloudflare.com:5349?transport=tcp",
            "turn:turn.cloudflare.com:53?transport=udp",
            "turn:turn.cloudflare.com:3478?transport=udp",
            "turn:turn.cloudflare.com:80?transport=tcp",
            "turn:turn.cloudflare.com:3478?transport=tcp"
          ],
          "username":"ephemeral-user",
          "credential":"ephemeral-password"
        }
      ]
    }"#;

    #[test]
    fn extracts_supported_routes_in_race_order() {
        let credentials = parse_credentials(DOCUMENT).unwrap();
        assert_eq!(credentials.username(), "ephemeral-user");
        assert_eq!(credentials.credential(), "ephemeral-password");
        assert_eq!(
            credentials.servers(),
            &[
                CloudflareTurnServer {
                    transport: RouteTransport::StunUdp,
                    host: "stun.cloudflare.com".to_owned(),
                    port: 3478,
                },
                CloudflareTurnServer {
                    transport: RouteTransport::StunUdp,
                    host: "stun.cloudflare.com".to_owned(),
                    port: 53,
                },
                CloudflareTurnServer {
                    transport: RouteTransport::TurnUdp,
                    host: "turn.cloudflare.com".to_owned(),
                    port: 3478,
                },
                CloudflareTurnServer {
                    transport: RouteTransport::TurnUdp,
                    host: "turn.cloudflare.com".to_owned(),
                    port: 53,
                },
                CloudflareTurnServer {
                    transport: RouteTransport::TurnTls,
                    host: "turn.cloudflare.com".to_owned(),
                    port: 443,
                },
                CloudflareTurnServer {
                    transport: RouteTransport::TurnTls,
                    host: "turn.cloudflare.com".to_owned(),
                    port: 5349,
                },
                CloudflareTurnServer {
                    transport: RouteTransport::TurnTcp,
                    host: "turn.cloudflare.com".to_owned(),
                    port: 80,
                },
                CloudflareTurnServer {
                    transport: RouteTransport::TurnTcp,
                    host: "turn.cloudflare.com".to_owned(),
                    port: 3478,
                },
            ]
        );
        assert!(
            credentials
                .servers()
                .iter()
                .any(|server| server.transport == RouteTransport::TurnTls && server.port == 443)
        );
        let bundle = credentials.route_bundle().unwrap();
        assert_eq!(bundle.turn().unwrap().username(), "ephemeral-user");
        let debug = format!("{credentials:?}");
        assert!(!debug.contains("ephemeral-user"));
        assert!(!debug.contains("ephemeral-password"));
    }

    #[test]
    fn issuer_debug_redacts_the_long_lived_token() {
        let config = CloudflareTurnConfig::new(
            "key_123",
            "long-lived-provider-token",
            3_600,
            Duration::from_secs(5),
        )
        .unwrap();
        let debug = format!("{config:?}");
        assert!(!debug.contains("long-lived-provider-token"));
    }

    #[test]
    fn accepts_provider_maximum_ttl_and_rejects_larger_credentials() {
        assert!(
            CloudflareTurnConfig::new(
                "key_123",
                "long-lived-provider-token",
                48 * 60 * 60,
                Duration::from_secs(5),
            )
            .is_ok()
        );
        assert!(matches!(
            CloudflareTurnConfig::new(
                "key_123",
                "long-lived-provider-token",
                48 * 60 * 60 + 1,
                Duration::from_secs(5),
            ),
            Err(CloudflareTurnError::InvalidConfig)
        ));
    }

    #[test]
    fn live_provider_issues_the_supported_route_bundle_when_enabled() {
        if std::env::var_os("RIFT_CLOUDFLARE_LIVE").is_none() {
            return;
        }
        let key_id = std::env::var("RIFT_CLOUDFLARE_TURN_KEY_ID").unwrap();
        let api_token = std::env::var("RIFT_CLOUDFLARE_TURN_API_TOKEN").unwrap();
        let config =
            CloudflareTurnConfig::new(key_id, api_token, 48 * 60 * 60, Duration::from_secs(10))
                .unwrap();
        let runtime = RuntimeBuilder::new().worker_threads(2).build().unwrap();
        let credentials = runtime.block_on(async move {
            let cx = Cx::current().unwrap();
            config.generate(&HttpClient::new(), &cx).await
        });
        let credentials = credentials.unwrap();
        assert!(
            credentials
                .servers()
                .iter()
                .any(|server| server.transport == RouteTransport::TurnUdp)
        );
        assert!(
            credentials
                .servers()
                .iter()
                .any(|server| server.transport == RouteTransport::TurnTls)
        );
        assert!(credentials.route_bundle().is_ok());
    }

    #[test]
    fn rejects_provider_documents_without_udp_credentials() {
        assert!(matches!(
            parse_credentials(br#"{"iceServers":[{"urls":["stun:example.test"]}]}"#),
            Err(CloudflareTurnError::MissingUdpTurn)
        ));
    }
}
