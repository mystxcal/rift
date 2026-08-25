#![forbid(unsafe_code)]

//! RIFT's human and stable JSON command surface.

use std::{
    env, fs,
    io::{self, IsTerminal, Write},
    net::SocketAddr,
    path::{Path, PathBuf},
    process::ExitCode,
    str::FromStr,
    sync::Mutex,
    time::{Duration, Instant},
};

use asupersync::{
    cx::Cx,
    net::{TcpListener, UdpSocket},
    tls::{Certificate, TlsAcceptor, TlsConnector},
};
use clap::{Parser, Subcommand};
use rift_protocol::{Capability, PairingCode};
use rift_relay::{
    CloudflareTurnConfig, RelayPolicy, RelayRouteIssuer, serve, serve_direct_rendezvous, serve_one,
    serve_one_wss, serve_one_wss_with_routes, serve_wss, serve_wss_with_routes,
};
use rift_runtime::{
    DirectAcquisitionStatus, DirectFailureStatus, MigrationReport, ReceiptDelivery, ReceiveTarget,
    RelayDialer, RelayEndpoint, RuntimePolicy, TransferObserver, TransferPolicy, TransferProfile,
    TransferProgress, TransferTransport, build_runtime,
    receive_via_pairing_target_observed_with_policy, reserve_fresh_pairing_sender_with,
    send_reserved_via_pairing_observed_with_policy,
};
use serde::{Deserialize, Serialize};

#[derive(Debug, Parser)]
#[command(
    name = "rift",
    version,
    about = "Send files and folders live, encrypted, and fast"
)]
struct Cli {
    /// Emit stable newline-delimited JSON events.
    #[arg(long, global = true)]
    json: bool,
    #[command(subcommand)]
    command: Command,
}

#[derive(Debug, Subcommand)]
enum Command {
    /// Inspect whether the local runtime and cryptographic entropy are usable.
    Doctor {
        /// Worker count used by the runtime smoke test.
        #[arg(long, default_value_t = 1)]
        workers: usize,
    },
    /// Create or inspect a transfer capability without contacting the network.
    #[command(hide = true)]
    Capability {
        #[command(subcommand)]
        command: CapabilityCommand,
    },
    /// Remember or inspect this device's relay connection.
    Config {
        #[command(subcommand)]
        command: ConfigCommand,
    },
    /// Run a persistent, bounded blind relay.
    Relay {
        /// Socket on which the relay listens.
        #[arg(long, default_value = "127.0.0.1:7337")]
        listen: SocketAddr,
        /// PEM certificate chain for authenticated WSS ingress.
        #[arg(long, requires = "tls_key")]
        tls_cert: Option<PathBuf>,
        /// PEM private key for authenticated WSS ingress.
        #[arg(long, requires = "tls_cert")]
        tls_key: Option<PathBuf>,
        /// Exit after one completed transfer (acceptance harness only).
        #[arg(long)]
        one_shot: bool,
        /// Maximum simultaneously active transfers.
        #[arg(long, default_value_t = 8)]
        max_sessions: u32,
        /// Maximum live unmatched sender reservations.
        #[arg(long, default_value_t = 256)]
        max_pending: u32,
        /// Maximum ciphertext window per active transfer, in MiB.
        #[arg(long, default_value_t = 2)]
        window_mib: u64,
    },
    /// Send one file or folder.
    #[command(visible_alias = "put")]
    Send {
        /// File or folder to stream exactly once.
        source: PathBuf,
        /// `wss://host/rift/v1`, or a loopback development socket.
        #[arg(long)]
        relay: Option<String>,
        /// PEM CA certificate for a private WSS relay.
        #[arg(long)]
        ca_cert: Option<PathBuf>,
        /// Fixed local UDP port for administered NAT/firewall mappings.
        #[arg(long, default_value_t = 0)]
        direct_port: u16,
    },
    /// Receive one file or folder.
    #[command(visible_aliases = ["get", "recv"])]
    Receive {
        /// Sender-provided four-digit and word pairing code.
        code: String,
        /// Optional new path or existing folder. Omit to save under the sender's name here.
        destination: Option<PathBuf>,
        /// `wss://host/rift/v1`, or a loopback development socket.
        #[arg(long)]
        relay: Option<String>,
        /// PEM CA certificate for a private WSS relay.
        #[arg(long)]
        ca_cert: Option<PathBuf>,
        /// Fixed local UDP port for administered NAT/firewall mappings.
        #[arg(long, default_value_t = 0)]
        direct_port: u16,
    },
}

#[derive(Debug, Subcommand)]
enum ConfigCommand {
    /// Remember the relay used by future send and receive commands.
    SetRelay {
        /// `wss://host/rift/v1`, or a loopback development socket.
        relay: String,
        /// PEM CA certificate for a private WSS relay.
        #[arg(long)]
        ca_cert: Option<PathBuf>,
    },
    /// Show the effective relay configuration without exposing secrets.
    Show,
}

#[derive(Debug, Subcommand)]
enum CapabilityCommand {
    /// Generate a new one-transfer capability.
    New {
        /// HTTPS rendezvous or loopback `rift+tcp` development locator.
        #[arg(long)]
        rendezvous: String,
    },
    /// Parse and validate a capability while keeping its secret redacted.
    Inspect {
        /// Printable RIFT capability.
        capability: String,
    },
}

#[derive(Default, Serialize)]
struct Output {
    ok: bool,
    kind: &'static str,
    #[serde(skip_serializing_if = "Option::is_none")]
    rendezvous: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    capability: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    code: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    address: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    destination: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    bytes: Option<u64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    blocks: Option<u64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    entries: Option<u64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    digest: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    transport: Option<&'static str>,
    #[serde(skip_serializing_if = "Option::is_none")]
    migration: Option<MigrationOutput>,
    #[serde(skip_serializing_if = "Option::is_none")]
    profile: Option<ProfileOutput>,
    #[serde(skip_serializing_if = "Option::is_none")]
    elapsed_ms: Option<u64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    bytes_per_second: Option<u64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    receipt: Option<&'static str>,
    #[serde(skip_serializing_if = "Option::is_none")]
    message: Option<String>,
}

#[derive(Clone, Debug, Default, Deserialize, Serialize)]
struct DeviceConfig {
    relay: Option<String>,
    ca_cert: Option<PathBuf>,
}

struct ConsoleProgress {
    action: &'static str,
    json: bool,
    interactive: bool,
    state: Mutex<ProgressState>,
}

struct ProgressState {
    started: Instant,
    last_emit: Instant,
    last_sample: Instant,
    last_bytes: u64,
    smoothed_bps: u64,
    total: u64,
    entries: u64,
    drew_line: bool,
}

#[derive(Serialize)]
struct ProgressOutput {
    ok: bool,
    kind: &'static str,
    action: &'static str,
    bytes: u64,
    total_bytes: u64,
    entries: u64,
    bytes_per_second: u64,
    eta_seconds: u64,
}

#[derive(Serialize)]
struct RouteOutput {
    ok: bool,
    kind: &'static str,
    route: &'static str,
    candidates: u16,
}

impl ConsoleProgress {
    fn new(action: &'static str, json: bool) -> Self {
        let now = Instant::now();
        Self {
            action,
            json,
            interactive: io::stderr().is_terminal(),
            state: Mutex::new(ProgressState {
                started: now,
                last_emit: now.checked_sub(Duration::from_secs(1)).unwrap_or(now),
                last_sample: now,
                last_bytes: 0,
                smoothed_bps: 0,
                total: 0,
                entries: 0,
                drew_line: false,
            }),
        }
    }

    fn finish(&self) {
        let mut state = self
            .state
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        if state.drew_line && !self.json {
            eprintln!();
            state.drew_line = false;
        }
    }

    fn peer_ready(&self) {
        if self.json {
            println!(
                "{}",
                serde_json::json!({
                    "ok": true,
                    "kind": "path_testing",
                })
            );
            let _ = io::stdout().flush();
        } else if self.interactive {
            eprintln!("Connected  ·  finding fastest path…");
        }
    }

    fn route_selected(&self, primary: TransferTransport, candidates: u16) {
        if self.json {
            println!(
                "{}",
                serde_json::to_string(&RouteOutput {
                    ok: true,
                    kind: "route",
                    route: transport_name(primary),
                    candidates,
                })
                .expect("serializable route")
            );
            let _ = io::stdout().flush();
        } else if self.interactive {
            eprintln!("Route  {}", transport_label(primary));
        }
    }

    fn recovering(&self) {
        if self.json {
            println!(
                "{}",
                serde_json::json!({
                    "ok": true,
                    "kind": "recovering",
                    "route": "relay",
                })
            );
            let _ = io::stdout().flush();
        } else if self.interactive {
            eprintln!("Path interrupted  ·  resuming safely over relay");
        }
    }

    fn declared(&self, state: &mut ProgressState, bytes: u64, entries: u64) {
        let now = Instant::now();
        state.started = now;
        state.last_emit = now;
        state.last_sample = now;
        state.last_bytes = 0;
        state.smoothed_bps = 0;
        state.total = bytes;
        state.entries = entries;
        if self.interactive && !self.json {
            eprint!(
                "\r{} {} {} ({})…",
                self.action,
                entries,
                if entries == 1 { "item" } else { "items" },
                human_bytes(bytes)
            );
            let _ = io::stderr().flush();
            state.drew_line = true;
        }
    }

    fn advanced(&self, state: &mut ProgressState, bytes: u64, total: u64) {
        let now = Instant::now();
        if bytes < total && now.duration_since(state.last_emit) < Duration::from_millis(250) {
            return;
        }
        state.last_emit = now;
        let sample_elapsed = now.duration_since(state.last_sample);
        if sample_elapsed >= Duration::from_millis(200) {
            let sample_rate = rate(bytes.saturating_sub(state.last_bytes), sample_elapsed);
            state.smoothed_bps = if state.smoothed_bps == 0 {
                sample_rate
            } else {
                state
                    .smoothed_bps
                    .saturating_mul(3)
                    .saturating_add(sample_rate)
                    / 4
            };
            state.last_sample = now;
            state.last_bytes = bytes;
        }
        let speed = if state.smoothed_bps == 0 {
            rate(bytes, now.duration_since(state.started))
        } else {
            state.smoothed_bps
        };
        let remaining = total.saturating_sub(bytes);
        let eta_seconds = if remaining == 0 {
            0
        } else {
            remaining.saturating_add(speed.max(1) - 1) / speed.max(1)
        };
        if self.json {
            println!(
                "{}",
                serde_json::to_string(&ProgressOutput {
                    ok: true,
                    kind: "progress",
                    action: self.action,
                    bytes,
                    total_bytes: total,
                    entries: state.entries,
                    bytes_per_second: speed,
                    eta_seconds,
                })
                .expect("serializable progress")
            );
            let _ = io::stdout().flush();
        } else if self.interactive {
            let percent = bytes.saturating_mul(100).checked_div(total).unwrap_or(100);
            let eta = if bytes >= total {
                "done".to_owned()
            } else {
                format!("{} left", human_duration(eta_seconds.saturating_mul(1_000)))
            };
            eprint!(
                "\r{:<9} {:>3}%  {} / {}  {}/s  {}\x1b[K",
                self.action,
                percent,
                human_bytes(bytes),
                human_bytes(total),
                human_bytes(speed),
                eta,
            );
            let _ = io::stderr().flush();
            state.drew_line = true;
        }
    }
}

impl TransferObserver for ConsoleProgress {
    fn observe(&self, event: TransferProgress) {
        let mut state = self
            .state
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        match event {
            TransferProgress::PeerReady => self.peer_ready(),
            TransferProgress::RouteSelected {
                primary,
                candidates,
            } => self.route_selected(primary, candidates),
            TransferProgress::Recovering => self.recovering(),
            TransferProgress::Declared { bytes, entries } => {
                self.declared(&mut state, bytes, entries);
            }
            TransferProgress::Advanced { bytes, total } => self.advanced(&mut state, bytes, total),
        }
    }
}

#[derive(Serialize)]
struct MigrationOutput {
    direct_acquisition: &'static str,
    relay_records: u64,
    direct_records: u64,
    fallback_events: u64,
    #[serde(skip_serializing_if = "Option::is_none")]
    relay_goodput_bps: Option<u64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    direct_goodput_floor_bps: Option<u64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    direct_validation_rtt_us: Option<u64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    direct_max_datagram_bytes: Option<u16>,
    #[serde(skip_serializing_if = "Option::is_none")]
    direct_smoothed_rtt_us: Option<u64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    direct_rto_us: Option<u64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    first_direct_sequence: Option<u64>,
    direct_datagrams: u64,
    direct_retransmitted_fragments: u64,
    direct_fast_retransmits: u64,
    direct_tail_probes: u64,
    direct_repair_symbols: u64,
    direct_send_batches: u64,
    direct_native_send_batches: u64,
    direct_gso_batches: u64,
    direct_gso_demotions: u64,
    direct_timeouts: u64,
    #[serde(skip_serializing_if = "Option::is_none")]
    last_direct_failure: Option<&'static str>,
}

#[derive(Serialize)]
struct ProfileOutput {
    elapsed_us: u64,
    source_scan_us: u64,
    source_read_us: u64,
    hash_verify_us: u64,
    path_queue_us: u64,
    quic_cpu_us: u64,
    socket_io_us: u64,
    staging_write_us: u64,
    durable_commit_us: u64,
    authenticated_paths: u16,
    payload_paths: u16,
    wire_sent_bytes: u64,
    wire_received_bytes: u64,
    lost_bytes: u64,
}

impl From<TransferProfile> for ProfileOutput {
    fn from(profile: TransferProfile) -> Self {
        Self {
            elapsed_us: profile.elapsed_us,
            source_scan_us: profile.source_scan_us,
            source_read_us: profile.source_read_us,
            hash_verify_us: profile.hash_verify_us,
            path_queue_us: profile.path_queue_us,
            quic_cpu_us: profile.quic_cpu_us,
            socket_io_us: profile.socket_io_us,
            staging_write_us: profile.staging_write_us,
            durable_commit_us: profile.durable_commit_us,
            authenticated_paths: profile.authenticated_paths,
            payload_paths: profile.payload_paths,
            wire_sent_bytes: profile.wire_sent_bytes,
            wire_received_bytes: profile.wire_received_bytes,
            lost_bytes: profile.lost_bytes,
        }
    }
}

impl From<MigrationReport> for MigrationOutput {
    fn from(report: MigrationReport) -> Self {
        Self {
            direct_acquisition: match report.direct_acquisition {
                DirectAcquisitionStatus::NotStarted => "not_started",
                DirectAcquisitionStatus::Incomplete => "incomplete",
                DirectAcquisitionStatus::Validated => "validated",
                DirectAcquisitionStatus::IoFailed => "io_failed",
                DirectAcquisitionStatus::AuthenticationFailed => "authentication_failed",
                DirectAcquisitionStatus::TimedOut => "timed_out",
                DirectAcquisitionStatus::Failed => "failed",
            },
            relay_records: report.relay_records,
            direct_records: report.direct_records,
            fallback_events: report.fallback_events,
            relay_goodput_bps: report.relay_goodput_bps,
            direct_goodput_floor_bps: report.direct_goodput_floor_bps,
            direct_validation_rtt_us: report.direct_validation_rtt_us,
            direct_max_datagram_bytes: report.direct_max_datagram_bytes,
            direct_smoothed_rtt_us: report.direct_smoothed_rtt_us,
            direct_rto_us: report.direct_rto_us,
            first_direct_sequence: report.first_direct_sequence,
            direct_datagrams: report.direct_datagrams,
            direct_retransmitted_fragments: report.direct_retransmitted_fragments,
            direct_fast_retransmits: report.direct_fast_retransmits,
            direct_tail_probes: report.direct_tail_probes,
            direct_repair_symbols: report.direct_repair_symbols,
            direct_send_batches: report.direct_send_batches,
            direct_native_send_batches: report.direct_native_send_batches,
            direct_gso_batches: report.direct_gso_batches,
            direct_gso_demotions: report.direct_gso_demotions,
            direct_timeouts: report.direct_timeouts,
            last_direct_failure: report.last_direct_failure.map(|failure| match failure {
                DirectFailureStatus::Timeout => "timeout",
                DirectFailureStatus::Io => "io",
                DirectFailureStatus::Protocol => "protocol",
                DirectFailureStatus::Authentication => "authentication",
                DirectFailureStatus::UnrelatedDatagramLimit => "unrelated_datagram_limit",
                DirectFailureStatus::InvalidPolicy => "invalid_policy",
            }),
        }
    }
}

fn main() -> ExitCode {
    let cli = Cli::parse();
    match run(&cli) {
        Ok(output) => {
            emit(&output, cli.json);
            ExitCode::SUCCESS
        }
        Err(message) => {
            emit_error(
                &Output {
                    kind: "error",
                    message: Some(message),
                    ..Output::default()
                },
                cli.json,
            );
            ExitCode::FAILURE
        }
    }
}

fn run(cli: &Cli) -> Result<Output, String> {
    match &cli.command {
        Command::Doctor { workers } => doctor(*workers),
        Command::Capability {
            command: CapabilityCommand::New { rendezvous },
        } => new_capability(rendezvous),
        Command::Capability {
            command: CapabilityCommand::Inspect { capability },
        } => inspect_capability(capability),
        Command::Config { command } => run_config(command),
        Command::Relay {
            listen,
            tls_cert,
            tls_key,
            one_shot,
            max_sessions,
            max_pending,
            window_mib,
        } => run_relay(
            *listen,
            tls_cert.as_deref(),
            tls_key.as_deref(),
            *one_shot,
            RelayPolicy {
                max_sessions: *max_sessions,
                max_pending_lookups: *max_pending,
                max_ciphertext_window_bytes: window_mib.saturating_mul(1024 * 1024),
                ..RelayPolicy::default()
            },
            cli.json,
        ),
        Command::Send {
            source,
            relay,
            ca_cert,
            direct_port,
        } => run_send(
            source,
            relay.as_deref(),
            ca_cert.as_deref(),
            *direct_port,
            cli.json,
        ),
        Command::Receive {
            code,
            destination,
            relay,
            ca_cert,
            direct_port,
        } => run_receive(
            code,
            destination.as_ref(),
            relay.as_deref(),
            ca_cert.as_deref(),
            *direct_port,
            cli.json,
        ),
    }
}

fn run_config(command: &ConfigCommand) -> Result<Output, String> {
    match command {
        ConfigCommand::SetRelay { relay, ca_cert } => {
            RelayEndpoint::from_str(relay).map_err(|error| error.to_string())?;
            if let Some(path) = ca_cert {
                Certificate::from_pem_file(path).map_err(|error| error.to_string())?;
            }
            let config = DeviceConfig {
                relay: Some(relay.clone()),
                ca_cert: ca_cert.clone(),
            };
            write_device_config(&config)?;
            Ok(Output {
                ok: true,
                kind: "config_saved",
                address: config.relay,
                message: Some("relay saved for this device".into()),
                ..Output::default()
            })
        }
        ConfigCommand::Show => {
            let (relay, ca_cert) = resolve_relay(None, None)?;
            Ok(Output {
                ok: true,
                kind: "config",
                address: Some(relay),
                message: Some(if ca_cert.is_some() {
                    "private CA configured".into()
                } else {
                    "system certificate roots".into()
                }),
                ..Output::default()
            })
        }
    }
}

fn doctor(workers: usize) -> Result<Output, String> {
    let code = PairingCode::generate().map_err(|error| error.to_string())?;
    let parsed = PairingCode::from_str(&code.to_string()).map_err(|error| error.to_string())?;
    if parsed != code {
        return Err("pairing-code self-check returned an impossible value".into());
    }
    let runtime = build_runtime(RuntimePolicy {
        worker_threads: workers,
    })
    .map_err(|error| error.to_string())?;
    if runtime.block_on(async { 42_u8 }) != 42 {
        return Err("runtime smoke test returned an impossible value".into());
    }
    Ok(Output {
        ok: true,
        kind: "doctor",
        message: Some("runtime, pairing, encrypted object, and local relay paths ready".into()),
        ..Output::default()
    })
}

fn new_capability(rendezvous: &str) -> Result<Output, String> {
    let capability =
        Capability::generate(rendezvous.to_owned()).map_err(|error| error.to_string())?;
    Ok(Output {
        ok: true,
        kind: "capability",
        rendezvous: Some(capability.rendezvous().to_owned()),
        capability: Some(capability.expose()),
        ..Output::default()
    })
}

fn inspect_capability(encoded: &str) -> Result<Output, String> {
    let capability = Capability::from_str(encoded).map_err(|error| error.to_string())?;
    Ok(Output {
        ok: true,
        kind: "capability",
        rendezvous: Some(capability.rendezvous().to_owned()),
        message: Some("valid capability; authorization secret redacted".into()),
        ..Output::default()
    })
}

fn run_relay(
    listen: SocketAddr,
    tls_cert: Option<&std::path::Path>,
    tls_key: Option<&std::path::Path>,
    one_shot: bool,
    policy: RelayPolicy,
    json: bool,
) -> Result<Output, String> {
    policy.validate().map_err(|error| error.to_string())?;
    if tls_cert.is_none() && !listen.ip().is_loopback() {
        return Err("a raw development relay may listen only on loopback".into());
    }
    let acceptor = match (tls_cert, tls_key) {
        (Some(cert), Some(key)) => Some(
            TlsAcceptor::builder_from_pem(cert, key)
                .map_err(|error| error.to_string())?
                .alpn_protocols_required(vec![b"http/1.1".to_vec()])
                .handshake_timeout(Duration::from_secs(10))
                .build()
                .map_err(|error| error.to_string())?,
        ),
        (None, None) => None,
        _ => return Err("both --tls-cert and --tls-key are required for WSS".into()),
    };
    let runtime = build_runtime(RuntimePolicy::default()).map_err(|error| error.to_string())?;
    let route_issuer = cloudflare_route_issuer()?;
    let (address, stats) = runtime.block_on(async move {
        let listener = TcpListener::bind(listen)
            .await
            .map_err(|error| error.to_string())?;
        let address = listener.local_addr().map_err(|error| error.to_string())?;
        let udp = UdpSocket::bind(address).await.map_err(|error| {
            format!("could not bind direct rendezvous UDP on {address}: {error}")
        })?;
        let cx = Cx::current().ok_or_else(|| "relay requires a runtime context".to_owned())?;
        let mut direct_task = cx
            .spawn(move |_direct_cx| async move { serve_direct_rendezvous(udp, policy).await })
            .map_err(|error| error.to_string())?;
        emit_intermediate(
            &Output {
                ok: true,
                kind: "relay_ready",
                address: Some(address.to_string()),
                message: Some(if one_shot {
                    "blind relay is waiting for one live pair".into()
                } else {
                    "bounded blind relay is ready".into()
                }),
                ..Output::default()
            },
            json,
        )?;
        let stats = if one_shot {
            Some(
                if let Some(acceptor) = acceptor {
                    if let Some(issuer) = route_issuer {
                        serve_one_wss_with_routes(listener, acceptor, policy, issuer).await
                    } else {
                        serve_one_wss(listener, acceptor, policy).await
                    }
                } else {
                    serve_one(listener, policy).await
                }
                .map_err(|error| error.to_string())?,
            )
        } else if let Some(acceptor) = acceptor {
            if let Some(issuer) = route_issuer {
                serve_wss_with_routes(listener, acceptor, policy, issuer)
                    .await
                    .map_err(|error| error.to_string())?;
            } else {
                serve_wss(listener, acceptor, policy)
                    .await
                    .map_err(|error| error.to_string())?;
            }
            None
        } else {
            serve(listener, policy)
                .await
                .map_err(|error| error.to_string())?;
            None
        };
        direct_task.abort();
        let _ = direct_task.join(&cx).await;
        Ok::<_, String>((address, stats))
    })?;
    let stats = stats.ok_or_else(|| "persistent relay stopped unexpectedly".to_owned())?;
    Ok(Output {
        ok: true,
        kind: "relay_complete",
        address: Some(address.to_string()),
        bytes: Some(stats.sender_to_receiver + stats.receiver_to_sender),
        message: Some("matched ciphertext path closed cleanly".into()),
        ..Output::default()
    })
}

fn cloudflare_route_issuer() -> Result<Option<RelayRouteIssuer>, String> {
    let key_id = env::var("RIFT_CLOUDFLARE_TURN_KEY_ID").ok();
    let token = env::var("RIFT_CLOUDFLARE_TURN_API_TOKEN").ok();
    match (key_id, token) {
        (None, None) => Ok(None),
        (Some(key_id), Some(token)) => {
            // A live transfer must not lose its carrier because a short setup
            // credential expired. Cloudflare bounds credentials at 48 hours;
            // the TURN engine refreshes the allocation within that envelope.
            // Clean and idle revocation belong to the transfer lease protocol,
            // not to a shorter wall-clock credential that can cut off useful
            // work.
            CloudflareTurnConfig::new(key_id, token, 48 * 60 * 60, Duration::from_secs(5))
                .map(RelayRouteIssuer::cloudflare)
                .map(Some)
                .map_err(|error| error.to_string())
        }
        _ => Err(
            "RIFT_CLOUDFLARE_TURN_KEY_ID and RIFT_CLOUDFLARE_TURN_API_TOKEN must be set together"
                .to_owned(),
        ),
    }
}

fn run_send(
    source: &PathBuf,
    relay: Option<&str>,
    ca_cert: Option<&std::path::Path>,
    direct_port: u16,
    json: bool,
) -> Result<Output, String> {
    preflight_source(source)?;
    let (relay, ca_cert) = resolve_relay(relay, ca_cert)?;
    let dialer = relay_dialer(&relay, ca_cert.as_deref())?;
    let runtime = build_runtime(RuntimePolicy::default()).map_err(|error| error.to_string())?;
    let (code, reservation) = runtime
        .block_on(reserve_fresh_pairing_sender_with(dialer))
        .map_err(|error| error.to_string())?;
    emit_intermediate(
        &Output {
            ok: true,
            kind: "offer",
            address: Some(relay),
            code: Some(code.to_string()),
            message: Some("share this code with the receiving device".into()),
            ..Output::default()
        },
        json,
    )?;

    let started = Instant::now();
    let progress = ConsoleProgress::new("Sending", json);
    let summary = runtime
        .block_on(send_reserved_via_pairing_observed_with_policy(
            reservation,
            &code,
            source,
            TransferPolicy {
                direct_bind_port: direct_port,
                ..TransferPolicy::default()
            },
            &progress,
        ))
        .map_err(|error| error.to_string());
    progress.finish();
    let summary = summary?;
    let elapsed = started.elapsed();
    Ok(Output {
        ok: true,
        kind: "send_complete",
        bytes: Some(summary.length),
        blocks: Some(summary.blocks),
        entries: Some(summary.entries),
        digest: Some(hex(&summary.digest.0)),
        transport: Some(transport_name(summary.transport)),
        migration: summary.migration.map(Into::into),
        profile: Some(summary.profile.into()),
        elapsed_ms: Some(duration_millis(elapsed)),
        bytes_per_second: Some(rate(summary.length, elapsed)),
        message: Some("receiver authenticated the complete atomic object".into()),
        ..Output::default()
    })
}

fn run_receive(
    code: &str,
    destination: Option<&PathBuf>,
    relay: Option<&str>,
    ca_cert: Option<&std::path::Path>,
    direct_port: u16,
    json: bool,
) -> Result<Output, String> {
    let code = PairingCode::from_str(code).map_err(|error| error.to_string())?;
    let target = match destination {
        Some(destination) => receive_target(destination)?,
        None => ReceiveTarget::Directory(env::current_dir().map_err(|error| error.to_string())?),
    };
    let (relay, ca_cert) = resolve_relay(relay, ca_cert)?;
    let dialer = relay_dialer(&relay, ca_cert.as_deref())?;
    let runtime = build_runtime(RuntimePolicy::default()).map_err(|error| error.to_string())?;
    let started = Instant::now();
    let progress = ConsoleProgress::new("Receiving", json);
    let summary = runtime
        .block_on(receive_via_pairing_target_observed_with_policy(
            dialer,
            &code,
            target,
            TransferPolicy {
                direct_bind_port: direct_port,
                ..TransferPolicy::default()
            },
            &progress,
        ))
        .map_err(|error| error.to_string());
    progress.finish();
    let summary = summary?;
    let elapsed = started.elapsed();
    Ok(Output {
        ok: true,
        kind: "receive_complete",
        bytes: Some(summary.length),
        blocks: Some(summary.blocks),
        entries: Some(summary.entries),
        destination: Some(summary.destination.to_string_lossy().into_owned()),
        digest: Some(hex(&summary.digest.0)),
        transport: Some(transport_name(summary.transport)),
        migration: summary.migration.map(Into::into),
        profile: Some(summary.profile.into()),
        elapsed_ms: Some(duration_millis(elapsed)),
        bytes_per_second: Some(rate(summary.length, elapsed)),
        receipt: Some(match summary.receipt {
            ReceiptDelivery::Sent => "sent",
            ReceiptDelivery::Failed => "failed",
        }),
        message: Some("object committed atomically".into()),
        ..Output::default()
    })
}

fn receive_target(destination: &Path) -> Result<ReceiveTarget, String> {
    if destination.is_dir() {
        return Ok(ReceiveTarget::Directory(destination.to_owned()));
    }
    preflight_destination(destination)?;
    Ok(ReceiveTarget::Exact(destination.to_owned()))
}

fn resolve_relay(
    relay: Option<&str>,
    ca_cert: Option<&std::path::Path>,
) -> Result<(String, Option<PathBuf>), String> {
    let config = read_device_config()?;
    let relay = relay
        .map(str::to_owned)
        .or_else(|| env::var("RIFT_RELAY").ok())
        .or(config.relay)
        .unwrap_or_else(|| "127.0.0.1:7337".to_owned());
    RelayEndpoint::from_str(&relay).map_err(|error| error.to_string())?;
    let ca_cert = ca_cert
        .map(PathBuf::from)
        .or_else(|| env::var_os("RIFT_CA_CERT").map(PathBuf::from))
        .or(config.ca_cert);
    Ok((relay, ca_cert))
}

fn preflight_source(source: &Path) -> Result<(), String> {
    let metadata = fs::symlink_metadata(source)
        .map_err(|error| format!("cannot read source {}: {error}", source.display()))?;
    if !metadata.is_file() && !metadata.is_dir() {
        return Err(format!(
            "source {} is not a regular file or folder",
            source.display()
        ));
    }
    if source.file_name().is_none() {
        return Err("source must name one file or folder, not a filesystem root".into());
    }
    Ok(())
}

fn preflight_destination(destination: &Path) -> Result<(), String> {
    if destination.file_name().is_none() {
        return Err("destination must name one new file or folder".into());
    }
    match fs::symlink_metadata(destination) {
        Ok(_) => {
            return Err(format!(
                "destination {} already exists; RIFT never replaces it",
                destination.display()
            ));
        }
        Err(error) if error.kind() == io::ErrorKind::NotFound => {}
        Err(error) => {
            return Err(format!(
                "cannot inspect destination {}: {error}",
                destination.display()
            ));
        }
    }
    let parent = destination
        .parent()
        .filter(|parent| !parent.as_os_str().is_empty())
        .unwrap_or_else(|| Path::new("."));
    if !parent.is_dir() {
        return Err(format!(
            "destination parent {} is not an existing folder",
            parent.display()
        ));
    }
    Ok(())
}

fn config_path() -> Result<PathBuf, String> {
    if let Some(path) = env::var_os("RIFT_CONFIG") {
        return Ok(PathBuf::from(path));
    }
    #[cfg(windows)]
    if let Some(root) = env::var_os("APPDATA") {
        return Ok(PathBuf::from(root).join("rift/config.json"));
    }
    #[cfg(not(windows))]
    if let Some(root) = env::var_os("XDG_CONFIG_HOME") {
        return Ok(PathBuf::from(root).join("rift/config.json"));
    }
    env::var_os("HOME")
        .map(PathBuf::from)
        .map(|root| root.join(".config/rift/config.json"))
        .ok_or_else(|| "cannot resolve a per-user RIFT config directory".to_owned())
}

fn read_device_config() -> Result<DeviceConfig, String> {
    let path = config_path()?;
    match fs::read(&path) {
        Ok(bytes) => serde_json::from_slice(&bytes)
            .map_err(|error| format!("invalid RIFT config {}: {error}", path.display())),
        Err(error) if error.kind() == io::ErrorKind::NotFound => Ok(DeviceConfig::default()),
        Err(error) => Err(format!(
            "could not read RIFT config {}: {error}",
            path.display()
        )),
    }
}

fn write_device_config(config: &DeviceConfig) -> Result<(), String> {
    let path = config_path()?;
    write_device_config_at(&path, config)
}

fn write_device_config_at(path: &Path, config: &DeviceConfig) -> Result<(), String> {
    let parent = path
        .parent()
        .ok_or_else(|| "invalid RIFT config path".to_owned())?;
    fs::create_dir_all(parent).map_err(|error| error.to_string())?;
    let bytes = serde_json::to_vec_pretty(config).map_err(|error| error.to_string())?;
    let temporary = path.with_extension("json.new");
    fs::write(&temporary, bytes).map_err(|error| error.to_string())?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        fs::set_permissions(&temporary, fs::Permissions::from_mode(0o600))
            .map_err(|error| error.to_string())?;
    }
    replace_config(&temporary, path)
}

#[cfg(not(windows))]
fn replace_config(temporary: &Path, destination: &Path) -> Result<(), String> {
    fs::rename(temporary, destination).map_err(|error| error.to_string())
}

#[cfg(windows)]
fn replace_config(temporary: &Path, destination: &Path) -> Result<(), String> {
    if destination.exists() {
        fs::remove_file(destination).map_err(|error| error.to_string())?;
    }
    fs::rename(temporary, destination).map_err(|error| error.to_string())
}

fn duration_millis(duration: Duration) -> u64 {
    u64::try_from(duration.as_millis()).unwrap_or(u64::MAX)
}

fn rate(bytes: u64, elapsed: Duration) -> u64 {
    let micros = u64::try_from(elapsed.as_micros())
        .unwrap_or(u64::MAX)
        .max(1);
    bytes.saturating_mul(1_000_000) / micros
}

fn relay_dialer(relay: &str, ca_cert: Option<&std::path::Path>) -> Result<RelayDialer, String> {
    let endpoint = RelayEndpoint::from_str(relay).map_err(|error| error.to_string())?;
    let Some(ca_cert) = ca_cert else {
        return Ok(RelayDialer::new(endpoint));
    };
    let roots = Certificate::from_pem_file(ca_cert).map_err(|error| error.to_string())?;
    let connector = TlsConnector::builder()
        .with_strict_ca_validation()
        .add_root_certificates(roots)
        .alpn_protocols_required(vec![b"http/1.1".to_vec()])
        .handshake_timeout(Duration::from_secs(10))
        .build()
        .map_err(|error| error.to_string())?;
    RelayDialer::with_tls(endpoint, connector).map_err(|error| error.to_string())
}

fn emit_intermediate(output: &Output, json: bool) -> Result<(), String> {
    emit(output, json);
    io::stdout().flush().map_err(|error| error.to_string())
}

fn emit(output: &Output, json: bool) {
    if json {
        println!(
            "{}",
            serde_json::to_string(output).expect("serializable CLI output")
        );
        return;
    }
    if output.kind == "offer" {
        if let Some(code) = &output.code {
            println!("Ready to send\n");
            println!("  {code}\n");
            println!("On the other device:");
            println!("  rift receive {code}\n");
            println!("Waiting for receiver…");
        }
    } else if matches!(output.kind, "send_complete" | "receive_complete") {
        let verb = if output.kind == "send_complete" {
            "Sent"
        } else {
            "Received"
        };
        let bytes = output.bytes.unwrap_or_default();
        let elapsed = output.elapsed_ms.unwrap_or_default();
        let rate = output.bytes_per_second.unwrap_or_default();
        let entries = output.entries.unwrap_or(1);
        let route = output
            .transport
            .map_or("Secure relay", transport_name_label);
        println!(
            "{verb} {} in {}  ·  {}/s",
            human_bytes(bytes),
            human_duration(elapsed),
            human_bytes(rate),
        );
        println!(
            "{}  ·  {route}  ·  {} {}",
            if output.kind == "send_complete" {
                "Verified by receiver"
            } else {
                "Verified and committed"
            },
            entries,
            if entries == 1 { "item" } else { "items" },
        );
        if output.kind == "receive_complete"
            && let Some(destination) = &output.destination
        {
            println!("Saved to {destination}");
        }
        if output.receipt == Some("failed") {
            eprintln!("Warning: saved successfully, but the sender did not receive the receipt");
        }
    } else if output.kind == "config" {
        println!("Relay: {}", output.address.as_deref().unwrap_or("not set"));
        if let Some(message) = &output.message {
            println!("TLS: {message}");
        }
    } else if output.kind == "config_saved" {
        println!(
            "Relay saved: {}",
            output.address.as_deref().unwrap_or("not set")
        );
    } else if output.kind == "relay_ready" {
        println!(
            "{} on {}",
            output.message.as_deref().unwrap_or("relay ready"),
            output.address.as_deref().unwrap_or("unknown address")
        );
    } else if let Some(capability) = &output.capability {
        println!("{capability}");
    } else if let Some(message) = &output.message {
        println!("{message}");
    }
}

const fn transport_name(transport: TransferTransport) -> &'static str {
    match transport {
        TransferTransport::Relay => "relay",
        TransferTransport::LanQuic => "lan_quic",
        TransferTransport::DirectQuic => "direct_quic",
        TransferTransport::TurnUdpQuic => "turn_udp_quic",
        TransferTransport::TurnTcpQuic => "turn_tcp_quic",
        TransferTransport::TurnTlsQuic => "turn_tls_quic",
        TransferTransport::PathPoolQuic => "path_pool_quic",
    }
}

const fn transport_label(transport: TransferTransport) -> &'static str {
    match transport {
        TransferTransport::Relay => "Secure relay",
        TransferTransport::LanQuic => "Local network  ·  direct",
        TransferTransport::DirectQuic => "Internet  ·  direct",
        TransferTransport::TurnUdpQuic => "TURN  ·  UDP",
        TransferTransport::TurnTcpQuic => "TURN  ·  TCP",
        TransferTransport::TurnTlsQuic => "TURN  ·  TLS",
        TransferTransport::PathPoolQuic => "Adaptive path pool",
    }
}

fn transport_name_label(transport: &str) -> &'static str {
    match transport {
        "lan_quic" => "Local network",
        "direct_quic" => "Internet direct",
        "turn_udp_quic" => "TURN over UDP",
        "turn_tcp_quic" => "TURN over TCP",
        "turn_tls_quic" => "TURN over TLS",
        "path_pool_quic" => "Adaptive path pool",
        _ => "Secure relay",
    }
}

fn emit_error(output: &Output, json: bool) {
    if json {
        emit(output, true);
    } else {
        eprintln!(
            "Error: {}",
            output.message.as_deref().unwrap_or("unknown failure")
        );
    }
}

fn human_bytes(bytes: u64) -> String {
    const UNITS: [&str; 5] = ["B", "KiB", "MiB", "GiB", "TiB"];
    let mut divisor = 1_u64;
    let mut unit = 0_usize;
    while bytes / divisor >= 1024 && unit + 1 < UNITS.len() {
        divisor = divisor.saturating_mul(1024);
        unit += 1;
    }
    if unit == 0 {
        format!("{bytes} {}", UNITS[unit])
    } else {
        let tenths = bytes.saturating_mul(10) / divisor;
        format!("{}.{:01} {}", tenths / 10, tenths % 10, UNITS[unit])
    }
}

fn human_duration(milliseconds: u64) -> String {
    if milliseconds < 1_000 {
        format!("{milliseconds} ms")
    } else if milliseconds < 60_000 {
        let tenths = milliseconds / 100;
        format!("{}.{:01} s", tenths / 10, tenths % 10)
    } else if milliseconds < 3_600_000 {
        let seconds = milliseconds / 1_000;
        format!("{}m {}s", seconds / 60, seconds % 60)
    } else {
        let minutes = milliseconds / 60_000;
        format!("{}h {}m", minutes / 60, minutes % 60)
    }
}

fn hex(bytes: &[u8]) -> String {
    const DIGITS: &[u8; 16] = b"0123456789abcdef";
    let mut encoded = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        encoded.push(char::from(DIGITS[usize::from(byte >> 4)]));
        encoded.push(char::from(DIGITS[usize::from(byte & 0x0f)]));
    }
    encoded
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn everyday_receive_aliases_resolve_to_the_same_command() {
        for alias in ["receive", "recv", "get"] {
            let parsed = Cli::try_parse_from(["rift", alias, "1234-lumeko"]).unwrap();
            assert!(matches!(parsed.command, Command::Receive { .. }));
        }
    }

    #[test]
    fn preflight_rejects_local_errors_before_network_use() {
        let directory = tempfile::tempdir().unwrap();
        let file = directory.path().join("source.bin");
        let folder = directory.path().join("source-dir");
        std::fs::write(&file, b"data").unwrap();
        std::fs::create_dir(&folder).unwrap();
        assert!(preflight_source(&file).is_ok());
        assert!(preflight_source(&folder).is_ok());
        assert!(preflight_source(&directory.path().join("missing")).is_err());

        let destination = directory.path().join("new-root");
        assert!(preflight_destination(&destination).is_ok());
        assert_eq!(
            receive_target(directory.path()).unwrap(),
            ReceiveTarget::Directory(directory.path().to_owned())
        );
        assert_eq!(
            receive_target(&destination).unwrap(),
            ReceiveTarget::Exact(destination.clone())
        );
        std::fs::write(&destination, b"occupied").unwrap();
        assert!(preflight_destination(&destination).is_err());
        assert!(preflight_destination(&directory.path().join("missing/child")).is_err());
    }

    #[cfg(unix)]
    #[test]
    fn saved_config_is_owner_only() {
        use std::os::unix::fs::PermissionsExt;

        let directory = tempfile::tempdir().unwrap();
        let path = directory.path().join("config.json");
        write_device_config_at(
            &path,
            &DeviceConfig {
                relay: Some("127.0.0.1:7337".into()),
                ca_cert: None,
            },
        )
        .unwrap();
        assert_eq!(
            std::fs::metadata(path).unwrap().permissions().mode() & 0o777,
            0o600
        );
    }

    #[cfg(unix)]
    #[test]
    fn source_preflight_rejects_symbolic_links() {
        let directory = tempfile::tempdir().unwrap();
        let file = directory.path().join("source.bin");
        let link = directory.path().join("link.bin");
        std::fs::write(&file, b"data").unwrap();
        std::os::unix::fs::symlink(&file, &link).unwrap();
        assert!(preflight_source(&link).is_err());
    }
}
