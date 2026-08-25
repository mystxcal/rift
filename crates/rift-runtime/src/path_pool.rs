//! Bounded portfolio of independently congestion-controlled QUIC paths.

use std::{
    collections::BTreeMap,
    time::{Duration, Instant},
};

use crate::{DirectQuicLink, DirectQuicLinkError, TransferTransport};
use rift_core::{
    BlockId, BlockPhase, CompletionAction, CompletionPath, PathId, PieceWork, plan_completion,
};

const RECEIVE_SLICE: Duration = Duration::from_micros(250);
const MIN_PROVISIONAL_RATE_BPS: u64 = 64 * 1024;
const MAX_PATH_LANES: u16 = 64;
const SECONDARY_PROBE_AFTER_PIECES: u64 = 64;
const PROBE_PROGRESS_SLICE: Duration = Duration::from_micros(100);
const PATH_STATE_MAGIC: [u8; 8] = *b"RFPATH01";
const PATH_STATE_BYTES: usize = PATH_STATE_MAGIC.len() + 2;

/// Reachability provenance used for conservative shared-bottleneck grouping.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum CarrierKind {
    Lan,
    Direct,
    ServerReflexive,
    TurnUdp,
    TurnStream,
}

struct LivePath {
    id: PathId,
    kind: CarrierKind,
    bottleneck_group: u32,
    link: DirectQuicLink,
    queued_until_us: u64,
    piece_lanes: u64,
    probe: Option<(Instant, u32)>,
    proven_rate_bps: Option<u64>,
    retired: bool,
    remote_active: bool,
}

/// A small authenticated path portfolio governed by completion time.
///
/// The first member is the control path.  Piece lanes may use any member, but
/// all object truth remains path-independent in the reconstruction ledger.
pub(crate) struct QuicPathPool {
    paths: Vec<LivePath>,
    started: Instant,
    receive_cursor: usize,
    active_receive_mask: u8,
}

#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub(crate) struct PathPoolMetrics {
    pub(crate) paths: u16,
    pub(crate) payload_paths: u16,
    pub(crate) quic_cpu_us: u64,
    pub(crate) socket_io_us: u64,
    pub(crate) wire_sent_bytes: u64,
    pub(crate) wire_received_bytes: u64,
    pub(crate) lost_bytes: u64,
}

impl QuicPathPool {
    pub(crate) fn new(links: Vec<(CarrierKind, DirectQuicLink)>) -> Self {
        let paths: Vec<LivePath> = links
            .into_iter()
            .enumerate()
            .map(|(index, (kind, link))| LivePath {
                id: PathId(u32::try_from(index).unwrap_or(u32::MAX)),
                kind,
                // Every currently gathered carrier leaves through the same
                // endpoint access network. Separate sockets, relays, and QUIC
                // controllers are not evidence of separate capacity. A future
                // multi-interface gather may assign different groups only
                // after route provenance proves that independence.
                bottleneck_group: 1,
                link,
                queued_until_us: 0,
                piece_lanes: 0,
                probe: None,
                proven_rate_bps: None,
                retired: false,
                remote_active: index == 0,
            })
            .collect();
        let active_receive_mask = u8::from(!paths.is_empty());
        Self {
            paths,
            started: Instant::now(),
            receive_cursor: 0,
            active_receive_mask,
        }
    }

    pub(crate) fn transport(&self) -> TransferTransport {
        if self.paths.len() > 1 {
            TransferTransport::PathPoolQuic
        } else {
            self.primary_transport()
        }
    }

    pub(crate) fn primary_transport(&self) -> TransferTransport {
        self.paths
            .first()
            .map_or(TransferTransport::Relay, |path| match path.kind {
                CarrierKind::Lan => TransferTransport::LanQuic,
                CarrierKind::Direct | CarrierKind::ServerReflexive => TransferTransport::DirectQuic,
                CarrierKind::TurnUdp => TransferTransport::TurnUdpQuic,
                CarrierKind::TurnStream => path.link.transport(),
            })
    }

    pub(crate) fn path_count(&self) -> u16 {
        u16::try_from(self.paths.len()).unwrap_or(u16::MAX)
    }

    pub(crate) fn metrics(&self) -> PathPoolMetrics {
        self.paths.iter().fold(
            PathPoolMetrics {
                paths: u16::try_from(self.paths.len()).unwrap_or(u16::MAX),
                ..PathPoolMetrics::default()
            },
            |mut total, path| {
                let measured = path.link.metrics();
                total.payload_paths = total
                    .payload_paths
                    .saturating_add(u16::from(path.piece_lanes != 0));
                total.quic_cpu_us = total.quic_cpu_us.saturating_add(measured.quic_cpu_us);
                total.socket_io_us = total.socket_io_us.saturating_add(measured.socket_io_us);
                total.wire_sent_bytes = total
                    .wire_sent_bytes
                    .saturating_add(measured.path.sent_bytes);
                total.wire_received_bytes = total
                    .wire_received_bytes
                    .saturating_add(measured.path.received_bytes);
                total.lost_bytes = total.lost_bytes.saturating_add(measured.path.lost_bytes);
                total
            },
        )
    }

    pub(crate) async fn queue_control(
        &mut self,
        bytes: &[u8],
        maximum: usize,
        timeout: Duration,
    ) -> Result<(), DirectQuicLinkError> {
        self.primary()?.queue_lane(bytes, maximum, timeout).await
    }

    pub(crate) async fn receive_control(
        &mut self,
        maximum: usize,
        timeout: Duration,
    ) -> Result<Vec<u8>, DirectQuicLinkError> {
        let deadline = Instant::now() + timeout;
        loop {
            let slice = deadline
                .saturating_duration_since(Instant::now())
                .min(RECEIVE_SLICE);
            if slice.is_zero() {
                return Err(DirectQuicLinkError::Timeout);
            }
            match self.primary()?.receive_lane(maximum, slice).await {
                Ok(bytes) => return Ok(bytes),
                Err(DirectQuicLinkError::Timeout) => {}
                Err(error) => return Err(error),
            }
            // Control records are pinned to path zero. Polling the remaining
            // connections here is nevertheless essential: it advances ACK,
            // loss-recovery, pacing, and TURN refresh state while the caller
            // waits for a receipt on the control path.
            for path in self.paths.iter_mut().skip(1) {
                let slice = deadline
                    .saturating_duration_since(Instant::now())
                    .min(RECEIVE_SLICE);
                if slice.is_zero() {
                    return Err(DirectQuicLinkError::Timeout);
                }
                match path.link.receive_lane(maximum, slice).await {
                    Err(DirectQuicLinkError::Timeout) => {}
                    Ok(_) => {
                        return Err(DirectQuicLinkError::Io(std::io::Error::new(
                            std::io::ErrorKind::InvalidData,
                            "control record arrived on a data-only path",
                        )));
                    }
                    Err(error) => return Err(error),
                }
            }
        }
    }

    pub(crate) async fn queue_piece(
        &mut self,
        block: BlockId,
        bytes: &[u8],
        maximum: usize,
        timeout: Duration,
    ) -> Result<(), DirectQuicLinkError> {
        self.progress_secondary_probes().await;
        let now_us = self.now_us();
        let piece = PieceWork {
            block,
            bytes: u32::try_from(bytes.len()).unwrap_or(u32::MAX),
            source_ready_us: now_us,
            phase: BlockPhase::Missing,
            flight: None,
        };
        let estimates = self.completion_paths(now_us);
        let selected = match plan_completion(now_us, &[piece], &estimates) {
            Ok(CompletionAction::Assign { path, .. }) => usize::try_from(path.0).unwrap_or(0),
            _ => 0,
        };
        let selected = selected.min(self.paths.len().saturating_sub(1));
        if selected != 0 && !self.paths[selected].remote_active {
            self.set_remote_path_state(selected, true, timeout).await?;
            self.paths[selected].remote_active = true;
        }
        if let Err(error) = self.paths[selected]
            .link
            .queue_lane(bytes, maximum, timeout)
            .await
        {
            if selected == 0 {
                return Err(error);
            }
            self.paths[selected].retired = true;
            if self.paths[selected].remote_active {
                let _ = self.set_remote_path_state(selected, false, timeout).await;
                self.paths[selected].remote_active = false;
            }
            self.paths[0]
                .link
                .queue_lane(bytes, maximum, timeout)
                .await?;
            self.account_piece(0, bytes.len(), now_us, &estimates);
            return Ok(());
        }
        if selected != 0 && self.paths[selected].proven_rate_bps.is_none() {
            self.paths[selected].probe = Some((Instant::now(), piece.bytes));
        }
        self.account_piece(selected, bytes.len(), now_us, &estimates);
        Ok(())
    }

    async fn set_remote_path_state(
        &mut self,
        index: usize,
        active: bool,
        timeout: Duration,
    ) -> Result<(), DirectQuicLinkError> {
        let mut state = [0_u8; PATH_STATE_BYTES];
        state[..PATH_STATE_MAGIC.len()].copy_from_slice(&PATH_STATE_MAGIC);
        state[PATH_STATE_MAGIC.len()] = u8::try_from(index).map_err(|_| invalid_path_state())?;
        state[PATH_STATE_MAGIC.len() + 1] = u8::from(active);
        self.primary()?
            .queue_lane(&state, PATH_STATE_BYTES, timeout)
            .await?;
        self.primary()?.flush_lanes().await
    }

    fn account_piece(
        &mut self,
        selected: usize,
        bytes: usize,
        now_us: u64,
        estimates: &[CompletionPath],
    ) {
        self.paths[selected].piece_lanes = self.paths[selected].piece_lanes.saturating_add(1);
        let rate = estimates
            .get(selected)
            .map_or(MIN_PROVISIONAL_RATE_BPS, |path| path.delivery_rate_bps);
        let serialization = transmission_us(bytes, rate);
        self.paths[selected].queued_until_us = now_us
            .max(self.paths[selected].queued_until_us)
            .saturating_add(serialization);
    }

    async fn progress_secondary_probes(&mut self) {
        let mut retired = Vec::new();
        for (index, path) in self.paths.iter_mut().enumerate().skip(1) {
            let Some((started, bytes)) = path.probe else {
                continue;
            };
            if path.retired || path.proven_rate_bps.is_some() {
                continue;
            }
            if path
                .link
                .poll_lane_progress(PROBE_PROGRESS_SLICE)
                .await
                .is_err()
            {
                path.retired = true;
                retired.push(index);
                continue;
            }
            if path.link.in_flight_lanes() == 0 {
                let elapsed_us = u64::try_from(started.elapsed().as_micros()).unwrap_or(u64::MAX);
                let bits = u128::from(bytes).saturating_mul(8_000_000);
                path.proven_rate_bps = Some(
                    u64::try_from(bits / u128::from(elapsed_us.max(1)))
                        .unwrap_or(u64::MAX)
                        .max(MIN_PROVISIONAL_RATE_BPS),
                );
            }
        }
        for index in retired {
            if self.paths[index].remote_active {
                let _ = self
                    .set_remote_path_state(index, false, Duration::from_secs(1))
                    .await;
                self.paths[index].remote_active = false;
            }
        }
    }

    pub(crate) async fn flush_all(&mut self) -> Result<(), DirectQuicLinkError> {
        for path in &mut self.paths {
            path.link.flush_lanes().await?;
        }
        Ok(())
    }

    /// Receive the first complete lane from any live path.
    pub(crate) async fn receive_any(
        &mut self,
        maximum: usize,
        timeout: Duration,
    ) -> Result<Vec<u8>, DirectQuicLinkError> {
        let deadline = Instant::now() + timeout;
        loop {
            let count = self.paths.len();
            for _ in 0..count {
                let index = self.receive_cursor % count;
                self.receive_cursor = (index + 1) % count;
                if self.active_receive_mask & (1_u8 << index) == 0 {
                    continue;
                }
                let slice = deadline
                    .saturating_duration_since(Instant::now())
                    .min(RECEIVE_SLICE);
                if slice.is_zero() {
                    return Err(DirectQuicLinkError::Timeout);
                }
                match self.paths[index].link.receive_lane(maximum, slice).await {
                    Ok(bytes) => {
                        if index == 0 && self.apply_path_state(&bytes)? {
                            continue;
                        }
                        self.paths[index].piece_lanes =
                            self.paths[index].piece_lanes.saturating_add(1);
                        return Ok(bytes);
                    }
                    Err(DirectQuicLinkError::Timeout) => {}
                    Err(error) if index == 0 => return Err(error),
                    Err(_) => {
                        self.paths[index].retired = true;
                        self.active_receive_mask &= !(1_u8 << index);
                    }
                }
            }
            if Instant::now() >= deadline {
                return Err(DirectQuicLinkError::Timeout);
            }
        }
    }

    fn apply_path_state(&mut self, bytes: &[u8]) -> Result<bool, DirectQuicLinkError> {
        if !bytes.starts_with(&PATH_STATE_MAGIC) {
            return Ok(false);
        }
        if bytes.len() != PATH_STATE_BYTES || bytes[PATH_STATE_MAGIC.len() + 1] > 1 {
            return Err(invalid_path_state());
        }
        let index = usize::from(bytes[PATH_STATE_MAGIC.len()]);
        if index == 0 || index >= self.paths.len() {
            return Err(invalid_path_state());
        }
        let bit = 1_u8 << index;
        if bytes[PATH_STATE_MAGIC.len() + 1] == 1 {
            self.active_receive_mask |= bit;
        } else {
            self.active_receive_mask &= !bit;
        }
        Ok(true)
    }

    fn primary(&mut self) -> Result<&mut DirectQuicLink, DirectQuicLinkError> {
        self.paths
            .first_mut()
            .map(|path| &mut path.link)
            .ok_or_else(|| {
                DirectQuicLinkError::Io(std::io::Error::new(
                    std::io::ErrorKind::NotConnected,
                    "authenticated QUIC path pool is empty",
                ))
            })
    }

    fn now_us(&self) -> u64 {
        u64::try_from(self.started.elapsed().as_micros()).unwrap_or(u64::MAX)
    }

    #[cfg(test)]
    pub(crate) fn used_piece_paths(&self) -> usize {
        self.paths
            .iter()
            .filter(|path| path.piece_lanes != 0)
            .count()
    }

    #[cfg(test)]
    pub(crate) fn mark_test_paths_independent(&mut self) {
        for (index, path) in self.paths.iter_mut().enumerate() {
            path.bottleneck_group = u32::try_from(index + 1).unwrap_or(u32::MAX);
            if index != 0 {
                path.proven_rate_bps = Some(100 * 1024 * 1024);
            }
        }
    }

    fn completion_paths(&self, now_us: u64) -> Vec<CompletionPath> {
        let primary_pieces = self.paths.first().map_or(0, |path| path.piece_lanes);
        let mut group_queue = BTreeMap::<u32, (u64, u16)>::new();
        for path in &self.paths {
            let aggregate = group_queue.entry(path.bottleneck_group).or_default();
            aggregate.0 = aggregate.0.max(path.queued_until_us);
            aggregate.1 = aggregate.1.saturating_add(
                u16::try_from(path.link.in_flight_lanes()).unwrap_or(MAX_PATH_LANES),
            );
        }
        self.paths
            .iter()
            .enumerate()
            .map(|(index, path)| {
                let stats = path.link.path_stats();
                let rtt_us = stats.rtt_us.max(1_000);
                let window_rate = stats
                    .congestion_window
                    .saturating_mul(8)
                    .saturating_mul(1_000_000)
                    / rtt_us;
                let rate = path
                    .proven_rate_bps
                    .unwrap_or_else(|| window_rate.max(MIN_PROVISIONAL_RATE_BPS));
                let loss_bps = stats
                    .lost_packets
                    .saturating_mul(10_000)
                    .checked_div(stats.sent_packets)
                    .unwrap_or(0);
                let uncertainty = if stats.sent_packets < 8 { 6_000 } else { 2_000 };
                CompletionPath {
                    id: path.id,
                    bottleneck_group: path.bottleneck_group,
                    validated: path_is_admitted(
                        index,
                        path.retired,
                        path.proven_rate_bps.is_some(),
                        path.probe.is_some(),
                        primary_pieces,
                    ),
                    ready_at_us: now_us,
                    queue_free_at_us: group_queue
                        .get(&path.bottleneck_group)
                        .map_or(now_us, |aggregate| aggregate.0.max(now_us)),
                    delivery_rate_bps: rate,
                    uncertainty_bps: u16::try_from(uncertainty + loss_bps.min(1_500))
                        .unwrap_or(9_999),
                    latency_and_repair_us: rtt_us,
                    receiver_backlog_us: 0,
                    max_in_flight: MAX_PATH_LANES,
                    in_flight: group_queue
                        .get(&path.bottleneck_group)
                        .map_or(0, |aggregate| aggregate.1.min(MAX_PATH_LANES)),
                }
            })
            .collect()
    }
}

fn transmission_us(bytes: usize, rate_bps: u64) -> u64 {
    let bits = (bytes as u128).saturating_mul(8_000_000);
    u64::try_from(bits.div_ceil(u128::from(rate_bps.max(1)))).unwrap_or(u64::MAX)
}

fn invalid_path_state() -> DirectQuicLinkError {
    DirectQuicLinkError::Io(std::io::Error::new(
        std::io::ErrorKind::InvalidData,
        "invalid authenticated path-pool state",
    ))
}

fn path_is_admitted(
    index: usize,
    retired: bool,
    proven: bool,
    probe_pending: bool,
    primary_pieces: u64,
) -> bool {
    !retired
        && (index == 0
            || proven
            || !probe_pending && primary_pieces >= SECONDARY_PROBE_AFTER_PIECES)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn transmission_estimate_is_conservative_and_integral() {
        assert_eq!(transmission_us(1_000_000, 8_000_000), 1_000_000);
        assert_eq!(transmission_us(1, 3), 2_666_667);
    }

    #[test]
    fn cold_secondary_gets_one_large_object_probe_not_small_object_payload() {
        assert!(!path_is_admitted(1, false, false, false, 32));
        assert!(path_is_admitted(1, false, false, false, 64));
        assert!(!path_is_admitted(1, false, false, true, 65));
        assert!(path_is_admitted(1, false, true, true, 65));
        assert!(!path_is_admitted(1, true, true, false, 65));
    }
}
