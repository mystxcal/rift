//! Replay-safe, congestion-bounded record delivery over an authenticated direct path.

use std::{cmp::min, io, time::Duration};

use asupersync::{
    net::{UdpOutboundDatagram, UdpSendBatchStrategy},
    time::{sleep, timeout_at, wall_now},
    types::Time,
};
use rift_core::{
    CodingError, Digest, MAX_REPAIR_SYMBOLS, RecoveryAction, RecoveryCause, RecoveryEvent,
    RecoveryPolicy, RecoveryStrategy, RepairSymbol, RttEstimator, choose_recovery_action,
    encode_repair, recover_sources,
};
use rift_protocol::{
    DirectCiphertext, DirectPacket, DirectProtocolError, MAX_DIRECT_DATAGRAM_BYTES,
    SequencedRecord, fragment_bytes_for_datagram,
};
use thiserror::Error;

use crate::{CryptoError, DirectPath};

/// Reliability and congestion envelope for direct record delivery.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct DirectRecordPolicy {
    /// Initial datagram flight.
    pub initial_window: u8,
    /// Hard ceiling for additive window growth.
    pub max_window: u8,
    /// Consecutive zero-progress timeouts before relay fallback.
    pub max_timeouts: u8,
    /// Lower retransmission-timeout bound.
    pub min_rto: Duration,
    /// Upper exponential-backoff bound.
    pub max_rto: Duration,
    /// Gap between bounded datagram batches in a flight.
    pub pacing_interval: Duration,
    /// Maximum independently authenticated datagrams submitted per send batch.
    pub max_batch_datagrams: u8,
    /// Maximum idle wait for a record or receipt.
    pub idle_timeout: Duration,
    /// Unrelated datagrams accepted per wait operation.
    pub max_unrelated_datagrams: u16,
    /// Pure, safety-projected information-recovery controller.
    pub recovery: RecoveryPolicy,
    /// Earliest partial-flight tail probe, even on a very low-latency path.
    pub minimum_tail_probe: Duration,
}

impl Default for DirectRecordPolicy {
    fn default() -> Self {
        Self {
            initial_window: 10,
            max_window: 32,
            max_timeouts: 6,
            // The estimator still seeds at roughly 3x the authenticated path
            // RTT. This floor only prevents sub-timer retransmission on very
            // low-latency paths; a fixed 200 ms floor made isolated ACK loss
            // dominate completion despite a microsecond-scale measured RTT.
            min_rto: Duration::from_millis(20),
            max_rto: Duration::from_secs(2),
            pacing_interval: Duration::from_micros(500),
            max_batch_datagrams: 4,
            // Covers the sender's bounded no-progress backoff (about seven
            // seconds at the defaults) without hiding an already-buffered
            // relay fallback or receipt for half a minute.
            idle_timeout: Duration::from_secs(10),
            max_unrelated_datagrams: 128,
            recovery: RecoveryPolicy::default(),
            minimum_tail_probe: Duration::from_millis(20),
        }
    }
}

impl DirectRecordPolicy {
    pub(crate) fn validate(self) -> Result<Self, DirectRecordError> {
        if self.initial_window == 0
            || self.initial_window > self.max_window
            || self.max_window > 64
            || self.max_timeouts == 0
            || self.max_timeouts > 12
            || self.min_rto.is_zero()
            || self.min_rto > self.max_rto
            || self.max_rto > Duration::from_secs(10)
            || self.pacing_interval > Duration::from_millis(10)
            || self.max_batch_datagrams == 0
            || self.max_batch_datagrams > 64
            || self.idle_timeout.is_zero()
            || self.idle_timeout < self.max_rto
            || self.idle_timeout > Duration::from_mins(5)
            || self.max_unrelated_datagrams == 0
            || self.max_unrelated_datagrams > 4_096
            || self.recovery.reordering_threshold == 0
            || self.recovery.reordering_threshold >= 64
            || self.recovery.max_early_actions_per_flight == 0
            || self.recovery.max_early_actions_per_flight > 64
            || self.minimum_tail_probe.is_zero()
            || self.minimum_tail_probe > self.max_rto
        {
            return Err(DirectRecordError::InvalidPolicy);
        }
        Ok(self)
    }
}

/// Per-record delivery evidence.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct DirectSendStats {
    /// UDP datagrams sent, including retransmissions.
    pub datagrams_sent: u64,
    /// Ciphertext bytes sent.
    pub bytes_sent: u64,
    /// Timeout-driven congestion responses.
    pub timeouts: u8,
    /// Smoothed round-trip estimate after this record completed.
    pub smoothed_rtt_us: u64,
    /// Retransmission timeout projected from the current path estimate.
    pub rto_us: u64,
    /// Fragments transmitted more than once.
    pub retransmitted_fragments: u32,
    /// Exact retransmissions admitted by selective-ack gap evidence.
    pub fast_retransmitted_fragments: u32,
    /// Exact retransmissions admitted by the bounded tail probe.
    pub tail_probe_fragments: u32,
    /// Fresh MDS repair symbols admitted by stale-feedback tail probes.
    pub repair_symbols: u32,
    /// Multi-datagram flight batches submitted to the portable UDP layer.
    pub send_batches: u32,
    /// Batches that used a native multi-message send operation.
    pub native_send_batches: u32,
    /// Batches that used UDP generic segmentation offload.
    pub gso_batches: u32,
    /// Clean-path GSO modes disabled after authenticated loss evidence.
    pub gso_demotions: u8,
}

struct RecordSendState {
    encoded: Vec<u8>,
    count: u8,
    acknowledged: u64,
    send_counts: Vec<u8>,
    consecutive_timeouts: u8,
    next_repair_index: u8,
    stats: DirectSendStats,
}

impl RecordSendState {
    fn new(record: &SequencedRecord, fragment_bytes: usize) -> Result<Self, DirectRecordError> {
        let encoded = record.encode()?;
        let count = u8::try_from(encoded.len().div_ceil(fragment_bytes))
            .map_err(|_| DirectRecordError::InconsistentRecord)?;
        Ok(Self {
            encoded,
            count,
            acknowledged: 0,
            send_counts: vec![0; usize::from(count)],
            consecutive_timeouts: 0,
            next_repair_index: 0,
            stats: DirectSendStats::default(),
        })
    }

    fn complete(&self) -> bool {
        self.acknowledged == bitmap_for(self.count)
    }

    fn account_fragment(&mut self, index: u8, bytes: usize, recovery: Option<RecoveryCause>) {
        self.stats.datagrams_sent = self.stats.datagrams_sent.saturating_add(1);
        self.stats.bytes_sent = self
            .stats
            .bytes_sent
            .saturating_add(u64::try_from(bytes).unwrap_or(u64::MAX));
        if self.send_counts[usize::from(index)] > 0 {
            self.stats.retransmitted_fragments =
                self.stats.retransmitted_fragments.saturating_add(1);
        }
        match recovery {
            Some(RecoveryCause::SelectiveAckGap) => {
                self.stats.fast_retransmitted_fragments =
                    self.stats.fast_retransmitted_fragments.saturating_add(1);
            }
            Some(RecoveryCause::TailProbe) => {
                self.stats.tail_probe_fragments = self.stats.tail_probe_fragments.saturating_add(1);
            }
            None => {}
        }
        self.send_counts[usize::from(index)] =
            self.send_counts[usize::from(index)].saturating_add(1);
    }

    fn account_batch(&mut self, native: bool, gso: bool) {
        self.stats.send_batches = self.stats.send_batches.saturating_add(1);
        self.stats.native_send_batches = self
            .stats
            .native_send_batches
            .saturating_add(u32::from(native));
        self.stats.gso_batches = self.stats.gso_batches.saturating_add(u32::from(gso));
    }
}

struct FlightState {
    indexes: Vec<u8>,
    bitmap: u64,
    before: u64,
    started: Time,
    deadline: Time,
    probe_at: Time,
    exact_attempted: u64,
    early_actions: u8,
    recovery_signal: bool,
    probe_enabled: bool,
}

impl FlightState {
    fn complete(&self, acknowledged: u64) -> bool {
        self.indexes
            .iter()
            .all(|index| acknowledged & (1_u64 << index) != 0)
    }

    fn rearm_probe(&mut self, delay: Duration, policy: RecoveryPolicy) {
        if policy.strategy != RecoveryStrategy::RtoOnly
            && self.early_actions < policy.max_early_actions_per_flight
        {
            self.probe_at = wall_now().saturating_add_nanos(duration_nanos(delay));
            self.probe_enabled = true;
        }
    }
}

/// Direct-record failure. The same sequence may be replayed on relay.
#[derive(Debug, Error)]
pub enum DirectRecordError {
    /// Policy is inert or unbounded.
    #[error("invalid direct-record policy")]
    InvalidPolicy,
    /// UDP operation failed.
    #[error("direct-record I/O failed: {0}")]
    Io(#[from] io::Error),
    /// Packet or global record was malformed.
    #[error(transparent)]
    Protocol(#[from] DirectProtocolError),
    /// Bounded repair state was invalid or contradictory.
    #[error(transparent)]
    Coding(#[from] CodingError),
    /// Noise authentication or nonce allocation failed.
    #[error(transparent)]
    Crypto(#[from] CryptoError),
    /// Retry budget expired.
    #[error("direct record delivery timed out")]
    Timeout,
    /// Unauthenticated or unrelated traffic exhausted the packet budget.
    #[error("too many unrelated direct-path datagrams")]
    UnrelatedDatagramLimit,
    /// Authenticated fragments contradict one another or expected ordering.
    #[error("inconsistent authenticated direct-record fragments")]
    InconsistentRecord,
    /// Commit receipt does not match object truth.
    #[error("direct commit receipt does not match the object")]
    InvalidReceipt,
}

/// Sender half of one direct file-transfer path.
pub struct DirectRecordSender {
    path: DirectPath,
    policy: DirectRecordPolicy,
    replay: ReplayWindow,
    congestion_window: u8,
    rtt: RttEstimator,
    rto: Duration,
    tail_probe_delay: Duration,
    fragment_bytes: usize,
    gso_enabled: bool,
}

/// Receiver half of one direct file-transfer path.
pub struct DirectRecordReceiver {
    path: DirectPath,
    policy: DirectRecordPolicy,
    replay: ReplayWindow,
    assembler: RecordAssembler,
}

impl DirectRecordSender {
    /// Consume an authenticated path as a record sender.
    ///
    /// # Errors
    ///
    /// Rejects invalid congestion policy.
    pub fn new(path: DirectPath, policy: DirectRecordPolicy) -> Result<Self, DirectRecordError> {
        let policy = policy.validate()?;
        let rtt = RttEstimator::new(path.validation_rtt_us().max(1))
            .map_err(|_| DirectRecordError::InvalidPolicy)?;
        let (rto, tail_probe_delay) = projected_timing(rtt, policy)?;
        let fragment_bytes = fragment_bytes_for_datagram(path.max_datagram_bytes())
            .ok_or(DirectRecordError::InvalidPolicy)?;
        Ok(Self {
            path,
            policy,
            replay: ReplayWindow::default(),
            congestion_window: policy.initial_window,
            rtt,
            rto,
            tail_probe_delay,
            fragment_bytes,
            gso_enabled: true,
        })
    }

    /// Reliably deliver one global record or stop for relay fallback.
    ///
    /// # Errors
    ///
    /// Returns on path/protocol failure or after bounded congestion backoff.
    pub async fn send_record(
        &mut self,
        record: &SequencedRecord,
    ) -> Result<DirectSendStats, DirectRecordError> {
        let mut state = RecordSendState::new(record, self.fragment_bytes)?;
        while !state.complete() {
            let mut flight = self.start_flight(record.sequence, &mut state).await?;
            self.receive_flight(record.sequence, &mut state, &mut flight)
                .await?;
            self.finish_flight(&mut state, &flight)?;
        }
        state.stats.smoothed_rtt_us = self.rtt.smoothed_us();
        state.stats.rto_us = duration_micros(self.rto);
        Ok(state.stats)
    }

    async fn start_flight(
        &mut self,
        sequence: u64,
        state: &mut RecordSendState,
    ) -> Result<FlightState, DirectRecordError> {
        let indexes = (0..state.count)
            .filter(|index| state.acknowledged & (1_u64 << index) == 0)
            .take(usize::from(self.congestion_window))
            .collect::<Vec<_>>();
        let bitmap = indexes
            .iter()
            .fold(0_u64, |bits, index| bits | (1_u64 << index));
        self.send_fragments(sequence, &indexes, state, None).await?;
        let started = wall_now();
        Ok(FlightState {
            indexes,
            bitmap,
            before: state.acknowledged,
            started,
            deadline: started.saturating_add_nanos(duration_nanos(self.rto)),
            probe_at: started.saturating_add_nanos(duration_nanos(self.tail_probe_delay)),
            exact_attempted: 0,
            early_actions: 0,
            recovery_signal: false,
            probe_enabled: self.policy.recovery.strategy != RecoveryStrategy::RtoOnly,
        })
    }

    async fn receive_flight(
        &mut self,
        sequence: u64,
        state: &mut RecordSendState,
        flight: &mut FlightState,
    ) -> Result<(), DirectRecordError> {
        loop {
            let wait_deadline = if flight.probe_enabled {
                min(flight.deadline, flight.probe_at)
            } else {
                flight.deadline
            };
            match receive_packet(
                &mut self.path,
                &mut self.replay,
                wait_deadline,
                self.policy.max_unrelated_datagrams,
            )
            .await?
            {
                Some(DirectPacket::Ack {
                    sequence: ack_sequence,
                    count,
                    bitmap,
                }) if ack_sequence == sequence && count == state.count => {
                    let previous = state.acknowledged;
                    state.acknowledged |= bitmap;
                    if state.complete() || flight.complete(state.acknowledged) {
                        break;
                    }
                    self.recover_for(RecoveryEvent::AckObserved, sequence, state, flight)
                        .await?;
                    if state.acknowledged != previous {
                        flight.rearm_probe(self.tail_probe_delay, self.policy.recovery);
                    }
                }
                Some(_) => {}
                None if flight.probe_enabled && wall_now() < flight.deadline => {
                    let sent = self
                        .recover_for(RecoveryEvent::TailStalled, sequence, state, flight)
                        .await?;
                    if sent {
                        flight.probe_at =
                            wall_now().saturating_add_nanos(duration_nanos(self.tail_probe_delay));
                    }
                    flight.probe_enabled = sent
                        && flight.early_actions < self.policy.recovery.max_early_actions_per_flight;
                }
                None => break,
            }
        }
        Ok(())
    }

    async fn recover_for(
        &mut self,
        event: RecoveryEvent,
        sequence: u64,
        state: &mut RecordSendState,
        flight: &mut FlightState,
    ) -> Result<bool, DirectRecordError> {
        let action = choose_recovery_action(
            state.count,
            flight.bitmap,
            state.acknowledged & flight.bitmap,
            flight.exact_attempted,
            flight.early_actions,
            event,
            self.policy.recovery,
        )
        .map_err(|_| DirectRecordError::InconsistentRecord)?;
        let Some(action) = action else {
            return Ok(false);
        };
        let (attempted, cost, sent) = self.apply_recovery_action(action, sequence, state).await?;
        flight.exact_attempted |= attempted;
        flight.early_actions = flight.early_actions.saturating_add(cost);
        flight.recovery_signal |= sent;
        Ok(sent)
    }

    fn finish_flight(
        &mut self,
        state: &mut RecordSendState,
        flight: &FlightState,
    ) -> Result<(), DirectRecordError> {
        if flight.complete(state.acknowledged) {
            state.consecutive_timeouts = 0;
            if flight.recovery_signal {
                self.congestion_window = (self.congestion_window / 2).max(2);
            } else {
                let sample_us = wall_now()
                    .duration_since(flight.started)
                    .div_ceil(1_000)
                    .max(1);
                self.rtt
                    .observe(sample_us)
                    .map_err(|_| DirectRecordError::InvalidPolicy)?;
                let gained = (state.acknowledged ^ flight.before).count_ones().max(1);
                self.congestion_window = self
                    .congestion_window
                    .saturating_add(u8::try_from(gained).unwrap_or(u8::MAX))
                    .min(self.policy.max_window);
            }
            (self.rto, self.tail_probe_delay) = projected_timing(self.rtt, self.policy)?;
            return Ok(());
        }
        state.stats.timeouts = state.stats.timeouts.saturating_add(1);
        self.demote_gso(&mut state.stats);
        self.congestion_window = (self.congestion_window / 2).max(2);
        self.rto = self.rto.saturating_mul(2).min(self.policy.max_rto);
        state.consecutive_timeouts = if state.acknowledged == flight.before {
            state.consecutive_timeouts.saturating_add(1)
        } else {
            0
        };
        if state.consecutive_timeouts >= self.policy.max_timeouts {
            return Err(DirectRecordError::Timeout);
        }
        Ok(())
    }

    async fn apply_recovery_action(
        &mut self,
        action: RecoveryAction,
        sequence: u64,
        state: &mut RecordSendState,
    ) -> Result<(u64, u8, bool), DirectRecordError> {
        match action {
            RecoveryAction::Retransmit { bitmap, cause } => {
                self.demote_gso(&mut state.stats);
                self.send_recovery(sequence, bitmap, state, cause).await?;
                let cost = u8::try_from(bitmap.count_ones()).unwrap_or(u8::MAX);
                Ok((bitmap, cost, true))
            }
            RecoveryAction::SendRepair {
                source_bitmap,
                cause: _,
            } if state.next_repair_index < MAX_REPAIR_SYMBOLS => {
                self.demote_gso(&mut state.stats);
                self.send_repair(sequence, source_bitmap, state).await?;
                state.next_repair_index = state.next_repair_index.saturating_add(1);
                Ok((0, 1, true))
            }
            RecoveryAction::SendRepair { .. } => Ok((0, 0, false)),
        }
    }

    async fn send_recovery(
        &mut self,
        sequence: u64,
        bitmap: u64,
        state: &mut RecordSendState,
        cause: RecoveryCause,
    ) -> Result<(), DirectRecordError> {
        let indexes = (0..state.count)
            .filter(|index| bitmap & (1_u64 << index) != 0)
            .collect::<Vec<_>>();
        self.send_fragments(sequence, &indexes, state, Some(cause))
            .await
    }

    async fn send_fragments(
        &mut self,
        sequence: u64,
        indexes: &[u8],
        state: &mut RecordSendState,
        recovery: Option<RecoveryCause>,
    ) -> Result<(), DirectRecordError> {
        let batch_limit = usize::from(self.policy.max_batch_datagrams);
        for (batch, chunk) in indexes.chunks(batch_limit).enumerate() {
            let mut envelopes = Vec::with_capacity(chunk.len());
            for index in chunk.iter().copied() {
                let offset = usize::from(index) * self.fragment_bytes;
                let end = state.encoded.len().min(offset + self.fragment_bytes);
                let packet = DirectPacket::Fragment {
                    sequence,
                    index,
                    count: state.count,
                    total_len: u32::try_from(state.encoded.len())
                        .map_err(|_| DirectRecordError::InconsistentRecord)?,
                    offset: u32::try_from(offset)
                        .map_err(|_| DirectRecordError::InconsistentRecord)?,
                    data: state.encoded[offset..end].to_vec(),
                };
                envelopes.push(seal_packet(&mut self.path, &packet)?);
            }
            let outbound = envelopes
                .iter()
                .map(|payload| UdpOutboundDatagram {
                    dst_addr: self.path.peer,
                    payload,
                })
                .collect::<Vec<_>>();
            let strategy = UdpSendBatchStrategy {
                prefer_gso: self.gso_enabled && recovery.is_none(),
                gso_segment_bytes: self.path.max_datagram_bytes(),
                max_sendmmsg_batch: chunk.len(),
                max_gso_segments: chunk.len(),
                ..UdpSendBatchStrategy::default()
            };
            let report = self
                .path
                .socket
                .send_batch_to_with_strategy(&outbound, strategy)
                .await?;
            let processed = report.packets_processed.min(chunk.len());
            let expected_bytes = envelopes
                .iter()
                .take(processed)
                .map(Vec::len)
                .sum::<usize>();
            for (index, bytes) in chunk
                .iter()
                .copied()
                .zip(envelopes.iter().map(Vec::len))
                .take(processed)
            {
                state.account_fragment(index, bytes, recovery);
            }
            if chunk.len() > 1 {
                state.account_batch(report.native_send_batch_used, report.gso_send_used);
            }
            if processed != chunk.len()
                || report.bytes_processed != expected_bytes
                || report.error.is_some()
            {
                return Err(io::Error::other(
                    report
                        .error
                        .unwrap_or_else(|| "partial direct datagram batch send".to_owned()),
                )
                .into());
            }
            if (batch + 1) * batch_limit < indexes.len() && !self.policy.pacing_interval.is_zero() {
                sleep(wall_now(), self.policy.pacing_interval).await;
            }
        }
        Ok(())
    }

    fn demote_gso(&mut self, stats: &mut DirectSendStats) {
        if self.gso_enabled {
            self.gso_enabled = false;
            stats.gso_demotions = stats.gso_demotions.saturating_add(1);
        }
    }

    async fn send_repair(
        &mut self,
        sequence: u64,
        source_bitmap: u64,
        state: &mut RecordSendState,
    ) -> Result<(), DirectRecordError> {
        let sources = state
            .encoded
            .chunks(self.fragment_bytes)
            .collect::<Vec<_>>();
        if sources.len() != usize::from(state.count) {
            return Err(DirectRecordError::InconsistentRecord);
        }
        let repair = encode_repair(
            &sources,
            self.fragment_bytes,
            state.next_repair_index,
            source_bitmap,
        )?;
        let packet = DirectPacket::Repair {
            sequence,
            repair_index: state.next_repair_index,
            count: state.count,
            total_len: u32::try_from(state.encoded.len())
                .map_err(|_| DirectRecordError::InconsistentRecord)?,
            source_bitmap,
            data: repair.data,
        };
        let bytes = send_packet(&mut self.path, &packet).await?;
        state.stats.datagrams_sent = state.stats.datagrams_sent.saturating_add(1);
        state.stats.bytes_sent = state
            .stats
            .bytes_sent
            .saturating_add(u64::try_from(bytes).unwrap_or(u64::MAX));
        state.stats.repair_symbols = state.stats.repair_symbols.saturating_add(1);
        Ok(())
    }

    /// Wait for an exact authenticated object commit receipt.
    ///
    /// # Errors
    ///
    /// Returns on timeout/path failure or a mismatched receipt.
    pub async fn receive_receipt(
        &mut self,
        expected_digest: Digest,
        expected_length: u64,
    ) -> Result<(), DirectRecordError> {
        let deadline = wall_now().saturating_add_nanos(duration_nanos(self.policy.idle_timeout));
        loop {
            match receive_packet(
                &mut self.path,
                &mut self.replay,
                deadline,
                self.policy.max_unrelated_datagrams,
            )
            .await?
            {
                Some(DirectPacket::Receipt { digest, length }) => {
                    return if digest == expected_digest.0 && length == expected_length {
                        Ok(())
                    } else {
                        Err(DirectRecordError::InvalidReceipt)
                    };
                }
                Some(_) => {}
                None => return Err(DirectRecordError::Timeout),
            }
        }
    }
}

impl DirectRecordReceiver {
    /// Consume a path at the first sequence not already accepted over relay.
    ///
    /// # Errors
    ///
    /// Rejects invalid policy.
    pub fn new(
        path: DirectPath,
        next_sequence: u64,
        policy: DirectRecordPolicy,
    ) -> Result<Self, DirectRecordError> {
        let policy = policy.validate()?;
        let fragment_bytes = fragment_bytes_for_datagram(path.max_datagram_bytes())
            .ok_or(DirectRecordError::InvalidPolicy)?;
        Ok(Self {
            path,
            policy,
            replay: ReplayWindow::default(),
            assembler: RecordAssembler::new(next_sequence, fragment_bytes),
        })
    }

    /// Receive, reassemble, and cumulatively acknowledge the next sequence.
    ///
    /// # Errors
    ///
    /// Returns on timeout/path failure or contradictory authenticated data.
    pub async fn receive_record(&mut self) -> Result<SequencedRecord, DirectRecordError> {
        let deadline = wall_now().saturating_add_nanos(duration_nanos(self.policy.idle_timeout));
        loop {
            match receive_packet(
                &mut self.path,
                &mut self.replay,
                deadline,
                self.policy.max_unrelated_datagrams,
            )
            .await?
            {
                Some(packet @ (DirectPacket::Fragment { .. } | DirectPacket::Repair { .. })) => {
                    let outcome = self.assembler.accept(packet)?;
                    send_packet(&mut self.path, &outcome.ack).await?;
                    if let Some(record) = outcome.complete {
                        return Ok(record);
                    }
                }
                Some(DirectPacket::Confirm { challenge })
                    if challenge == self.path.local_challenge =>
                {
                    let challenge = self.path.peer_challenge;
                    send_packet(&mut self.path, &DirectPacket::Confirm { challenge }).await?;
                }
                Some(_) => {}
                None => return Err(DirectRecordError::Timeout),
            }
        }
    }

    /// Send the authenticated end-to-end commit receipt redundantly.
    ///
    /// # Errors
    ///
    /// Returns for encoding, encryption, or UDP send failure.
    pub async fn send_receipt(
        &mut self,
        digest: Digest,
        length: u64,
    ) -> Result<(), DirectRecordError> {
        let receipt = DirectPacket::Receipt {
            digest: digest.0,
            length,
        };
        for attempt in 0..3 {
            send_packet(&mut self.path, &receipt).await?;
            if attempt < 2 && !self.policy.pacing_interval.is_zero() {
                sleep(wall_now(), self.policy.pacing_interval).await;
            }
        }
        Ok(())
    }
}

async fn send_packet(
    path: &mut DirectPath,
    packet: &DirectPacket,
) -> Result<usize, DirectRecordError> {
    let envelope = seal_packet(path, packet)?;
    let sent = path.socket.send_to(&envelope, path.peer).await?;
    if sent != envelope.len() {
        return Err(io::Error::new(
            io::ErrorKind::WriteZero,
            "partial encrypted direct datagram send",
        )
        .into());
    }
    Ok(sent)
}

fn seal_packet(path: &mut DirectPath, packet: &DirectPacket) -> Result<Vec<u8>, DirectRecordError> {
    let plaintext = packet.encode()?;
    let mut encrypted = [0_u8; MAX_DIRECT_DATAGRAM_BYTES];
    let (nonce, length) = path.cipher.seal(&plaintext, &mut encrypted)?;
    DirectCiphertext {
        path_id: path.path_id,
        nonce,
        payload: encrypted[..length].to_vec(),
    }
    .encode()
    .map_err(Into::into)
}

async fn receive_packet(
    path: &mut DirectPath,
    replay: &mut ReplayWindow,
    deadline: Time,
    max_unrelated: u16,
) -> Result<Option<DirectPacket>, DirectRecordError> {
    let mut datagram = [0_u8; MAX_DIRECT_DATAGRAM_BYTES];
    let mut unrelated = 0_u16;
    loop {
        let Ok(received) = timeout_at(deadline, path.socket.recv_from(&mut datagram)).await else {
            return Ok(None);
        };
        let (length, source) = received?;
        if let Some(packet) = open_packet_from_peer(path, replay, source, &datagram[..length]) {
            return Ok(Some(packet));
        }
        unrelated = unrelated.saturating_add(1);
        if unrelated >= max_unrelated {
            return Err(DirectRecordError::UnrelatedDatagramLimit);
        }
    }
}

fn open_packet_from_peer(
    path: &DirectPath,
    replay: &mut ReplayWindow,
    source: std::net::SocketAddr,
    datagram: &[u8],
) -> Option<DirectPacket> {
    if source != path.peer {
        return None;
    }
    let envelope = DirectCiphertext::decode(datagram).ok()?;
    if envelope.path_id != path.path_id || !replay.may_accept(envelope.nonce) {
        return None;
    }
    let mut plaintext = [0_u8; rift_protocol::MAX_DIRECT_PACKET_BYTES];
    let length = path
        .cipher
        .open(envelope.nonce, &envelope.payload, &mut plaintext)
        .ok()?;
    let packet = DirectPacket::decode(&plaintext[..length]).ok()?;
    replay.commit(envelope.nonce);
    Some(packet)
}

#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
struct ReplayWindow {
    highest: Option<u64>,
    bitmap: u128,
}

impl ReplayWindow {
    fn may_accept(self, nonce: u64) -> bool {
        let Some(highest) = self.highest else {
            return true;
        };
        if nonce > highest {
            return true;
        }
        let delta = highest - nonce;
        delta < 128 && self.bitmap & (1_u128 << delta) == 0
    }

    fn commit(&mut self, nonce: u64) {
        debug_assert!(self.may_accept(nonce));
        let Some(highest) = self.highest else {
            self.highest = Some(nonce);
            self.bitmap = 1;
            return;
        };
        if nonce > highest {
            let delta = nonce - highest;
            self.bitmap = if delta >= 128 {
                1
            } else {
                (self.bitmap << delta) | 1
            };
            self.highest = Some(nonce);
        } else {
            self.bitmap |= 1_u128 << (highest - nonce);
        }
    }
}

#[derive(Debug)]
struct PartialRecord {
    sequence: u64,
    count: u8,
    total_len: usize,
    fragments: Vec<Option<Vec<u8>>>,
    repairs: Vec<RepairSymbol>,
    bitmap: u64,
}

#[derive(Debug)]
struct RecordAssembler {
    next_sequence: u64,
    fragment_bytes: usize,
    partial: Option<PartialRecord>,
    last_complete: Option<(u64, u8)>,
}

struct AssemblyOutcome {
    ack: DirectPacket,
    complete: Option<SequencedRecord>,
}

fn packet_matches_symbol_width(packet: &DirectPacket, symbol_bytes: usize) -> bool {
    match packet {
        DirectPacket::Fragment {
            index,
            count,
            total_len,
            offset,
            data,
            ..
        } => {
            let Ok(total_len) = usize::try_from(*total_len) else {
                return false;
            };
            let Ok(offset) = usize::try_from(*offset) else {
                return false;
            };
            *count != 0
                && usize::from(*count) == total_len.div_ceil(symbol_bytes)
                && offset == usize::from(*index) * symbol_bytes
                && if index + 1 < *count {
                    data.len() == symbol_bytes
                } else {
                    offset.checked_add(data.len()) == Some(total_len)
                }
        }
        DirectPacket::Repair {
            count,
            total_len,
            data,
            ..
        } => {
            let Ok(total_len) = usize::try_from(*total_len) else {
                return false;
            };
            *count != 0
                && usize::from(*count) == total_len.div_ceil(symbol_bytes)
                && data.len() == symbol_bytes
        }
        _ => false,
    }
}

impl RecordAssembler {
    const fn new(next_sequence: u64, fragment_bytes: usize) -> Self {
        Self {
            next_sequence,
            fragment_bytes,
            partial: None,
            last_complete: None,
        }
    }

    fn accept(&mut self, packet: DirectPacket) -> Result<AssemblyOutcome, DirectRecordError> {
        if !packet_matches_symbol_width(&packet, self.fragment_bytes) {
            return Err(DirectRecordError::InconsistentRecord);
        }
        let (sequence, count, total_len) = symbol_identity(&packet)?;
        if let Some(outcome) = self.replayed_outcome(sequence, count)? {
            return Ok(outcome);
        }
        let total_len =
            usize::try_from(total_len).map_err(|_| DirectRecordError::InconsistentRecord)?;
        let partial = self.partial.get_or_insert_with(|| PartialRecord {
            sequence,
            count,
            total_len,
            fragments: vec![None; usize::from(count)],
            repairs: Vec::new(),
            bitmap: 0,
        });
        if partial.sequence != sequence || partial.count != count || partial.total_len != total_len
        {
            return Err(DirectRecordError::InconsistentRecord);
        }
        absorb_symbol(partial, packet)?;
        apply_repairs(partial, self.fragment_bytes)?;
        let ack = DirectPacket::Ack {
            sequence,
            count,
            bitmap: partial.bitmap,
        };
        if partial.bitmap != bitmap_for(count) {
            return Ok(AssemblyOutcome {
                ack,
                complete: None,
            });
        }
        self.complete_record(sequence, count, ack)
    }

    fn replayed_outcome(
        &self,
        sequence: u64,
        count: u8,
    ) -> Result<Option<AssemblyOutcome>, DirectRecordError> {
        if sequence == self.next_sequence {
            return Ok(None);
        }
        if sequence < self.next_sequence && self.last_complete == Some((sequence, count)) {
            return Ok(Some(AssemblyOutcome {
                ack: DirectPacket::Ack {
                    sequence,
                    count,
                    bitmap: bitmap_for(count),
                },
                complete: None,
            }));
        }
        Err(DirectRecordError::InconsistentRecord)
    }

    fn complete_record(
        &mut self,
        sequence: u64,
        count: u8,
        ack: DirectPacket,
    ) -> Result<AssemblyOutcome, DirectRecordError> {
        let partial = self
            .partial
            .take()
            .ok_or(DirectRecordError::InconsistentRecord)?;
        let mut encoded = Vec::with_capacity(partial.total_len);
        for fragment in partial.fragments {
            encoded.extend_from_slice(&fragment.ok_or(DirectRecordError::InconsistentRecord)?);
        }
        if encoded.len() != partial.total_len {
            return Err(DirectRecordError::InconsistentRecord);
        }
        let record = SequencedRecord::decode(&encoded)?;
        if record.sequence != sequence {
            return Err(DirectRecordError::InconsistentRecord);
        }
        self.next_sequence = self.next_sequence.saturating_add(1);
        self.last_complete = Some((sequence, count));
        Ok(AssemblyOutcome {
            ack,
            complete: Some(record),
        })
    }
}

fn symbol_identity(packet: &DirectPacket) -> Result<(u64, u8, u32), DirectRecordError> {
    match packet {
        DirectPacket::Fragment {
            sequence,
            count,
            total_len,
            ..
        }
        | DirectPacket::Repair {
            sequence,
            count,
            total_len,
            ..
        } => Ok((*sequence, *count, *total_len)),
        _ => Err(DirectRecordError::InconsistentRecord),
    }
}

fn absorb_symbol(
    partial: &mut PartialRecord,
    packet: DirectPacket,
) -> Result<(), DirectRecordError> {
    match packet {
        DirectPacket::Fragment { index, data, .. } => {
            let slot = &mut partial.fragments[usize::from(index)];
            if let Some(existing) = slot {
                if existing != &data {
                    return Err(DirectRecordError::InconsistentRecord);
                }
            } else {
                *slot = Some(data);
                partial.bitmap |= 1_u64 << index;
            }
            Ok(())
        }
        DirectPacket::Repair {
            repair_index,
            source_bitmap,
            data,
            ..
        } => {
            let repair = RepairSymbol {
                index: repair_index,
                source_bitmap,
                data,
            };
            if let Some(existing) = partial
                .repairs
                .iter()
                .find(|existing| existing.index == repair_index)
            {
                if existing != &repair {
                    return Err(DirectRecordError::InconsistentRecord);
                }
            } else {
                partial.repairs.push(repair);
            }
            Ok(())
        }
        _ => Err(DirectRecordError::InconsistentRecord),
    }
}

fn apply_repairs(
    partial: &mut PartialRecord,
    fragment_bytes: usize,
) -> Result<(), DirectRecordError> {
    if partial.repairs.is_empty() {
        return Ok(());
    }
    let prefix = usize::from(partial.count.saturating_sub(1))
        .checked_mul(fragment_bytes)
        .ok_or(DirectRecordError::InconsistentRecord)?;
    let final_source_bytes = partial
        .total_len
        .checked_sub(prefix)
        .ok_or(DirectRecordError::InconsistentRecord)?;
    let mut generations = Vec::new();
    for repair in &partial.repairs {
        if !generations.contains(&repair.source_bitmap) {
            generations.push(repair.source_bitmap);
        }
    }
    for source_bitmap in generations {
        let repairs = partial
            .repairs
            .iter()
            .filter(|repair| repair.source_bitmap == source_bitmap)
            .cloned()
            .collect::<Vec<_>>();
        let _ = recover_sources(
            &mut partial.fragments,
            fragment_bytes,
            final_source_bytes,
            &repairs,
        )?;
    }
    partial.bitmap = partial
        .fragments
        .iter()
        .enumerate()
        .fold(0_u64, |bitmap, (index, source)| {
            bitmap | u64::from(source.is_some()) << index
        });
    Ok(())
}

fn bitmap_for(count: u8) -> u64 {
    if count == 64 {
        u64::MAX
    } else {
        (1_u64 << count) - 1
    }
}

fn duration_nanos(duration: Duration) -> u64 {
    u64::try_from(duration.as_nanos()).unwrap_or(u64::MAX)
}

fn projected_timing(
    rtt: RttEstimator,
    policy: DirectRecordPolicy,
) -> Result<(Duration, Duration), DirectRecordError> {
    let minimum_us = duration_micros(policy.min_rto);
    let maximum_us = duration_micros(policy.max_rto);
    let rto_us = rtt
        .rto_us(1_000, minimum_us, maximum_us)
        .map_err(|_| DirectRecordError::InvalidPolicy)?;
    let tail_us = rtt
        .tail_probe_us(duration_micros(policy.minimum_tail_probe), rto_us)
        .map_err(|_| DirectRecordError::InvalidPolicy)?;
    Ok((
        Duration::from_micros(rto_us),
        Duration::from_micros(tail_us),
    ))
}

fn duration_micros(duration: Duration) -> u64 {
    u64::try_from(duration.as_micros()).unwrap_or(u64::MAX)
}

#[cfg(test)]
mod tests {
    use std::time::Instant;

    use asupersync::{
        cx::Cx,
        net::UdpSocket,
        runtime::{RuntimeBuilder, TaskHandle},
    };
    use rift_protocol::{MAX_DIRECT_FRAGMENT_BYTES, Role};
    use rift_relay::{RelayPolicy, serve_direct_rendezvous};

    use super::*;
    use crate::{DirectAcquirePolicy, RelayEndpoint, acquire_direct_path};

    #[test]
    fn receiver_deadline_cannot_expire_inside_sender_rto() {
        let policy = DirectRecordPolicy {
            max_rto: Duration::from_secs(2),
            idle_timeout: Duration::from_secs(1),
            ..DirectRecordPolicy::default()
        };
        assert!(matches!(
            policy.validate(),
            Err(DirectRecordError::InvalidPolicy)
        ));
    }

    fn fragments(record: &SequencedRecord) -> Vec<DirectPacket> {
        let encoded = record.encode().unwrap();
        let count = u8::try_from(encoded.len().div_ceil(MAX_DIRECT_FRAGMENT_BYTES)).unwrap();
        encoded
            .chunks(MAX_DIRECT_FRAGMENT_BYTES)
            .enumerate()
            .map(|(index, data)| DirectPacket::Fragment {
                sequence: record.sequence,
                index: u8::try_from(index).unwrap(),
                count,
                total_len: u32::try_from(encoded.len()).unwrap(),
                offset: u32::try_from(index * MAX_DIRECT_FRAGMENT_BYTES).unwrap(),
                data: data.to_vec(),
            })
            .collect()
    }

    fn spawn_reordering_proxy(
        cx: &Cx,
        mut proxy: UdpSocket,
        sender: std::net::SocketAddr,
        receiver: std::net::SocketAddr,
        drop_sender_packet: Option<u8>,
        drop_receiver_packets: u8,
    ) -> TaskHandle<()> {
        cx.spawn(move |proxy_cx| async move {
            let mut buffer = [0_u8; MAX_DIRECT_DATAGRAM_BYTES];
            let mut held = None;
            let mut sender_packets = 0_u8;
            let mut receiver_packets = 0_u8;
            loop {
                if proxy_cx.checkpoint().is_err() {
                    break;
                }
                let Ok((length, source)) = proxy.recv_from(&mut buffer).await else {
                    break;
                };
                if source == sender {
                    sender_packets = sender_packets.saturating_add(1);
                    if sender_packets == 1 {
                        held = Some(buffer[..length].to_vec());
                    } else if sender_packets == 2 {
                        proxy.send_to(&buffer[..length], receiver).await.unwrap();
                        proxy
                            .send_to(&held.take().unwrap(), receiver)
                            .await
                            .unwrap();
                    } else if Some(sender_packets) != drop_sender_packet {
                        proxy.send_to(&buffer[..length], receiver).await.unwrap();
                    }
                } else if source == receiver {
                    receiver_packets = receiver_packets.saturating_add(1);
                    if receiver_packets > drop_receiver_packets {
                        proxy.send_to(&buffer[..length], sender).await.unwrap();
                    }
                }
            }
        })
        .unwrap()
    }

    fn spawn_packet_holes_proxy(
        cx: &Cx,
        mut proxy: UdpSocket,
        sender: std::net::SocketAddr,
        receiver: std::net::SocketAddr,
        drop_sender_packets: Vec<u8>,
    ) -> TaskHandle<()> {
        cx.spawn(move |proxy_cx| async move {
            let mut buffer = [0_u8; MAX_DIRECT_DATAGRAM_BYTES];
            let mut sender_packets = 0_u8;
            loop {
                if proxy_cx.checkpoint().is_err() {
                    break;
                }
                let Ok((length, source)) = proxy.recv_from(&mut buffer).await else {
                    break;
                };
                if source == sender {
                    sender_packets = sender_packets.saturating_add(1);
                    if !drop_sender_packets.contains(&sender_packets) {
                        proxy.send_to(&buffer[..length], receiver).await.unwrap();
                    }
                } else if source == receiver {
                    proxy.send_to(&buffer[..length], sender).await.unwrap();
                }
            }
        })
        .unwrap()
    }

    fn spawn_stale_feedback_proxy(
        cx: &Cx,
        mut proxy: UdpSocket,
        sender: std::net::SocketAddr,
        receiver: std::net::SocketAddr,
    ) -> TaskHandle<()> {
        cx.spawn(move |proxy_cx| async move {
            let mut buffer = [0_u8; MAX_DIRECT_DATAGRAM_BYTES];
            let mut sender_packets = 0_u8;
            let mut receiver_packets = 0_u8;
            loop {
                if proxy_cx.checkpoint().is_err() {
                    break;
                }
                let Ok((length, source)) = proxy.recv_from(&mut buffer).await else {
                    break;
                };
                if source == sender {
                    sender_packets = sender_packets.saturating_add(1);
                    if ![3, 4].contains(&sender_packets) {
                        proxy.send_to(&buffer[..length], receiver).await.unwrap();
                    }
                } else if source == receiver {
                    receiver_packets = receiver_packets.saturating_add(1);
                    if receiver_packets <= 2 || receiver_packets >= 9 {
                        proxy.send_to(&buffer[..length], sender).await.unwrap();
                    }
                }
            }
        })
        .unwrap()
    }

    fn run_single_hole_trial(strategy: RecoveryStrategy) -> (Duration, DirectSendStats) {
        let runtime = RuntimeBuilder::new().worker_threads(6).build().unwrap();
        runtime.block_on(async move {
            let udp = UdpSocket::bind("127.0.0.1:0").await.unwrap();
            let relay = udp.local_addr().unwrap();
            let cx = Cx::current().unwrap();
            let mut relay_task = cx
                .spawn(move |_cx| async move {
                    serve_direct_rendezvous(udp, RelayPolicy::default()).await
                })
                .unwrap();
            let acquire = DirectAcquirePolicy {
                initial_rto: Duration::from_millis(100),
                max_attempts: 8,
                max_unrelated_datagrams: 64,
            };
            let mut sender_acquisition = cx
                .spawn(move |_cx| async move {
                    acquire_direct_path(
                        &RelayEndpoint::Loopback(relay),
                        [0xD1; 16],
                        &[0xE2; 32],
                        Role::Sender,
                        acquire,
                    )
                    .await
                })
                .unwrap();
            let mut receiver_acquisition = cx
                .spawn(move |_cx| async move {
                    acquire_direct_path(
                        &RelayEndpoint::Loopback(relay),
                        [0xD1; 16],
                        &[0xE2; 32],
                        Role::Receiver,
                        acquire,
                    )
                    .await
                })
                .unwrap();
            let mut sender_path = sender_acquisition.join(&cx).await.unwrap().unwrap();
            let mut receiver_path = receiver_acquisition.join(&cx).await.unwrap().unwrap();
            let sender_actual = std::net::SocketAddr::new(
                "127.0.0.1".parse().unwrap(),
                sender_path.socket.local_addr().unwrap().port(),
            );
            let receiver_actual = std::net::SocketAddr::new(
                "127.0.0.1".parse().unwrap(),
                receiver_path.socket.local_addr().unwrap().port(),
            );
            let proxy = UdpSocket::bind("127.0.0.1:0").await.unwrap();
            let proxy_addr = proxy.local_addr().unwrap();
            sender_path.peer = proxy_addr;
            receiver_path.peer = proxy_addr;
            let mut proxy_task =
                spawn_packet_holes_proxy(&cx, proxy, sender_actual, receiver_actual, vec![2]);

            let policy = DirectRecordPolicy {
                initial_window: 8,
                max_window: 8,
                min_rto: Duration::from_millis(200),
                max_rto: Duration::from_millis(400),
                idle_timeout: Duration::from_secs(2),
                recovery: RecoveryPolicy {
                    strategy,
                    ..RecoveryPolicy::default()
                },
                ..DirectRecordPolicy::default()
            };
            let mut receiver = DirectRecordReceiver::new(receiver_path, 0, policy).unwrap();
            let mut delivery_task = cx
                .spawn(move |_cx| async move { receiver.receive_record().await.unwrap() })
                .unwrap();
            let expected = SequencedRecord {
                sequence: 0,
                payload: vec![0xF3; 12_000],
            };
            let mut sender = DirectRecordSender::new(sender_path, policy).unwrap();
            let started = Instant::now();
            let stats = sender.send_record(&expected).await.unwrap();
            let elapsed = started.elapsed();
            assert_eq!(delivery_task.join(&cx).await.unwrap(), expected);
            proxy_task.abort();
            let _ = proxy_task.join(&cx).await;
            relay_task.abort();
            let _ = relay_task.join(&cx).await;
            (elapsed, stats)
        })
    }

    fn run_stale_feedback_trial(strategy: RecoveryStrategy) -> (Duration, DirectSendStats) {
        let runtime = RuntimeBuilder::new().worker_threads(6).build().unwrap();
        runtime.block_on(async move {
            let udp = UdpSocket::bind("127.0.0.1:0").await.unwrap();
            let relay = udp.local_addr().unwrap();
            let cx = Cx::current().unwrap();
            let mut relay_task = cx
                .spawn(move |_cx| async move {
                    serve_direct_rendezvous(udp, RelayPolicy::default()).await
                })
                .unwrap();
            let acquire = DirectAcquirePolicy {
                initial_rto: Duration::from_millis(100),
                max_attempts: 8,
                max_unrelated_datagrams: 64,
            };
            let mut sender_acquisition = cx
                .spawn(move |_cx| async move {
                    acquire_direct_path(
                        &RelayEndpoint::Loopback(relay),
                        [0xD4; 16],
                        &[0xE5; 32],
                        Role::Sender,
                        acquire,
                    )
                    .await
                })
                .unwrap();
            let mut receiver_acquisition = cx
                .spawn(move |_cx| async move {
                    acquire_direct_path(
                        &RelayEndpoint::Loopback(relay),
                        [0xD4; 16],
                        &[0xE5; 32],
                        Role::Receiver,
                        acquire,
                    )
                    .await
                })
                .unwrap();
            let mut sender_path = sender_acquisition.join(&cx).await.unwrap().unwrap();
            let mut receiver_path = receiver_acquisition.join(&cx).await.unwrap().unwrap();
            let sender_actual = std::net::SocketAddr::new(
                "127.0.0.1".parse().unwrap(),
                sender_path.socket.local_addr().unwrap().port(),
            );
            let receiver_actual = std::net::SocketAddr::new(
                "127.0.0.1".parse().unwrap(),
                receiver_path.socket.local_addr().unwrap().port(),
            );
            let proxy = UdpSocket::bind("127.0.0.1:0").await.unwrap();
            let proxy_addr = proxy.local_addr().unwrap();
            sender_path.peer = proxy_addr;
            receiver_path.peer = proxy_addr;
            let mut proxy_task =
                spawn_stale_feedback_proxy(&cx, proxy, sender_actual, receiver_actual);

            let policy = DirectRecordPolicy {
                initial_window: 8,
                max_window: 8,
                min_rto: Duration::from_millis(200),
                max_rto: Duration::from_millis(400),
                idle_timeout: Duration::from_secs(2),
                recovery: RecoveryPolicy {
                    strategy,
                    ..RecoveryPolicy::default()
                },
                ..DirectRecordPolicy::default()
            };
            let mut receiver = DirectRecordReceiver::new(receiver_path, 0, policy).unwrap();
            let mut delivery_task = cx
                .spawn(move |_cx| async move { receiver.receive_record().await.unwrap() })
                .unwrap();
            let expected = SequencedRecord {
                sequence: 0,
                payload: vec![0xD6; 12_000],
            };
            let mut sender = DirectRecordSender::new(sender_path, policy).unwrap();
            let started = Instant::now();
            let stats = sender.send_record(&expected).await.unwrap();
            let elapsed = started.elapsed();
            assert_eq!(delivery_task.join(&cx).await.unwrap(), expected);
            proxy_task.abort();
            let _ = proxy_task.join(&cx).await;
            relay_task.abort();
            let _ = relay_task.join(&cx).await;
            (elapsed, stats)
        })
    }

    fn p95(samples: &mut [Duration]) -> Duration {
        samples.sort_unstable();
        samples[(samples.len() * 95).div_ceil(100).saturating_sub(1)]
    }

    #[test]
    fn replay_window_accepts_reordering_once_and_rejects_old_or_duplicate() {
        let mut window = ReplayWindow::default();
        for nonce in [5, 3, 4, 140, 139] {
            assert!(window.may_accept(nonce));
            window.commit(nonce);
            assert!(!window.may_accept(nonce));
        }
        assert!(!window.may_accept(5));
        assert!(window.may_accept(13));
    }

    #[test]
    fn reassembly_accepts_reverse_order_and_identical_duplicates() {
        let record = SequencedRecord {
            sequence: 9,
            payload: vec![0xA5; MAX_DIRECT_FRAGMENT_BYTES * 2],
        };
        let mut packets = fragments(&record);
        let duplicate = packets[0].clone();
        packets.reverse();
        packets.insert(1, duplicate);
        let mut assembler = RecordAssembler::new(9, MAX_DIRECT_FRAGMENT_BYTES);
        let mut complete = None;
        for packet in packets {
            if let Some(record) = assembler.accept(packet).unwrap().complete {
                complete = Some(record);
            }
        }
        assert_eq!(complete, Some(record));
    }

    #[test]
    fn contradictory_authenticated_duplicate_fails_closed() {
        let record = SequencedRecord {
            sequence: 0,
            payload: vec![0x11; MAX_DIRECT_FRAGMENT_BYTES * 2],
        };
        let mut packets = fragments(&record);
        let mut contradictory = packets[0].clone();
        if let DirectPacket::Fragment { data, .. } = &mut contradictory {
            data[0] ^= 0xFF;
        }
        let mut assembler = RecordAssembler::new(0, MAX_DIRECT_FRAGMENT_BYTES);
        assembler.accept(packets.remove(0)).unwrap();
        assert!(matches!(
            assembler.accept(contradictory),
            Err(DirectRecordError::InconsistentRecord)
        ));
    }

    #[test]
    fn authenticated_direct_records_and_receipt_cross_the_live_path() {
        let runtime = RuntimeBuilder::new().worker_threads(4).build().unwrap();
        runtime.block_on(async move {
            let udp = UdpSocket::bind("127.0.0.1:0").await.unwrap();
            let relay = udp.local_addr().unwrap();
            let cx = Cx::current().unwrap();
            let mut relay_task = cx
                .spawn(move |_cx| async move {
                    serve_direct_rendezvous(
                        udp,
                        RelayPolicy {
                            match_timeout_ms: 2_000,
                            ..RelayPolicy::default()
                        },
                    )
                    .await
                })
                .unwrap();
            let acquire_policy = DirectAcquirePolicy {
                initial_rto: Duration::from_millis(50),
                max_attempts: 8,
                max_unrelated_datagrams: 32,
            };
            let mut sender_acquire = cx
                .spawn(move |_cx| async move {
                    acquire_direct_path(
                        &RelayEndpoint::Loopback(relay),
                        [0x31; 16],
                        &[0x42; 32],
                        Role::Sender,
                        acquire_policy,
                    )
                    .await
                })
                .unwrap();
            let mut receiver_acquire = cx
                .spawn(move |_cx| async move {
                    acquire_direct_path(
                        &RelayEndpoint::Loopback(relay),
                        [0x31; 16],
                        &[0x42; 32],
                        Role::Receiver,
                        acquire_policy,
                    )
                    .await
                })
                .unwrap();
            let sender_path = sender_acquire.join(&cx).await.unwrap().unwrap();
            let receiver_path = receiver_acquire.join(&cx).await.unwrap().unwrap();
            assert!(sender_path.goodput_floor_bps() > 0);
            assert_eq!(
                sender_path.goodput_floor_bps(),
                receiver_path.goodput_floor_bps()
            );

            let policy = DirectRecordPolicy {
                min_rto: Duration::from_millis(50),
                max_rto: Duration::from_millis(500),
                idle_timeout: Duration::from_secs(2),
                ..DirectRecordPolicy::default()
            };
            let mut receiver = DirectRecordReceiver::new(receiver_path, 7, policy).unwrap();
            let mut receiver_task = cx
                .spawn(move |_cx| async move {
                    let record = receiver.receive_record().await.unwrap();
                    receiver
                        .send_receipt(Digest([0x55; 32]), 57_000)
                        .await
                        .unwrap();
                    record
                })
                .unwrap();
            let expected = SequencedRecord {
                sequence: 7,
                payload: vec![0xA7; 57_000],
            };
            let mut sender = DirectRecordSender::new(sender_path, policy).unwrap();
            let stats = sender.send_record(&expected).await.unwrap();
            sender
                .receive_receipt(Digest([0x55; 32]), 57_000)
                .await
                .unwrap();
            let delivered = receiver_task.join(&cx).await.unwrap();
            assert_eq!(delivered, expected);
            assert!(stats.datagrams_sent > 1);
            assert!(stats.send_batches > 0);
            #[cfg(target_os = "linux")]
            assert!(stats.native_send_batches > 0);
            relay_task.abort();
            let _ = relay_task.join(&cx).await;
        });
    }

    #[test]
    fn tail_loss_lost_ack_and_reordering_probe_before_rto() {
        let runtime = RuntimeBuilder::new().worker_threads(6).build().unwrap();
        runtime.block_on(async move {
            let udp = UdpSocket::bind("127.0.0.1:0").await.unwrap();
            let relay = udp.local_addr().unwrap();
            let cx = Cx::current().unwrap();
            let mut relay_task = cx
                .spawn(move |_cx| async move {
                    serve_direct_rendezvous(udp, RelayPolicy::default()).await
                })
                .unwrap();
            let acquire = DirectAcquirePolicy {
                initial_rto: Duration::from_millis(50),
                max_attempts: 8,
                max_unrelated_datagrams: 64,
            };
            let mut sender_acquisition = cx
                .spawn(move |_cx| async move {
                    acquire_direct_path(
                        &RelayEndpoint::Loopback(relay),
                        [0x61; 16],
                        &[0x72; 32],
                        Role::Sender,
                        acquire,
                    )
                    .await
                })
                .unwrap();
            let mut receiver_acquisition = cx
                .spawn(move |_cx| async move {
                    acquire_direct_path(
                        &RelayEndpoint::Loopback(relay),
                        [0x61; 16],
                        &[0x72; 32],
                        Role::Receiver,
                        acquire,
                    )
                    .await
                })
                .unwrap();
            let mut sender_path = sender_acquisition.join(&cx).await.unwrap().unwrap();
            let mut receiver_path = receiver_acquisition.join(&cx).await.unwrap().unwrap();
            let sender_actual = std::net::SocketAddr::new(
                "127.0.0.1".parse().unwrap(),
                sender_path.socket.local_addr().unwrap().port(),
            );
            let receiver_actual = std::net::SocketAddr::new(
                "127.0.0.1".parse().unwrap(),
                receiver_path.socket.local_addr().unwrap().port(),
            );
            let proxy = UdpSocket::bind("127.0.0.1:0").await.unwrap();
            let proxy_addr = proxy.local_addr().unwrap();
            sender_path.peer = proxy_addr;
            receiver_path.peer = proxy_addr;
            let mut proxy_task =
                spawn_reordering_proxy(&cx, proxy, sender_actual, receiver_actual, Some(3), 4);

            let policy = DirectRecordPolicy {
                initial_window: 4,
                max_window: 8,
                max_timeouts: 4,
                // Keep the oracle comfortably outside native Windows timer
                // and scheduler jitter. The tail probe still fires at the
                // policy's 20 ms floor, so a zero-timeout result continues to
                // prove early recovery rather than merely tolerating an RTO.
                min_rto: Duration::from_millis(200),
                max_rto: Duration::from_millis(500),
                idle_timeout: Duration::from_secs(2),
                recovery: RecoveryPolicy {
                    strategy: RecoveryStrategy::ExactOnly,
                    ..RecoveryPolicy::default()
                },
                ..DirectRecordPolicy::default()
            };
            let mut receiver = DirectRecordReceiver::new(receiver_path, 0, policy).unwrap();
            let mut delivery_task = cx
                .spawn(move |_cx| async move { receiver.receive_record().await.unwrap() })
                .unwrap();
            let expected = SequencedRecord {
                sequence: 0,
                payload: vec![0x9A; 12_000],
            };
            let mut sender = DirectRecordSender::new(sender_path, policy).unwrap();
            let stats = sender.send_record(&expected).await.unwrap();
            let delivered = delivery_task.join(&cx).await.unwrap();
            assert_eq!(delivered, expected);
            assert_eq!(stats.timeouts, 0);
            assert!(stats.tail_probe_fragments >= 1);
            assert!(stats.retransmitted_fragments >= 1);
            proxy_task.abort();
            let _ = proxy_task.join(&cx).await;
            relay_task.abort();
            let _ = relay_task.join(&cx).await;
        });
    }

    #[test]
    fn bounded_reordering_does_not_spend_recovery_budget() {
        let runtime = RuntimeBuilder::new().worker_threads(6).build().unwrap();
        runtime.block_on(async move {
            let udp = UdpSocket::bind("127.0.0.1:0").await.unwrap();
            let relay = udp.local_addr().unwrap();
            let cx = Cx::current().unwrap();
            let mut relay_task = cx
                .spawn(move |_cx| async move {
                    serve_direct_rendezvous(udp, RelayPolicy::default()).await
                })
                .unwrap();
            let acquire = DirectAcquirePolicy {
                initial_rto: Duration::from_millis(50),
                max_attempts: 8,
                max_unrelated_datagrams: 64,
            };
            let mut sender_acquisition = cx
                .spawn(move |_cx| async move {
                    acquire_direct_path(
                        &RelayEndpoint::Loopback(relay),
                        [0x62; 16],
                        &[0x73; 32],
                        Role::Sender,
                        acquire,
                    )
                    .await
                })
                .unwrap();
            let mut receiver_acquisition = cx
                .spawn(move |_cx| async move {
                    acquire_direct_path(
                        &RelayEndpoint::Loopback(relay),
                        [0x62; 16],
                        &[0x73; 32],
                        Role::Receiver,
                        acquire,
                    )
                    .await
                })
                .unwrap();
            let mut sender_path = sender_acquisition.join(&cx).await.unwrap().unwrap();
            let mut receiver_path = receiver_acquisition.join(&cx).await.unwrap().unwrap();
            let sender_actual = std::net::SocketAddr::new(
                "127.0.0.1".parse().unwrap(),
                sender_path.socket.local_addr().unwrap().port(),
            );
            let receiver_actual = std::net::SocketAddr::new(
                "127.0.0.1".parse().unwrap(),
                receiver_path.socket.local_addr().unwrap().port(),
            );
            let proxy = UdpSocket::bind("127.0.0.1:0").await.unwrap();
            let proxy_addr = proxy.local_addr().unwrap();
            sender_path.peer = proxy_addr;
            receiver_path.peer = proxy_addr;
            let mut proxy_task =
                spawn_reordering_proxy(&cx, proxy, sender_actual, receiver_actual, None, 0);

            let policy = DirectRecordPolicy {
                initial_window: 8,
                max_window: 8,
                min_rto: Duration::from_millis(200),
                max_rto: Duration::from_millis(400),
                idle_timeout: Duration::from_secs(2),
                recovery: RecoveryPolicy {
                    strategy: RecoveryStrategy::ExactOnly,
                    ..RecoveryPolicy::default()
                },
                ..DirectRecordPolicy::default()
            };
            let mut receiver = DirectRecordReceiver::new(receiver_path, 0, policy).unwrap();
            let mut delivery_task = cx
                .spawn(move |_cx| async move { receiver.receive_record().await.unwrap() })
                .unwrap();
            let expected = SequencedRecord {
                sequence: 0,
                payload: vec![0x9B; 12_000],
            };
            let mut sender = DirectRecordSender::new(sender_path, policy).unwrap();
            let stats = sender.send_record(&expected).await.unwrap();
            let delivered = delivery_task.join(&cx).await.unwrap();
            assert_eq!(delivered, expected);
            assert_eq!(stats.timeouts, 0);
            assert_eq!(stats.fast_retransmitted_fragments, 0);
            proxy_task.abort();
            let _ = proxy_task.join(&cx).await;
            relay_task.abort();
            let _ = relay_task.join(&cx).await;
        });
    }

    #[test]
    fn selective_ack_gap_recovers_before_tail_probe_or_rto() {
        let runtime = RuntimeBuilder::new().worker_threads(6).build().unwrap();
        runtime.block_on(async move {
            let udp = UdpSocket::bind("127.0.0.1:0").await.unwrap();
            let relay = udp.local_addr().unwrap();
            let cx = Cx::current().unwrap();
            let mut relay_task = cx
                .spawn(move |_cx| async move {
                    serve_direct_rendezvous(udp, RelayPolicy::default()).await
                })
                .unwrap();
            let acquire = DirectAcquirePolicy {
                initial_rto: Duration::from_millis(50),
                max_attempts: 8,
                max_unrelated_datagrams: 64,
            };
            let mut sender_acquisition = cx
                .spawn(move |_cx| async move {
                    acquire_direct_path(
                        &RelayEndpoint::Loopback(relay),
                        [0x81; 16],
                        &[0x92; 32],
                        Role::Sender,
                        acquire,
                    )
                    .await
                })
                .unwrap();
            let mut receiver_acquisition = cx
                .spawn(move |_cx| async move {
                    acquire_direct_path(
                        &RelayEndpoint::Loopback(relay),
                        [0x81; 16],
                        &[0x92; 32],
                        Role::Receiver,
                        acquire,
                    )
                    .await
                })
                .unwrap();
            let mut sender_path = sender_acquisition.join(&cx).await.unwrap().unwrap();
            let mut receiver_path = receiver_acquisition.join(&cx).await.unwrap().unwrap();
            let sender_actual = std::net::SocketAddr::new(
                "127.0.0.1".parse().unwrap(),
                sender_path.socket.local_addr().unwrap().port(),
            );
            let receiver_actual = std::net::SocketAddr::new(
                "127.0.0.1".parse().unwrap(),
                receiver_path.socket.local_addr().unwrap().port(),
            );
            let proxy = UdpSocket::bind("127.0.0.1:0").await.unwrap();
            let proxy_addr = proxy.local_addr().unwrap();
            sender_path.peer = proxy_addr;
            receiver_path.peer = proxy_addr;
            let mut proxy_task =
                spawn_packet_holes_proxy(&cx, proxy, sender_actual, receiver_actual, vec![2]);

            let policy = DirectRecordPolicy {
                initial_window: 8,
                max_window: 8,
                min_rto: Duration::from_millis(200),
                max_rto: Duration::from_millis(400),
                idle_timeout: Duration::from_secs(2),
                recovery: RecoveryPolicy {
                    strategy: RecoveryStrategy::ExactOnly,
                    ..RecoveryPolicy::default()
                },
                ..DirectRecordPolicy::default()
            };
            let mut receiver = DirectRecordReceiver::new(receiver_path, 0, policy).unwrap();
            let mut delivery_task = cx
                .spawn(move |_cx| async move { receiver.receive_record().await.unwrap() })
                .unwrap();
            let expected = SequencedRecord {
                sequence: 0,
                payload: vec![0xB3; 12_000],
            };
            let mut sender = DirectRecordSender::new(sender_path, policy).unwrap();
            let stats = sender.send_record(&expected).await.unwrap();
            assert_eq!(delivery_task.join(&cx).await.unwrap(), expected);
            assert_eq!(stats.timeouts, 0);
            assert!(stats.fast_retransmitted_fragments >= 1);
            proxy_task.abort();
            let _ = proxy_task.join(&cx).await;
            relay_task.abort();
            let _ = relay_task.join(&cx).await;
        });
    }

    #[test]
    fn fast_recovery_beats_the_fixed_rto_parent_at_p95() {
        let mut parent = Vec::new();
        let mut candidate = Vec::new();
        for _ in 0..5 {
            let (parent_elapsed, parent_stats) = run_single_hole_trial(RecoveryStrategy::RtoOnly);
            assert!(parent_stats.timeouts >= 1);
            assert_eq!(parent_stats.fast_retransmitted_fragments, 0);
            parent.push(parent_elapsed);

            let (candidate_elapsed, candidate_stats) =
                run_single_hole_trial(RecoveryStrategy::ExactOnly);
            assert_eq!(candidate_stats.timeouts, 0);
            assert!(candidate_stats.fast_retransmitted_fragments >= 1);
            assert_eq!(candidate_stats.gso_demotions, 1);
            candidate.push(candidate_elapsed);
        }
        let parent_p95 = p95(&mut parent);
        let candidate_p95 = p95(&mut candidate);
        eprintln!(
            "recovery_ablation parent_p95_us={} candidate_p95_us={}",
            parent_p95.as_micros(),
            candidate_p95.as_micros()
        );
        assert!(
            candidate_p95.as_nanos().saturating_mul(5) < parent_p95.as_nanos().saturating_mul(4),
            "candidate p95 {candidate_p95:?} did not beat parent p95 {parent_p95:?} by 20%"
        );
    }

    #[test]
    fn coded_tail_repair_beats_exact_recovery_under_stale_feedback() {
        let mut exact = Vec::new();
        let mut coded = Vec::new();
        for _ in 0..5 {
            let (exact_elapsed, exact_stats) =
                run_stale_feedback_trial(RecoveryStrategy::ExactOnly);
            assert!(exact_stats.timeouts >= 1);
            assert_eq!(exact_stats.repair_symbols, 0);
            exact.push(exact_elapsed);

            let (coded_elapsed, coded_stats) =
                run_stale_feedback_trial(RecoveryStrategy::AdaptiveRepair);
            assert_eq!(coded_stats.timeouts, 0);
            assert!(coded_stats.repair_symbols >= 2);
            coded.push(coded_elapsed);
        }
        let exact_p95 = p95(&mut exact);
        let coded_p95 = p95(&mut coded);
        eprintln!(
            "coded_repair_ablation exact_p95_us={} coded_p95_us={}",
            exact_p95.as_micros(),
            coded_p95.as_micros()
        );
        assert!(
            coded_p95.as_nanos().saturating_mul(5) < exact_p95.as_nanos().saturating_mul(4),
            "coded p95 {coded_p95:?} did not beat exact p95 {exact_p95:?} by 20%"
        );
    }

    #[test]
    fn bounded_tail_probes_recover_a_two_fragment_tail_burst() {
        let runtime = RuntimeBuilder::new().worker_threads(6).build().unwrap();
        runtime.block_on(async move {
            let udp = UdpSocket::bind("127.0.0.1:0").await.unwrap();
            let relay = udp.local_addr().unwrap();
            let cx = Cx::current().unwrap();
            let mut relay_task = cx
                .spawn(move |_cx| async move {
                    serve_direct_rendezvous(udp, RelayPolicy::default()).await
                })
                .unwrap();
            let acquire = DirectAcquirePolicy {
                initial_rto: Duration::from_millis(50),
                max_attempts: 8,
                max_unrelated_datagrams: 64,
            };
            let mut sender_acquisition = cx
                .spawn(move |_cx| async move {
                    acquire_direct_path(
                        &RelayEndpoint::Loopback(relay),
                        [0xA1; 16],
                        &[0xB2; 32],
                        Role::Sender,
                        acquire,
                    )
                    .await
                })
                .unwrap();
            let mut receiver_acquisition = cx
                .spawn(move |_cx| async move {
                    acquire_direct_path(
                        &RelayEndpoint::Loopback(relay),
                        [0xA1; 16],
                        &[0xB2; 32],
                        Role::Receiver,
                        acquire,
                    )
                    .await
                })
                .unwrap();
            let mut sender_path = sender_acquisition.join(&cx).await.unwrap().unwrap();
            let mut receiver_path = receiver_acquisition.join(&cx).await.unwrap().unwrap();
            let sender_actual = std::net::SocketAddr::new(
                "127.0.0.1".parse().unwrap(),
                sender_path.socket.local_addr().unwrap().port(),
            );
            let receiver_actual = std::net::SocketAddr::new(
                "127.0.0.1".parse().unwrap(),
                receiver_path.socket.local_addr().unwrap().port(),
            );
            let proxy = UdpSocket::bind("127.0.0.1:0").await.unwrap();
            let proxy_addr = proxy.local_addr().unwrap();
            sender_path.peer = proxy_addr;
            receiver_path.peer = proxy_addr;
            let mut proxy_task =
                spawn_packet_holes_proxy(&cx, proxy, sender_actual, receiver_actual, vec![7, 8]);

            let policy = DirectRecordPolicy {
                initial_window: 8,
                max_window: 8,
                min_rto: Duration::from_millis(200),
                max_rto: Duration::from_millis(400),
                idle_timeout: Duration::from_secs(2),
                recovery: RecoveryPolicy {
                    strategy: RecoveryStrategy::ExactOnly,
                    ..RecoveryPolicy::default()
                },
                ..DirectRecordPolicy::default()
            };
            let mut receiver = DirectRecordReceiver::new(receiver_path, 0, policy).unwrap();
            let mut delivery_task = cx
                .spawn(move |_cx| async move { receiver.receive_record().await.unwrap() })
                .unwrap();
            let expected = SequencedRecord {
                sequence: 0,
                payload: vec![0xC3; 12_000],
            };
            let mut sender = DirectRecordSender::new(sender_path, policy).unwrap();
            let stats = sender.send_record(&expected).await.unwrap();
            assert_eq!(delivery_task.join(&cx).await.unwrap(), expected);
            assert_eq!(stats.timeouts, 0);
            assert!(stats.tail_probe_fragments >= 2);
            assert_eq!(stats.fast_retransmitted_fragments, 0);
            proxy_task.abort();
            let _ = proxy_task.join(&cx).await;
            relay_task.abort();
            let _ = relay_task.join(&cx).await;
        });
    }
}
