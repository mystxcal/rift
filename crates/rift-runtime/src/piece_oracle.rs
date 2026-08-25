//! Out-of-order authenticated reconstruction over independent QUIC lanes.

use std::{
    collections::{BTreeMap, BTreeSet},
    ffi::OsString,
    io,
    path::{Path, PathBuf},
    time::{Duration, Instant},
};

use asupersync::{
    channel::mpsc,
    cx::Cx,
    fs::{self, File},
    io::AsyncWriteExt,
    runtime::TaskHandle,
};
use rift_core::{BlockId, BlockSpec, Digest, EntryId, ReconstructionGraph};
use rift_protocol::{HardLimits, PieceRecord, ResumeRange, decode_piece_record};

use crate::{
    FileOracleError, ReceiptDelivery, ReceiveSummary, ReceiveTarget, SendSummary, StagingFile,
    StagingTree, StagingTreeFile, TransferObserver, TransferProfile, TransferProgress,
    file_oracle::{
        ResumeToken, SourceEntry, SourceKind, apply_portable_metadata, component_bytes,
        portable_component_key, scan_source, validate_component,
    },
    piece_path::PiecePath,
};

/// Logical bytes per independently verifiable source piece.
pub const PIECE_BYTES: u32 = 256 * 1024;
const MAX_LANE_BYTES: usize = PIECE_BYTES as usize + 128;
const SOURCE_PREFETCH_PIECES: usize = 16;
const MAX_RESUME_RANGE_PIECES: u32 = 64;
const PIECE_STATE_BYTES: u64 = 96;
const JOURNAL_MAGIC: [u8; 4] = *b"RFSJ";
const JOURNAL_VERSION: u8 = 1;
const JOURNAL_HEADER_BYTES: usize = 4 + 1 + 3 + 16 + 8;
const JOURNAL_ENTRY_BYTES: usize = 8 + 8 + 8 + 4 + 32;
const LANE_IDLE_TIMEOUT: Duration = Duration::from_secs(30);

#[derive(Clone, Debug)]
struct ManifestEntry {
    id: EntryId,
    parent: Option<EntryId>,
    name: String,
    relative: PathBuf,
    kind: SourceKind,
    length: u64,
    metadata: u16,
    encoded: Vec<u8>,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct PiecePlan {
    block: BlockId,
    entry: EntryId,
    offset: u64,
    length: u32,
}

struct SourcePiece {
    plan: PiecePlan,
    bytes: Vec<u8>,
    digest: Digest,
    read_us: u64,
    hash_us: u64,
}

#[derive(Default)]
#[allow(clippy::struct_field_names)]
struct PieceTimings {
    source_read_us: u64,
    hash_verify_us: u64,
    path_queue_us: u64,
    staging_write_us: u64,
}

struct PieceReader {
    pieces: mpsc::Receiver<SourcePiece>,
    recycled: mpsc::Sender<Vec<u8>>,
    worker: Option<TaskHandle<Result<(), FileOracleError>>>,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct JournalPiece {
    plan: PiecePlan,
    digest: Digest,
}

enum PieceStaging {
    File {
        file: Box<StagingFile>,
        metadata: u16,
    },
    Tree {
        tree: StagingTree,
        files: BTreeMap<EntryId, StagingTreeFile>,
        metadata: Vec<(PathBuf, bool, u16)>,
    },
}

struct ReceivedPieceState {
    graph: ReconstructionGraph,
    digests: Vec<Option<Digest>>,
    offered: BTreeMap<BlockId, ResumeRange>,
    existing: BTreeMap<BlockId, Digest>,
    completed_bytes: u64,
}

struct Manifest {
    object_id: [u8; 16],
    entries: Vec<ManifestEntry>,
    total_length: u64,
    pieces: Vec<PiecePlan>,
    start_encoded: Vec<u8>,
}

/// Send one object through the independent-piece engine.
#[allow(clippy::too_many_lines)]
pub(crate) async fn send_object_piecewise<P: PiecePath>(
    links: &mut P,
    source: &Path,
    limits: HardLimits,
    observer: &dyn TransferObserver,
    token: &ResumeToken,
) -> Result<SendSummary, FileOracleError> {
    let transfer_started = Instant::now();
    let scan_started = Instant::now();
    let source = scan_source(source, limits).await?;
    let source_scan_us = elapsed_us(scan_started.elapsed());
    let mut timings = PieceTimings::default();
    let entries =
        u64::try_from(source.entries.len()).map_err(|_| FileOracleError::LimitExceeded)?;
    let pieces = source_piece_count(&source.entries)?;
    admit_piece_state(pieces, limits)?;
    observer.observe(TransferProgress::Declared {
        bytes: source.total_length,
        entries,
    });
    let object_id = piece_object_id(&source.entries, source.total_length, pieces, token)?;
    let start = PieceRecord::Start {
        object_id,
        entries,
        total_length: source.total_length,
        piece_bytes: PIECE_BYTES,
        pieces,
    }
    .encode()?;
    let queue_started = Instant::now();
    links
        .queue_control(&start, MAX_LANE_BYTES, LANE_IDLE_TIMEOUT)
        .await?;
    timings.path_queue_us = timings
        .path_queue_us
        .saturating_add(elapsed_us(queue_started.elapsed()));
    let mut entry_records = Vec::with_capacity(source.entries.len());
    for entry in &source.entries {
        let encoded = encode_source_entry(entry)?;
        let queue_started = Instant::now();
        links
            .queue_control(&encoded, MAX_LANE_BYTES, LANE_IDLE_TIMEOUT)
            .await?;
        timings.path_queue_us = timings
            .path_queue_us
            .saturating_add(elapsed_us(queue_started.elapsed()));
        entry_records.push(encoded);
    }
    links.flush_all().await?;

    let offer = links
        .receive_control(MAX_LANE_BYTES, LANE_IDLE_TIMEOUT)
        .await?;
    let offered = match decode_piece_record(&offer, PIECE_BYTES as usize)? {
        PieceRecord::ResumeOffer {
            object_id: offered_id,
            ranges,
        } if offered_id == object_id => validate_resume_offer(&ranges, pieces)?,
        _ => return Err(FileOracleError::UnexpectedRecord),
    };

    let mut commitment = object_commitment(&start, &entry_records);
    let mut offered = offered.into_iter().peekable();
    let mut block = 0_u64;
    let mut sent_bytes = 0_u64;
    for entry in &source.entries {
        if entry.kind == SourceKind::Directory {
            continue;
        }
        let mut reader = PieceReader::spawn(entry, BlockId(block))?;
        while let Some(piece) = reader.next().await? {
            timings.source_read_us = timings.source_read_us.saturating_add(piece.read_us);
            timings.hash_verify_us = timings.hash_verify_us.saturating_add(piece.hash_us);
            update_piece_commitment(&mut commitment, piece.plan, piece.digest);
            if offered
                .peek()
                .is_some_and(|range| range.start == piece.plan.block)
            {
                let range = offered.next().expect("peeked resume range");
                let mut buffered = Vec::with_capacity(range.count as usize);
                let mut range_hasher = range_commitment();
                let mut current = piece;
                for index in 0..range.count {
                    if current.plan.block.0 != range.start.0 + u64::from(index) {
                        reader.abort().await;
                        return Err(FileOracleError::UnexpectedRecord);
                    }
                    update_piece_commitment(&mut range_hasher, current.plan, current.digest);
                    buffered.push(encode_source_piece(&current)?);
                    reader.recycle(std::mem::take(&mut current.bytes));
                    sent_bytes = sent_bytes
                        .checked_add(u64::from(current.plan.length))
                        .ok_or(FileOracleError::LimitExceeded)?;
                    block = current.plan.block.0 + 1;
                    observer.observe(TransferProgress::Advanced {
                        bytes: sent_bytes,
                        total: source.total_length,
                    });
                    if index + 1 < range.count {
                        current = reader.next().await?.ok_or(FileOracleError::SourceChanged)?;
                        timings.source_read_us =
                            timings.source_read_us.saturating_add(current.read_us);
                        timings.hash_verify_us =
                            timings.hash_verify_us.saturating_add(current.hash_us);
                        update_piece_commitment(&mut commitment, current.plan, current.digest);
                    }
                }
                let range_digest = Digest(*range_hasher.finalize().as_bytes());
                if range_digest == range.commitment {
                    let decision = PieceRecord::ResumeDecision {
                        object_id,
                        ranges: vec![range],
                    }
                    .encode()?;
                    let queue_started = Instant::now();
                    links
                        .queue_control(&decision, MAX_LANE_BYTES, LANE_IDLE_TIMEOUT)
                        .await?;
                    timings.path_queue_us = timings
                        .path_queue_us
                        .saturating_add(elapsed_us(queue_started.elapsed()));
                } else {
                    for encoded in buffered {
                        let record = decode_piece_record(&encoded, PIECE_BYTES as usize)?;
                        let PieceRecord::Piece { block, .. } = record else {
                            return Err(FileOracleError::UnexpectedRecord);
                        };
                        let queue_started = Instant::now();
                        links
                            .queue_piece(block, &encoded, MAX_LANE_BYTES, LANE_IDLE_TIMEOUT)
                            .await?;
                        timings.path_queue_us = timings
                            .path_queue_us
                            .saturating_add(elapsed_us(queue_started.elapsed()));
                    }
                }
                continue;
            }

            let encoded = encode_source_piece(&piece)?;
            let queue_started = Instant::now();
            links
                .queue_piece(
                    piece.plan.block,
                    &encoded,
                    MAX_LANE_BYTES,
                    LANE_IDLE_TIMEOUT,
                )
                .await?;
            timings.path_queue_us = timings
                .path_queue_us
                .saturating_add(elapsed_us(queue_started.elapsed()));
            sent_bytes = sent_bytes
                .checked_add(u64::from(piece.plan.length))
                .ok_or(FileOracleError::LimitExceeded)?;
            block = piece.plan.block.0 + 1;
            observer.observe(TransferProgress::Advanced {
                bytes: sent_bytes,
                total: source.total_length,
            });
            reader.recycle(piece.bytes);
        }
        reader.finish().await?;
    }
    if offered.next().is_some() || block != pieces || sent_bytes != source.total_length {
        return Err(FileOracleError::SourceChanged);
    }

    let digest = Digest(*commitment.finalize().as_bytes());
    let seal = PieceRecord::ObjectSeal { digest }.encode()?;
    let queue_started = Instant::now();
    links
        .queue_control(&seal, MAX_LANE_BYTES, LANE_IDLE_TIMEOUT)
        .await?;
    timings.path_queue_us = timings
        .path_queue_us
        .saturating_add(elapsed_us(queue_started.elapsed()));
    links.flush_all().await?;
    let receipt = links
        .receive_control(MAX_LANE_BYTES, LANE_IDLE_TIMEOUT)
        .await?;
    match decode_piece_record(&receipt, PIECE_BYTES as usize)? {
        PieceRecord::CommitReceipt {
            digest: received,
            length,
        } if received == digest && length == source.total_length => {}
        PieceRecord::CommitReceipt { .. } => return Err(FileOracleError::ReceiptMismatch),
        _ => return Err(FileOracleError::UnexpectedRecord),
    }
    let acknowledgement = PieceRecord::CommitAck { digest }.encode()?;
    let queue_started = Instant::now();
    links
        .queue_control(&acknowledgement, MAX_LANE_BYTES, LANE_IDLE_TIMEOUT)
        .await?;
    timings.path_queue_us = timings
        .path_queue_us
        .saturating_add(elapsed_us(queue_started.elapsed()));
    links.flush_all().await?;
    let metrics = links.metrics();
    Ok(SendSummary {
        length: source.total_length,
        digest,
        blocks: pieces,
        entries,
        transport: links.transport(),
        migration: None,
        profile: TransferProfile {
            elapsed_us: elapsed_us(transfer_started.elapsed()),
            source_scan_us,
            source_read_us: timings.source_read_us,
            hash_verify_us: timings.hash_verify_us,
            path_queue_us: timings.path_queue_us,
            quic_cpu_us: metrics.quic_cpu_us,
            socket_io_us: metrics.socket_io_us,
            authenticated_paths: metrics.paths,
            payload_paths: metrics.payload_paths,
            wire_sent_bytes: metrics.wire_sent_bytes,
            wire_received_bytes: metrics.wire_received_bytes,
            lost_bytes: metrics.lost_bytes,
            ..TransferProfile::default()
        },
    })
}

/// Receive, reconstruct out of order, and atomically commit one object.
#[allow(clippy::too_many_lines)]
pub(crate) async fn receive_object_piecewise<P: PiecePath>(
    links: &mut P,
    target: ReceiveTarget,
    limits: HardLimits,
    observer: &dyn TransferObserver,
) -> Result<ReceiveSummary, FileOracleError> {
    let transfer_started = Instant::now();
    let mut timings = PieceTimings::default();
    let manifest = receive_manifest(links, limits).await?;
    observer.observe(TransferProgress::Declared {
        bytes: manifest.total_length,
        entries: manifest.entries.len() as u64,
    });
    let destination = target
        .resolve(
            &manifest.entries[0].name,
            manifest.entries[0].kind == SourceKind::Directory,
        )
        .await?;
    let state_path = journal_path(&destination, manifest.object_id)?;
    let mut staging = PieceStaging::open(&destination, &manifest).await?;
    let verify_started = Instant::now();
    let journal = load_and_reverify_journal(&state_path, &manifest, &mut staging).await?;
    timings.hash_verify_us = timings
        .hash_verify_us
        .saturating_add(elapsed_us(verify_started.elapsed()));
    let (ranges, existing) = journal_ranges(&journal);
    let offer = PieceRecord::ResumeOffer {
        object_id: manifest.object_id,
        ranges: ranges.clone(),
    }
    .encode()?;
    let queue_started = Instant::now();
    links
        .queue_control(&offer, MAX_LANE_BYTES, LANE_IDLE_TIMEOUT)
        .await?;
    timings.path_queue_us = timings
        .path_queue_us
        .saturating_add(elapsed_us(queue_started.elapsed()));
    links.flush_all().await?;

    let mut state = ReceivedPieceState::new(&manifest, ranges, existing)?;
    let result = receive_pieces(
        links,
        &manifest,
        &mut staging,
        &mut state,
        observer,
        &mut timings,
    )
    .await;
    let digest = match result {
        Ok(digest) => digest,
        Err(error) => {
            if error.is_retryable_path_failure() {
                staging.checkpoint().await?;
                write_journal(&state_path, manifest.object_id, &manifest, &state).await?;
                staging.retain().await?;
            }
            return Err(error);
        }
    };

    let commit_started = Instant::now();
    staging.checkpoint().await?;
    for plan in &manifest.pieces {
        if state.graph.phase(plan.block) == Some(rift_core::BlockPhase::Verified) {
            state.graph.mark_durable(plan.block)?;
        }
    }
    if !state.graph.all_durable() {
        return Err(FileOracleError::UnexpectedRecord);
    }
    let receipt = staging.commit(digest, manifest.total_length).await?;
    let durable_commit_us = elapsed_us(commit_started.elapsed());
    remove_journal(&state_path).await?;
    let encoded = PieceRecord::CommitReceipt {
        digest: receipt.digest,
        length: receipt.length,
    }
    .encode()?;
    let queue_started = Instant::now();
    let delivery = match links
        .queue_control(&encoded, MAX_LANE_BYTES, LANE_IDLE_TIMEOUT)
        .await
    {
        Err(_) => ReceiptDelivery::Failed,
        Ok(()) => match links.flush_all().await {
            Err(_) => ReceiptDelivery::Failed,
            Ok(()) => match links
                .receive_control(MAX_LANE_BYTES, LANE_IDLE_TIMEOUT)
                .await
            {
                Ok(acknowledgement)
                    if matches!(
                        decode_piece_record(&acknowledgement, PIECE_BYTES as usize),
                        Ok(PieceRecord::CommitAck { digest: accepted }) if accepted == receipt.digest
                    ) =>
                {
                    ReceiptDelivery::Sent
                }
                Ok(_) | Err(_) => ReceiptDelivery::Failed,
            },
        },
    };
    timings.path_queue_us = timings
        .path_queue_us
        .saturating_add(elapsed_us(queue_started.elapsed()));
    let metrics = links.metrics();
    Ok(ReceiveSummary {
        length: receipt.length,
        digest: receipt.digest,
        blocks: manifest.pieces.len() as u64,
        entries: manifest.entries.len() as u64,
        transport: links.transport(),
        destination,
        receipt: delivery,
        migration: None,
        profile: TransferProfile {
            elapsed_us: elapsed_us(transfer_started.elapsed()),
            hash_verify_us: timings.hash_verify_us,
            path_queue_us: timings.path_queue_us,
            quic_cpu_us: metrics.quic_cpu_us,
            socket_io_us: metrics.socket_io_us,
            staging_write_us: timings.staging_write_us,
            durable_commit_us,
            authenticated_paths: metrics.paths,
            payload_paths: metrics.payload_paths,
            wire_sent_bytes: metrics.wire_sent_bytes,
            wire_received_bytes: metrics.wire_received_bytes,
            lost_bytes: metrics.lost_bytes,
            ..TransferProfile::default()
        },
    })
}

impl PieceReader {
    fn spawn(entry: &SourceEntry, first_block: BlockId) -> Result<Self, FileOracleError> {
        let cx = Cx::current().ok_or_else(runtime_unavailable)?;
        let (piece_tx, pieces) = mpsc::channel(SOURCE_PREFETCH_PIECES);
        let (recycled, mut buffers) = mpsc::channel(SOURCE_PREFETCH_PIECES);
        for _ in 0..SOURCE_PREFETCH_PIECES {
            recycled
                .try_send(Vec::with_capacity(PIECE_BYTES as usize))
                .map_err(|_| runtime_unavailable())?;
        }
        let path = entry.path.clone();
        let length = entry.length;
        let entry_id = entry.id;
        let worker = cx
            .spawn(move |worker_cx| async move {
                let mut file = File::open(&path).await.map_err(FileOracleError::SourceIo)?;
                if file
                    .metadata()
                    .await
                    .map_err(FileOracleError::SourceIo)?
                    .len()
                    != length
                {
                    return Err(FileOracleError::SourceChanged);
                }
                let mut offset = 0_u64;
                let mut block = first_block.0;
                while offset < length {
                    let wanted = usize::try_from((length - offset).min(u64::from(PIECE_BYTES)))
                        .map_err(|_| FileOracleError::LimitExceeded)?;
                    let mut buffer = buffers
                        .recv(&worker_cx)
                        .await
                        .map_err(|_| pipeline_closed())?;
                    buffer.resize(wanted, 0);
                    let read_started = Instant::now();
                    let (buffer, read) = file
                        .read_into_vec(buffer)
                        .await
                        .map_err(FileOracleError::SourceIo)?;
                    let read_us = elapsed_us(read_started.elapsed());
                    if read != wanted {
                        return Err(FileOracleError::SourceChanged);
                    }
                    let hash_started = Instant::now();
                    let digest = Digest(*blake3::hash(&buffer[..read]).as_bytes());
                    let hash_us = elapsed_us(hash_started.elapsed());
                    piece_tx
                        .send(
                            &worker_cx,
                            SourcePiece {
                                plan: PiecePlan {
                                    block: BlockId(block),
                                    entry: entry_id,
                                    offset,
                                    length: u32::try_from(read)
                                        .map_err(|_| FileOracleError::LimitExceeded)?,
                                },
                                bytes: buffer,
                                digest,
                                read_us,
                                hash_us,
                            },
                        )
                        .await
                        .map_err(|_| pipeline_closed())?;
                    offset = offset
                        .checked_add(
                            u64::try_from(read).map_err(|_| FileOracleError::LimitExceeded)?,
                        )
                        .ok_or(FileOracleError::LimitExceeded)?;
                    block = block.checked_add(1).ok_or(FileOracleError::LimitExceeded)?;
                }
                let mut trailing = buffers
                    .recv(&worker_cx)
                    .await
                    .map_err(|_| pipeline_closed())?;
                trailing.resize(1, 0);
                let (_, read) = file
                    .read_into_vec(trailing)
                    .await
                    .map_err(FileOracleError::SourceIo)?;
                if read != 0 {
                    return Err(FileOracleError::SourceChanged);
                }
                Ok(())
            })
            .map_err(|_| runtime_unavailable())?;
        Ok(Self {
            pieces,
            recycled,
            worker: Some(worker),
        })
    }

    async fn next(&mut self) -> Result<Option<SourcePiece>, FileOracleError> {
        let cx = Cx::current().ok_or_else(runtime_unavailable)?;
        if let Ok(piece) = self.pieces.recv(&cx).await {
            Ok(Some(piece))
        } else {
            self.finish_inner().await?;
            Ok(None)
        }
    }

    fn recycle(&self, mut bytes: Vec<u8>) {
        bytes.clear();
        let _ = self.recycled.try_send(bytes);
    }

    async fn finish(mut self) -> Result<(), FileOracleError> {
        self.finish_inner().await
    }

    async fn finish_inner(&mut self) -> Result<(), FileOracleError> {
        let Some(mut worker) = self.worker.take() else {
            return Ok(());
        };
        let cx = Cx::current().ok_or_else(runtime_unavailable)?;
        worker.join(&cx).await.map_err(|_| pipeline_closed())?
    }

    async fn abort(&mut self) {
        if let Some(mut worker) = self.worker.take() {
            worker.abort();
            if let Some(cx) = Cx::current() {
                let _ = worker.join(&cx).await;
            }
        }
    }
}

impl ReceivedPieceState {
    fn new(
        manifest: &Manifest,
        ranges: Vec<ResumeRange>,
        existing: BTreeMap<BlockId, Digest>,
    ) -> Result<Self, FileOracleError> {
        let mut graph = ReconstructionGraph::new();
        for plan in &manifest.pieces {
            graph.declare_block(BlockSpec {
                id: plan.block,
                entry: plan.entry,
                offset: plan.offset,
                length: plan.length,
                source_symbols: 1,
            })?;
        }
        Ok(Self {
            graph,
            digests: vec![None; manifest.pieces.len()],
            offered: ranges
                .into_iter()
                .map(|range| (range.start, range))
                .collect(),
            existing,
            completed_bytes: 0,
        })
    }

    fn admit_digest(&mut self, plan: PiecePlan, digest: Digest) -> Result<bool, FileOracleError> {
        let index = usize::try_from(plan.block.0).map_err(|_| FileOracleError::LimitExceeded)?;
        let slot = self
            .digests
            .get_mut(index)
            .ok_or(FileOracleError::UnexpectedRecord)?;
        if let Some(existing) = *slot {
            if existing != digest {
                return Err(FileOracleError::UnexpectedRecord);
            }
            return Ok(false);
        }
        self.graph.advance_rank(plan.block, 1)?;
        self.graph.declare_block_seal(plan.block, digest)?;
        self.graph.verify_block(plan.block, digest)?;
        *slot = Some(digest);
        self.completed_bytes = self
            .completed_bytes
            .checked_add(u64::from(plan.length))
            .ok_or(FileOracleError::LimitExceeded)?;
        Ok(true)
    }
}

impl PieceStaging {
    async fn open(destination: &Path, manifest: &Manifest) -> Result<Self, FileOracleError> {
        let root = &manifest.entries[0];
        if root.kind == SourceKind::File {
            return Ok(Self::File {
                file: Box::new(
                    StagingFile::resume_piecewise(destination, root.length, manifest.object_id)
                        .await?,
                ),
                metadata: root.metadata,
            });
        }
        let mut tree = StagingTree::resume(destination, manifest.object_id).await?;
        let root_path = tree.root().to_owned();
        let mut files = BTreeMap::new();
        let mut metadata = vec![(root_path.clone(), true, root.metadata)];
        for entry in manifest.entries.iter().skip(1) {
            let path = root_path.join(&entry.relative);
            if entry.kind == SourceKind::Directory {
                tree.resume_directory(&path).await?;
                metadata.push((path, true, entry.metadata));
            } else {
                let file = tree.resume_piece_file(&path, entry.length).await?;
                metadata.push((path, false, entry.metadata));
                files.insert(entry.id, file);
            }
        }
        Ok(Self::Tree {
            tree,
            files,
            metadata,
        })
    }

    async fn write(&mut self, plan: PiecePlan, data: &[u8]) -> Result<(), FileOracleError> {
        match self {
            Self::File { file, .. } if plan.entry == EntryId(0) => {
                file.write_at(plan.offset, data).await?;
            }
            Self::Tree { files, .. } => {
                files
                    .get_mut(&plan.entry)
                    .ok_or(FileOracleError::UnexpectedRecord)?
                    .write_at(plan.offset, data)
                    .await?;
            }
            Self::File { .. } => return Err(FileOracleError::UnexpectedRecord),
        }
        Ok(())
    }

    async fn read(&mut self, plan: PiecePlan) -> Result<Vec<u8>, FileOracleError> {
        let length = usize::try_from(plan.length).map_err(|_| FileOracleError::LimitExceeded)?;
        match self {
            Self::File { file, .. } if plan.entry == EntryId(0) => {
                Ok(file.read_at(plan.offset, length).await?)
            }
            Self::Tree { files, .. } => Ok(files
                .get_mut(&plan.entry)
                .ok_or(FileOracleError::UnexpectedRecord)?
                .read_at(plan.offset, length)
                .await?),
            Self::File { .. } => Err(FileOracleError::UnexpectedRecord),
        }
    }

    async fn reset(&mut self) -> Result<(), FileOracleError> {
        match self {
            Self::File { file, .. } => file.reset_piecewise().await?,
            Self::Tree { files, .. } => {
                for file in files.values_mut() {
                    file.reset_piecewise().await?;
                }
            }
        }
        Ok(())
    }

    async fn checkpoint(&mut self) -> Result<(), FileOracleError> {
        match self {
            Self::File { file, .. } => file.checkpoint_piecewise().await?,
            Self::Tree { files, .. } => {
                for file in files.values_mut() {
                    file.checkpoint().await?;
                }
            }
        }
        Ok(())
    }

    async fn retain(self) -> Result<(), FileOracleError> {
        match self {
            Self::File { file, .. } => (*file).retain().await?,
            Self::Tree { tree, .. } => tree.retain()?,
        }
        Ok(())
    }

    async fn commit(
        self,
        digest: Digest,
        length: u64,
    ) -> Result<crate::CommitReceipt, FileOracleError> {
        match self {
            Self::File { file, metadata } => {
                apply_portable_metadata(file.staging_path(), false, metadata).await?;
                Ok((*file).finish_piecewise(digest).await?.commit().await?)
            }
            Self::Tree {
                tree,
                files,
                metadata,
            } => {
                for (_, file) in files {
                    file.finish_piecewise().await?;
                }
                let verified = tree.finish(digest, length).await?;
                for (path, directory, flags) in metadata.into_iter().rev() {
                    apply_portable_metadata(&path, directory, flags).await?;
                }
                Ok(verified.commit().await?)
            }
        }
    }
}

#[allow(clippy::too_many_lines)]
async fn receive_manifest<P: PiecePath>(
    links: &mut P,
    limits: HardLimits,
) -> Result<Manifest, FileOracleError> {
    let mut start = None;
    let mut entries = BTreeMap::new();
    let mut admitted_bytes = 0_u64;
    loop {
        let encoded = links
            .receive_control(MAX_LANE_BYTES, LANE_IDLE_TIMEOUT)
            .await?;
        admitted_bytes = admitted_bytes
            .checked_add(u64::try_from(encoded.len()).map_err(|_| FileOracleError::LimitExceeded)?)
            .ok_or(FileOracleError::LimitExceeded)?;
        if admitted_bytes > limits.max_reconstruction_bytes {
            return Err(FileOracleError::LimitExceeded);
        }
        match decode_piece_record(&encoded, PIECE_BYTES as usize)? {
            PieceRecord::Start {
                object_id,
                entries: declared_entries,
                total_length,
                piece_bytes,
                pieces,
            } => {
                if start.is_some()
                    || declared_entries == 0
                    || declared_entries > limits.max_entries
                    || total_length > limits.max_object_bytes
                    || piece_bytes != PIECE_BYTES
                {
                    return Err(FileOracleError::LimitExceeded);
                }
                admit_piece_state(pieces, limits)?;
                start = Some((object_id, declared_entries, total_length, pieces, encoded));
            }
            PieceRecord::Entry {
                entry,
                parent,
                directory,
                length,
                metadata,
                name,
            } => {
                validate_component(name, limits)?;
                let record = ManifestEntry {
                    id: entry,
                    parent,
                    name: name.to_owned(),
                    relative: PathBuf::new(),
                    kind: if directory {
                        SourceKind::Directory
                    } else {
                        SourceKind::File
                    },
                    length,
                    metadata,
                    encoded,
                };
                if entries.insert(entry, record).is_some()
                    || entries.len() as u64 > limits.max_entries
                {
                    return Err(FileOracleError::UnexpectedRecord);
                }
            }
            _ => return Err(FileOracleError::UnexpectedRecord),
        }
        if let Some((_, declared, _, _, _)) = &start
            && entries.len() as u64 == *declared
        {
            break;
        }
    }
    let (object_id, declared_entries, total_length, declared_pieces, start_encoded) =
        start.ok_or(FileOracleError::UnexpectedRecord)?;
    if entries.len() as u64 != declared_entries {
        return Err(FileOracleError::UnexpectedRecord);
    }
    let mut ordered = Vec::with_capacity(entries.len());
    let mut locations: BTreeMap<EntryId, (PathBuf, u16, u32, bool)> = BTreeMap::new();
    let mut portable = BTreeSet::new();
    let mut observed_length = 0_u64;
    for expected in 0..declared_entries {
        let id = EntryId(expected);
        let mut entry = entries
            .remove(&id)
            .ok_or(FileOracleError::UnexpectedRecord)?;
        if !portable.insert((entry.parent, portable_component_key(&entry.name))) {
            return Err(FileOracleError::InvalidComponent);
        }
        let component = component_bytes(&entry.name)?;
        let (relative, depth, path_bytes) = if id == EntryId(0) {
            if entry.parent.is_some() {
                return Err(FileOracleError::UnexpectedRecord);
            }
            (PathBuf::new(), 1_u16, component)
        } else {
            let parent_id = entry.parent.ok_or(FileOracleError::UnexpectedRecord)?;
            let (parent_path, parent_depth, parent_bytes, directory) = locations
                .get(&parent_id)
                .ok_or(FileOracleError::UnexpectedRecord)?;
            if !*directory {
                return Err(FileOracleError::UnexpectedRecord);
            }
            (
                parent_path.join(&entry.name),
                parent_depth
                    .checked_add(1)
                    .ok_or(FileOracleError::LimitExceeded)?,
                parent_bytes
                    .checked_add(1)
                    .and_then(|value| value.checked_add(component))
                    .ok_or(FileOracleError::LimitExceeded)?,
            )
        };
        if depth > limits.max_depth || path_bytes > limits.max_path_bytes {
            return Err(FileOracleError::LimitExceeded);
        }
        if entry.kind == SourceKind::Directory && entry.length != 0 {
            return Err(FileOracleError::UnexpectedRecord);
        }
        if entry.kind == SourceKind::File {
            observed_length = observed_length
                .checked_add(entry.length)
                .ok_or(FileOracleError::LimitExceeded)?;
        }
        entry.relative.clone_from(&relative);
        locations.insert(
            id,
            (
                relative,
                depth,
                path_bytes,
                entry.kind == SourceKind::Directory,
            ),
        );
        ordered.push(entry);
    }
    if observed_length != total_length {
        return Err(FileOracleError::UnexpectedRecord);
    }
    let pieces = plan_pieces(&ordered)?;
    if pieces.len() as u64 != declared_pieces {
        return Err(FileOracleError::UnexpectedRecord);
    }
    Ok(Manifest {
        object_id,
        entries: ordered,
        total_length,
        pieces,
        start_encoded,
    })
}

#[allow(clippy::too_many_lines)]
async fn receive_pieces<P: PiecePath>(
    links: &mut P,
    manifest: &Manifest,
    staging: &mut PieceStaging,
    state: &mut ReceivedPieceState,
    observer: &dyn TransferObserver,
    timings: &mut PieceTimings,
) -> Result<Digest, FileOracleError> {
    let mut declared_seal = None;
    while declared_seal.is_none() || state.digests.iter().any(Option::is_none) {
        let encoded = links.receive_any(MAX_LANE_BYTES, LANE_IDLE_TIMEOUT).await?;
        match decode_piece_record(&encoded, PIECE_BYTES as usize)? {
            PieceRecord::Piece {
                block,
                entry,
                offset,
                digest,
                data,
            } => {
                let index = usize::try_from(block.0).map_err(|_| FileOracleError::LimitExceeded)?;
                let plan = *manifest
                    .pieces
                    .get(index)
                    .ok_or(FileOracleError::UnexpectedRecord)?;
                let hash_started = Instant::now();
                let observed_digest = Digest(*blake3::hash(data).as_bytes());
                timings.hash_verify_us = timings
                    .hash_verify_us
                    .saturating_add(elapsed_us(hash_started.elapsed()));
                if plan.entry != entry
                    || plan.offset != offset
                    || usize::try_from(plan.length).map_err(|_| FileOracleError::LimitExceeded)?
                        != data.len()
                    || observed_digest != digest
                {
                    return Err(FileOracleError::UnexpectedRecord);
                }
                if state.admit_digest(plan, digest)? {
                    let write_started = Instant::now();
                    staging.write(plan, data).await?;
                    timings.staging_write_us = timings
                        .staging_write_us
                        .saturating_add(elapsed_us(write_started.elapsed()));
                    observer.observe(TransferProgress::Advanced {
                        bytes: state.completed_bytes,
                        total: manifest.total_length,
                    });
                }
            }
            PieceRecord::ResumeDecision { object_id, ranges }
                if object_id == manifest.object_id =>
            {
                for range in ranges {
                    let offered = state
                        .offered
                        .remove(&range.start)
                        .ok_or(FileOracleError::UnexpectedRecord)?;
                    if offered != range {
                        return Err(FileOracleError::UnexpectedRecord);
                    }
                    for offset in 0..range.count {
                        let block = BlockId(range.start.0 + u64::from(offset));
                        let index =
                            usize::try_from(block.0).map_err(|_| FileOracleError::LimitExceeded)?;
                        let plan = *manifest
                            .pieces
                            .get(index)
                            .ok_or(FileOracleError::UnexpectedRecord)?;
                        let digest = state
                            .existing
                            .get(&block)
                            .copied()
                            .ok_or(FileOracleError::UnexpectedRecord)?;
                        if state.admit_digest(plan, digest)? {
                            state.graph.mark_durable(block)?;
                            observer.observe(TransferProgress::Advanced {
                                bytes: state.completed_bytes,
                                total: manifest.total_length,
                            });
                        }
                    }
                }
            }
            PieceRecord::ObjectSeal { digest } => {
                if declared_seal
                    .replace(digest)
                    .is_some_and(|existing| existing != digest)
                {
                    return Err(FileOracleError::UnexpectedRecord);
                }
            }
            PieceRecord::LeaseLiveness { .. } => {}
            _ => return Err(FileOracleError::UnexpectedRecord),
        }
    }
    if state.completed_bytes != manifest.total_length {
        return Err(FileOracleError::UnexpectedRecord);
    }
    let entry_records = manifest
        .entries
        .iter()
        .map(|entry| entry.encoded.clone())
        .collect::<Vec<_>>();
    let mut commitment = object_commitment(&manifest.start_encoded, &entry_records);
    for (plan, digest) in manifest.pieces.iter().zip(&state.digests) {
        update_piece_commitment(
            &mut commitment,
            *plan,
            digest.ok_or(FileOracleError::UnexpectedRecord)?,
        );
    }
    let object_digest = Digest(*commitment.finalize().as_bytes());
    let declared = declared_seal.ok_or(FileOracleError::UnexpectedRecord)?;
    if declared != object_digest {
        return Err(FileOracleError::UnexpectedRecord);
    }
    state.graph.declare_final_seal(declared)?;
    state.graph.verify_final(object_digest)?;
    Ok(object_digest)
}

fn encode_source_entry(entry: &SourceEntry) -> Result<Vec<u8>, FileOracleError> {
    Ok(PieceRecord::Entry {
        entry: entry.id,
        parent: entry.parent,
        directory: entry.kind == SourceKind::Directory,
        length: entry.length,
        metadata: entry.metadata,
        name: &entry.name,
    }
    .encode()?)
}

fn encode_source_piece(piece: &SourcePiece) -> Result<Vec<u8>, FileOracleError> {
    Ok(PieceRecord::Piece {
        block: piece.plan.block,
        entry: piece.plan.entry,
        offset: piece.plan.offset,
        digest: piece.digest,
        data: &piece.bytes,
    }
    .encode()?)
}

fn source_piece_count(entries: &[SourceEntry]) -> Result<u64, FileOracleError> {
    entries.iter().try_fold(0_u64, |total, entry| {
        let pieces = if entry.kind == SourceKind::File {
            entry.length.div_ceil(u64::from(PIECE_BYTES))
        } else {
            0
        };
        total
            .checked_add(pieces)
            .ok_or(FileOracleError::LimitExceeded)
    })
}

fn plan_pieces(entries: &[ManifestEntry]) -> Result<Vec<PiecePlan>, FileOracleError> {
    let pieces = entries.iter().try_fold(0_u64, |total, entry| {
        total
            .checked_add(if entry.kind == SourceKind::File {
                entry.length.div_ceil(u64::from(PIECE_BYTES))
            } else {
                0
            })
            .ok_or(FileOracleError::LimitExceeded)
    })?;
    let capacity = usize::try_from(pieces).map_err(|_| FileOracleError::LimitExceeded)?;
    let mut plans = Vec::with_capacity(capacity);
    let mut block = 0_u64;
    for entry in entries {
        if entry.kind == SourceKind::Directory {
            continue;
        }
        let mut offset = 0_u64;
        while offset < entry.length {
            let length = u32::try_from((entry.length - offset).min(u64::from(PIECE_BYTES)))
                .map_err(|_| FileOracleError::LimitExceeded)?;
            plans.push(PiecePlan {
                block: BlockId(block),
                entry: entry.id,
                offset,
                length,
            });
            block = block.checked_add(1).ok_or(FileOracleError::LimitExceeded)?;
            offset = offset
                .checked_add(u64::from(length))
                .ok_or(FileOracleError::LimitExceeded)?;
        }
    }
    Ok(plans)
}

fn admit_piece_state(pieces: u64, limits: HardLimits) -> Result<(), FileOracleError> {
    let bytes = pieces
        .checked_mul(PIECE_STATE_BYTES)
        .ok_or(FileOracleError::LimitExceeded)?;
    if bytes > limits.max_reconstruction_bytes || usize::try_from(pieces).is_err() {
        return Err(FileOracleError::LimitExceeded);
    }
    Ok(())
}

fn piece_object_id(
    entries: &[SourceEntry],
    total_length: u64,
    pieces: u64,
    token: &ResumeToken,
) -> Result<[u8; 16], FileOracleError> {
    let mut hasher = blake3::Hasher::new_keyed(&token.0);
    hasher.update(b"RIFT live piece object v2\0");
    hasher.update(&total_length.to_be_bytes());
    hasher.update(&pieces.to_be_bytes());
    hasher.update(&PIECE_BYTES.to_be_bytes());
    for entry in entries {
        let encoded = encode_source_entry(entry)?;
        hasher.update(&(encoded.len() as u64).to_be_bytes());
        hasher.update(&encoded);
    }
    let mut id = [0; 16];
    id.copy_from_slice(&hasher.finalize().as_bytes()[..16]);
    Ok(id)
}

fn object_commitment(start: &[u8], entries: &[Vec<u8>]) -> blake3::Hasher {
    let mut hasher = blake3::Hasher::new_derive_key("RIFT authenticated piece object v2");
    update_framed(&mut hasher, start);
    for entry in entries {
        update_framed(&mut hasher, entry);
    }
    hasher
}

fn range_commitment() -> blake3::Hasher {
    blake3::Hasher::new_derive_key("RIFT sparse durable range v1")
}

fn update_piece_commitment(hasher: &mut blake3::Hasher, plan: PiecePlan, digest: Digest) {
    hasher.update(b"piece\0");
    hasher.update(&plan.block.0.to_be_bytes());
    hasher.update(&plan.entry.0.to_be_bytes());
    hasher.update(&plan.offset.to_be_bytes());
    hasher.update(&plan.length.to_be_bytes());
    hasher.update(&digest.0);
}

fn update_framed(hasher: &mut blake3::Hasher, bytes: &[u8]) {
    hasher.update(&(bytes.len() as u64).to_be_bytes());
    hasher.update(bytes);
}

fn validate_resume_offer(
    ranges: &[ResumeRange],
    pieces: u64,
) -> Result<Vec<ResumeRange>, FileOracleError> {
    for range in ranges {
        if range.count > MAX_RESUME_RANGE_PIECES
            || range
                .start
                .0
                .checked_add(u64::from(range.count))
                .is_none_or(|end| end > pieces)
        {
            return Err(FileOracleError::UnexpectedRecord);
        }
    }
    Ok(ranges.to_vec())
}

fn journal_ranges(entries: &[JournalPiece]) -> (Vec<ResumeRange>, BTreeMap<BlockId, Digest>) {
    let existing = entries
        .iter()
        .map(|entry| (entry.plan.block, entry.digest))
        .collect::<BTreeMap<_, _>>();
    let mut ranges = Vec::new();
    let mut index = 0;
    while index < entries.len() {
        let start = index;
        let mut count = 1_usize;
        while start + count < entries.len()
            && count < MAX_RESUME_RANGE_PIECES as usize
            && entries[start + count - 1].plan.block.0 + 1 == entries[start + count].plan.block.0
            && entries[start + count - 1].plan.entry == entries[start + count].plan.entry
        {
            count += 1;
        }
        let mut hasher = range_commitment();
        for entry in &entries[start..start + count] {
            update_piece_commitment(&mut hasher, entry.plan, entry.digest);
        }
        ranges.push(ResumeRange {
            start: entries[start].plan.block,
            count: u32::try_from(count).expect("resume range is protocol-bounded"),
            commitment: Digest(*hasher.finalize().as_bytes()),
        });
        index = start + count;
    }
    (ranges, existing)
}

fn journal_path(destination: &Path, object_id: [u8; 16]) -> Result<PathBuf, FileOracleError> {
    let parent = destination.parent().unwrap_or_else(|| Path::new("."));
    let name = destination
        .file_name()
        .ok_or(FileOracleError::InvalidComponent)?;
    let mut state = OsString::from(".");
    state.push(name);
    state.push(".rift-");
    for byte in object_id {
        state.push(format!("{byte:02x}"));
    }
    state.push(".pieces");
    Ok(parent.join(state))
}

async fn load_and_reverify_journal(
    path: &Path,
    manifest: &Manifest,
    staging: &mut PieceStaging,
) -> Result<Vec<JournalPiece>, FileOracleError> {
    if !fs::try_exists(path).await.map_err(stage_io)? {
        return Ok(Vec::new());
    }
    let encoded = fs::read(path).await.map_err(stage_io)?;
    let parsed = decode_journal(&encoded, manifest);
    let Ok(entries) = parsed else {
        staging.reset().await?;
        remove_journal(path).await?;
        return Ok(Vec::new());
    };
    let mut valid = Vec::new();
    for entry in entries {
        let bytes = staging.read(entry.plan).await?;
        if Digest(*blake3::hash(&bytes).as_bytes()) == entry.digest {
            valid.push(entry);
        }
    }
    Ok(valid)
}

fn decode_journal(
    encoded: &[u8],
    manifest: &Manifest,
) -> Result<Vec<JournalPiece>, FileOracleError> {
    if encoded.len() < JOURNAL_HEADER_BYTES
        || encoded[..4] != JOURNAL_MAGIC
        || encoded[4] != JOURNAL_VERSION
        || encoded[5..8] != [0; 3]
        || encoded[8..24] != manifest.object_id
    {
        return Err(FileOracleError::UnexpectedRecord);
    }
    let count = u64::from_be_bytes(
        encoded[24..32]
            .try_into()
            .map_err(|_| FileOracleError::UnexpectedRecord)?,
    );
    let count = usize::try_from(count).map_err(|_| FileOracleError::LimitExceeded)?;
    let expected = JOURNAL_HEADER_BYTES
        .checked_add(
            count
                .checked_mul(JOURNAL_ENTRY_BYTES)
                .ok_or(FileOracleError::LimitExceeded)?,
        )
        .ok_or(FileOracleError::LimitExceeded)?;
    if encoded.len() != expected || count > manifest.pieces.len() {
        return Err(FileOracleError::UnexpectedRecord);
    }
    let mut entries = Vec::with_capacity(count);
    let mut previous = None;
    for index in 0..count {
        let offset = JOURNAL_HEADER_BYTES + index * JOURNAL_ENTRY_BYTES;
        let block = BlockId(read_u64(encoded, offset)?);
        let plan_index = usize::try_from(block.0).map_err(|_| FileOracleError::LimitExceeded)?;
        let plan = *manifest
            .pieces
            .get(plan_index)
            .ok_or(FileOracleError::UnexpectedRecord)?;
        if previous.is_some_and(|id: BlockId| id >= block)
            || plan.entry.0 != read_u64(encoded, offset + 8)?
            || plan.offset != read_u64(encoded, offset + 16)?
            || plan.length != read_u32(encoded, offset + 24)?
        {
            return Err(FileOracleError::UnexpectedRecord);
        }
        let mut digest = [0; 32];
        digest.copy_from_slice(&encoded[offset + 28..offset + 60]);
        entries.push(JournalPiece {
            plan,
            digest: Digest(digest),
        });
        previous = Some(block);
    }
    Ok(entries)
}

async fn write_journal(
    path: &Path,
    object_id: [u8; 16],
    manifest: &Manifest,
    state: &ReceivedPieceState,
) -> Result<(), FileOracleError> {
    let mut encoded = Vec::with_capacity(
        JOURNAL_HEADER_BYTES + state.digests.len().saturating_mul(JOURNAL_ENTRY_BYTES),
    );
    encoded.extend_from_slice(&JOURNAL_MAGIC);
    encoded.push(JOURNAL_VERSION);
    encoded.extend_from_slice(&[0; 3]);
    encoded.extend_from_slice(&object_id);
    let count = state
        .digests
        .iter()
        .filter(|digest| digest.is_some())
        .count();
    encoded.extend_from_slice(&(count as u64).to_be_bytes());
    for (plan, digest) in manifest.pieces.iter().zip(&state.digests) {
        let Some(digest) = digest else {
            continue;
        };
        encoded.extend_from_slice(&plan.block.0.to_be_bytes());
        encoded.extend_from_slice(&plan.entry.0.to_be_bytes());
        encoded.extend_from_slice(&plan.offset.to_be_bytes());
        encoded.extend_from_slice(&plan.length.to_be_bytes());
        encoded.extend_from_slice(&digest.0);
    }
    let mut file = File::create(path).await.map_err(stage_io)?;
    file.write_all(&encoded).await.map_err(stage_io)?;
    file.sync_all().await.map_err(stage_io)?;
    Ok(())
}

async fn remove_journal(path: &Path) -> Result<(), FileOracleError> {
    match fs::remove_file(path).await {
        Ok(()) => Ok(()),
        Err(error) if error.kind() == io::ErrorKind::NotFound => Ok(()),
        Err(error) => Err(stage_io(error)),
    }
}

fn read_u64(encoded: &[u8], offset: usize) -> Result<u64, FileOracleError> {
    Ok(u64::from_be_bytes(
        encoded
            .get(offset..offset + 8)
            .and_then(|bytes| bytes.try_into().ok())
            .ok_or(FileOracleError::UnexpectedRecord)?,
    ))
}

fn read_u32(encoded: &[u8], offset: usize) -> Result<u32, FileOracleError> {
    Ok(u32::from_be_bytes(
        encoded
            .get(offset..offset + 4)
            .and_then(|bytes| bytes.try_into().ok())
            .ok_or(FileOracleError::UnexpectedRecord)?,
    ))
}

fn runtime_unavailable() -> FileOracleError {
    FileOracleError::SourceIo(io::Error::other("piece pipeline runtime unavailable"))
}

fn pipeline_closed() -> FileOracleError {
    FileOracleError::SourceIo(io::Error::new(
        io::ErrorKind::BrokenPipe,
        "piece pipeline closed",
    ))
}

fn stage_io(error: io::Error) -> FileOracleError {
    FileOracleError::Stage(crate::StageError::Io(error))
}

fn elapsed_us(duration: Duration) -> u64 {
    u64::try_from(duration.as_micros()).unwrap_or(u64::MAX)
}

#[cfg(test)]
mod tests {
    use asupersync::{cx::Cx, net::UdpSocket, runtime::RuntimeBuilder};
    use rift_transport::QuicServerIdentity;
    use tempfile::tempdir;

    use super::*;
    use crate::{
        DirectQuicLink,
        path_pool::{CarrierKind, QuicPathPool},
    };

    #[test]
    fn piece_engine_commits_a_reordered_file_exactly() {
        let directory = tempdir().unwrap();
        let source = directory.path().join("source.bin");
        let destination = directory.path().join("received.bin");
        let contents = (0..3 * PIECE_BYTES as usize + 17)
            .map(|index| u8::try_from(index % 251).unwrap())
            .collect::<Vec<_>>();
        std::fs::write(&source, &contents).unwrap();
        let runtime = RuntimeBuilder::new().worker_threads(4).build().unwrap();
        let (send, receive) = runtime.block_on(async move {
            let receiver_socket = UdpSocket::bind("127.0.0.1:0").await.unwrap();
            let receiver_address = receiver_socket.local_addr().unwrap();
            let sender_socket = UdpSocket::bind("127.0.0.1:0").await.unwrap();
            let sender_address = sender_socket.local_addr().unwrap();
            let identity = QuicServerIdentity::generate().unwrap();
            let certificate = identity.certificate();
            let receiver = DirectQuicLink::listen(receiver_socket, sender_address, &identity);
            let sender =
                DirectQuicLink::connect(sender_socket, receiver_address, &certificate).unwrap();
            let mut receiver = QuicPathPool::new(vec![(CarrierKind::Direct, receiver)]);
            let mut sender = QuicPathPool::new(vec![(CarrierKind::Direct, sender)]);
            let token = ResumeToken::generate().unwrap();
            let cx = Cx::current().unwrap();
            let mut receive_task = cx
                .spawn(move |_cx| async move {
                    receive_object_piecewise(
                        &mut receiver,
                        ReceiveTarget::Exact(destination),
                        HardLimits::CONSERVATIVE,
                        &crate::file_oracle::NoopObserver,
                    )
                    .await
                })
                .unwrap();
            let send = send_object_piecewise(
                &mut sender,
                &source,
                HardLimits::CONSERVATIVE,
                &crate::file_oracle::NoopObserver,
                &token,
            )
            .await
            .unwrap();
            let receive = receive_task.join(&cx).await.unwrap().unwrap();
            (send, receive)
        });
        assert_eq!(send.digest, receive.digest);
        assert_eq!(receive.receipt, ReceiptDelivery::Sent);
        assert!(
            send.profile.elapsed_us < 5_000_000 && receive.profile.elapsed_us < 5_000_000,
            "unexpected file-transfer tail: send={:?} receive={:?}",
            send.profile,
            receive.profile
        );
        assert_eq!(send.blocks, 4);
        let received = std::fs::read(directory.path().join("received.bin")).unwrap();
        assert_eq!(received.len(), contents.len());
        assert_eq!(blake3::hash(&received), blake3::hash(&contents));
    }

    #[test]
    fn range_commitments_change_with_geometry_not_only_payload_digest() {
        let digest = Digest([7; 32]);
        let mut left = range_commitment();
        update_piece_commitment(
            &mut left,
            PiecePlan {
                block: BlockId(0),
                entry: EntryId(0),
                offset: 0,
                length: 3,
            },
            digest,
        );
        let mut right = range_commitment();
        update_piece_commitment(
            &mut right,
            PiecePlan {
                block: BlockId(0),
                entry: EntryId(0),
                offset: 1,
                length: 3,
            },
            digest,
        );
        assert_ne!(left.finalize(), right.finalize());
    }

    #[test]
    fn proved_independent_connection_earns_piece_work() {
        let directory = tempdir().unwrap();
        let source = directory.path().join("source-pool.bin");
        let destination = directory.path().join("received-pool.bin");
        let contents = (0..70 * PIECE_BYTES as usize + 31)
            .map(|index| u8::try_from(index % 239).unwrap())
            .collect::<Vec<_>>();
        std::fs::write(&source, &contents).unwrap();
        let runtime = RuntimeBuilder::new().worker_threads(4).build().unwrap();
        let (send, receive, used_paths) = runtime.block_on(async move {
            let identity = QuicServerIdentity::generate().unwrap();
            let certificate = identity.certificate();

            let receiver_socket_a = UdpSocket::bind("127.0.0.1:0").await.unwrap();
            let receiver_address_a = receiver_socket_a.local_addr().unwrap();
            let sender_socket_a = UdpSocket::bind("127.0.0.1:0").await.unwrap();
            let sender_address_a = sender_socket_a.local_addr().unwrap();
            let receiver_a = DirectQuicLink::listen(receiver_socket_a, sender_address_a, &identity);
            let sender_a =
                DirectQuicLink::connect(sender_socket_a, receiver_address_a, &certificate).unwrap();

            let receiver_socket_b = UdpSocket::bind("127.0.0.1:0").await.unwrap();
            let receiver_address_b = receiver_socket_b.local_addr().unwrap();
            let sender_socket_b = UdpSocket::bind("127.0.0.1:0").await.unwrap();
            let sender_address_b = sender_socket_b.local_addr().unwrap();
            let receiver_b = DirectQuicLink::listen(receiver_socket_b, sender_address_b, &identity);
            let sender_b =
                DirectQuicLink::connect(sender_socket_b, receiver_address_b, &certificate).unwrap();

            let mut receiver = QuicPathPool::new(vec![
                (CarrierKind::Direct, receiver_a),
                (CarrierKind::TurnUdp, receiver_b),
            ]);
            let mut sender = QuicPathPool::new(vec![
                (CarrierKind::Direct, sender_a),
                (CarrierKind::TurnUdp, sender_b),
            ]);
            sender.mark_test_paths_independent();
            let token = ResumeToken::generate().unwrap();
            let cx = Cx::current().unwrap();
            let mut receive_task = cx
                .spawn(move |_cx| async move {
                    receive_object_piecewise(
                        &mut receiver,
                        ReceiveTarget::Exact(destination),
                        HardLimits::CONSERVATIVE,
                        &crate::file_oracle::NoopObserver,
                    )
                    .await
                })
                .unwrap();
            let send = send_object_piecewise(
                &mut sender,
                &source,
                HardLimits::CONSERVATIVE,
                &crate::file_oracle::NoopObserver,
                &token,
            )
            .await;
            let used_paths = sender.used_piece_paths();
            let receive = receive_task.join(&cx).await.unwrap();
            (send, receive, used_paths)
        });
        assert!(send.is_ok(), "send={send:?} receive={receive:?}");
        assert!(receive.is_ok(), "send={send:?} receive={receive:?}");
        let send = send.unwrap();
        let receive = receive.unwrap();
        assert_eq!(send.digest, receive.digest);
        assert_eq!(send.transport, crate::TransferTransport::PathPoolQuic);
        assert_eq!(receive.transport, crate::TransferTransport::PathPoolQuic);
        assert_eq!(receive.receipt, ReceiptDelivery::Sent);
        assert_eq!(used_paths, 2);
        let received = std::fs::read(directory.path().join("received-pool.bin")).unwrap();
        assert_eq!(blake3::hash(&received), blake3::hash(&contents));
    }

    #[test]
    fn sparse_journal_reuses_only_locally_reverified_pieces() {
        let directory = tempdir().unwrap();
        let destination = directory.path().join("resume.bin");
        let journal = directory.path().join("resume.pieces");
        let runtime = RuntimeBuilder::new().worker_threads(2).build().unwrap();
        runtime.block_on(async move {
            let object_id = [7; 16];
            let entry = ManifestEntry {
                id: EntryId(0),
                parent: None,
                name: "resume.bin".to_owned(),
                relative: PathBuf::new(),
                kind: SourceKind::File,
                length: u64::from(PIECE_BYTES) * 3,
                metadata: 0,
                encoded: Vec::new(),
            };
            let manifest = Manifest {
                object_id,
                entries: vec![entry],
                total_length: u64::from(PIECE_BYTES) * 3,
                pieces: vec![
                    PiecePlan {
                        block: BlockId(0),
                        entry: EntryId(0),
                        offset: 0,
                        length: PIECE_BYTES,
                    },
                    PiecePlan {
                        block: BlockId(1),
                        entry: EntryId(0),
                        offset: u64::from(PIECE_BYTES),
                        length: PIECE_BYTES,
                    },
                    PiecePlan {
                        block: BlockId(2),
                        entry: EntryId(0),
                        offset: u64::from(PIECE_BYTES) * 2,
                        length: PIECE_BYTES,
                    },
                ],
                start_encoded: Vec::new(),
            };
            let mut staging = PieceStaging::open(&destination, &manifest).await.unwrap();
            let mut state =
                ReceivedPieceState::new(&manifest, Vec::new(), BTreeMap::new()).unwrap();
            for (block, byte) in [(0_u64, 3_u8), (2, 9)] {
                let plan = manifest.pieces[usize::try_from(block).unwrap()];
                let data = vec![byte; PIECE_BYTES as usize];
                let digest = Digest(*blake3::hash(&data).as_bytes());
                staging.write(plan, &data).await.unwrap();
                state.admit_digest(plan, digest).unwrap();
            }
            staging.checkpoint().await.unwrap();
            write_journal(&journal, object_id, &manifest, &state)
                .await
                .unwrap();
            staging.retain().await.unwrap();

            let mut reopened = PieceStaging::open(&destination, &manifest).await.unwrap();
            let valid = load_and_reverify_journal(&journal, &manifest, &mut reopened)
                .await
                .unwrap();
            assert_eq!(
                valid
                    .iter()
                    .map(|piece| piece.plan.block)
                    .collect::<Vec<_>>(),
                vec![BlockId(0), BlockId(2)]
            );

            reopened
                .write(manifest.pieces[2], &vec![0; PIECE_BYTES as usize])
                .await
                .unwrap();
            reopened.checkpoint().await.unwrap();
            let reverified = load_and_reverify_journal(&journal, &manifest, &mut reopened)
                .await
                .unwrap();
            assert_eq!(
                reverified
                    .iter()
                    .map(|piece| piece.plan.block)
                    .collect::<Vec<_>>(),
                vec![BlockId(0)]
            );
        });
    }

    #[test]
    #[allow(clippy::too_many_lines)]
    fn accepted_resume_range_larger_than_source_arena_cannot_stall() {
        let directory = tempdir().unwrap();
        let source = directory.path().join("resume-source.bin");
        let destination = directory.path().join("resume-destination.bin");
        let contents = (0..(SOURCE_PREFETCH_PIECES + 4) * PIECE_BYTES as usize)
            .map(|index| u8::try_from(index % 233).unwrap())
            .collect::<Vec<_>>();
        let expected = contents.clone();
        std::fs::write(&source, &contents).unwrap();
        let runtime = RuntimeBuilder::new().worker_threads(4).build().unwrap();
        let (send, receive) = runtime.block_on(async move {
            let token = ResumeToken::generate().unwrap();
            let scanned = scan_source(&source, HardLimits::CONSERVATIVE)
                .await
                .unwrap();
            let piece_count = source_piece_count(&scanned.entries).unwrap();
            let object_id =
                piece_object_id(&scanned.entries, scanned.total_length, piece_count, &token)
                    .unwrap();
            let entries = scanned
                .entries
                .iter()
                .map(|entry| ManifestEntry {
                    id: entry.id,
                    parent: entry.parent,
                    name: entry.name.clone(),
                    relative: PathBuf::new(),
                    kind: entry.kind,
                    length: entry.length,
                    metadata: entry.metadata,
                    encoded: encode_source_entry(entry).unwrap(),
                })
                .collect::<Vec<_>>();
            let manifest = Manifest {
                object_id,
                total_length: scanned.total_length,
                pieces: plan_pieces(&entries).unwrap(),
                start_encoded: PieceRecord::Start {
                    object_id,
                    entries: entries.len() as u64,
                    total_length: scanned.total_length,
                    piece_bytes: PIECE_BYTES,
                    pieces: piece_count,
                }
                .encode()
                .unwrap(),
                entries,
            };
            let mut staging = PieceStaging::open(&destination, &manifest).await.unwrap();
            let mut state =
                ReceivedPieceState::new(&manifest, Vec::new(), BTreeMap::new()).unwrap();
            for plan in &manifest.pieces {
                let start = usize::try_from(plan.offset).unwrap();
                let end = start + usize::try_from(plan.length).unwrap();
                let bytes = &contents[start..end];
                let digest = Digest(*blake3::hash(bytes).as_bytes());
                staging.write(*plan, bytes).await.unwrap();
                state.admit_digest(*plan, digest).unwrap();
            }
            staging.checkpoint().await.unwrap();
            let journal = journal_path(&destination, object_id).unwrap();
            write_journal(&journal, object_id, &manifest, &state)
                .await
                .unwrap();
            staging.retain().await.unwrap();

            let receiver_socket = UdpSocket::bind("127.0.0.1:0").await.unwrap();
            let receiver_address = receiver_socket.local_addr().unwrap();
            let sender_socket = UdpSocket::bind("127.0.0.1:0").await.unwrap();
            let sender_address = sender_socket.local_addr().unwrap();
            let identity = QuicServerIdentity::generate().unwrap();
            let certificate = identity.certificate();
            let receiver = DirectQuicLink::listen(receiver_socket, sender_address, &identity);
            let sender =
                DirectQuicLink::connect(sender_socket, receiver_address, &certificate).unwrap();
            let mut receiver = QuicPathPool::new(vec![(CarrierKind::Direct, receiver)]);
            let mut sender = QuicPathPool::new(vec![(CarrierKind::Direct, sender)]);
            let cx = Cx::current().unwrap();
            let mut receive_task = cx
                .spawn(move |_cx| async move {
                    receive_object_piecewise(
                        &mut receiver,
                        ReceiveTarget::Exact(destination),
                        HardLimits::CONSERVATIVE,
                        &crate::file_oracle::NoopObserver,
                    )
                    .await
                })
                .unwrap();
            let send = send_object_piecewise(
                &mut sender,
                &source,
                HardLimits::CONSERVATIVE,
                &crate::file_oracle::NoopObserver,
                &token,
            )
            .await
            .unwrap();
            let receive = receive_task.join(&cx).await.unwrap().unwrap();
            (send, receive)
        });
        assert_eq!(send.digest, receive.digest);
        assert_eq!(receive.receipt, ReceiptDelivery::Sent);
        assert_eq!(send.blocks, (SOURCE_PREFETCH_PIECES + 4) as u64);
        assert!(send.profile.elapsed_us < 5_000_000);
        assert_eq!(
            std::fs::read(directory.path().join("resume-destination.bin")).unwrap(),
            expected
        );
    }

    #[test]
    fn piece_engine_commits_a_tree_as_one_visibility_unit() {
        let directory = tempdir().unwrap();
        let source = directory.path().join("tree-source");
        let destination = directory.path().join("tree-received");
        std::fs::create_dir(&source).unwrap();
        std::fs::create_dir(source.join("nested")).unwrap();
        std::fs::write(source.join("empty.txt"), []).unwrap();
        std::fs::write(
            source.join("nested/data.bin"),
            vec![5; PIECE_BYTES as usize + 7],
        )
        .unwrap();
        let runtime = RuntimeBuilder::new().worker_threads(4).build().unwrap();
        let (send, receive) = runtime.block_on(async move {
            let receiver_socket = UdpSocket::bind("127.0.0.1:0").await.unwrap();
            let receiver_address = receiver_socket.local_addr().unwrap();
            let sender_socket = UdpSocket::bind("127.0.0.1:0").await.unwrap();
            let sender_address = sender_socket.local_addr().unwrap();
            let identity = QuicServerIdentity::generate().unwrap();
            let certificate = identity.certificate();
            let receiver = DirectQuicLink::listen(receiver_socket, sender_address, &identity);
            let sender =
                DirectQuicLink::connect(sender_socket, receiver_address, &certificate).unwrap();
            let mut receiver = QuicPathPool::new(vec![(CarrierKind::Direct, receiver)]);
            let mut sender = QuicPathPool::new(vec![(CarrierKind::Direct, sender)]);
            let token = ResumeToken::generate().unwrap();
            let cx = Cx::current().unwrap();
            let mut receive_task = cx
                .spawn(move |_cx| async move {
                    receive_object_piecewise(
                        &mut receiver,
                        ReceiveTarget::Exact(destination),
                        HardLimits::CONSERVATIVE,
                        &crate::file_oracle::NoopObserver,
                    )
                    .await
                })
                .unwrap();
            let send = send_object_piecewise(
                &mut sender,
                &source,
                HardLimits::CONSERVATIVE,
                &crate::file_oracle::NoopObserver,
                &token,
            )
            .await
            .unwrap();
            let receive = receive_task.join(&cx).await.unwrap().unwrap();
            (send, receive)
        });
        assert_eq!(send.digest, receive.digest);
        assert_eq!(receive.receipt, ReceiptDelivery::Sent);
        assert!(
            send.profile.elapsed_us < 5_000_000 && receive.profile.elapsed_us < 5_000_000,
            "unexpected tree-transfer tail: send={:?} receive={:?}",
            send.profile,
            receive.profile
        );
        assert_eq!(
            std::fs::read(directory.path().join("tree-received/empty.txt")).unwrap(),
            Vec::<u8>::new()
        );
        assert_eq!(
            std::fs::read(directory.path().join("tree-received/nested/data.bin")).unwrap(),
            vec![5; PIECE_BYTES as usize + 7]
        );
    }
}
