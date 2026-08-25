//! Authenticated, bounded file-or-directory object transfer over one record path.

use std::{
    collections::{BTreeMap, BTreeSet},
    ffi::OsStr,
    io,
    io::SeekFrom,
    path::{Path, PathBuf},
    time::Duration,
};

use asupersync::{
    channel::mpsc,
    cx::Cx,
    fs::{self, File},
    io::{AsyncRead, AsyncWrite},
    runtime::TaskHandle,
};
use rift_core::{BlockId, BlockSpec, Digest, EntryId, GraphError, ReconstructionGraph};
use rift_protocol::{
    DirectProtocolError, HardLimits, MAX_STREAM_BLOCK_BYTES, MAX_STREAM_COMPONENT_BYTES,
    PieceRecordError, STREAM_BLOCK_BYTES, StreamRecord, StreamRecordError, decode_stream_record,
};
use thiserror::Error;
use unicode_normalization::UnicodeNormalization;
use zeroize::{Zeroize, ZeroizeOnDrop};

use crate::{
    CommitError, DirectQuicLink, DirectQuicLinkError, DirectRecordError, MigrationReport,
    SecureStream, SecureStreamError, StageError, StagingFile, StagingTree, TransferTransport,
    stream_crypto::MAX_STREAM_PLAINTEXT,
};

const UNIX_MODE: u16 = 0x8000;
const PORTABLE_READONLY: u16 = 0x0001;
const PORTABLE_EXECUTABLE: u16 = 0x0002;
const METADATA_ENTRY_OVERHEAD: u64 = 256;
const DEFAULT_QUIC_IDLE_TIMEOUT: Duration = Duration::from_secs(30);
const SOURCE_PREFETCH_BLOCKS: usize = 16;

/// High-entropy identity retained only while one live transfer retries.
#[derive(Zeroize, ZeroizeOnDrop)]
pub(crate) struct ResumeToken(pub(crate) [u8; 32]);

impl ResumeToken {
    pub(crate) fn generate() -> Result<Self, FileOracleError> {
        let mut token = [0_u8; 32];
        getrandom::fill(&mut token).map_err(|_| FileOracleError::EntropyUnavailable)?;
        Ok(Self(token))
    }
}

/// Sender's authenticated view of a completed receiver commit.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct SendSummary {
    /// Logical regular-file bytes read and committed.
    pub length: u64,
    /// Complete authenticated object-graph digest.
    pub digest: Digest,
    /// Number of source blocks.
    pub blocks: u64,
    /// Number of filesystem entries.
    pub entries: u64,
    /// Authenticated carrier that moved the committed object payload.
    pub transport: TransferTransport,
    /// Relay/direct decision evidence when migration was active.
    pub migration: Option<MigrationReport>,
    /// Bounded end-to-end measurement spine for this completed transfer.
    pub profile: TransferProfile,
}

/// Whether the receiver could acknowledge an already-completed commit.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ReceiptDelivery {
    /// Sender accepted the authenticated receipt.
    Sent,
    /// Destination is committed but the path died before receipt delivery.
    Failed,
}

/// Receiver's truthful local outcome.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ReceiveSummary {
    /// Logical regular-file bytes committed.
    pub length: u64,
    /// Complete authenticated object-graph digest.
    pub digest: Digest,
    /// Number of verified source blocks.
    pub blocks: u64,
    /// Number of committed filesystem entries.
    pub entries: u64,
    /// Authenticated carrier that moved the committed object payload.
    pub transport: TransferTransport,
    /// Exact local root path installed at the atomic visibility boundary.
    pub destination: PathBuf,
    /// Receipt delivery is deliberately separate from local commit truth.
    pub receipt: ReceiptDelivery,
    /// Relay/direct decision evidence when migration was active.
    pub migration: Option<MigrationReport>,
    /// Bounded end-to-end measurement spine for this completed transfer.
    pub profile: TransferProfile,
}

/// Cumulative stage and carrier evidence for one completed endpoint role.
///
/// Durations are intentionally integral microseconds. They are diagnostic
/// evidence, never commit authority or a source of nondeterministic protocol
/// behavior.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct TransferProfile {
    /// Wall time from admitted object to authenticated completion.
    pub elapsed_us: u64,
    /// Source filesystem discovery and metadata admission.
    pub source_scan_us: u64,
    /// Source payload reads.
    pub source_read_us: u64,
    /// Piece hashing or receiver-side digest verification.
    pub hash_verify_us: u64,
    /// Application time spent admitting records to path queues.
    pub path_queue_us: u64,
    /// QUIC packet protection and protocol-machine CPU time.
    pub quic_cpu_us: u64,
    /// Awaited concrete socket I/O time.
    pub socket_io_us: u64,
    /// Out-of-order staging writes.
    pub staging_write_us: u64,
    /// Durable flush, final verification, and atomic visibility.
    pub durable_commit_us: u64,
    /// Number of independently congestion-controlled authenticated paths.
    pub authenticated_paths: u16,
    /// Authenticated paths that actually carried object pieces.
    pub payload_paths: u16,
    /// UDP or TURN-carried QUIC bytes emitted on the wire.
    pub wire_sent_bytes: u64,
    /// UDP or TURN-carried QUIC bytes accepted from the wire.
    pub wire_received_bytes: u64,
    /// Bytes QUIC declared lost.
    pub lost_bytes: u64,
}

/// Low-frequency, non-authoritative progress evidence for user interfaces.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum TransferProgress {
    /// The peer authenticated successfully; candidate paths are being measured.
    PeerReady,
    /// The authenticated path portfolio selected for this attempt.
    RouteSelected {
        /// Initial control and payload carrier.
        primary: TransferTransport,
        /// Mutually authenticated carriers available to the controller.
        candidates: u16,
    },
    /// A failed accelerated attempt will resume over the secure relay.
    Recovering,
    /// Immutable object geometry passed admission checks.
    Declared {
        /// Total regular-file bytes.
        bytes: u64,
        /// Total filesystem entries.
        entries: u64,
    },
    /// This many authenticated regular-file bytes crossed the object oracle.
    Advanced {
        /// Completed logical bytes.
        bytes: u64,
        /// Immutable total logical bytes.
        total: u64,
    },
}

/// Read-only observation hook. It cannot influence transfer policy or truth.
pub trait TransferObserver: Send + Sync {
    /// Observe one monotonic event. Implementations should return quickly.
    fn observe(&self, event: TransferProgress);
}

pub(crate) struct NoopObserver;

impl TransferObserver for NoopObserver {
    fn observe(&self, _event: TransferProgress) {}
}

/// Receiver-selected placement policy for one authenticated root entry.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum ReceiveTarget {
    /// Commit at this exact absent path, regardless of the sender's root name.
    Exact(PathBuf),
    /// Preserve the authenticated root name beneath this existing directory.
    Directory(PathBuf),
}

impl ReceiveTarget {
    pub(crate) async fn resolve(
        &self,
        root_name: &str,
        directory: bool,
    ) -> Result<PathBuf, FileOracleError> {
        match self {
            Self::Exact(path) => Ok(path.clone()),
            Self::Directory(parent) => {
                let original = parent.join(root_name);
                if !fs::try_exists(&original).await.map_err(StageError::Io)? {
                    return Ok(original);
                }
                for suffix in 1_u32..=10_000 {
                    let name = numbered_destination_name(root_name, directory, suffix);
                    let candidate = parent.join(name);
                    if !fs::try_exists(&candidate).await.map_err(StageError::Io)? {
                        return Ok(candidate);
                    }
                }
                Err(FileOracleError::Stage(StageError::Io(io::Error::new(
                    io::ErrorKind::AlreadyExists,
                    "could not choose an unused destination name",
                ))))
            }
        }
    }
}

fn numbered_destination_name(root_name: &str, directory: bool, suffix: u32) -> String {
    if directory {
        return format!("{root_name} ({suffix})");
    }
    let path = Path::new(root_name);
    match (
        path.file_stem().and_then(OsStr::to_str),
        path.extension().and_then(OsStr::to_str),
    ) {
        (Some(stem), Some(extension)) if !extension.is_empty() => {
            format!("{stem} ({suffix}).{extension}")
        }
        _ => format!("{root_name} ({suffix})"),
    }
}

/// Object-transfer failure.
#[derive(Debug, Error)]
pub enum FileOracleError {
    /// Source I/O failed or changed after its immutable declaration.
    #[error("source object I/O failed: {0}")]
    SourceIo(#[source] io::Error),
    /// Secure object identity entropy was unavailable.
    #[error("secure operating-system entropy unavailable")]
    EntropyUnavailable,
    /// Secure object path failed before the local role completed.
    #[error(transparent)]
    Stream(#[from] SecureStreamError),
    /// Authenticated peer record was malformed or out of order.
    #[error(transparent)]
    Record(#[from] StreamRecordError),
    /// Independent piece-lane record was malformed or exceeded bounds.
    #[error(transparent)]
    PieceRecord(#[from] PieceRecordError),
    /// Receiver staging failed before visibility.
    #[error(transparent)]
    Stage(#[from] StageError),
    /// Receiver commit failed with explicit visibility semantics.
    #[error(transparent)]
    Commit(#[from] CommitError),
    /// Authenticated records violated monotonic reconstruction state.
    #[error(transparent)]
    Graph(#[from] GraphError),
    /// Peer sent a valid record type at an impossible protocol point.
    #[error("authenticated object record arrived out of order")]
    UnexpectedRecord,
    /// Declared object exceeds negotiated receiver authority.
    #[error("object exceeds negotiated hard limits")]
    LimitExceeded,
    /// Source changed after its immutable declaration.
    #[error("source object changed during transfer")]
    SourceChanged,
    /// Receiver receipt disagrees with the object sent.
    #[error("authenticated commit receipt disagrees with sent object")]
    ReceiptMismatch,
    /// Source contains a file type whose safe portable semantics are not negotiated.
    #[error("symbolic links and special files are not supported by this transfer")]
    UnsupportedFileType,
    /// A source or authenticated component is not one portable UTF-8 file name.
    #[error("object contains a non-portable path component")]
    InvalidComponent,
    /// Authenticated direct record delivery failed before relay recovery.
    #[error(transparent)]
    Direct(#[from] DirectRecordError),
    /// Migration control records or global sequences contradicted one another.
    #[error("authenticated path-migration protocol violation")]
    MigrationProtocol,
    /// Global sequence or direct packet envelope was malformed.
    #[error(transparent)]
    DirectProtocol(#[from] DirectProtocolError),
    /// Authenticated QUIC path failed before the local role completed.
    #[error(transparent)]
    Quic(#[from] DirectQuicLinkError),
}

impl FileOracleError {
    pub(crate) fn is_retryable_path_failure(&self) -> bool {
        matches!(self, Self::Stream(_) | Self::Direct(_) | Self::Quic(_))
    }

    pub(crate) fn is_accelerated_path_failure(&self) -> bool {
        matches!(self, Self::Direct(_) | Self::Quic(_))
    }
}

pub(crate) trait SendRecordPath {
    async fn send_record(
        &mut self,
        encoded: Vec<u8>,
        remaining_object_bytes: u64,
    ) -> Result<(), FileOracleError>;

    async fn receive_resume_offer(
        &mut self,
        entry: EntryId,
    ) -> Result<(u64, Digest), FileOracleError>;

    async fn send_resume_decision(
        &mut self,
        entry: EntryId,
        prefix: u64,
    ) -> Result<(), FileOracleError>;

    async fn receive_receipt(
        &mut self,
        expected_digest: Digest,
        expected_length: u64,
    ) -> Result<(), FileOracleError>;
}

pub(crate) trait ReceiveRecordPath {
    async fn receive_record(&mut self) -> Result<Vec<u8>, FileOracleError>;

    async fn send_resume_offer(
        &mut self,
        entry: EntryId,
        prefix: u64,
        digest: Digest,
    ) -> Result<(), FileOracleError>;

    async fn receive_resume_decision(&mut self, entry: EntryId) -> Result<u64, FileOracleError>;

    async fn send_receipt(
        &mut self,
        digest: Digest,
        length: u64,
    ) -> Result<ReceiptDelivery, FileOracleError>;
}

struct SecureSendPath<'a, S>(&'a mut SecureStream<S>);
struct SecureReceivePath<'a, S>(&'a mut SecureStream<S>);
struct QuicSendPath<'a>(&'a mut DirectQuicLink);
struct QuicReceivePath<'a>(&'a mut DirectQuicLink);

impl<S> SendRecordPath for SecureSendPath<'_, S>
where
    S: AsyncRead + AsyncWrite + Unpin,
{
    async fn send_record(
        &mut self,
        encoded: Vec<u8>,
        _remaining_object_bytes: u64,
    ) -> Result<(), FileOracleError> {
        self.0.send(&encoded).await?;
        Ok(())
    }

    async fn receive_resume_offer(
        &mut self,
        entry: EntryId,
    ) -> Result<(u64, Digest), FileOracleError> {
        self.0.flush().await?;
        decode_resume_offer(&self.0.receive().await?, entry)
    }

    async fn send_resume_decision(
        &mut self,
        entry: EntryId,
        prefix: u64,
    ) -> Result<(), FileOracleError> {
        self.0
            .send(&StreamRecord::ResumeDecision { entry, prefix }.encode()?)
            .await?;
        self.0.flush().await?;
        Ok(())
    }

    async fn receive_receipt(
        &mut self,
        expected_digest: Digest,
        expected_length: u64,
    ) -> Result<(), FileOracleError> {
        self.0.flush().await?;
        let receipt = self.0.receive().await?;
        match decode_stream_record(&receipt, MAX_STREAM_BLOCK_BYTES)? {
            StreamRecord::CommitReceipt { digest, length }
                if digest == expected_digest && length == expected_length =>
            {
                Ok(())
            }
            StreamRecord::CommitReceipt { .. } => Err(FileOracleError::ReceiptMismatch),
            _ => Err(FileOracleError::UnexpectedRecord),
        }
    }
}

impl<S> ReceiveRecordPath for SecureReceivePath<'_, S>
where
    S: AsyncRead + AsyncWrite + Unpin,
{
    async fn receive_record(&mut self) -> Result<Vec<u8>, FileOracleError> {
        self.0.receive().await.map_err(FileOracleError::from)
    }

    async fn send_resume_offer(
        &mut self,
        entry: EntryId,
        prefix: u64,
        digest: Digest,
    ) -> Result<(), FileOracleError> {
        self.0
            .send(
                &StreamRecord::ResumeOffer {
                    entry,
                    prefix,
                    digest,
                }
                .encode()?,
            )
            .await?;
        self.0.flush().await?;
        Ok(())
    }

    async fn receive_resume_decision(&mut self, entry: EntryId) -> Result<u64, FileOracleError> {
        decode_resume_decision(&self.0.receive().await?, entry)
    }

    async fn send_receipt(
        &mut self,
        digest: Digest,
        length: u64,
    ) -> Result<ReceiptDelivery, FileOracleError> {
        let encoded = StreamRecord::CommitReceipt { digest, length }.encode()?;
        Ok(
            if self.0.send(&encoded).await.is_ok() && self.0.flush().await.is_ok() {
                ReceiptDelivery::Sent
            } else {
                ReceiptDelivery::Failed
            },
        )
    }
}

impl SendRecordPath for QuicSendPath<'_> {
    async fn send_record(
        &mut self,
        encoded: Vec<u8>,
        _remaining_object_bytes: u64,
    ) -> Result<(), FileOracleError> {
        self.0
            .queue_frame(&encoded, MAX_STREAM_PLAINTEXT, DEFAULT_QUIC_IDLE_TIMEOUT)
            .await?;
        Ok(())
    }

    async fn receive_resume_offer(
        &mut self,
        entry: EntryId,
    ) -> Result<(u64, Digest), FileOracleError> {
        self.0.flush_frames().await?;
        let encoded = self
            .0
            .receive_frame(MAX_STREAM_PLAINTEXT, DEFAULT_QUIC_IDLE_TIMEOUT)
            .await?;
        decode_resume_offer(&encoded, entry)
    }

    async fn send_resume_decision(
        &mut self,
        entry: EntryId,
        prefix: u64,
    ) -> Result<(), FileOracleError> {
        self.0
            .send_frame(
                &StreamRecord::ResumeDecision { entry, prefix }.encode()?,
                MAX_STREAM_PLAINTEXT,
                DEFAULT_QUIC_IDLE_TIMEOUT,
            )
            .await?;
        Ok(())
    }

    async fn receive_receipt(
        &mut self,
        expected_digest: Digest,
        expected_length: u64,
    ) -> Result<(), FileOracleError> {
        self.0.finish_send_stream(DEFAULT_QUIC_IDLE_TIMEOUT).await?;
        let receipt = self
            .0
            .receive_frame(MAX_STREAM_PLAINTEXT, DEFAULT_QUIC_IDLE_TIMEOUT)
            .await?;
        match decode_stream_record(&receipt, MAX_STREAM_BLOCK_BYTES)? {
            StreamRecord::CommitReceipt { digest, length }
                if digest == expected_digest && length == expected_length =>
            {
                self.0
                    .finish_receive_stream(DEFAULT_QUIC_IDLE_TIMEOUT)
                    .await?;
                Ok(())
            }
            StreamRecord::CommitReceipt { .. } => Err(FileOracleError::ReceiptMismatch),
            _ => Err(FileOracleError::UnexpectedRecord),
        }
    }
}

impl ReceiveRecordPath for QuicReceivePath<'_> {
    async fn receive_record(&mut self) -> Result<Vec<u8>, FileOracleError> {
        self.0
            .receive_frame(MAX_STREAM_PLAINTEXT, DEFAULT_QUIC_IDLE_TIMEOUT)
            .await
            .map_err(FileOracleError::from)
    }

    async fn send_resume_offer(
        &mut self,
        entry: EntryId,
        prefix: u64,
        digest: Digest,
    ) -> Result<(), FileOracleError> {
        self.0
            .send_frame(
                &StreamRecord::ResumeOffer {
                    entry,
                    prefix,
                    digest,
                }
                .encode()?,
                MAX_STREAM_PLAINTEXT,
                DEFAULT_QUIC_IDLE_TIMEOUT,
            )
            .await?;
        Ok(())
    }

    async fn receive_resume_decision(&mut self, entry: EntryId) -> Result<u64, FileOracleError> {
        let encoded = self
            .0
            .receive_frame(MAX_STREAM_PLAINTEXT, DEFAULT_QUIC_IDLE_TIMEOUT)
            .await?;
        decode_resume_decision(&encoded, entry)
    }

    async fn send_receipt(
        &mut self,
        digest: Digest,
        length: u64,
    ) -> Result<ReceiptDelivery, FileOracleError> {
        let encoded = StreamRecord::CommitReceipt { digest, length }.encode()?;
        if self
            .0
            .send_frame(&encoded, MAX_STREAM_PLAINTEXT, DEFAULT_QUIC_IDLE_TIMEOUT)
            .await
            .is_err()
        {
            return Ok(ReceiptDelivery::Failed);
        }
        Ok(
            if self
                .0
                .finish_send_stream(DEFAULT_QUIC_IDLE_TIMEOUT)
                .await
                .is_ok()
            {
                ReceiptDelivery::Sent
            } else {
                ReceiptDelivery::Failed
            },
        )
    }
}

fn decode_resume_offer(
    encoded: &[u8],
    expected_entry: EntryId,
) -> Result<(u64, Digest), FileOracleError> {
    match decode_stream_record(encoded, MAX_STREAM_BLOCK_BYTES)? {
        StreamRecord::ResumeOffer {
            entry,
            prefix,
            digest,
        } if entry == expected_entry => Ok((prefix, digest)),
        _ => Err(FileOracleError::UnexpectedRecord),
    }
}

fn decode_resume_decision(encoded: &[u8], expected_entry: EntryId) -> Result<u64, FileOracleError> {
    match decode_stream_record(encoded, MAX_STREAM_BLOCK_BYTES)? {
        StreamRecord::ResumeDecision { entry, prefix } if entry == expected_entry => Ok(prefix),
        _ => Err(FileOracleError::UnexpectedRecord),
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum SourceKind {
    Directory,
    File,
}

#[derive(Debug)]
pub(crate) struct SourceEntry {
    pub(crate) id: EntryId,
    pub(crate) parent: Option<EntryId>,
    pub(crate) name: String,
    pub(crate) path: PathBuf,
    pub(crate) kind: SourceKind,
    pub(crate) length: u64,
    pub(crate) metadata: u16,
}

#[derive(Debug)]
pub(crate) struct SourceObject {
    pub(crate) entries: Vec<SourceEntry>,
    pub(crate) total_length: u64,
}

#[derive(Debug)]
struct PendingSource {
    path: PathBuf,
    parent: Option<EntryId>,
    depth: u16,
    path_bytes: u32,
}

struct SendCursor {
    block: u64,
    sent_bytes: u64,
    total_length: u64,
}

struct SourceBlock {
    offset: u64,
    bytes: Vec<u8>,
    digest: Digest,
}

struct SourceReader {
    blocks: mpsc::Receiver<SourceBlock>,
    recycled: mpsc::Sender<Vec<u8>>,
    worker: Option<TaskHandle<Result<Digest, FileOracleError>>>,
}

struct SourcePrefix {
    digest: Digest,
    file_hasher: blake3::Hasher,
    object_hasher: blake3::Hasher,
}

struct AcceptedSourcePrefix {
    length: u64,
    file_hasher: blake3::Hasher,
    object_hasher: blake3::Hasher,
}

#[derive(Debug)]
struct ReceivedEntry {
    relative: PathBuf,
    directory: bool,
    depth: u16,
    path_bytes: u32,
}

struct IncomingEntry<'a> {
    id: EntryId,
    relative: &'a Path,
    root_name: &'a str,
    kind: SourceKind,
    length: u64,
    metadata: u16,
}

enum StagedRoot {
    File {
        file: Box<StagingFile>,
        metadata: u16,
    },
    Tree {
        tree: StagingTree,
        metadata: Vec<(PathBuf, bool, u16)>,
    },
}

struct ReceiveState {
    object_id: [u8; 16],
    resumable: bool,
    entries: u64,
    total_length: u64,
    block_bytes: u32,
    object_hasher: blake3::Hasher,
    graph: ReconstructionGraph,
    received_entries: BTreeMap<EntryId, ReceivedEntry>,
    portable_locations: BTreeSet<(Option<EntryId>, String)>,
    metadata_bytes: u64,
    staged_root: Option<StagedRoot>,
    destination: Option<PathBuf>,
    block_index: u64,
    received_bytes: u64,
    root_file_digest: Option<Digest>,
}

/// Stream one regular file or directory tree and wait for an authenticated commit receipt.
///
/// # Errors
///
/// Returns for source mutation/I/O, unsupported file kinds, negotiated-limit
/// violations, secure-path failure, malformed peer records, or receipt mismatch.
pub async fn send_object<S>(
    stream: &mut SecureStream<S>,
    source: impl AsRef<Path>,
    limits: HardLimits,
) -> Result<SendSummary, FileOracleError>
where
    S: AsyncRead + AsyncWrite + Unpin,
{
    let mut path = SecureSendPath(stream);
    send_file_on(&mut path, source, limits).await
}

/// Stream one regular file or directory tree over a saturated authenticated
/// QUIC path and wait for the receiver's commit receipt.
///
/// Records remain canonical correctness boundaries, but no longer impose one
/// network acknowledgement boundary each. QUIC may keep the bandwidth-delay
/// product occupied while the object oracle preserves verification and commit
/// truth.
///
/// # Errors
///
/// Returns for source mutation/I/O, unsupported file kinds, negotiated-limit
/// violations, QUIC path failure, malformed peer records, or receipt mismatch.
pub async fn send_object_quic(
    link: &mut DirectQuicLink,
    source: impl AsRef<Path>,
    limits: HardLimits,
) -> Result<SendSummary, FileOracleError> {
    let transport = link.transport();
    let mut path = QuicSendPath(link);
    let mut summary = send_file_on(&mut path, source, limits).await?;
    summary.transport = transport;
    Ok(summary)
}

/// Backward-compatible name for sending one object; directories are accepted.
///
/// # Errors
///
/// Has the same failure contract as [`send_object`].
pub async fn send_file<S>(
    stream: &mut SecureStream<S>,
    source: impl AsRef<Path>,
    limits: HardLimits,
) -> Result<SendSummary, FileOracleError>
where
    S: AsyncRead + AsyncWrite + Unpin,
{
    send_object(stream, source, limits).await
}

pub(crate) async fn send_file_on<P>(
    path: &mut P,
    source: impl AsRef<Path>,
    limits: HardLimits,
) -> Result<SendSummary, FileOracleError>
where
    P: SendRecordPath,
{
    send_object_on(path, source, limits, &NoopObserver).await
}

pub(crate) async fn send_object_on<P>(
    path: &mut P,
    source: impl AsRef<Path>,
    limits: HardLimits,
    observer: &dyn TransferObserver,
) -> Result<SendSummary, FileOracleError>
where
    P: SendRecordPath,
{
    send_object_on_with_resume(path, source, limits, observer, None).await
}

async fn send_object_on_with_resume<P>(
    path: &mut P,
    source: impl AsRef<Path>,
    limits: HardLimits,
    observer: &dyn TransferObserver,
    resume: Option<&ResumeToken>,
) -> Result<SendSummary, FileOracleError>
where
    P: SendRecordPath,
{
    let source = scan_source(source.as_ref(), limits).await?;
    let entries =
        u64::try_from(source.entries.len()).map_err(|_| FileOracleError::LimitExceeded)?;
    observer.observe(TransferProgress::Declared {
        bytes: source.total_length,
        entries,
    });
    let object_id = if let Some(token) = resume {
        resume_object_id(&source, token)?
    } else {
        let mut object_id = [0_u8; 16];
        getrandom::fill(&mut object_id).map_err(|_| FileOracleError::EntropyUnavailable)?;
        object_id
    };

    send_record_on(
        path,
        StreamRecord::TreeStart {
            object_id,
            entries,
            total_length: source.total_length,
            block_bytes: STREAM_BLOCK_BYTES,
        },
        source.total_length,
    )
    .await?;

    let mut object_hasher = object_hasher(entries, source.total_length, STREAM_BLOCK_BYTES);
    let mut cursor = SendCursor {
        block: 0,
        sent_bytes: 0,
        total_length: source.total_length,
    };
    for entry in &source.entries {
        send_source_entry(path, entry, &mut cursor, &mut object_hasher, observer).await?;
    }

    let digest = Digest(*object_hasher.finalize().as_bytes());
    send_record_on(path, StreamRecord::ObjectSeal { digest }, 0).await?;
    path.receive_receipt(digest, source.total_length).await?;
    Ok(SendSummary {
        length: source.total_length,
        digest,
        blocks: cursor.block,
        entries,
        transport: TransferTransport::Relay,
        migration: None,
        profile: TransferProfile::default(),
    })
}

async fn send_source_entry<P>(
    path: &mut P,
    entry: &SourceEntry,
    cursor: &mut SendCursor,
    object_hasher: &mut blake3::Hasher,
    observer: &dyn TransferObserver,
) -> Result<(), FileOracleError>
where
    P: SendRecordPath,
{
    send_entry_declaration(path, entry, cursor, object_hasher).await?;
    if entry.kind == SourceKind::Directory {
        return Ok(());
    }

    let accepted = negotiate_source_prefix(path, entry, object_hasher).await?;
    *object_hasher = accepted.object_hasher;
    let skipped_blocks = blocks_for_prefix(accepted.length)?;
    cursor.block = cursor
        .block
        .checked_add(skipped_blocks)
        .ok_or(FileOracleError::LimitExceeded)?;
    cursor.sent_bytes = cursor
        .sent_bytes
        .checked_add(accepted.length)
        .ok_or(FileOracleError::LimitExceeded)?;
    if accepted.length != 0 {
        observer.observe(TransferProgress::Advanced {
            bytes: cursor.sent_bytes,
            total: cursor.total_length,
        });
    }

    let mut reader = SourceReader::spawn(entry, accepted.length, accepted.file_hasher)?;
    let mut offset = accepted.length;
    while offset < entry.length {
        let wanted = usize::try_from((entry.length - offset).min(u64::from(STREAM_BLOCK_BYTES)))
            .map_err(|_| FileOracleError::LimitExceeded)?;
        let block = match reader.next().await {
            Ok(block) => block,
            Err(error) => {
                reader.abort().await;
                return Err(error);
            }
        };
        if block.offset != offset || block.bytes.len() != wanted {
            reader.abort().await;
            return Err(FileOracleError::SourceChanged);
        }
        let bytes = block.bytes.as_slice();
        object_hasher.update(bytes);
        let block_id = BlockId(cursor.block);
        if let Err(error) = send_record_on(
            path,
            StreamRecord::BlockData {
                block: block_id,
                offset,
                data: bytes,
            },
            cursor.total_length.saturating_sub(cursor.sent_bytes),
        )
        .await
        {
            reader.abort().await;
            return Err(error);
        }
        if let Err(error) = send_record_on(
            path,
            StreamRecord::BlockSeal {
                block: block_id,
                digest: block.digest,
            },
            cursor.total_length.saturating_sub(cursor.sent_bytes),
        )
        .await
        {
            reader.abort().await;
            return Err(error);
        }
        let read = u64::try_from(block.bytes.len()).map_err(|_| FileOracleError::LimitExceeded)?;
        reader.recycle(block.bytes);
        offset += read;
        cursor.sent_bytes += read;
        cursor.block += 1;
        observer.observe(TransferProgress::Advanced {
            bytes: cursor.sent_bytes,
            total: cursor.total_length,
        });
    }
    let file_digest = reader.finish().await?;
    send_record_on(
        path,
        StreamRecord::EntrySeal {
            entry: entry.id,
            digest: file_digest,
        },
        cursor.total_length.saturating_sub(cursor.sent_bytes),
    )
    .await
}

async fn send_entry_declaration<P>(
    path: &mut P,
    entry: &SourceEntry,
    cursor: &SendCursor,
    object_hasher: &mut blake3::Hasher,
) -> Result<(), FileOracleError>
where
    P: SendRecordPath,
{
    let encoded = StreamRecord::TreeEntry {
        entry: entry.id,
        parent: entry.parent,
        directory: entry.kind == SourceKind::Directory,
        length: entry.length,
        metadata: entry.metadata,
        name: &entry.name,
    }
    .encode()?;
    object_hasher.update(&encoded);
    path.send_record(
        encoded,
        cursor.total_length.saturating_sub(cursor.sent_bytes),
    )
    .await
}

async fn negotiate_source_prefix<P>(
    path: &mut P,
    entry: &SourceEntry,
    object_hasher: &blake3::Hasher,
) -> Result<AcceptedSourcePrefix, FileOracleError>
where
    P: SendRecordPath,
{
    let (offered, offered_digest) = path.receive_resume_offer(entry.id).await?;
    validate_resume_prefix(offered, entry.length)?;
    let candidate = hash_source_prefix(entry, offered, object_hasher).await?;
    let accepted = if candidate.digest == offered_digest {
        offered
    } else {
        0
    };
    path.send_resume_decision(entry.id, accepted).await?;
    if accepted == offered {
        Ok(AcceptedSourcePrefix {
            length: accepted,
            file_hasher: candidate.file_hasher,
            object_hasher: candidate.object_hasher,
        })
    } else {
        Ok(AcceptedSourcePrefix {
            length: 0,
            file_hasher: blake3::Hasher::new(),
            object_hasher: object_hasher.clone(),
        })
    }
}

fn resume_object_id(
    source: &SourceObject,
    token: &ResumeToken,
) -> Result<[u8; 16], FileOracleError> {
    let mut hasher = blake3::Hasher::new_keyed(&token.0);
    hasher.update(b"RIFT live resume object v1\0");
    hasher.update(&source.total_length.to_be_bytes());
    hasher.update(
        &u64::try_from(source.entries.len())
            .map_err(|_| FileOracleError::LimitExceeded)?
            .to_be_bytes(),
    );
    hasher.update(&STREAM_BLOCK_BYTES.to_be_bytes());
    for entry in &source.entries {
        hasher.update(
            &StreamRecord::TreeEntry {
                entry: entry.id,
                parent: entry.parent,
                directory: entry.kind == SourceKind::Directory,
                length: entry.length,
                metadata: entry.metadata,
                name: &entry.name,
            }
            .encode()?,
        );
    }
    let mut id = [0_u8; 16];
    id.copy_from_slice(&hasher.finalize().as_bytes()[..16]);
    Ok(id)
}

fn validate_resume_prefix(prefix: u64, length: u64) -> Result<(), FileOracleError> {
    if prefix > length
        || (prefix != length && !prefix.is_multiple_of(u64::from(STREAM_BLOCK_BYTES)))
    {
        return Err(FileOracleError::UnexpectedRecord);
    }
    Ok(())
}

fn blocks_for_prefix(prefix: u64) -> Result<u64, FileOracleError> {
    let block = u64::from(STREAM_BLOCK_BYTES);
    prefix
        .checked_add(block.saturating_sub(1))
        .map(|rounded| rounded / block)
        .ok_or(FileOracleError::LimitExceeded)
}

async fn hash_source_prefix(
    entry: &SourceEntry,
    prefix: u64,
    object_hasher: &blake3::Hasher,
) -> Result<SourcePrefix, FileOracleError> {
    let mut file = File::open(&entry.path)
        .await
        .map_err(FileOracleError::SourceIo)?;
    if file
        .metadata()
        .await
        .map_err(FileOracleError::SourceIo)?
        .len()
        != entry.length
    {
        return Err(FileOracleError::SourceChanged);
    }
    let block_bytes =
        usize::try_from(STREAM_BLOCK_BYTES).map_err(|_| FileOracleError::LimitExceeded)?;
    let mut buffer = Vec::with_capacity(block_bytes);
    let mut file_hasher = blake3::Hasher::new();
    let mut object_hasher = object_hasher.clone();
    let mut offset = 0_u64;
    while offset < prefix {
        let wanted = usize::try_from((prefix - offset).min(u64::from(STREAM_BLOCK_BYTES)))
            .map_err(|_| FileOracleError::LimitExceeded)?;
        buffer.resize(wanted, 0);
        let (next, read) = file
            .read_into_vec(buffer)
            .await
            .map_err(FileOracleError::SourceIo)?;
        buffer = next;
        if read != wanted {
            return Err(FileOracleError::SourceChanged);
        }
        file_hasher.update(&buffer[..read]);
        object_hasher.update(&buffer[..read]);
        offset = offset
            .checked_add(u64::try_from(read).map_err(|_| FileOracleError::LimitExceeded)?)
            .ok_or(FileOracleError::LimitExceeded)?;
        buffer.clear();
    }
    Ok(SourcePrefix {
        digest: Digest(*file_hasher.clone().finalize().as_bytes()),
        file_hasher,
        object_hasher,
    })
}

impl SourceReader {
    fn spawn(
        entry: &SourceEntry,
        start_offset: u64,
        start_hasher: blake3::Hasher,
    ) -> Result<Self, FileOracleError> {
        let cx = Cx::current().ok_or_else(source_runtime_unavailable)?;
        let block_bytes =
            usize::try_from(STREAM_BLOCK_BYTES).map_err(|_| FileOracleError::LimitExceeded)?;
        let (block_tx, blocks) = mpsc::channel(SOURCE_PREFETCH_BLOCKS);
        let (recycled, mut buffers) = mpsc::channel(SOURCE_PREFETCH_BLOCKS);
        for _ in 0..SOURCE_PREFETCH_BLOCKS {
            recycled
                .try_send(Vec::with_capacity(block_bytes))
                .map_err(|_| source_runtime_unavailable())?;
        }
        let path = entry.path.clone();
        let length = entry.length;
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
                file.seek(SeekFrom::Start(start_offset))
                    .await
                    .map_err(FileOracleError::SourceIo)?;
                let mut file_hasher = start_hasher;
                let mut offset = start_offset;
                while offset < length {
                    let wanted =
                        usize::try_from((length - offset).min(u64::from(STREAM_BLOCK_BYTES)))
                            .map_err(|_| FileOracleError::LimitExceeded)?;
                    let mut buffer = buffers
                        .recv(&worker_cx)
                        .await
                        .map_err(|_| source_pipeline_closed())?;
                    buffer.resize(wanted, 0);
                    let (buffer, read) = file
                        .read_into_vec(buffer)
                        .await
                        .map_err(FileOracleError::SourceIo)?;
                    if read != wanted {
                        return Err(FileOracleError::SourceChanged);
                    }
                    let bytes = &buffer[..read];
                    file_hasher.update(bytes);
                    let digest = Digest(*blake3::hash(bytes).as_bytes());
                    block_tx
                        .send(
                            &worker_cx,
                            SourceBlock {
                                offset,
                                bytes: buffer,
                                digest,
                            },
                        )
                        .await
                        .map_err(|_| source_pipeline_closed())?;
                    offset = offset
                        .checked_add(
                            u64::try_from(read).map_err(|_| FileOracleError::LimitExceeded)?,
                        )
                        .ok_or(FileOracleError::LimitExceeded)?;
                }
                let mut trailing = buffers
                    .recv(&worker_cx)
                    .await
                    .map_err(|_| source_pipeline_closed())?;
                trailing.resize(1, 0);
                let (_, read) = file
                    .read_into_vec(trailing)
                    .await
                    .map_err(FileOracleError::SourceIo)?;
                if read != 0 {
                    return Err(FileOracleError::SourceChanged);
                }
                Ok(Digest(*file_hasher.finalize().as_bytes()))
            })
            .map_err(|_| source_runtime_unavailable())?;
        Ok(Self {
            blocks,
            recycled,
            worker: Some(worker),
        })
    }

    async fn next(&mut self) -> Result<SourceBlock, FileOracleError> {
        let cx = Cx::current().ok_or_else(source_runtime_unavailable)?;
        match self.blocks.recv(&cx).await {
            Ok(block) => Ok(block),
            Err(_) => match self.join_worker().await {
                Ok(_) => Err(FileOracleError::SourceChanged),
                Err(error) => Err(error),
            },
        }
    }

    fn recycle(&self, mut buffer: Vec<u8>) {
        buffer.clear();
        let _ = self.recycled.try_send(buffer);
    }

    async fn finish(mut self) -> Result<Digest, FileOracleError> {
        self.join_worker().await
    }

    async fn abort(&mut self) {
        if let Some(mut worker) = self.worker.take() {
            worker.abort();
            if let Some(cx) = Cx::current() {
                let _ = worker.join(&cx).await;
            }
        }
    }

    async fn join_worker(&mut self) -> Result<Digest, FileOracleError> {
        let cx = Cx::current().ok_or_else(source_runtime_unavailable)?;
        self.worker
            .take()
            .ok_or_else(source_pipeline_closed)?
            .join(&cx)
            .await
            .map_err(|_| source_pipeline_closed())?
    }
}

fn source_runtime_unavailable() -> FileOracleError {
    FileOracleError::SourceIo(io::Error::other("source pipeline runtime unavailable"))
}

fn source_pipeline_closed() -> FileOracleError {
    FileOracleError::SourceIo(io::Error::new(
        io::ErrorKind::BrokenPipe,
        "source pipeline closed before completion",
    ))
}

/// Reconstruct, verify, atomically commit, and acknowledge one object.
///
/// # Errors
///
/// Returns for secure-path failure before commit, malformed/out-of-order
/// records, reconstruction failure, staging failure, or commit failure.
pub async fn receive_object<S>(
    stream: &mut SecureStream<S>,
    destination: impl AsRef<Path>,
    limits: HardLimits,
) -> Result<ReceiveSummary, FileOracleError>
where
    S: AsyncRead + AsyncWrite + Unpin,
{
    let mut path = SecureReceivePath(stream);
    receive_object_on(
        &mut path,
        ReceiveTarget::Exact(destination.as_ref().to_owned()),
        limits,
    )
    .await
}

/// Receive, verify, stage, and atomically commit one object from an
/// authenticated saturated QUIC path.
///
/// # Errors
///
/// Returns for QUIC path failure, malformed records, negotiated-limit
/// violations, staging failure, verification failure, or commit failure.
pub async fn receive_object_quic(
    link: &mut DirectQuicLink,
    destination: ReceiveTarget,
    limits: HardLimits,
) -> Result<ReceiveSummary, FileOracleError> {
    let transport = link.transport();
    let mut path = QuicReceivePath(link);
    let mut summary = receive_object_on(&mut path, destination, limits).await?;
    summary.transport = transport;
    Ok(summary)
}

/// Backward-compatible name for receiving one file or directory object.
///
/// # Errors
///
/// Has the same failure contract as [`receive_object`].
pub async fn receive_file<S>(
    stream: &mut SecureStream<S>,
    destination: impl AsRef<Path>,
    limits: HardLimits,
) -> Result<ReceiveSummary, FileOracleError>
where
    S: AsyncRead + AsyncWrite + Unpin,
{
    receive_object(stream, destination, limits).await
}

pub(crate) async fn receive_object_on<P>(
    path: &mut P,
    destination: ReceiveTarget,
    limits: HardLimits,
) -> Result<ReceiveSummary, FileOracleError>
where
    P: ReceiveRecordPath,
{
    receive_object_observed_on(path, destination, limits, &NoopObserver).await
}

pub(crate) async fn receive_object_observed_on<P>(
    path: &mut P,
    destination: ReceiveTarget,
    limits: HardLimits,
    observer: &dyn TransferObserver,
) -> Result<ReceiveSummary, FileOracleError>
where
    P: ReceiveRecordPath,
{
    receive_object_observed_on_with_resume(path, destination, limits, observer, false).await
}

async fn receive_object_observed_on_with_resume<P>(
    path: &mut P,
    destination: ReceiveTarget,
    limits: HardLimits,
    observer: &dyn TransferObserver,
    resumable: bool,
) -> Result<ReceiveSummary, FileOracleError>
where
    P: ReceiveRecordPath,
{
    let (object_id, entries, total_length, block_bytes) = receive_geometry(path, limits).await?;
    observer.observe(TransferProgress::Declared {
        bytes: total_length,
        entries,
    });
    let mut state = ReceiveState {
        object_id,
        resumable,
        entries,
        total_length,
        block_bytes,
        object_hasher: object_hasher(entries, total_length, block_bytes),
        graph: ReconstructionGraph::new(),
        received_entries: BTreeMap::new(),
        portable_locations: BTreeSet::new(),
        metadata_bytes: 0,
        staged_root: None,
        destination: None,
        block_index: 0,
        received_bytes: 0,
        root_file_digest: None,
    };
    for expected_entry in 0..entries {
        if let Err(error) = receive_entry(
            path,
            &mut state,
            EntryId(expected_entry),
            &destination,
            limits,
            observer,
        )
        .await
        {
            if state.resumable && error.is_retryable_path_failure() {
                retain_received(&mut state).await?;
            }
            return Err(error);
        }
    }
    commit_received(path, state).await
}

async fn receive_geometry<P>(
    path: &mut P,
    limits: HardLimits,
) -> Result<([u8; 16], u64, u64, u32), FileOracleError>
where
    P: ReceiveRecordPath,
{
    let start = path.receive_record().await?;
    let StreamRecord::TreeStart {
        object_id,
        entries,
        total_length,
        block_bytes,
        ..
    } = decode_stream_record(&start, MAX_STREAM_BLOCK_BYTES)?
    else {
        return Err(FileOracleError::UnexpectedRecord);
    };
    if entries == 0
        || entries > limits.max_entries
        || total_length > limits.max_object_bytes
        || usize::try_from(block_bytes).map_err(|_| FileOracleError::LimitExceeded)?
            > MAX_STREAM_BLOCK_BYTES
    {
        return Err(FileOracleError::LimitExceeded);
    }
    Ok((object_id, entries, total_length, block_bytes))
}

async fn receive_entry<P>(
    path: &mut P,
    state: &mut ReceiveState,
    expected_entry: EntryId,
    destination: &ReceiveTarget,
    limits: HardLimits,
    observer: &dyn TransferObserver,
) -> Result<(), FileOracleError>
where
    P: ReceiveRecordPath,
{
    let encoded = path.receive_record().await?;
    let StreamRecord::TreeEntry {
        entry,
        parent,
        directory,
        length,
        metadata,
        name,
    } = decode_stream_record(&encoded, MAX_STREAM_BLOCK_BYTES)?
    else {
        return Err(FileOracleError::UnexpectedRecord);
    };
    if entry != expected_entry {
        return Err(FileOracleError::UnexpectedRecord);
    }
    validate_component(name, limits)?;
    if !state
        .portable_locations
        .insert((parent, portable_component_key(name)))
    {
        return Err(FileOracleError::InvalidComponent);
    }
    state.object_hasher.update(&encoded);
    let (relative, depth, path_bytes) = receive_location(state, entry, parent, name, limits)?;
    state.metadata_bytes = admit_metadata(
        state.metadata_bytes,
        path_bytes,
        encoded.len(),
        limits.max_reconstruction_bytes,
    )?;
    let incoming = IncomingEntry {
        id: entry,
        relative: &relative,
        root_name: name,
        kind: if directory {
            SourceKind::Directory
        } else {
            SourceKind::File
        },
        length,
        metadata,
    };
    stage_entry(state, destination, &incoming).await?;
    state.received_entries.insert(
        entry,
        ReceivedEntry {
            relative: relative.clone(),
            directory,
            depth,
            path_bytes,
        },
    );
    if !directory {
        receive_file_payload(path, state, entry, &relative, length, metadata, observer).await?;
    }
    Ok(())
}

fn receive_location(
    state: &ReceiveState,
    entry: EntryId,
    parent: Option<EntryId>,
    name: &str,
    limits: HardLimits,
) -> Result<(PathBuf, u16, u32), FileOracleError> {
    let location = if entry == EntryId(0) {
        if parent.is_some() {
            return Err(FileOracleError::UnexpectedRecord);
        }
        (PathBuf::new(), 1, component_bytes(name)?)
    } else {
        let parent = state
            .received_entries
            .get(&parent.ok_or(FileOracleError::UnexpectedRecord)?)
            .ok_or(FileOracleError::UnexpectedRecord)?;
        if !parent.directory {
            return Err(FileOracleError::UnexpectedRecord);
        }
        let depth = parent
            .depth
            .checked_add(1)
            .ok_or(FileOracleError::LimitExceeded)?;
        let path_bytes = parent
            .path_bytes
            .checked_add(1)
            .and_then(|bytes| bytes.checked_add(component_bytes(name).ok()?))
            .ok_or(FileOracleError::LimitExceeded)?;
        (parent.relative.join(name), depth, path_bytes)
    };
    if location.1 > limits.max_depth || location.2 > limits.max_path_bytes {
        return Err(FileOracleError::LimitExceeded);
    }
    Ok(location)
}

async fn stage_entry(
    state: &mut ReceiveState,
    destination: &ReceiveTarget,
    entry: &IncomingEntry<'_>,
) -> Result<(), FileOracleError> {
    if entry.id == EntryId(0) {
        let destination = destination
            .resolve(entry.root_name, entry.kind == SourceKind::Directory)
            .await?;
        state.destination = Some(destination.clone());
        state.staged_root = Some(if entry.kind == SourceKind::Directory {
            let tree = if state.resumable {
                StagingTree::resume(&destination, state.object_id).await?
            } else {
                StagingTree::create(&destination).await?
            };
            let root = tree.root().to_owned();
            StagedRoot::Tree {
                tree,
                metadata: vec![(root, true, entry.metadata)],
            }
        } else {
            StagedRoot::File {
                file: Box::new(if state.resumable {
                    StagingFile::resume(&destination, entry.length, state.object_id).await?
                } else {
                    StagingFile::create(&destination, entry.length).await?
                }),
                metadata: entry.metadata,
            }
        });
        return Ok(());
    }
    let StagedRoot::Tree {
        tree,
        metadata: staged_metadata,
    } = state
        .staged_root
        .as_mut()
        .ok_or(FileOracleError::UnexpectedRecord)?
    else {
        return Err(FileOracleError::UnexpectedRecord);
    };
    if entry.kind == SourceKind::Directory {
        let path = tree.root().join(entry.relative);
        if state.resumable {
            tree.resume_directory(&path).await?;
        } else {
            tree.create_directory(&path).await?;
        }
        staged_metadata.push((path, true, entry.metadata));
    }
    Ok(())
}

async fn receive_file_payload<P>(
    path: &mut P,
    state: &mut ReceiveState,
    entry: EntryId,
    relative: &Path,
    length: u64,
    metadata: u16,
    observer: &dyn TransferObserver,
) -> Result<(), FileOracleError>
where
    P: ReceiveRecordPath,
{
    let mut staged_file = match state
        .staged_root
        .as_mut()
        .ok_or(FileOracleError::UnexpectedRecord)?
    {
        StagedRoot::File { .. } if entry == EntryId(0) => None,
        StagedRoot::Tree {
            tree,
            metadata: staged_metadata,
        } => {
            let staged_path = tree.root().join(relative);
            staged_metadata.push((staged_path.clone(), false, metadata));
            Some(if state.resumable {
                tree.resume_file(&staged_path, length).await?
            } else {
                tree.create_file(&staged_path, length).await?
            })
        }
        StagedRoot::File { .. } => return Err(FileOracleError::UnexpectedRecord),
    };
    let (accepted, mut file_hasher) =
        negotiate_received_prefix(path, state, entry, length, &mut staged_file, observer).await?;
    let mut offset = accepted;
    while offset < length {
        let block_length = match receive_block(
            path,
            state,
            entry,
            offset,
            length,
            &mut staged_file,
            &mut file_hasher,
        )
        .await
        {
            Ok(length) => length,
            Err(error) => {
                if state.resumable
                    && error.is_retryable_path_failure()
                    && let Some(file) = staged_file.as_mut()
                {
                    file.checkpoint().await?;
                }
                return Err(error);
            }
        };
        offset += u64::from(block_length);
        observer.observe(TransferProgress::Advanced {
            bytes: state.received_bytes,
            total: state.total_length,
        });
    }
    let digest = match receive_entry_seal(path, entry, file_hasher).await {
        Ok(digest) => digest,
        Err(error) => {
            if state.resumable
                && error.is_retryable_path_failure()
                && let Some(file) = staged_file.as_mut()
            {
                file.checkpoint().await?;
            }
            return Err(error);
        }
    };
    match (&mut state.staged_root, staged_file) {
        (Some(StagedRoot::File { file, metadata }), None) => {
            apply_portable_metadata(file.staging_path(), false, *metadata).await?;
            state.root_file_digest = Some(digest);
        }
        (_, Some(file)) => file.finish(digest).await?,
        _ => return Err(FileOracleError::UnexpectedRecord),
    }
    Ok(())
}

async fn negotiate_received_prefix<P>(
    path: &mut P,
    state: &mut ReceiveState,
    entry: EntryId,
    length: u64,
    staged_file: &mut Option<crate::StagingTreeFile>,
    observer: &dyn TransferObserver,
) -> Result<(u64, blake3::Hasher), FileOracleError>
where
    P: ReceiveRecordPath,
{
    let offer = match (&state.staged_root, &*staged_file) {
        (Some(StagedRoot::File { file, .. }), None) => file.resume_prefix(),
        (_, Some(file)) => file.resume_prefix(),
        _ => return Err(FileOracleError::UnexpectedRecord),
    };
    validate_resume_prefix(offer.length, length)?;
    path.send_resume_offer(entry, offer.length, offer.digest)
        .await?;
    let accepted = path.receive_resume_decision(entry).await?;
    if accepted != 0 && accepted != offer.length {
        return Err(FileOracleError::UnexpectedRecord);
    }
    if accepted == 0 && offer.length != 0 {
        match (&mut state.staged_root, &mut *staged_file) {
            (Some(StagedRoot::File { file, .. }), None) => file.reset().await?,
            (_, Some(file)) => file.reset().await?,
            _ => return Err(FileOracleError::UnexpectedRecord),
        }
    }
    let mut hasher = blake3::Hasher::new();
    if accepted != 0 {
        let staged_path = match (&state.staged_root, &*staged_file) {
            (Some(StagedRoot::File { file, .. }), None) => file.staging_path().to_owned(),
            (_, Some(file)) => file.path().to_owned(),
            _ => return Err(FileOracleError::UnexpectedRecord),
        };
        rehydrate_prefix(&staged_path, state, entry, accepted, &mut hasher).await?;
        observer.observe(TransferProgress::Advanced {
            bytes: state.received_bytes,
            total: state.total_length,
        });
    }
    Ok((accepted, hasher))
}

async fn receive_block<P>(
    path: &mut P,
    state: &mut ReceiveState,
    entry: EntryId,
    offset: u64,
    file_length: u64,
    staged_file: &mut Option<crate::StagingTreeFile>,
    file_hasher: &mut blake3::Hasher,
) -> Result<u32, FileOracleError>
where
    P: ReceiveRecordPath,
{
    let max_block =
        usize::try_from(state.block_bytes).map_err(|_| FileOracleError::LimitExceeded)?;
    let encoded = path.receive_record().await?;
    let StreamRecord::BlockData {
        block,
        offset: record_offset,
        data,
    } = decode_stream_record(&encoded, max_block)?
    else {
        return Err(FileOracleError::UnexpectedRecord);
    };
    let expected = usize::try_from((file_length - offset).min(u64::from(state.block_bytes)))
        .map_err(|_| FileOracleError::LimitExceeded)?;
    if block != BlockId(state.block_index) || record_offset != offset || data.len() != expected {
        return Err(FileOracleError::UnexpectedRecord);
    }
    let length = u32::try_from(data.len()).map_err(|_| FileOracleError::LimitExceeded)?;
    state.graph.declare_block(BlockSpec {
        id: block,
        entry,
        offset,
        length,
        source_symbols: 1,
    })?;
    state.graph.advance_rank(block, 1)?;
    verify_block_seal(path, &mut state.graph, block, data, max_block).await?;
    match (&mut state.staged_root, staged_file) {
        (Some(StagedRoot::File { file, .. }), None) => file.write(data).await?,
        (_, Some(file)) => file.write(data).await?,
        _ => return Err(FileOracleError::UnexpectedRecord),
    }
    state.object_hasher.update(data);
    file_hasher.update(data);
    state.received_bytes = state
        .received_bytes
        .checked_add(u64::from(length))
        .ok_or(FileOracleError::LimitExceeded)?;
    state.block_index += 1;
    Ok(length)
}

async fn rehydrate_prefix(
    staged_path: &Path,
    state: &mut ReceiveState,
    entry: EntryId,
    prefix: u64,
    file_hasher: &mut blake3::Hasher,
) -> Result<(), FileOracleError> {
    let mut file = File::open(staged_path)
        .await
        .map_err(|error| FileOracleError::Stage(StageError::Io(error)))?;
    let max_block =
        usize::try_from(state.block_bytes).map_err(|_| FileOracleError::LimitExceeded)?;
    let mut buffer = Vec::with_capacity(max_block);
    let mut offset = 0_u64;
    while offset < prefix {
        let wanted = usize::try_from((prefix - offset).min(u64::from(state.block_bytes)))
            .map_err(|_| FileOracleError::LimitExceeded)?;
        buffer.resize(wanted, 0);
        let (next, read) = file
            .read_into_vec(buffer)
            .await
            .map_err(|error| FileOracleError::Stage(StageError::Io(error)))?;
        buffer = next;
        if read != wanted {
            return Err(FileOracleError::UnexpectedRecord);
        }
        let data = &buffer[..read];
        let block = BlockId(state.block_index);
        let length = u32::try_from(read).map_err(|_| FileOracleError::LimitExceeded)?;
        let digest = Digest(*blake3::hash(data).as_bytes());
        state.graph.declare_block(BlockSpec {
            id: block,
            entry,
            offset,
            length,
            source_symbols: 1,
        })?;
        state.graph.advance_rank(block, 1)?;
        state.graph.declare_block_seal(block, digest)?;
        state.graph.verify_block(block, digest)?;
        state.object_hasher.update(data);
        file_hasher.update(data);
        state.received_bytes = state
            .received_bytes
            .checked_add(u64::from(length))
            .ok_or(FileOracleError::LimitExceeded)?;
        state.block_index = state
            .block_index
            .checked_add(1)
            .ok_or(FileOracleError::LimitExceeded)?;
        offset = offset
            .checked_add(u64::from(length))
            .ok_or(FileOracleError::LimitExceeded)?;
        buffer.clear();
    }
    Ok(())
}

async fn retain_received(state: &mut ReceiveState) -> Result<(), FileOracleError> {
    match state.staged_root.take() {
        Some(StagedRoot::File { file, .. }) => (*file).retain().await?,
        Some(StagedRoot::Tree { tree, .. }) => tree.retain()?,
        None => {}
    }
    Ok(())
}

async fn verify_block_seal<P>(
    path: &mut P,
    graph: &mut ReconstructionGraph,
    block: BlockId,
    data: &[u8],
    max_block: usize,
) -> Result<(), FileOracleError>
where
    P: ReceiveRecordPath,
{
    let digest = Digest(*blake3::hash(data).as_bytes());
    let encoded = path.receive_record().await?;
    let StreamRecord::BlockSeal {
        block: sealed,
        digest: declared,
    } = decode_stream_record(&encoded, max_block)?
    else {
        return Err(FileOracleError::UnexpectedRecord);
    };
    if sealed != block || declared != digest {
        return Err(FileOracleError::UnexpectedRecord);
    }
    graph.declare_block_seal(block, declared)?;
    graph.verify_block(block, digest)?;
    Ok(())
}

async fn receive_entry_seal<P>(
    path: &mut P,
    entry: EntryId,
    hasher: blake3::Hasher,
) -> Result<Digest, FileOracleError>
where
    P: ReceiveRecordPath,
{
    let digest = Digest(*hasher.finalize().as_bytes());
    let encoded = path.receive_record().await?;
    let StreamRecord::EntrySeal {
        entry: sealed,
        digest: declared,
    } = decode_stream_record(&encoded, MAX_STREAM_BLOCK_BYTES)?
    else {
        return Err(FileOracleError::UnexpectedRecord);
    };
    if sealed != entry || declared != digest {
        return Err(FileOracleError::UnexpectedRecord);
    }
    Ok(digest)
}

async fn commit_received<P>(
    path: &mut P,
    mut state: ReceiveState,
) -> Result<ReceiveSummary, FileOracleError>
where
    P: ReceiveRecordPath,
{
    if state.received_bytes != state.total_length {
        return Err(FileOracleError::UnexpectedRecord);
    }
    let encoded = path.receive_record().await?;
    let StreamRecord::ObjectSeal { digest } =
        decode_stream_record(&encoded, MAX_STREAM_BLOCK_BYTES)?
    else {
        return Err(FileOracleError::UnexpectedRecord);
    };
    let computed = Digest(*state.object_hasher.finalize().as_bytes());
    if digest != computed {
        return Err(FileOracleError::UnexpectedRecord);
    }
    state.graph.declare_final_seal(digest)?;
    state.graph.verify_final(computed)?;
    if !state.graph.ready_to_commit() {
        return Err(FileOracleError::UnexpectedRecord);
    }
    let destination = state
        .destination
        .take()
        .ok_or(FileOracleError::UnexpectedRecord)?;
    let receipt = commit_staging(
        state.staged_root,
        state.root_file_digest,
        digest,
        state.total_length,
    )
    .await?;
    let delivery = path.send_receipt(receipt.digest, receipt.length).await?;
    Ok(ReceiveSummary {
        length: receipt.length,
        digest: receipt.digest,
        blocks: state.block_index,
        entries: state.entries,
        transport: TransferTransport::Relay,
        destination,
        receipt: delivery,
        migration: None,
        profile: TransferProfile::default(),
    })
}

async fn commit_staging(
    staged: Option<StagedRoot>,
    root_file_digest: Option<Digest>,
    object_digest: Digest,
    length: u64,
) -> Result<crate::CommitReceipt, FileOracleError> {
    match staged.ok_or(FileOracleError::UnexpectedRecord)? {
        StagedRoot::File { file, .. } => {
            let mut receipt = (*file)
                .finish(root_file_digest.ok_or(FileOracleError::UnexpectedRecord)?)
                .await?
                .commit()
                .await?;
            receipt.digest = object_digest;
            Ok(receipt)
        }
        StagedRoot::Tree { tree, metadata } => {
            // Open and flush directory handles before authenticated metadata can
            // remove traversal permission. The verified tree retains those
            // handles and syncs through them again before atomic visibility.
            let verified = tree.finish(object_digest, length).await?;
            for (path, directory, metadata) in metadata.into_iter().rev() {
                apply_portable_metadata(&path, directory, metadata).await?;
            }
            Ok(verified.commit().await?)
        }
    }
}

pub(crate) async fn scan_source(
    source: &Path,
    limits: HardLimits,
) -> Result<SourceObject, FileOracleError> {
    let root_name = portable_component(
        source
            .file_name()
            .ok_or(FileOracleError::InvalidComponent)?,
    )?;
    let root_bytes = component_bytes(&root_name)?;
    let mut pending = vec![PendingSource {
        path: source.to_owned(),
        parent: None,
        depth: 1,
        path_bytes: root_bytes,
    }];
    let mut entries = Vec::new();
    let mut total_length = 0_u64;
    let mut metadata_bytes = 0_u64;

    while let Some(pending_entry) = pending.pop() {
        if pending_entry.depth > limits.max_depth
            || pending_entry.path_bytes > limits.max_path_bytes
        {
            return Err(FileOracleError::LimitExceeded);
        }
        if u64::try_from(entries.len()).map_err(|_| FileOracleError::LimitExceeded)?
            >= limits.max_entries
        {
            return Err(FileOracleError::LimitExceeded);
        }
        let id = EntryId(u64::try_from(entries.len()).map_err(|_| FileOracleError::LimitExceeded)?);
        let entry = inspect_source_entry(&pending_entry, id).await?;
        total_length = total_length
            .checked_add(entry.length)
            .ok_or(FileOracleError::LimitExceeded)?;
        if total_length > limits.max_object_bytes {
            return Err(FileOracleError::LimitExceeded);
        }
        metadata_bytes = admit_metadata(
            metadata_bytes,
            pending_entry.path_bytes,
            30_usize
                .checked_add(entry.name.len())
                .ok_or(FileOracleError::LimitExceeded)?,
            limits.max_reconstruction_bytes,
        )?;
        if entry.kind == SourceKind::Directory {
            enqueue_children(&mut pending, &pending_entry, id).await?;
        }
        entries.push(entry);
    }
    Ok(SourceObject {
        entries,
        total_length,
    })
}

async fn inspect_source_entry(
    pending: &PendingSource,
    id: EntryId,
) -> Result<SourceEntry, FileOracleError> {
    let metadata = fs::symlink_metadata(&pending.path)
        .await
        .map_err(FileOracleError::SourceIo)?;
    let kind = if metadata.is_file() {
        SourceKind::File
    } else if metadata.is_dir() {
        SourceKind::Directory
    } else {
        return Err(FileOracleError::UnsupportedFileType);
    };
    let length = if kind == SourceKind::File {
        metadata.len()
    } else {
        0
    };
    Ok(SourceEntry {
        id,
        parent: pending.parent,
        name: portable_component(
            pending
                .path
                .file_name()
                .ok_or(FileOracleError::InvalidComponent)?,
        )?,
        path: pending.path.clone(),
        kind,
        length,
        metadata: metadata_flags(&metadata),
    })
}

async fn enqueue_children(
    pending: &mut Vec<PendingSource>,
    directory: &PendingSource,
    parent: EntryId,
) -> Result<(), FileOracleError> {
    let depth = directory
        .depth
        .checked_add(1)
        .ok_or(FileOracleError::LimitExceeded)?;
    for (name, path) in sorted_children(&directory.path).await?.into_iter().rev() {
        let path_bytes = directory
            .path_bytes
            .checked_add(1)
            .and_then(|bytes| bytes.checked_add(component_bytes(&name).ok()?))
            .ok_or(FileOracleError::LimitExceeded)?;
        pending.push(PendingSource {
            path,
            parent: Some(parent),
            depth,
            path_bytes,
        });
    }
    Ok(())
}

async fn sorted_children(path: &Path) -> Result<Vec<(String, PathBuf)>, FileOracleError> {
    let mut directory = fs::read_dir(path)
        .await
        .map_err(FileOracleError::SourceIo)?;
    let mut children = Vec::new();
    let mut portable_names = BTreeSet::new();
    while let Some(child) = directory
        .next_entry()
        .await
        .map_err(FileOracleError::SourceIo)?
    {
        let name = portable_component(&child.file_name())?;
        if !portable_names.insert(portable_component_key(&name)) {
            return Err(FileOracleError::InvalidComponent);
        }
        children.push((name, child.path()));
    }
    children.sort_by(|left, right| left.0.as_bytes().cmp(right.0.as_bytes()));
    Ok(children)
}

fn portable_component(component: &OsStr) -> Result<String, FileOracleError> {
    let component = component
        .to_str()
        .ok_or(FileOracleError::InvalidComponent)?;
    validate_component(component, HardLimits::CONSERVATIVE)?;
    Ok(component.to_owned())
}

pub(crate) fn validate_component(
    component: &str,
    limits: HardLimits,
) -> Result<(), FileOracleError> {
    let bytes = component.as_bytes();
    if component.is_empty()
        || component == "."
        || component == ".."
        || bytes.len() > MAX_STREAM_COMPONENT_BYTES
        || u32::try_from(bytes.len()).map_or(true, |length| length > limits.max_path_bytes)
        || bytes.contains(&0)
        || component
            .chars()
            .any(|character| character <= '\u{1f}' || "<>:\"/\\|?*".contains(character))
        || component.ends_with([' ', '.'])
        || !component.nfc().eq(component.chars())
        || windows_reserved_component(component)
    {
        return Err(FileOracleError::InvalidComponent);
    }
    Ok(())
}

pub(crate) fn portable_component_key(component: &str) -> String {
    component.nfc().flat_map(char::to_lowercase).nfc().collect()
}

fn windows_reserved_component(component: &str) -> bool {
    let base = component.split('.').next().unwrap_or_default();
    let upper = base.to_ascii_uppercase();
    matches!(
        upper.as_str(),
        "CON" | "PRN" | "AUX" | "NUL" | "CLOCK$" | "CONIN$" | "CONOUT$"
    ) || upper.len() == 4
        && matches!(&upper[..3], "COM" | "LPT")
        && matches!(upper.as_bytes()[3], b'1'..=b'9')
}

pub(crate) fn component_bytes(component: &str) -> Result<u32, FileOracleError> {
    u32::try_from(component.len()).map_err(|_| FileOracleError::LimitExceeded)
}

fn admit_metadata(
    current: u64,
    path_bytes: u32,
    record_bytes: usize,
    limit: u64,
) -> Result<u64, FileOracleError> {
    let record_bytes = u64::try_from(record_bytes).map_err(|_| FileOracleError::LimitExceeded)?;
    let entry_bytes = u64::from(path_bytes)
        .checked_mul(2)
        .and_then(|bytes| bytes.checked_add(record_bytes))
        .and_then(|bytes| bytes.checked_add(METADATA_ENTRY_OVERHEAD))
        .ok_or(FileOracleError::LimitExceeded)?;
    let total = current
        .checked_add(entry_bytes)
        .ok_or(FileOracleError::LimitExceeded)?;
    if total > limit {
        return Err(FileOracleError::LimitExceeded);
    }
    Ok(total)
}

fn object_hasher(entries: u64, total_length: u64, block_bytes: u32) -> blake3::Hasher {
    let mut hasher = blake3::Hasher::new_derive_key("RIFT authenticated filesystem object v1");
    hasher.update(&entries.to_be_bytes());
    hasher.update(&total_length.to_be_bytes());
    hasher.update(&block_bytes.to_be_bytes());
    hasher
}

fn metadata_flags(metadata: &asupersync::fs::Metadata) -> u16 {
    #[cfg(unix)]
    {
        let mode = metadata.permissions().mode() & 0o7777;
        UNIX_MODE | u16::try_from(mode).unwrap_or(0)
    }
    #[cfg(not(unix))]
    {
        let readonly = metadata.permissions().readonly();
        let executable = false;
        u16::from(readonly) * PORTABLE_READONLY | u16::from(executable) * PORTABLE_EXECUTABLE
    }
}

pub(crate) async fn apply_portable_metadata(
    path: &Path,
    directory: bool,
    metadata: u16,
) -> Result<(), FileOracleError> {
    let current = fs::metadata(path).await.map_err(StageError::Io)?;
    let mut permissions = current.permissions();
    #[cfg(unix)]
    {
        let mode = if metadata & UNIX_MODE != 0 {
            u32::from(metadata & 0o7777)
        } else {
            let mut mode = if directory { 0o755 } else { 0o644 };
            if metadata & PORTABLE_EXECUTABLE != 0 {
                mode |= 0o111;
            }
            if metadata & PORTABLE_READONLY != 0 {
                mode &= !0o222;
            }
            mode
        };
        permissions.set_mode(mode);
    }
    #[cfg(not(unix))]
    {
        let readonly = if metadata & UNIX_MODE != 0 {
            metadata & 0o222 == 0
        } else {
            metadata & PORTABLE_READONLY != 0
        };
        let _ = directory;
        permissions.set_readonly(readonly);
    }
    fs::set_permissions(path, permissions)
        .await
        .map_err(StageError::Io)?;
    Ok(())
}

async fn send_record_on<P>(
    path: &mut P,
    record: StreamRecord<'_>,
    remaining_object_bytes: u64,
) -> Result<(), FileOracleError>
where
    P: SendRecordPath,
{
    path.send_record(record.encode()?, remaining_object_bytes)
        .await
}

#[cfg(test)]
mod tests {
    use std::collections::VecDeque;
    use std::sync::{
        Arc,
        atomic::{AtomicU64, Ordering},
    };

    use asupersync::net::{TcpListener, TcpStream, UdpSocket};
    use rift_transport::QuicServerIdentity;

    use super::*;
    use crate::{HandshakeRole, RuntimePolicy, build_runtime};

    struct ScriptedReceivePath {
        records: VecDeque<Vec<u8>>,
    }

    struct ChannelSendPath {
        outgoing: mpsc::Sender<Vec<u8>>,
        incoming: mpsc::Receiver<Vec<u8>>,
        fail_after_blocks: Option<u64>,
        sealed_blocks: u64,
        payload_bytes: Arc<AtomicU64>,
    }

    struct ChannelReceivePath {
        incoming: mpsc::Receiver<Vec<u8>>,
        outgoing: mpsc::Sender<Vec<u8>>,
    }

    fn interrupted() -> FileOracleError {
        FileOracleError::Stream(SecureStreamError::Io(io::Error::new(
            io::ErrorKind::ConnectionReset,
            "injected path interruption",
        )))
    }

    impl SendRecordPath for ChannelSendPath {
        async fn send_record(
            &mut self,
            encoded: Vec<u8>,
            _remaining_object_bytes: u64,
        ) -> Result<(), FileOracleError> {
            if self
                .fail_after_blocks
                .is_some_and(|limit| self.sealed_blocks >= limit)
            {
                return Err(interrupted());
            }
            match decode_stream_record(&encoded, MAX_STREAM_BLOCK_BYTES)? {
                StreamRecord::BlockData { data, .. } => {
                    self.payload_bytes.fetch_add(
                        u64::try_from(data.len()).map_err(|_| FileOracleError::LimitExceeded)?,
                        Ordering::Relaxed,
                    );
                }
                StreamRecord::BlockSeal { .. } => {
                    self.sealed_blocks = self.sealed_blocks.saturating_add(1);
                }
                _ => {}
            }
            let cx = Cx::current().ok_or_else(interrupted)?;
            self.outgoing
                .send(&cx, encoded)
                .await
                .map_err(|_| interrupted())
        }

        async fn receive_resume_offer(
            &mut self,
            entry: EntryId,
        ) -> Result<(u64, Digest), FileOracleError> {
            let cx = Cx::current().ok_or_else(interrupted)?;
            let encoded = self.incoming.recv(&cx).await.map_err(|_| interrupted())?;
            decode_resume_offer(&encoded, entry)
        }

        async fn send_resume_decision(
            &mut self,
            entry: EntryId,
            prefix: u64,
        ) -> Result<(), FileOracleError> {
            let cx = Cx::current().ok_or_else(interrupted)?;
            self.outgoing
                .send(
                    &cx,
                    StreamRecord::ResumeDecision { entry, prefix }.encode()?,
                )
                .await
                .map_err(|_| interrupted())
        }

        async fn receive_receipt(
            &mut self,
            expected_digest: Digest,
            expected_length: u64,
        ) -> Result<(), FileOracleError> {
            let cx = Cx::current().ok_or_else(interrupted)?;
            let encoded = self.incoming.recv(&cx).await.map_err(|_| interrupted())?;
            match decode_stream_record(&encoded, MAX_STREAM_BLOCK_BYTES)? {
                StreamRecord::CommitReceipt { digest, length }
                    if digest == expected_digest && length == expected_length =>
                {
                    Ok(())
                }
                _ => Err(FileOracleError::ReceiptMismatch),
            }
        }
    }

    impl ReceiveRecordPath for ChannelReceivePath {
        async fn receive_record(&mut self) -> Result<Vec<u8>, FileOracleError> {
            let cx = Cx::current().ok_or_else(interrupted)?;
            self.incoming.recv(&cx).await.map_err(|_| interrupted())
        }

        async fn send_resume_offer(
            &mut self,
            entry: EntryId,
            prefix: u64,
            digest: Digest,
        ) -> Result<(), FileOracleError> {
            let cx = Cx::current().ok_or_else(interrupted)?;
            self.outgoing
                .send(
                    &cx,
                    StreamRecord::ResumeOffer {
                        entry,
                        prefix,
                        digest,
                    }
                    .encode()?,
                )
                .await
                .map_err(|_| interrupted())
        }

        async fn receive_resume_decision(
            &mut self,
            entry: EntryId,
        ) -> Result<u64, FileOracleError> {
            let cx = Cx::current().ok_or_else(interrupted)?;
            let encoded = self.incoming.recv(&cx).await.map_err(|_| interrupted())?;
            decode_resume_decision(&encoded, entry)
        }

        async fn send_receipt(
            &mut self,
            digest: Digest,
            length: u64,
        ) -> Result<ReceiptDelivery, FileOracleError> {
            let cx = Cx::current().ok_or_else(interrupted)?;
            self.outgoing
                .send(
                    &cx,
                    StreamRecord::CommitReceipt { digest, length }.encode()?,
                )
                .await
                .map_err(|_| interrupted())?;
            Ok(ReceiptDelivery::Sent)
        }
    }

    fn channel_paths(
        fail_after_blocks: Option<u64>,
        payload_bytes: Arc<AtomicU64>,
    ) -> (ChannelSendPath, ChannelReceivePath) {
        let (to_receiver, receiver_incoming) = mpsc::channel(64);
        let (to_sender, sender_incoming) = mpsc::channel(64);
        (
            ChannelSendPath {
                outgoing: to_receiver,
                incoming: sender_incoming,
                fail_after_blocks,
                sealed_blocks: 0,
                payload_bytes,
            },
            ChannelReceivePath {
                incoming: receiver_incoming,
                outgoing: to_sender,
            },
        )
    }

    impl ReceiveRecordPath for ScriptedReceivePath {
        async fn receive_record(&mut self) -> Result<Vec<u8>, FileOracleError> {
            self.records
                .pop_front()
                .ok_or(FileOracleError::UnexpectedRecord)
        }

        async fn send_resume_offer(
            &mut self,
            _entry: EntryId,
            _prefix: u64,
            _digest: Digest,
        ) -> Result<(), FileOracleError> {
            Ok(())
        }

        async fn receive_resume_decision(
            &mut self,
            _entry: EntryId,
        ) -> Result<u64, FileOracleError> {
            Ok(0)
        }

        async fn send_receipt(
            &mut self,
            _digest: Digest,
            _length: u64,
        ) -> Result<ReceiptDelivery, FileOracleError> {
            Ok(ReceiptDelivery::Sent)
        }
    }

    fn transfer(source: PathBuf, destination: PathBuf) -> (SendSummary, ReceiveSummary) {
        let runtime = build_runtime(RuntimePolicy { worker_threads: 2 }).unwrap();
        let handle = runtime.handle();
        runtime.block_on(async move {
            let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
            let address = listener.local_addr().unwrap();
            let receiver = handle.spawn(async move {
                let (tcp, _) = listener.accept().await.unwrap();
                let mut stream = SecureStream::establish(
                    tcp,
                    HandshakeRole::Responder,
                    &[9; 32],
                    b"oracle-tree-test",
                )
                .await
                .unwrap();
                receive_object(&mut stream, destination, HardLimits::CONSERVATIVE)
                    .await
                    .unwrap()
            });
            let tcp = TcpStream::connect(address).await.unwrap();
            let mut stream = SecureStream::establish(
                tcp,
                HandshakeRole::Initiator,
                &[9; 32],
                b"oracle-tree-test",
            )
            .await
            .unwrap();
            let sent = send_object(&mut stream, source, HardLimits::CONSERVATIVE)
                .await
                .unwrap();
            (sent, receiver.await)
        })
    }

    fn quic_transfer(source: PathBuf, destination: PathBuf) -> (SendSummary, ReceiveSummary) {
        let runtime = build_runtime(RuntimePolicy { worker_threads: 4 }).unwrap();
        let handle = runtime.handle();
        runtime.block_on(async move {
            let receiver_socket = UdpSocket::bind("127.0.0.1:0").await.unwrap();
            let receiver_address = receiver_socket.local_addr().unwrap();
            let sender_socket = UdpSocket::bind("127.0.0.1:0").await.unwrap();
            let sender_address = sender_socket.local_addr().unwrap();
            let identity = QuicServerIdentity::generate().unwrap();
            let certificate = identity.certificate();
            let receiver = handle.spawn(async move {
                let mut link = DirectQuicLink::listen(receiver_socket, sender_address, &identity);
                receive_object_quic(
                    &mut link,
                    ReceiveTarget::Exact(destination),
                    HardLimits::CONSERVATIVE,
                )
                .await
                .unwrap()
            });
            let mut link =
                DirectQuicLink::connect(sender_socket, receiver_address, &certificate).unwrap();
            let sent = send_object_quic(&mut link, source, HardLimits::CONSERVATIVE)
                .await
                .unwrap();
            (sent, receiver.await)
        })
    }

    #[test]
    fn directory_target_chooses_a_familiar_non_clobbering_name() {
        let directory = tempfile::tempdir().unwrap();
        std::fs::write(directory.path().join("report.pdf"), b"first").unwrap();
        std::fs::write(directory.path().join("report (1).pdf"), b"second").unwrap();
        std::fs::create_dir(directory.path().join("photos")).unwrap();
        let runtime = build_runtime(RuntimePolicy { worker_threads: 1 }).unwrap();

        runtime.block_on(async {
            let target = ReceiveTarget::Directory(directory.path().to_owned());
            assert_eq!(
                target.resolve("report.pdf", false).await.unwrap(),
                directory.path().join("report (2).pdf")
            );
            assert_eq!(
                target.resolve("photos", true).await.unwrap(),
                directory.path().join("photos (1)")
            );
        });
    }

    #[test]
    fn exact_target_remains_strict_even_when_it_already_exists() {
        let directory = tempfile::tempdir().unwrap();
        let destination = directory.path().join("report.pdf");
        std::fs::write(&destination, b"original").unwrap();
        let runtime = build_runtime(RuntimePolicy { worker_threads: 1 }).unwrap();

        let resolved = runtime.block_on(async {
            ReceiveTarget::Exact(destination.clone())
                .resolve("ignored.pdf", false)
                .await
                .unwrap()
        });
        assert_eq!(resolved, destination);
    }

    #[test]
    fn interrupted_live_transfer_reuses_only_a_locally_reverified_prefix() {
        let directory = tempfile::tempdir().unwrap();
        let source = directory.path().join("source.bin");
        let destination = directory.path().join("destination.bin");
        let contents: Vec<u8> = (0_u32..1_500_000).flat_map(u32::to_be_bytes).collect();
        std::fs::write(&source, &contents).unwrap();
        let runtime = build_runtime(RuntimePolicy { worker_threads: 4 }).unwrap();
        let handle = runtime.handle();

        runtime.block_on(async {
            let token = ResumeToken::generate().unwrap();
            let first_bytes = Arc::new(AtomicU64::new(0));
            let (mut sender, mut receiver) = channel_paths(Some(7), Arc::clone(&first_bytes));
            let first_destination = destination.clone();
            let first_receiver = handle.spawn(async move {
                receive_object_observed_on_with_resume(
                    &mut receiver,
                    ReceiveTarget::Exact(first_destination),
                    HardLimits::CONSERVATIVE,
                    &NoopObserver,
                    true,
                )
                .await
            });
            let first_sender = send_object_on_with_resume(
                &mut sender,
                &source,
                HardLimits::CONSERVATIVE,
                &NoopObserver,
                Some(&token),
            )
            .await;
            drop(sender);
            let first_receiver = first_receiver.await;
            assert!(first_sender.is_err());
            assert!(first_receiver.is_err());
            assert!(!destination.exists());
            assert_eq!(
                first_bytes.load(Ordering::Relaxed),
                7 * u64::from(STREAM_BLOCK_BYTES)
            );

            let resumed_bytes = Arc::new(AtomicU64::new(0));
            let (mut sender, mut receiver) = channel_paths(None, Arc::clone(&resumed_bytes));
            let resumed_destination = destination.clone();
            let resumed_receiver = handle.spawn(async move {
                receive_object_observed_on_with_resume(
                    &mut receiver,
                    ReceiveTarget::Exact(resumed_destination),
                    HardLimits::CONSERVATIVE,
                    &NoopObserver,
                    true,
                )
                .await
                .unwrap()
            });
            let sent = send_object_on_with_resume(
                &mut sender,
                &source,
                HardLimits::CONSERVATIVE,
                &NoopObserver,
                Some(&token),
            )
            .await
            .unwrap();
            let received_summary = resumed_receiver.await;
            assert_eq!(sent.digest, received_summary.digest);
            assert_eq!(std::fs::read(&destination).unwrap(), contents);
            assert_eq!(
                resumed_bytes.load(Ordering::Relaxed),
                sent.length - 7 * u64::from(STREAM_BLOCK_BYTES)
            );
        });
    }

    #[test]
    fn encrypted_loopback_transfers_directory_atomically() {
        let directory = tempfile::tempdir().unwrap();
        let source = directory.path().join("source");
        let destination = directory.path().join("destination");
        std::fs::create_dir(&source).unwrap();
        std::fs::create_dir(source.join("empty")).unwrap();
        std::fs::create_dir(source.join("nested")).unwrap();
        std::fs::write(source.join("empty.txt"), b"").unwrap();
        std::fs::write(source.join("hello.txt"), b"hello").unwrap();
        let contents: Vec<u8> = (0_u32..50_000).flat_map(u32::to_be_bytes).collect();
        std::fs::write(source.join("nested/data.bin"), &contents).unwrap();

        let (sent, received) = transfer(source, destination);

        assert_eq!(sent.digest, received.digest);
        assert_eq!(sent.length, received.length);
        assert_eq!(sent.transport, TransferTransport::Relay);
        assert_eq!(received.transport, TransferTransport::Relay);
        assert_eq!(sent.entries, 6);
        assert_eq!(received.receipt, ReceiptDelivery::Sent);
        assert!(directory.path().join("destination/empty").is_dir());
        assert_eq!(
            std::fs::read(directory.path().join("destination/empty.txt")).unwrap(),
            b""
        );
        assert_eq!(
            std::fs::read(directory.path().join("destination/nested/data.bin")).unwrap(),
            contents
        );
        assert_eq!(
            std::fs::read(directory.path().join("destination/hello.txt")).unwrap(),
            b"hello"
        );
    }

    #[test]
    fn quic_loopback_streams_and_atomically_commits_a_large_file() {
        let directory = tempfile::tempdir().unwrap();
        let source = directory.path().join("source.bin");
        let destination = directory.path().join("destination.bin");
        let contents = (0..8 * 1024 * 1024)
            .map(|index| u8::try_from(index % 251).unwrap())
            .collect::<Vec<_>>();
        std::fs::write(&source, &contents).unwrap();

        let (sent, received) = quic_transfer(source, destination.clone());

        assert_eq!(sent.digest, received.digest);
        assert_eq!(sent.length, received.length);
        assert_eq!(sent.transport, TransferTransport::DirectQuic);
        assert_eq!(received.transport, TransferTransport::DirectQuic);
        assert_eq!(received.receipt, ReceiptDelivery::Sent);
        assert_eq!(std::fs::read(destination).unwrap(), contents);
    }

    #[test]
    fn encrypted_loopback_transfers_an_empty_tree() {
        let directory = tempfile::tempdir().unwrap();
        let source = directory.path().join("empty-root");
        let destination = directory.path().join("destination");
        std::fs::create_dir(&source).unwrap();

        let (sent, received) = transfer(source, destination.clone());

        assert_eq!(sent.digest, received.digest);
        assert_eq!(sent.length, 0);
        assert_eq!(sent.blocks, 0);
        assert_eq!(sent.entries, 1);
        assert_eq!(received.receipt, ReceiptDelivery::Sent);
        assert!(destination.is_dir());
        assert_eq!(std::fs::read_dir(destination).unwrap().count(), 0);
    }

    #[test]
    fn source_manifest_is_bounded_by_the_reconstruction_budget() {
        let directory = tempfile::tempdir().unwrap();
        let source = directory.path().join("source");
        std::fs::create_dir(&source).unwrap();
        std::fs::write(source.join("child-name-long"), b"").unwrap();
        let limits = HardLimits {
            max_reconstruction_bytes: 512,
            ..HardLimits::CONSERVATIVE
        };
        let runtime = build_runtime(RuntimePolicy { worker_threads: 1 }).unwrap();

        assert!(matches!(
            runtime.block_on(scan_source(&source, limits)),
            Err(FileOracleError::LimitExceeded)
        ));
    }

    #[test]
    fn receiver_rejects_tree_metadata_beyond_its_memory_authority() {
        let directory = tempfile::tempdir().unwrap();
        let destination = directory.path().join("destination");
        let long_name = "x".repeat(100);
        let other_long_name = "y".repeat(100);
        let records = [
            StreamRecord::TreeStart {
                object_id: [1; 16],
                entries: 3,
                total_length: 0,
                block_bytes: STREAM_BLOCK_BYTES,
            }
            .encode()
            .unwrap(),
            StreamRecord::TreeEntry {
                entry: EntryId(0),
                parent: None,
                directory: true,
                length: 0,
                metadata: 0,
                name: "root",
            }
            .encode()
            .unwrap(),
            StreamRecord::TreeEntry {
                entry: EntryId(1),
                parent: Some(EntryId(0)),
                directory: true,
                length: 0,
                metadata: 0,
                name: &other_long_name,
            }
            .encode()
            .unwrap(),
            StreamRecord::TreeEntry {
                entry: EntryId(2),
                parent: Some(EntryId(0)),
                directory: true,
                length: 0,
                metadata: 0,
                name: &long_name,
            }
            .encode()
            .unwrap(),
        ];
        let mut path = ScriptedReceivePath {
            records: records.into(),
        };
        let limits = HardLimits {
            max_reconstruction_bytes: 1_200,
            ..HardLimits::CONSERVATIVE
        };
        let runtime = build_runtime(RuntimePolicy { worker_threads: 1 }).unwrap();

        assert!(matches!(
            runtime.block_on(receive_object_on(
                &mut path,
                ReceiveTarget::Exact(destination.clone()),
                limits,
            )),
            Err(FileOracleError::LimitExceeded)
        ));
        assert!(!destination.exists());
        assert_eq!(std::fs::read_dir(directory.path()).unwrap().count(), 0);
    }

    #[test]
    fn scan_order_is_canonical_and_symlinks_are_rejected() {
        let directory = tempfile::tempdir().unwrap();
        let source = directory.path().join("root");
        std::fs::create_dir(&source).unwrap();
        std::fs::write(source.join("z"), b"z").unwrap();
        std::fs::write(source.join("a"), b"a").unwrap();
        let runtime = build_runtime(RuntimePolicy { worker_threads: 1 }).unwrap();
        let scanned = runtime
            .block_on(scan_source(&source, HardLimits::CONSERVATIVE))
            .unwrap();
        assert_eq!(
            scanned
                .entries
                .iter()
                .map(|entry| entry.name.as_str())
                .collect::<Vec<_>>(),
            vec!["root", "a", "z"]
        );

        #[cfg(unix)]
        {
            std::os::unix::fs::symlink("a", source.join("link")).unwrap();
            assert!(matches!(
                runtime.block_on(scan_source(&source, HardLimits::CONSERVATIVE)),
                Err(FileOracleError::UnsupportedFileType)
            ));
        }
    }

    #[test]
    fn portable_components_reject_windows_aliases_and_normalization_ambiguity() {
        for invalid in [
            "NUL.txt",
            "COM1",
            "trailing.",
            "trailing ",
            "a:b",
            "e\u{301}",
        ] {
            assert!(matches!(
                validate_component(invalid, HardLimits::CONSERVATIVE),
                Err(FileOracleError::InvalidComponent)
            ));
        }
        assert!(validate_component("é", HardLimits::CONSERVATIVE).is_ok());
        assert_eq!(
            portable_component_key("Readme"),
            portable_component_key("README")
        );
    }

    #[test]
    fn receiver_rejects_case_equivalent_siblings_before_visibility() {
        let directory = tempfile::tempdir().unwrap();
        let destination = directory.path().join("destination");
        let records = [
            StreamRecord::TreeStart {
                object_id: [2; 16],
                entries: 3,
                total_length: 0,
                block_bytes: STREAM_BLOCK_BYTES,
            }
            .encode()
            .unwrap(),
            StreamRecord::TreeEntry {
                entry: EntryId(0),
                parent: None,
                directory: true,
                length: 0,
                metadata: 0,
                name: "root",
            }
            .encode()
            .unwrap(),
            StreamRecord::TreeEntry {
                entry: EntryId(1),
                parent: Some(EntryId(0)),
                directory: true,
                length: 0,
                metadata: 0,
                name: "Readme",
            }
            .encode()
            .unwrap(),
            StreamRecord::TreeEntry {
                entry: EntryId(2),
                parent: Some(EntryId(0)),
                directory: true,
                length: 0,
                metadata: 0,
                name: "README",
            }
            .encode()
            .unwrap(),
        ];
        let mut path = ScriptedReceivePath {
            records: records.into(),
        };
        let runtime = build_runtime(RuntimePolicy { worker_threads: 1 }).unwrap();

        assert!(matches!(
            runtime.block_on(receive_object_on(
                &mut path,
                ReceiveTarget::Exact(destination.clone()),
                HardLimits::CONSERVATIVE,
            )),
            Err(FileOracleError::InvalidComponent)
        ));
        assert!(!destination.exists());
        assert_eq!(std::fs::read_dir(directory.path()).unwrap().count(), 0);
    }

    #[cfg(not(windows))]
    #[test]
    fn source_rejects_case_equivalent_siblings_before_network_use() {
        let directory = tempfile::tempdir().unwrap();
        let source = directory.path().join("root");
        std::fs::create_dir(&source).unwrap();
        std::fs::write(source.join("Readme"), b"one").unwrap();
        std::fs::write(source.join("README"), b"two").unwrap();
        let runtime = build_runtime(RuntimePolicy { worker_threads: 1 }).unwrap();

        assert!(matches!(
            runtime.block_on(scan_source(&source, HardLimits::CONSERVATIVE)),
            Err(FileOracleError::InvalidComponent)
        ));
    }
}
