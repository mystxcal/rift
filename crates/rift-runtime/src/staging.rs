//! Streaming file/tree staging and atomic no-clobber commit.

use std::{
    ffi::OsString,
    io,
    io::SeekFrom,
    path::{Path, PathBuf},
};

use asupersync::{
    fs::{self, File, OpenOptions},
    io::{AsyncReadExt, AsyncWriteExt},
};
use rift_core::Digest;
use thiserror::Error;

const CREATE_ATTEMPTS: usize = 16;
const STAGING_WRITE_BUFFER_BYTES: usize = 1024 * 1024;

/// Locally re-verified contiguous bytes available for live retry.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) struct ResumePrefix {
    pub(crate) length: u64,
    pub(crate) digest: Digest,
}

/// Mutable, invisible receiver staging file.
pub struct StagingFile {
    file: Option<File>,
    guard: Option<StagingGuard>,
    destination: PathBuf,
    expected_length: u64,
    written: u64,
    hasher: blake3::Hasher,
    pending: Vec<u8>,
}

/// Invisible sibling directory containing one staged object graph.
pub struct StagingTree {
    guard: Option<TreeGuard>,
    destination: PathBuf,
    directories: Vec<PathBuf>,
}

/// One regular file being written beneath an invisible staged tree.
pub struct StagingTreeFile {
    file: File,
    path: PathBuf,
    expected_length: u64,
    written: u64,
    hasher: blake3::Hasher,
    pending: Vec<u8>,
}

/// Fully verified tree that has not crossed the visibility boundary.
#[must_use = "verified tree staging must be committed or deliberately dropped"]
pub struct VerifiedStagingTree {
    guard: Option<TreeGuard>,
    destination: PathBuf,
    directory_handles: Vec<File>,
    parent_handle: Option<File>,
    length: u64,
    digest: Digest,
}

/// Integrity-verified file that has not crossed the visibility boundary.
#[must_use = "verified staging must be committed or deliberately dropped"]
pub struct VerifiedStaging {
    file: Option<File>,
    guard: Option<StagingGuard>,
    destination: PathBuf,
    length: u64,
    digest: Digest,
}

#[derive(Debug)]
struct StagingGuard {
    path: PathBuf,
    armed: bool,
}

#[derive(Debug)]
struct TreeGuard {
    path: PathBuf,
    armed: bool,
}

/// Failure before integrity verification.
#[derive(Debug, Error)]
pub enum StageError {
    /// Destination does not name a regular path entry with an existing parent.
    #[error("destination must include a file name and an existing parent")]
    InvalidDestination,
    /// Secure staging-name entropy was unavailable.
    #[error("secure operating-system entropy unavailable")]
    EntropyUnavailable,
    /// Filesystem operation failed before visibility.
    #[error("staging filesystem operation failed: {0}")]
    Io(#[from] io::Error),
    /// More bytes arrived than the immutable object declaration permits.
    #[error("received bytes exceed declared file length")]
    LengthExceeded,
    /// The stream ended before the declared length.
    #[error("received {actual} bytes, expected {expected}")]
    LengthMismatch {
        /// Declared logical length.
        expected: u64,
        /// Bytes actually staged.
        actual: u64,
    },
    /// Staged bytes do not satisfy the authenticated block/object commitment.
    #[error("staged file digest does not match the authenticated declaration")]
    DigestMismatch,
    /// An authenticated tree entry would collide with a prior staged entry.
    #[error("staged tree entry already exists")]
    EntryExists,
}

/// Atomic commit failure with an explicit visibility boundary.
#[derive(Debug, Error)]
pub enum CommitError {
    /// Defensive failure before visibility for impossible ownership corruption.
    #[error("verified staging ownership invariant failed")]
    InvariantViolation,
    /// Destination was not created. Retrying at a different destination is safe.
    #[error("commit failed before destination visibility: {0}")]
    BeforeVisibility(#[source] io::Error),
    /// Complete verified bytes are visible, but directory durability is unknown.
    #[error("destination is visible but directory durability could not be confirmed: {0}")]
    VisibleDurabilityUnknown(#[source] io::Error),
}

/// Whether the private staging link was removed after commit.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum CleanupStatus {
    /// Private staging name was removed.
    Cleaned,
    /// Destination is valid; removing a redundant private link must be retried.
    Deferred,
}

/// Truth required to construct an authenticated commit receipt.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct CommitReceipt {
    /// Digest of the committed logical bytes.
    pub digest: Digest,
    /// Committed logical byte length.
    pub length: u64,
    /// Non-semantic cleanup status for local observability.
    pub cleanup: CleanupStatus,
}

impl StagingFile {
    /// Atomically reserve a private sibling path and pre-size it.
    ///
    /// # Errors
    ///
    /// Returns [`StageError`] for invalid destination geometry, unavailable
    /// entropy, exhausted collision retries, or filesystem failure.
    pub async fn create(
        destination: impl AsRef<Path>,
        expected_length: u64,
    ) -> Result<Self, StageError> {
        let destination = destination.as_ref().to_owned();
        let parent = normalized_parent(&destination)?;
        let file_name = destination
            .file_name()
            .ok_or(StageError::InvalidDestination)?;

        if !fs::try_exists(&parent).await? {
            return Err(StageError::InvalidDestination);
        }

        for _ in 0..CREATE_ATTEMPTS {
            let staging = staging_path(&parent, file_name)?;
            match File::create_new(&staging).await {
                Ok(file) => {
                    return Ok(Self {
                        file: Some(file),
                        guard: Some(StagingGuard {
                            path: staging,
                            armed: true,
                        }),
                        destination,
                        expected_length,
                        written: 0,
                        hasher: blake3::Hasher::new(),
                        pending: Vec::with_capacity(STAGING_WRITE_BUFFER_BYTES),
                    });
                }
                Err(error) if error.kind() == io::ErrorKind::AlreadyExists => {}
                Err(error) => return Err(StageError::Io(error)),
            }
        }

        Err(StageError::Io(io::Error::new(
            io::ErrorKind::AlreadyExists,
            "could not reserve a unique staging path",
        )))
    }

    /// Open or create the stable invisible file for one live resume identity.
    pub(crate) async fn resume(
        destination: impl AsRef<Path>,
        expected_length: u64,
        object_id: [u8; 16],
    ) -> Result<Self, StageError> {
        let destination = destination.as_ref().to_owned();
        let parent = normalized_parent(&destination)?;
        let file_name = destination
            .file_name()
            .ok_or(StageError::InvalidDestination)?;
        if !fs::try_exists(&parent).await? || fs::try_exists(&destination).await? {
            return Err(StageError::InvalidDestination);
        }
        let staging = resumable_staging_path(&parent, file_name, object_id, "part");
        let file = open_append_file(&staging).await?;
        let written = file.metadata().await?.len();
        if written > expected_length {
            return Err(StageError::LengthExceeded);
        }
        let hasher = hash_prefix(&staging, written).await?;
        Ok(Self {
            file: Some(file),
            guard: Some(StagingGuard {
                path: staging,
                armed: true,
            }),
            destination,
            expected_length,
            written,
            hasher,
            pending: Vec::with_capacity(STAGING_WRITE_BUFFER_BYTES),
        })
    }

    pub(crate) async fn resume_piecewise(
        destination: impl AsRef<Path>,
        expected_length: u64,
        object_id: [u8; 16],
    ) -> Result<Self, StageError> {
        let destination = destination.as_ref().to_owned();
        let parent = normalized_parent(&destination)?;
        let file_name = destination
            .file_name()
            .ok_or(StageError::InvalidDestination)?;
        if !fs::try_exists(&parent).await? || fs::try_exists(&destination).await? {
            return Err(StageError::InvalidDestination);
        }
        let staging = resumable_staging_path(&parent, file_name, object_id, "part");
        let file = open_piece_file(&staging).await?;
        if file.metadata().await?.len() > expected_length {
            return Err(StageError::LengthExceeded);
        }
        Ok(Self {
            file: Some(file),
            guard: Some(StagingGuard {
                path: staging,
                armed: true,
            }),
            destination,
            expected_length,
            written: 0,
            hasher: blake3::Hasher::new(),
            pending: Vec::with_capacity(STAGING_WRITE_BUFFER_BYTES),
        })
    }

    pub(crate) fn resume_prefix(&self) -> ResumePrefix {
        ResumePrefix {
            length: self.written,
            digest: Digest(*self.hasher.clone().finalize().as_bytes()),
        }
    }

    pub(crate) async fn reset(&mut self) -> Result<(), StageError> {
        self.pending.clear();
        self.file_mut()?.set_len(0).await?;
        self.file_mut()?.seek(SeekFrom::Start(0)).await?;
        self.written = 0;
        self.hasher = blake3::Hasher::new();
        Ok(())
    }

    pub(crate) async fn retain(mut self) -> Result<(), StageError> {
        self.flush_pending().await?;
        self.file_mut()?.sync_all().await?;
        self.guard
            .as_mut()
            .ok_or_else(|| StageError::Io(io::Error::other("lost staging guard")))?
            .disarm();
        Ok(())
    }

    /// Append authenticated logical bytes in canonical order.
    ///
    /// # Errors
    ///
    /// Returns [`StageError`] when the write exceeds the immutable length or
    /// the staging filesystem write fails.
    pub async fn write(&mut self, bytes: &[u8]) -> Result<(), StageError> {
        let additional = u64::try_from(bytes.len()).map_err(|_| StageError::LengthExceeded)?;
        let next = self
            .written
            .checked_add(additional)
            .ok_or(StageError::LengthExceeded)?;
        if next > self.expected_length {
            return Err(StageError::LengthExceeded);
        }
        self.hasher.update(bytes);
        self.written = next;
        self.pending.extend_from_slice(bytes);
        if self.pending.len() >= STAGING_WRITE_BUFFER_BYTES {
            self.flush_pending().await?;
        }
        Ok(())
    }

    /// Write one independently verified piece at its immutable logical offset.
    ///
    /// This is deliberately separate from [`Self::write`]: piecewise writes
    /// are authenticated by the reconstruction graph and may arrive out of
    /// order, so the append hasher is neither advanced nor trusted.
    pub(crate) async fn write_at(&mut self, offset: u64, bytes: &[u8]) -> Result<(), StageError> {
        let length = u64::try_from(bytes.len()).map_err(|_| StageError::LengthExceeded)?;
        let end = offset
            .checked_add(length)
            .ok_or(StageError::LengthExceeded)?;
        if bytes.is_empty() || end > self.expected_length {
            return Err(StageError::LengthExceeded);
        }
        self.flush_pending().await?;
        self.file_mut()?.seek(SeekFrom::Start(offset)).await?;
        self.file_mut()?.write_all(bytes).await?;
        Ok(())
    }

    pub(crate) async fn read_at(
        &mut self,
        offset: u64,
        length: usize,
    ) -> Result<Vec<u8>, StageError> {
        let end = offset
            .checked_add(u64::try_from(length).map_err(|_| StageError::LengthExceeded)?)
            .ok_or(StageError::LengthExceeded)?;
        if end > self.expected_length {
            return Err(StageError::LengthExceeded);
        }
        self.flush_pending().await?;
        self.file_mut()?.seek(SeekFrom::Start(offset)).await?;
        let mut output = vec![0; length];
        self.file_mut()?.read_exact(&mut output).await?;
        Ok(output)
    }

    pub(crate) async fn reset_piecewise(&mut self) -> Result<(), StageError> {
        self.pending.clear();
        self.file_mut()?.set_len(0).await?;
        self.file_mut()?.seek(SeekFrom::Start(0)).await?;
        self.written = 0;
        self.hasher = blake3::Hasher::new();
        Ok(())
    }

    pub(crate) async fn checkpoint_piecewise(&mut self) -> Result<(), StageError> {
        self.flush_pending().await?;
        self.file_mut()?.sync_all().await?;
        Ok(())
    }

    /// Private staging path for metadata application before verification.
    ///
    /// # Panics
    ///
    /// Panics only if internal staging ownership was previously consumed while
    /// the mutable staging value remained accessible.
    #[must_use]
    pub fn staging_path(&self) -> &Path {
        &self.guard.as_ref().expect("live staging guard").path
    }

    /// Verify length and digest, then durably flush the private inode.
    ///
    /// # Errors
    ///
    /// Returns [`StageError`] for incomplete or corrupt bytes, lost staging
    /// ownership, or filesystem durability failure.
    pub async fn finish(mut self, expected_digest: Digest) -> Result<VerifiedStaging, StageError> {
        if self.written != self.expected_length {
            return Err(StageError::LengthMismatch {
                expected: self.expected_length,
                actual: self.written,
            });
        }
        let observed = Digest(*self.hasher.finalize().as_bytes());
        if observed != expected_digest {
            return Err(StageError::DigestMismatch);
        }
        self.flush_pending().await?;
        self.file_mut()?.sync_all().await?;

        Ok(VerifiedStaging {
            file: self.file.take(),
            guard: self.guard.take(),
            destination: self.destination.clone(),
            length: self.expected_length,
            digest: observed,
        })
    }

    /// Durably close a piecewise-verified file.
    ///
    /// The caller must have proved complete, non-overlapping geometry and the
    /// canonical object commitment. This method enforces the final filesystem
    /// length and durability boundary without re-reading the file.
    pub(crate) async fn finish_piecewise(
        mut self,
        expected_digest: Digest,
    ) -> Result<VerifiedStaging, StageError> {
        self.flush_pending().await?;
        let actual = self.file_mut()?.metadata().await?.len();
        if actual != self.expected_length {
            return Err(StageError::LengthMismatch {
                expected: self.expected_length,
                actual,
            });
        }
        self.file_mut()?.sync_all().await?;
        Ok(VerifiedStaging {
            file: self.file.take(),
            guard: self.guard.take(),
            destination: self.destination.clone(),
            length: self.expected_length,
            digest: expected_digest,
        })
    }

    fn file_mut(&mut self) -> Result<&mut File, StageError> {
        self.file.as_mut().ok_or_else(|| {
            StageError::Io(io::Error::other(
                "staging file ownership was already consumed",
            ))
        })
    }

    async fn flush_pending(&mut self) -> Result<(), StageError> {
        if self.pending.is_empty() {
            return Ok(());
        }
        let mut pending = std::mem::replace(
            &mut self.pending,
            Vec::with_capacity(STAGING_WRITE_BUFFER_BYTES),
        );
        self.file_mut()?.write_all(&pending).await?;
        pending.clear();
        self.pending = pending;
        Ok(())
    }
}

impl StagingTree {
    /// Reserve one private sibling directory for a complete object graph.
    ///
    /// # Errors
    ///
    /// Returns for invalid destination geometry, unavailable entropy,
    /// collision exhaustion, or filesystem failure.
    pub async fn create(destination: impl AsRef<Path>) -> Result<Self, StageError> {
        let destination = destination.as_ref().to_owned();
        let parent = normalized_parent(&destination)?;
        let file_name = destination
            .file_name()
            .ok_or(StageError::InvalidDestination)?;
        if !fs::try_exists(&parent).await? {
            return Err(StageError::InvalidDestination);
        }
        if fs::try_exists(&destination).await? {
            return Err(StageError::EntryExists);
        }

        for _ in 0..CREATE_ATTEMPTS {
            let staging = staging_tree_path(&parent, file_name)?;
            match fs::create_dir(&staging).await {
                Ok(()) => {
                    return Ok(Self {
                        guard: Some(TreeGuard {
                            path: staging.clone(),
                            armed: true,
                        }),
                        destination,
                        directories: vec![staging],
                    });
                }
                Err(error) if error.kind() == io::ErrorKind::AlreadyExists => {}
                Err(error) => return Err(StageError::Io(error)),
            }
        }
        Err(StageError::Io(io::Error::new(
            io::ErrorKind::AlreadyExists,
            "could not reserve a unique tree staging path",
        )))
    }

    /// Open or create the stable invisible tree for one live resume identity.
    pub(crate) async fn resume(
        destination: impl AsRef<Path>,
        object_id: [u8; 16],
    ) -> Result<Self, StageError> {
        let destination = destination.as_ref().to_owned();
        let parent = normalized_parent(&destination)?;
        let file_name = destination
            .file_name()
            .ok_or(StageError::InvalidDestination)?;
        if !fs::try_exists(&parent).await? || fs::try_exists(&destination).await? {
            return Err(StageError::InvalidDestination);
        }
        let staging = resumable_staging_path(&parent, file_name, object_id, "tree");
        if fs::try_exists(&staging).await? {
            if !fs::metadata(&staging).await?.is_dir() {
                return Err(StageError::EntryExists);
            }
        } else {
            fs::create_dir(&staging).await?;
        }
        Ok(Self {
            guard: Some(TreeGuard {
                path: staging.clone(),
                armed: true,
            }),
            destination,
            directories: vec![staging],
        })
    }

    /// Private staging root. Callers may only append validated components.
    ///
    /// # Panics
    ///
    /// Panics only if internal tree ownership was previously consumed while
    /// the mutable staging value remained accessible.
    #[must_use]
    pub fn root(&self) -> &Path {
        &self.guard.as_ref().expect("live tree guard").path
    }

    /// Create one directory below the staging root without replacing anything.
    ///
    /// # Errors
    ///
    /// Returns when the entry exists or filesystem creation fails.
    pub async fn create_directory(&mut self, path: &Path) -> Result<(), StageError> {
        match fs::create_dir(path).await {
            Ok(()) => {
                self.directories.push(path.to_owned());
                Ok(())
            }
            Err(error) if error.kind() == io::ErrorKind::AlreadyExists => {
                Err(StageError::EntryExists)
            }
            Err(error) => Err(StageError::Io(error)),
        }
    }

    pub(crate) async fn resume_directory(&mut self, path: &Path) -> Result<(), StageError> {
        if fs::try_exists(path).await? {
            if !fs::metadata(path).await?.is_dir() {
                return Err(StageError::EntryExists);
            }
        } else {
            fs::create_dir(path).await?;
        }
        self.directories.push(path.to_owned());
        Ok(())
    }

    /// Create one regular file below the staging root without replacement.
    ///
    /// # Errors
    ///
    /// Returns when the entry exists, cannot be pre-sized, or creation fails.
    pub async fn create_file(
        &self,
        path: &Path,
        expected_length: u64,
    ) -> Result<StagingTreeFile, StageError> {
        let file = File::create_new(path).await.map_err(|error| {
            if error.kind() == io::ErrorKind::AlreadyExists {
                StageError::EntryExists
            } else {
                StageError::Io(error)
            }
        })?;
        Ok(StagingTreeFile {
            file,
            path: path.to_owned(),
            expected_length,
            written: 0,
            hasher: blake3::Hasher::new(),
            pending: Vec::with_capacity(STAGING_WRITE_BUFFER_BYTES),
        })
    }

    pub(crate) async fn resume_file(
        &self,
        path: &Path,
        expected_length: u64,
    ) -> Result<StagingTreeFile, StageError> {
        let file = open_append_file(path).await?;
        let written = file.metadata().await?.len();
        if written > expected_length {
            return Err(StageError::LengthExceeded);
        }
        let hasher = hash_prefix(path, written).await?;
        Ok(StagingTreeFile {
            file,
            path: path.to_owned(),
            expected_length,
            written,
            hasher,
            pending: Vec::with_capacity(STAGING_WRITE_BUFFER_BYTES),
        })
    }

    pub(crate) async fn resume_piece_file(
        &self,
        path: &Path,
        expected_length: u64,
    ) -> Result<StagingTreeFile, StageError> {
        let file = open_piece_file(path).await?;
        if file.metadata().await?.len() > expected_length {
            return Err(StageError::LengthExceeded);
        }
        Ok(StagingTreeFile {
            file,
            path: path.to_owned(),
            expected_length,
            written: 0,
            hasher: blake3::Hasher::new(),
            pending: Vec::with_capacity(STAGING_WRITE_BUFFER_BYTES),
        })
    }

    pub(crate) fn retain(mut self) -> Result<(), StageError> {
        self.guard
            .as_mut()
            .ok_or_else(|| StageError::Io(io::Error::other("lost staging tree guard")))?
            .disarm();
        Ok(())
    }

    /// Durably close the invisible namespace after the caller has verified its
    /// complete authenticated graph.
    ///
    /// # Errors
    ///
    /// Returns when a directory flush fails.
    pub async fn finish(
        mut self,
        digest: Digest,
        length: u64,
    ) -> Result<VerifiedStagingTree, StageError> {
        let parent = normalized_parent(&self.destination)?;
        #[cfg(not(windows))]
        let directory_handles = {
            let mut handles = Vec::new();
            for directory in self.directories.iter().rev() {
                let handle = File::open(directory).await?;
                handle.sync_all().await?;
                handles.push(handle);
            }
            handles
        };
        #[cfg(windows)]
        let directory_handles = {
            let _ = &self.directories;
            Vec::new()
        };
        #[cfg(not(windows))]
        let parent_handle = {
            let handle = File::open(&parent).await?;
            handle.sync_all().await?;
            Some(handle)
        };
        #[cfg(windows)]
        let parent_handle = {
            let _ = parent;
            None
        };
        Ok(VerifiedStagingTree {
            guard: self.guard.take(),
            destination: self.destination.clone(),
            directory_handles,
            parent_handle,
            length,
            digest,
        })
    }
}

impl StagingTreeFile {
    /// Append bytes in canonical file order.
    ///
    /// # Errors
    ///
    /// Returns when the immutable length would be exceeded or writing fails.
    pub async fn write(&mut self, bytes: &[u8]) -> Result<(), StageError> {
        let additional = u64::try_from(bytes.len()).map_err(|_| StageError::LengthExceeded)?;
        let next = self
            .written
            .checked_add(additional)
            .ok_or(StageError::LengthExceeded)?;
        if next > self.expected_length {
            return Err(StageError::LengthExceeded);
        }
        self.hasher.update(bytes);
        self.written = next;
        self.pending.extend_from_slice(bytes);
        if self.pending.len() >= STAGING_WRITE_BUFFER_BYTES {
            self.flush_pending().await?;
        }
        Ok(())
    }

    /// Write one independently verified out-of-order piece.
    pub(crate) async fn write_at(&mut self, offset: u64, bytes: &[u8]) -> Result<(), StageError> {
        let length = u64::try_from(bytes.len()).map_err(|_| StageError::LengthExceeded)?;
        let end = offset
            .checked_add(length)
            .ok_or(StageError::LengthExceeded)?;
        if bytes.is_empty() || end > self.expected_length {
            return Err(StageError::LengthExceeded);
        }
        self.flush_pending().await?;
        self.file.seek(SeekFrom::Start(offset)).await?;
        self.file.write_all(bytes).await?;
        Ok(())
    }

    pub(crate) async fn read_at(
        &mut self,
        offset: u64,
        length: usize,
    ) -> Result<Vec<u8>, StageError> {
        let end = offset
            .checked_add(u64::try_from(length).map_err(|_| StageError::LengthExceeded)?)
            .ok_or(StageError::LengthExceeded)?;
        if end > self.expected_length {
            return Err(StageError::LengthExceeded);
        }
        self.flush_pending().await?;
        self.file.seek(SeekFrom::Start(offset)).await?;
        let mut output = vec![0; length];
        self.file.read_exact(&mut output).await?;
        Ok(output)
    }

    pub(crate) fn resume_prefix(&self) -> ResumePrefix {
        ResumePrefix {
            length: self.written,
            digest: Digest(*self.hasher.clone().finalize().as_bytes()),
        }
    }

    pub(crate) async fn reset(&mut self) -> Result<(), StageError> {
        self.pending.clear();
        self.file.set_len(0).await?;
        self.file.seek(SeekFrom::Start(0)).await?;
        self.written = 0;
        self.hasher = blake3::Hasher::new();
        Ok(())
    }

    pub(crate) async fn checkpoint(&mut self) -> Result<(), StageError> {
        self.flush_pending().await?;
        self.file.sync_all().await?;
        Ok(())
    }

    pub(crate) async fn reset_piecewise(&mut self) -> Result<(), StageError> {
        self.pending.clear();
        self.file.set_len(0).await?;
        self.file.seek(SeekFrom::Start(0)).await?;
        self.written = 0;
        self.hasher = blake3::Hasher::new();
        Ok(())
    }

    /// Flush a piecewise-verified file without a second content pass.
    pub(crate) async fn finish_piecewise(mut self) -> Result<(), StageError> {
        self.flush_pending().await?;
        let actual = self.file.metadata().await?.len();
        if actual != self.expected_length {
            return Err(StageError::LengthMismatch {
                expected: self.expected_length,
                actual,
            });
        }
        self.file.sync_all().await?;
        Ok(())
    }

    /// Verify and flush one file while it remains below the invisible root.
    ///
    /// # Errors
    ///
    /// Returns for an incomplete/corrupt file or a durability failure.
    pub async fn finish(mut self, expected_digest: Digest) -> Result<(), StageError> {
        if self.written != self.expected_length {
            return Err(StageError::LengthMismatch {
                expected: self.expected_length,
                actual: self.written,
            });
        }
        if Digest(*self.hasher.finalize().as_bytes()) != expected_digest {
            return Err(StageError::DigestMismatch);
        }
        self.flush_pending().await?;
        self.file.sync_all().await?;
        Ok(())
    }

    /// Path used for portable metadata application after verification.
    #[must_use]
    pub fn path(&self) -> &Path {
        &self.path
    }

    async fn flush_pending(&mut self) -> Result<(), StageError> {
        if self.pending.is_empty() {
            return Ok(());
        }
        self.file.write_all(&self.pending).await?;
        self.pending.clear();
        Ok(())
    }
}

impl Drop for StagingFile {
    fn drop(&mut self) {
        drop(self.file.take());
        drop(self.guard.take());
    }
}

impl VerifiedStaging {
    /// Install the verified inode without replacing an existing destination.
    ///
    /// The hard-link operation is the single visibility point. Staging and
    /// destination are siblings, so this cannot cross filesystems.
    ///
    /// # Errors
    ///
    /// Returns [`CommitError::BeforeVisibility`] when no destination was
    /// created, or [`CommitError::VisibleDurabilityUnknown`] when complete
    /// verified bytes are visible but parent-directory sync failed.
    pub async fn commit(mut self) -> Result<CommitReceipt, CommitError> {
        drop(self.file.take());
        let staging = self
            .guard
            .as_ref()
            .ok_or(CommitError::InvariantViolation)?
            .path
            .clone();
        let parent =
            normalized_parent(&self.destination).map_err(|_| CommitError::InvariantViolation)?;

        fs::hard_link(&staging, &self.destination)
            .await
            .map_err(CommitError::BeforeVisibility)?;

        sync_parent_directory(&parent)
            .await
            .map_err(CommitError::VisibleDurabilityUnknown)?;

        let cleanup = match fs::remove_file(&staging).await {
            Ok(()) => {
                self.guard
                    .as_mut()
                    .ok_or(CommitError::InvariantViolation)?
                    .disarm();
                CleanupStatus::Cleaned
            }
            Err(_) => CleanupStatus::Deferred,
        };

        Ok(CommitReceipt {
            digest: self.digest,
            length: self.length,
            cleanup,
        })
    }
}

impl Drop for VerifiedStaging {
    fn drop(&mut self) {
        drop(self.file.take());
        drop(self.guard.take());
    }
}

impl VerifiedStagingTree {
    /// Atomically expose a verified tree at an absent destination.
    ///
    /// Local sibling-directory ownership is part of the receiver trust
    /// boundary; network input never controls either absolute path.
    ///
    /// # Errors
    ///
    /// Returns before visibility if the destination appeared or rename failed,
    /// and after visibility only when the parent durability check fails.
    pub async fn commit(mut self) -> Result<CommitReceipt, CommitError> {
        let staging = self
            .guard
            .as_ref()
            .ok_or(CommitError::InvariantViolation)?
            .path
            .clone();
        if fs::try_exists(&self.destination)
            .await
            .map_err(CommitError::BeforeVisibility)?
        {
            return Err(CommitError::BeforeVisibility(io::Error::new(
                io::ErrorKind::AlreadyExists,
                "destination already exists",
            )));
        }
        for directory in &self.directory_handles {
            directory
                .sync_all()
                .await
                .map_err(CommitError::BeforeVisibility)?;
        }
        if let Some(parent) = &self.parent_handle {
            parent
                .sync_all()
                .await
                .map_err(CommitError::BeforeVisibility)?;
        }
        fs::rename(&staging, &self.destination)
            .await
            .map_err(CommitError::BeforeVisibility)?;
        self.guard
            .as_mut()
            .ok_or(CommitError::InvariantViolation)?
            .disarm();
        if let Some(parent) = &self.parent_handle {
            parent
                .sync_all()
                .await
                .map_err(CommitError::VisibleDurabilityUnknown)?;
        } else {
            let parent = normalized_parent(&self.destination)
                .map_err(|_| CommitError::InvariantViolation)?;
            sync_parent_directory(&parent)
                .await
                .map_err(CommitError::VisibleDurabilityUnknown)?;
        }
        Ok(CommitReceipt {
            digest: self.digest,
            length: self.length,
            cleanup: CleanupStatus::Cleaned,
        })
    }
}

impl StagingGuard {
    fn disarm(&mut self) {
        self.armed = false;
    }
}

impl TreeGuard {
    fn disarm(&mut self) {
        self.armed = false;
    }
}

impl Drop for StagingGuard {
    fn drop(&mut self) {
        if self.armed {
            let _ = std::fs::remove_file(&self.path);
            self.armed = false;
        }
    }
}

impl Drop for TreeGuard {
    fn drop(&mut self) {
        if self.armed {
            let _ = std::fs::remove_dir_all(&self.path);
            self.armed = false;
        }
    }
}

fn normalized_parent(path: &Path) -> Result<PathBuf, StageError> {
    if path.file_name().is_none() {
        return Err(StageError::InvalidDestination);
    }
    Ok(match path.parent() {
        Some(parent) if !parent.as_os_str().is_empty() => parent.to_owned(),
        _ => PathBuf::from("."),
    })
}

async fn sync_parent_directory(parent: &Path) -> io::Result<()> {
    #[cfg(windows)]
    {
        // Windows denies ordinary file opens on directories and does not
        // expose a supported directory equivalent of fsync. The verified
        // staging file was flushed before the atomic hard-link visibility
        // boundary; a receipt therefore attests to that visible, verified
        // link without pretending that Windows performed a directory flush.
        let _ = parent;
        Ok(())
    }

    #[cfg(not(windows))]
    {
        let directory = File::open(parent).await?;
        directory.sync_all().await
    }
}

fn staging_path(parent: &Path, file_name: &std::ffi::OsStr) -> Result<PathBuf, StageError> {
    let mut random = [0_u8; 8];
    getrandom::fill(&mut random).map_err(|_| StageError::EntropyUnavailable)?;
    let nonce = u64::from_be_bytes(random);
    let mut name = OsString::from(".");
    name.push(file_name);
    name.push(format!(".rift-{nonce:016x}.part"));
    Ok(parent.join(name))
}

fn staging_tree_path(parent: &Path, file_name: &std::ffi::OsStr) -> Result<PathBuf, StageError> {
    let mut random = [0_u8; 8];
    getrandom::fill(&mut random).map_err(|_| StageError::EntropyUnavailable)?;
    let nonce = u64::from_be_bytes(random);
    let mut name = OsString::from(".");
    name.push(file_name);
    name.push(format!(".rift-{nonce:016x}.tree"));
    Ok(parent.join(name))
}

fn resumable_staging_path(
    parent: &Path,
    file_name: &std::ffi::OsStr,
    object_id: [u8; 16],
    suffix: &str,
) -> PathBuf {
    let mut name = OsString::from(".");
    name.push(file_name);
    name.push(format!(".rift-{}.{suffix}", hex_id(object_id)));
    parent.join(name)
}

fn hex_id(id: [u8; 16]) -> String {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let mut output = String::with_capacity(32);
    for byte in id {
        output.push(char::from(HEX[usize::from(byte >> 4)]));
        output.push(char::from(HEX[usize::from(byte & 0x0f)]));
    }
    output
}

async fn open_append_file(path: &Path) -> Result<File, StageError> {
    OpenOptions::new()
        .read(true)
        .append(true)
        .create(true)
        .open(path)
        .await
        .map_err(StageError::Io)
}

async fn open_piece_file(path: &Path) -> Result<File, StageError> {
    OpenOptions::new()
        .read(true)
        .write(true)
        .create(true)
        .open(path)
        .await
        .map_err(StageError::Io)
}

async fn hash_prefix(path: &Path, length: u64) -> Result<blake3::Hasher, StageError> {
    let mut file = File::open(path).await?;
    let mut hasher = blake3::Hasher::new();
    let mut offset = 0_u64;
    let mut buffer = Vec::with_capacity(STAGING_WRITE_BUFFER_BYTES);
    while offset < length {
        let wanted = usize::try_from((length - offset).min(STAGING_WRITE_BUFFER_BYTES as u64))
            .map_err(|_| StageError::LengthExceeded)?;
        buffer.resize(wanted, 0);
        let (next, read) = file.read_into_vec(buffer).await?;
        buffer = next;
        if read != wanted {
            return Err(StageError::LengthMismatch {
                expected: length,
                actual: offset + u64::try_from(read).unwrap_or(u64::MAX),
            });
        }
        hasher.update(&buffer[..read]);
        offset += u64::try_from(read).map_err(|_| StageError::LengthExceeded)?;
        buffer.clear();
    }
    Ok(hasher)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{RuntimePolicy, build_runtime};

    fn digest(bytes: &[u8]) -> Digest {
        Digest(*blake3::hash(bytes).as_bytes())
    }

    #[test]
    fn commit_is_verified_atomic_and_no_clobber() {
        let directory = tempfile::tempdir().unwrap();
        let destination = directory.path().join("result.bin");
        let runtime = build_runtime(RuntimePolicy { worker_threads: 1 }).unwrap();

        let receipt = runtime.block_on(async {
            let mut staging = StagingFile::create(&destination, 6).await.unwrap();
            staging.write(b"abc").await.unwrap();
            staging.write(b"def").await.unwrap();
            staging
                .finish(digest(b"abcdef"))
                .await
                .unwrap()
                .commit()
                .await
                .unwrap()
        });

        assert_eq!(std::fs::read(&destination).unwrap(), b"abcdef");
        assert_eq!(receipt.length, 6);
        assert_eq!(receipt.digest, digest(b"abcdef"));
    }

    #[test]
    fn digest_failure_never_creates_destination_and_cleans_staging() {
        let directory = tempfile::tempdir().unwrap();
        let destination = directory.path().join("result.bin");
        let runtime = build_runtime(RuntimePolicy { worker_threads: 1 }).unwrap();

        runtime.block_on(async {
            let mut staging = StagingFile::create(&destination, 3).await.unwrap();
            staging.write(b"bad").await.unwrap();
            assert!(matches!(
                staging.finish(digest(b"good")).await,
                Err(StageError::DigestMismatch)
            ));
        });

        assert!(!destination.exists());
        assert_eq!(std::fs::read_dir(directory.path()).unwrap().count(), 0);
    }

    #[test]
    fn existing_destination_is_never_replaced() {
        let directory = tempfile::tempdir().unwrap();
        let destination = directory.path().join("result.bin");
        std::fs::write(&destination, b"original").unwrap();
        let runtime = build_runtime(RuntimePolicy { worker_threads: 1 }).unwrap();

        runtime.block_on(async {
            let mut staging = StagingFile::create(&destination, 3).await.unwrap();
            staging.write(b"new").await.unwrap();
            let verified = staging.finish(digest(b"new")).await.unwrap();
            assert!(matches!(
                verified.commit().await,
                Err(CommitError::BeforeVisibility(_))
            ));
        });

        assert_eq!(std::fs::read(&destination).unwrap(), b"original");
    }

    #[test]
    fn verified_tree_is_invisible_then_commits_as_one_root() {
        let directory = tempfile::tempdir().unwrap();
        let destination = directory.path().join("result");
        let runtime = build_runtime(RuntimePolicy { worker_threads: 1 }).unwrap();

        runtime.block_on(async {
            let mut tree = StagingTree::create(&destination).await.unwrap();
            let nested = tree.root().join("nested");
            tree.create_directory(&nested).await.unwrap();
            let mut file = tree.create_file(&nested.join("data"), 3).await.unwrap();
            file.write(b"abc").await.unwrap();
            file.finish(digest(b"abc")).await.unwrap();
            assert!(!destination.exists());
            tree.finish(digest(b"tree"), 3)
                .await
                .unwrap()
                .commit()
                .await
                .unwrap();
        });

        assert_eq!(
            std::fs::read(destination.join("nested/data")).unwrap(),
            b"abc"
        );
    }

    #[test]
    fn failed_tree_never_replaces_existing_destination() {
        let directory = tempfile::tempdir().unwrap();
        let destination = directory.path().join("result");
        std::fs::create_dir(&destination).unwrap();
        std::fs::write(destination.join("original"), b"safe").unwrap();
        let runtime = build_runtime(RuntimePolicy { worker_threads: 1 }).unwrap();

        assert!(matches!(
            runtime.block_on(StagingTree::create(&destination)),
            Err(StageError::EntryExists)
        ));
        assert_eq!(
            std::fs::read(destination.join("original")).unwrap(),
            b"safe"
        );
    }
}
