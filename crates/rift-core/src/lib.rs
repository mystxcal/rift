#![forbid(unsafe_code)]

//! Deterministic object and control logic for RIFT.
//!
//! This crate deliberately has no ambient I/O, clock, entropy, or runtime.

pub mod coding;
pub mod completion;
pub mod lifecycle;
pub mod object;
pub mod path;
pub mod recovery;
pub mod rtt;
pub mod scheduler;

pub use coding::{
    CodingError, MAX_CODING_SOURCES, MAX_CODING_SYMBOL_BYTES, MAX_REPAIR_SYMBOLS, RepairSymbol,
    encode_repair, recover_sources,
};
pub use completion::{
    CompletionAction, CompletionError, CompletionPath, Flight, PieceWork, plan_completion,
};
pub use lifecycle::{
    LifecycleError, PathEvent, PathLifecycle, PathLifecycleError, PathPhase, TransferEvent,
    TransferLifecycle, TransferPhase,
};
pub use object::{
    BlockId, BlockPhase, BlockSpec, Digest, DurableRange, EntryId, GraphError, ReconstructionGraph,
};
pub use path::{
    MigrationDecision, PathEstimate, PathId, PathKind, PathModelError, PathPrediction,
    PathReadiness, choose_migration, choose_path,
};
pub use recovery::{
    RecoveryAction, RecoveryCause, RecoveryError, RecoveryEvent, RecoveryPolicy, RecoveryStrategy,
    choose_recovery_action,
};
pub use rtt::{RttError, RttEstimator};
pub use scheduler::{
    Action, Candidate, Decision, ResourceCost, SchedulerError, ShadowPrices, select_action,
};
