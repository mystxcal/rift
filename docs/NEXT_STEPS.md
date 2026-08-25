# Next steps

## Implemented foundation

The first four construction stages are now executable on the normal QUIC path:
bounded stage/path measurements, the authenticated sparse piece graph,
independent out-of-order QUIC lanes, and a measured completion-time controller
over a bounded pool of independent connections. The remaining sections define
the evidence contract and later optimizations; they are not claims that every
listed mechanism is already shipped.

## Build a completion engine, not a faster stream

RIFT's next performance boundary is not "multipath" by itself. It is the time
between the sender accepting an object and the receiver atomically exposing a
verified copy. Network goodput matters only when it shortens that interval.

The next data plane should therefore optimize one quantity:

```text
T_visible = time(final verified byte is durably and atomically committed)
```

Every mechanism competes on its effect on `T_visible`, including path
discovery, reads, hashing, encryption, congestion control, receiver writes,
verification, retries, compression, sparse reconstruction, and local reuse.
The controller may use more paths, fewer paths, or deliberately wait. It must
not maximize traffic, socket count, or an isolated throughput counter.

This is a protocol evolution, not a patch on the current ordered stream. The
foundation is one authenticated reconstruction graph shared by every way bytes
can be obtained.

## Correct two assumptions first

### A TURN allocation limit is only one possible bottleneck

Cloudflare currently documents throughput and packet-rate limits per TURN
allocation, rather than account-wide. Multiple allocations can therefore
expose additional relay capacity. They do not guarantee additional end-to-end
capacity: the allocations may still share the client, access network, relay
edge, CPU, storage, or another congestion bottleneck.

RIFT may create another allocation to test useful capacity or route diversity,
or to recover from failure. It must not assume that allocation count predicts
completion time. New paths are admitted by measured marginal completion-time
improvement and retired when that evidence disappears.

### Credential expiry must never become a transfer deadline

Cloudflare credentials have an absolute expiry rather than an inactivity TTL.
RIFT should therefore issue the provider maximum of 48 hours for each matched
pair. The TURN engine refreshes allocations, permissions, and channel bindings
while that credential remains valid. A short credential must never terminate a
healthy long-running transfer.

The completion engine should layer a transfer lease over that hard provider
ceiling:

- retain the issued username server-side without logging it;
- keep low-rate, authenticated control-plane liveness independent of payload
  traffic;
- revoke immediately after verified commit or explicit cancellation;
- revoke after one hour without transfer-liveness evidence;
- rotate credentials and migrate the allocation before the 48-hour boundary
  if useful work is still active;
- fall back to the provider expiry if either endpoint or the issuer crashes.

Disappearance of the original WSS path is not, by itself, proof of inactivity:
independent QUIC may still be transferring correctly. Revocation therefore
belongs to the explicit lease lifecycle rather than connection teardown.

### Ordered transport is not ordered object reconstruction

One long ordered application stream creates head-of-line coupling above QUIC:
a delayed early record can prevent useful later bytes from becoming verified
work. Adding connections without changing this object model would move the
problem rather than solve it.

The object must be independently reconstructible from authenticated pieces.
Transport order then becomes a local scheduling choice, not a correctness
requirement.

## The reconstruction plane

### Pieces

The sender maps every regular file into fixed-size pieces. A piece is
identified by:

```text
(object version, entry id, offset, length, piece digest)
```

Metadata, empty files, directories, and the ordered entry structure are leaves
in the same graph. Domain separation prevents a data leaf from being confused
with metadata or a node of another type.

The piece size is a protocol parameter selected from a small bounded set. It
must be large enough to keep framing and digest overhead negligible, but small
enough to support useful reassignment and tail repair. It is not coupled to a
QUIC packet, stream, disk write, or emission-window size.

### One canonical root

Ordered leaf commitments are reduced into a canonical object root. That root
binds names, kinds, lengths, topology, piece positions, and piece digests. The
receiver commits only when every required leaf is present and the reconstructed
root matches the authenticated object seal.

The sender computes each piece digest while reading the piece for transmission;
there is no pre-hash pass and no second source read. The root is accumulated
from the ordered commitments as they become available. The receiver may write
pieces out of order into invisible staging while preserving the existing
complete-or-absent visibility rule.

### Sparse verified state

The current contiguous verified prefix becomes a sparse verified-piece ledger.
Each state transition is monotonic:

```text
missing -> in flight -> received -> verified -> durable
```

Cancellation or path failure returns only unverified work to `missing`.
Verified bytes never depend on the path that supplied them. Memory remains
bounded because payload buffers are released after verification and the ledger
stores compact piece state, not duplicated content.

Resume exchanges an authenticated compressed set of verified piece ranges and
their object identity. The sender validates those claims against the unchanged
source graph. A false or stale claim can at worst cause a piece to be resent;
it can never cause corrupt output to be accepted.

This ledger is the unifying primitive. Direct bytes, relayed bytes, tail-repair
symbols, sparse holes, decompressed bytes, and receiver-local reuse all satisfy
the same piece commitments before becoming durable truth.

## The path plane

### Continuously discover, prove, and classify paths

Candidate discovery should continue after the first usable carrier is selected.
A transfer can begin immediately on the best known path while later direct,
server-reflexive, TURN, or interface candidates are proved in the background.
A late path may join without restarting the object or invalidating completed
work.

Every live path owns independent transport state:

- authenticated peer and route identity;
- congestion controller, pacing, RTT, loss, and delivery-rate estimates;
- bounded send queue and memory budget;
- observed setup, liveness, and repair cost;
- an explicit drain and retirement state.

Initially, each concurrently used path should be an independent QUIC
connection. Standardized Multipath QUIC is still evolving, and the current
`quinn-proto` engine does not expose that extension. The object-global ledger
gives RIFT the useful semantics now without inventing a private QUIC dialect.
The wire can later adopt standardized Multipath QUIC without changing object
reconstruction.

### Distinguish paths from bottlenecks

Two sockets are not necessarily two resources. The controller should infer
shared bottlenecks from route provenance and correlated changes in RTT, loss,
ECN, and delivery rate. Paths in the same likely bottleneck group share an
aggregate admission and pacing budget. A second path that merely competes with
the first is drained.

The normal state remains one path. Additional paths earn work only when their
conservative predicted contribution exceeds their setup, CPU, memory, and
congestion costs. WSS remains an availability path, not a speculative
bandwidth contributor.

## The completion-time controller

The controller is deterministic, bounded, and inspectable. It operates on a
short receding horizon over ready pieces and live paths. For each possible
assignment it predicts:

```text
piece arrival = max(source ready, path queue ready)
              + serialization at conservative delivery rate
              + latency and repair risk
              + receiver verification/write backlog
```

The assignment is accepted only if it reduces the predicted global makespan.
Its estimates use recent delivery evidence with an uncertainty penalty, so an
unproven fast path receives probes rather than the object tail.

This controller needs four actions, not just path selection:

1. assign a missing piece to a path;
2. wait because every available assignment is predicted to hurt the tail;
3. cancel and reassign stale unverified work;
4. send bounded redundant repair when it is predicted to arrive before the
   original.

The explicit wait action is important. On heterogeneous paths, sending now on
a slow route can finish later than waiting briefly for a fast route. A simple
weighted round-robin scheduler cannot express that decision.

Scheduling runs only when evidence changes: a piece becomes ready, a path
reports delivery, a timer expires, congestion changes materially, or receiver
backpressure moves. It must not become a high-frequency control loop whose CPU
cost competes with encryption and I/O.

## Remove application head-of-line blocking

Pieces should travel on bounded independent QUIC lanes or short-lived
unidirectional streams rather than one object-wide ordered byte stream. Stream
creation is amortized over small piece batches where measurements show that a
stream per piece is too expensive.

The receiver parses each lane within hard limits, verifies pieces
independently, and writes them by offset. A stalled lane cannot prevent another
lane from completing useful verified work. QUIC still owns packet loss,
congestion safety, and delivery inside each connection; RIFT does not recreate
those mechanisms at the application layer.

## Tail repair, only when the tail exists

Always-on application FEC wastes bytes on a reliable QUIC path. The first
baseline should instead allow one bounded duplicate of a predicted straggler
on a genuinely independent path. Duplication is useful only when its expected
earliest arrival beats both waiting and transport retransmission.

If residual tail measurements justify more machinery, evaluate a systematic
fountain code over a small final generation. Original pieces remain the
systematic symbols; repair symbols are generated only when the completion
controller predicts a net win. The receiver discards the generation as soon as
enough independent symbols reconstruct its missing pieces.

Coding must lose to plain scheduling in an ablation before it is admitted.
There is no permanent coding tax and no user-facing mode.

## Reduce information before moving it

The fastest byte is one that does not cross the network. Compression, sparse
holes, and receiver-local reuse should be candidate producers for the same
reconstruction graph, not separate transfer modes.

- Sparse extents become authenticated zero-piece runs without reading or
  transmitting their contents.
- Compression is sampled online and enabled per bounded extent only when the
  predicted network time saved exceeds CPU and framing cost.
- Local reuse proposes bytes already available to the receiver, but those bytes
  become verified only after satisfying the expected piece digest.

Each producer has a cheap potency probe and disables itself when it cannot
change `T_visible`. No producer may change names, bytes, object identity, or the
atomic commit rule.

## Feed the machine without copying the machine

Network work is only useful while source reads, hashing, encryption, receiver
verification, and writes can keep up. The runtime should expose one bounded
buffer arena whose ownership moves through explicit stages:

```text
free -> reading -> hashing -> encrypting -> in flight
     -> received -> verifying -> writing -> free
```

The controller observes queueing at every stage. When CPU or storage is the
bottleneck, it stops adding network paths.

Portable buffered I/O remains the reference implementation. Platform fast
paths are admitted only after profiling identifies a copy or syscall boundary:

- parallel BLAKE3 piece hashing with deterministic root order;
- vectored reads and writes into reusable aligned buffers;
- Linux `io_uring` fixed buffers, multishot receive, or zero-copy receive when
  the kernel, NIC, and driver expose a real end-to-end benefit;
- native Windows overlapped I/O and registered-buffer facilities when the same
  potency gate passes;
- direct I/O only for workloads where page-cache bypass wins after alignment
  and tail costs.

Unsafe code, pinned memory, and platform-specific backends stay isolated behind
the same safe buffer-ownership contract.

## Congestion control is an experiment boundary

RIFT should make the QUIC congestion controller selectable inside the lab, not
promise one algorithm universally. CUBIC remains the reference. A BBR-family
controller is useful only if its implementation is compatible with the QUIC
stack and wins across high-bandwidth/high-delay, mobile, lossy, asymmetric, and
shared-bottleneck tests without unacceptable fairness or tail regressions.

The completion controller never overrides congestion safety. It schedules
application work into the capacity each connection is allowed to use.

## Construction order

Build the next engine in dependency order. Each stage must be independently
correct and benchmarkable.

1. **Measurement spine.** Record source-read, hash, encrypt, path queue,
   delivery, verify, write, and durable-commit timing with bounded overhead.
   Separately measure raw path capacity so the active bottleneck is visible.
2. **Authenticated piece graph.** Add canonical piece commitments, sparse
   verified state, out-of-order staging, and sparse resume while still using one
   path and the current scheduler.
3. **Independent lanes.** Remove object-wide application ordering on one QUIC
   connection and prove that reordering, loss, cancellation, and resume preserve
   exact output.
4. **Two-path completion controller.** Add deterministic earliest-completion
   scheduling, the wait action, bounded probing, and automatic self-disable.
5. **Trickle path admission.** Let proved direct or relayed candidates join and
   leave a live transfer without restarting it. Add shared-bottleneck grouping.
6. **Tail repair.** Compare no repair, one duplicate, and systematic repair on
   forced stragglers. Keep the smallest mechanism that wins.
7. **Information reducers.** Add sparse extents, sampled compression, and local
   reuse one at a time against the unchanged piece graph.
8. **Platform fast paths.** Profile first, then attack the demonstrated CPU,
   memory-copy, syscall, or storage limit on Linux and native Windows.
9. **Standard multipath wire.** Re-evaluate Multipath QUIC when the standard and
   Rust implementation are mature enough to replace the connection pool
   without weakening the controller or reconstruction plane.

Do not begin a later stage to conceal a failure in an earlier one.

## Frozen evidence contract

Before implementing each mechanism, freeze the revision, machines, network
shapes, object corpus, baselines, metrics, and adoption threshold. Preserve
failed runs.

The minimum matrix includes:

- 1 KiB, 1 MiB, 64 MiB, and 1 GiB files;
- a many-small-files tree, incompressible data, compressible data, and a sparse
  object;
- same-LAN, high-bandwidth/high-delay, mobile-hotspot/CGNAT, asymmetric,
  lossy/reordered, TURN, and WSS paths;
- one path, two independent paths, and two paths sharing one bottleneck;
- forced path death near the beginning, middle, and final five percent;
- sender and receiver CPU throttling plus slow source and destination storage.

Record end-to-end `T_visible`, time to first verified piece, median and tail
goodput, CPU-seconds per GiB, peak RSS, bytes read and written, wire
amplification, packet loss, retransmission, and relay cost.

The hard acceptance rules are:

1. every byte and metadata result is identical, atomic, and bounded under all
   fault cases;
2. direct single-path transfer has no statistically meaningful regression;
3. an adaptive feature disables itself in regimes where it cannot improve
   completion time;
4. a multipath win must persist across held-out traces, both endpoint roles,
   and repeated runs, not only one shaped link;
5. added wire, CPU, and memory cost is reported next to time saved rather than
   hidden inside a throughput number.

Quantitative promotion thresholds should be frozen from baseline variance
before a mechanism is tested. They are test contracts, not constants embedded
in product policy.

## What not to build

- no unbounded pool of TURN allocations or assumption that nominal per-
  allocation limits imply additive end-to-end capacity;
- no short credential lifetime that silently becomes a maximum file-transfer
  duration;
- no scheduler that equates recent throughput with future completion time;
- no second object lifecycle for coded, compressed, sparse, or reused bytes;
- no pre-hash pass over the source;
- no always-on FEC tax;
- no private QUIC multipath dialect while the object layer can express the same
  useful work over ordinary connections;
- no platform fast path without a measured bottleneck and portable fallback;
- no new command-line mode for an internal optimization.

The intended result is simple at the surface: one send, one receive, and the
shortest safe path to a visible object. The sophistication belongs entirely
inside the completion engine.

## Research anchors

- [Multipath Extension for QUIC](https://datatracker.ietf.org/doc/draft-ietf-quic-multipath/)
- [BLEST: Blocking Estimation-based MPTCP Scheduler](https://olivier.mehani.name/publications/2016ferlin_blest_blocking_estimation_mptcp_scheduler.pdf)
- [RaptorQ Forward Error Correction Scheme](https://www.rfc-editor.org/rfc/rfc6330.html)
- [Linux `io_uring` zero-copy receive](https://docs.kernel.org/networking/iou-zcrx.html)
- [Cloudflare Realtime TURN FAQ](https://developers.cloudflare.com/realtime/turn/faq/)
