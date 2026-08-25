# RIFT architecture

RIFT moves one file or directory from one live machine to another. The relay
introduces the machines and remains the last-resort data path, but never stores
the object.

## The shape of a transfer

```text
sender ── authenticated rendezvous/control ── receiver
   ╲                 │                         ╱
    ╲──── direct QUIC or QUIC over TURN ─────╱
     ╲════════ encrypted WSS fallback ══════╱
```

One four-digit-and-word code gives the two live processes both a rendezvous
name and a password-authenticated secret. The rendezvous forwards opaque
control bytes and, when configured, issues short-lived network routes. The two
endpoints agree on one data carrier before object records begin.

The carrier does not change object semantics. Direct UDP, Cloudflare TURN over
UDP, TURN over TCP/TLS, and the WSS fallback all feed the same bounded object
oracle and the same atomic commit boundary.

## Session establishment

The sender reserves the numeric nameplate before showing the code. A receiver
cannot reserve an empty nameplate. Once matched, the endpoints run SPAKE2 with
the word and explicitly confirm the result. The resulting secret authenticates
a Noise control channel.

The relay sees the numeric lookup, roles, addresses, timing, and ciphertext
volume. It never receives the word, derived session secret, names, metadata, or
file bytes in plaintext.

## Route acquisition

Candidate work begins while the authenticated control channel is coming up:

1. The relay's UDP rendezvous returns the source addresses it observed. A
   keyed simultaneous-open exchange proves peer ownership of the candidate.
2. Provider-issued STUN routes discover server-reflexive addresses on the
   exact sockets that may carry QUIC. Those addresses receive a second,
   session-bound simultaneous-open proof.
3. Each endpoint allocates short-lived TURN/UDP and TURN/TCP-or-TLS routes.
4. If no common accelerated carrier establishes, the existing end-to-end
   encrypted WSS stream remains the correctness path.

All provider-returned ports and both reachable address families are raced with
small head starts. Primary ports start first; alternate ports do not hold the
transfer hostage to a timeout. The bounded gather retains mutually proved
carriers long enough to form a small portfolio. Carriers with the same known
bottleneck share one admission budget; unusable acquisition tasks are
cancelled.

Cloudflare is an optional route provider, not a trust anchor. Only the relay
holds the long-lived TURN key. It mints a credential for the matched live pair
and sends a bounded provider-independent route bundle. The endpoints still
authenticate each other end to end and pin the receiver's transfer-scoped QUIC
certificate.

## Data plane

RIFT uses `quinn-proto` as a sans-I/O QUIC state machine. Asupersync owns UDP
readiness, timers, task lifetimes, cancellation, batched receive, `sendmmsg`,
and UDP GSO. The same QUIC engine is driven by three replaceable path adapters:

- native UDP;
- TURN channel data over UDP;
- TURN channel data over an ordered TCP or certificate-validated TLS stream.

TURN and WSS see only already encrypted traffic. There is no plaintext data
fallback.

Each authenticated object piece travels on a bounded short unidirectional lane.
A stalled lane cannot block later pieces at the application layer. Every QUIC
connection retains independent congestion control, pacing, loss recovery, and
flow control. A deterministic completion controller uses RTT, congestion
window, loss, and queue evidence to admit work only where its conservative
durable-arrival bound improves. Carriers gathered through the same endpoint
network are one bottleneck group by default; a second socket never masquerades
as extra capacity. A secondary is announced over the primary only when it has
earned object work, so an idle fallback adds no per-piece polling delay. Linux
uses batched datagrams and GSO when available; other platforms use the same
contract through portable I/O.

## File pipeline

The sender performs one bounded metadata scan, then pipelines source reads and
hashing through a fixed reusable buffer arena. It emits canonical metadata and
independently reconstructible pieces:

```text
Start
  Entry
    Piece
ObjectSeal
```

The receiver validates every declaration before allocating from fixed limits.
It verifies and writes pieces by offset in invisible staging, checks the
complete object seal, durably flushes, and atomically exposes the root. The CLI
JSON result includes bounded stage timings and aggregate QUIC path evidence so
read, hash, network, write, and commit bottlenecks are distinguishable.

## Live recovery

One sender process creates a high-entropy resume token for the transfer's
bounded retry window. The token is not derived from the human code and never
becomes an offline password verifier.

After a path interruption, the receiver reopens the stable invisible staging
object and re-hashes every journaled piece. It offers canonical sparse ranges
with commitments over their exact geometry and digests. The sender validates
those commitments during its ordinary one-pass read and resends anything stale
or contradictory. Both endpoints reconstruct graph state from authenticated
local bytes; internal hasher state is never serialized or trusted.

Only path failures are retried. Authentication, malformed records, source
mutation, and integrity failures stop immediately. A normal command permits
eight reconnects within two minutes with bounded backoff.

This is live recovery, not deferred storage. Closing the process or losing the
peer ends the transfer.

## Stable invariants

1. Visible output is complete and verified or absent.
2. Every name and byte is bound into one canonical object digest.
3. Existing destinations are never overwritten.
4. Network input cannot allocate beyond negotiated limits.
5. A candidate address grants no authority by itself.
6. A relay may deny service but cannot decrypt or forge accepted content.
7. Losing a path cannot weaken authentication or commit rules.
8. No payload survives at a rendezvous or relay after the live pair closes.

## Deliberate boundaries

RIFT is not a sync engine, cloud drive, mailbox, browser download service, or
multi-recipient distributor. Symlinks, special files, ownership, ACLs, xattrs,
and timestamps are rejected or omitted until their cross-platform meaning can
be made exact.
