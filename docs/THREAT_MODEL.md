# RIFT threat model

Status: pre-release security contract.

## Protected properties

- object names and bytes are confidential from rendezvous and relay operators;
- accepted metadata and bytes are authenticated end to end;
- the human code authorizes one ephemeral live transfer;
- the requested destination is complete and verified or absent;
- parsing, memory, staging growth, retries, and relay residency are bounded;
- interrupted-path recovery cannot reuse unverified local bytes.

## Adversaries

The network may observe, drop, delay, duplicate, reorder, corrupt, and inject
traffic. A rendezvous, TURN provider, or WSS relay may be curious or malicious
and may collude with a network observer. Either endpoint may send hostile
protocol bytes or filesystem metadata.

RIFT does not protect a compromised endpoint, a code copied from the user's
screen, traffic-analysis anonymity, or availability against a party able to
block every route.

## Human-code boundary

The numeric nameplate is public routing metadata. The pronounceable word is
random one-shot SPAKE2 input and never enters the relay envelope. A passive
observer receives no offline dictionary verifier. An active attacker can make
one online attempt; the rendezvous is consumed whether confirmation succeeds
or fails.

This short-code design intentionally trades denial-of-service resistance for a
small human surface. Someone who learns a live nameplate may race the intended
receiver and consume it, but receiver-first squatting cannot fill the pending
table.

## Relay and provider leakage

The WSS rendezvous sees lookup, roles, endpoint addresses, timing, and encrypted
volume. A TURN provider additionally sees allocation credentials, client and
peer addresses, ports, session duration, and relayed encrypted volume. STUN
sees the requesting address and transaction timing.

None of those services receives the pairing word, PAKE secret, transfer-scoped
QUIC private key, filenames, metadata, or plaintext payload. QUIC remains
encrypted end to end inside TURN/TLS; the outer TLS connection protects only
the client-to-provider hop.

The long-lived Cloudflare TURN key is server-only. The relay uses it to mint a
bounded 48-hour credential for a matched pair. It is never placed in route
bundles, logs, debug output, or client configuration. Pair credentials grant
temporary relay use, not RIFT peer identity or object authority. A future
transfer lease will revoke them after verified completion, cancellation, or one
hour without authenticated liveness; the provider expiry remains the crash-safe
outer bound.

Relays may delay, truncate, replay, or substitute route bundles. They cannot
turn an address into authority: direct candidates require session-bound keyed
proofs, and the sender pins the receiver certificate delivered through the
authenticated control channel. A malicious relay can force fallback or deny
service, but cannot forge accepted content.

## QUIC boundary

QUIC TLS 1.3 supplies packet confidentiality, integrity, replay handling,
ordering, loss recovery, and congestion control. RIFT uses a transfer-scoped
receiver identity and exact certificate pin rather than ambient peer PKI. The
same authenticated connection semantics apply over direct UDP and every TURN
carrier.

Off-path UDP traffic is ignored within a fixed noise budget. Oversized
datagrams, excessive unrelated traffic, malformed TURN framing, protocol
timeouts, and peer closure terminate the path. Failure may trigger a bounded
live retry; it never selects plaintext or weakens object verification.

## Filesystem boundary

Network records never choose an absolute path. The receiver joins individually
validated components beneath one invisible sibling staging root. Both endpoints
reject non-NFC names, separators, dot components, portable case collisions,
Windows aliases, symlinks, and special files before visibility.

Existing destinations are never replaced. Regular files and directory trees
cross the visibility boundary only after every seal and the complete object
digest verify and the staging object has been durably flushed. Metadata is a
small portable subset; ownership, ACLs, xattrs, links, and timestamps are
omitted rather than guessed.

## Resume boundary

The stable staging name is keyed by a fresh high-entropy token held only by the
live sender process. Deriving it from the low-entropy word would create an
offline verifier, so RIFT does not do that.

On reconnect, the receiver hashes its actual contiguous staging bytes and the
sender hashes the corresponding source bytes. Only an exact digest match may
skip transfer. Any disagreement resets the file to zero. Internal hasher state
is reconstructed from bytes and is never trusted from disk or peer input.

Retryable path failures may retain invisible verified staging. Authentication,
source mutation, malformed records, and integrity failures clean up and stop.

## Resource bounds

Hard limits are checked before allocation: prelude size and time, pending and
active relay sessions, route count and encoded size, certificate size, STUN and
TURN messages, unrelated packets, QUIC windows, record length, tree entries,
depth, component and path bytes, total object bytes, staging writes, retry count,
and retry wall time.

## Review blockers

Pre-release does not mean independently audited. A production security claim
still requires independent cryptographic review, parser fuzzing, hostile
filesystem race testing on every supported OS, provider-failure drills, and
reproducible native release verification. Passing unit and integration tests is
necessary evidence, not a substitute for that review.
