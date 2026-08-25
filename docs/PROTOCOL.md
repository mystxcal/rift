# RIFT protocol contract

Status: pre-release; numeric assignments may still change.

## Human code

The ordinary capability is:

```text
4827-lumeko
```

The four digits are a public, ephemeral rendezvous nameplate. The six-letter
word is uniformly generated PAKE input and never crosses the relay protocol.
The sender reserves the nameplate before displaying it. Receiver-first joins
are rejected, and a failed authentication consumes the one-shot rendezvous.

RIFT also retains a long binary capability codec as an internal compatibility
and differential-test oracle. It is not the normal user surface.

## Stream rendezvous

Internet rendezvous uses an authenticated WebSocket endpoint:

```text
wss://host/rift/v1
```

Only a raw loopback TCP endpoint is accepted for local development. Plain
WebSocket and public raw TCP fail before the lookup is disclosed.

Each client opens with one fixed 24-byte prelude:

```text
"RFTJ" | version | role | reserved | 128-bit lookup
```

The relay returns a fixed result: `Reserved`, `Matched`, a bounded refusal, or
`MatchedWithRoutes`. Waiting senders, prelude readers, pending lookups, active
copies, buffer windows, and idle time are independently bounded.

With `MatchedWithRoutes`, a length-bounded route bundle follows. It contains
only supported `(transport, host, port)` entries and, if TURN routes exist, one
short-lived username and credential. Duplicate, incoherent, non-canonical, or
oversized bundles are rejected before candidate work.

## Endpoint authentication

Matched peers exchange fixed-width role-tagged P-256 SPAKE2 shares and
confirmation MACs. The word is never sent. Message type, version, role, and
reserved bytes are canonical. Explicit mutual confirmation must complete
before names or payload records can flow.

The PAKE result then authenticates an ephemeral Noise channel whose prologue
binds protocol version, lookup, roles, algorithms, and conservative limits.
The WSS relay carries this channel blindly and remains the fallback data path.

## Direct candidates

The relay may also match bounded UDP registrations on the same numeric port:

```text
"RFDR" | version | role | reserved | lookup | nonce | authenticator
```

The authenticator is derived from the PAKE secret. The relay cannot verify it;
the peer can. After verifying the returned peer registration, both endpoints
exchange fresh role-bound keyed challenges on the exact mapped sockets.

An RFC 8489 STUN Binding result is treated only as an address hint. RIFT checks
the transaction identifier, message length, padding, required attributes,
fingerprint, and mapped-address consistency. The peers then perform another
session-bound simultaneous-open proof. STUN never authenticates a peer.

The production QUIC path begins after this proof. The older direct-record
Noise, MTU trial, and custom reliability phases are not repeated underneath
QUIC.

## TURN routes

RIFT accepts these provider-independent carriers:

- STUN over UDP;
- TURN allocation over UDP;
- TURN allocation over TCP;
- TURN allocation over TLS.

Primary and alternate ports and reachable IPv4/IPv6 server addresses are
stagger-raced. TURN state is sans-I/O: allocation, nonce/realm authentication,
refresh, permission, channel binding, framing, and deadlines are driven by the
RIFT runtime. TURN/TCP and TURN/TLS still relay UDP datagrams; the client-to-
TURN hop merely uses an ordered carrier.

## Pinned QUIC

The receiver creates one transfer-scoped certificate. Its exact DER bytes are
sent only inside authenticated control. The sender trusts that certificate and
no other for the data connection. QUIC uses TLS 1.3, the `rift/1` ALPN, bounded
stream and connection windows, congestion control, pacing, loss recovery, and
flow control from `quinn-proto`.

Independent pinned QUIC connections may travel through direct UDP, TURN/UDP,
or TURN/TCP-or-TLS. The application controller can use more than one when the
measured completion bound improves. The path adapter and connection count may
change; peer identity and object semantics do not.

The primary connection carries a fixed internal path-state notice before a
secondary begins carrying object lanes. This notice only changes which proved
connection the receiver polls; it is not an object record and cannot satisfy a
piece commitment. Unknown, malformed, or out-of-range path state fails closed.

## Object records

The WSS availability path retains the ordered record sequence below:

The reliable application stream is a sequence of length-prefixed records:

- `TreeStart(object_id, entries, total_length, block_bytes)`
- `TreeEntry(entry, parent, kind, length, metadata, name)`
- `ResumeOffer(entry, prefix, digest)`
- `ResumeDecision(entry, prefix)`
- `BlockData(block, offset, bytes)`
- `BlockSeal(block, digest)`
- `EntrySeal(entry, digest)`
- `ObjectSeal(digest)`
- `CommitReceipt(digest, total_length)`
- `Cancel`

Accelerated QUIC uses one bounded record per independent unidirectional lane:

- `Start(object_id, entries, total_length, piece_bytes, pieces)`
- `Entry(entry, parent, kind, length, metadata, name)`
- `Piece(block, entry, offset, digest, bytes)`
- `ResumeOffer(object_id, sparse_ranges)`
- `ResumeDecision(object_id, accepted_ranges)`
- `ObjectSeal(digest)`
- `CommitReceipt(digest, total_length)`
- `CommitAck(digest)`
- `LeaseLiveness(progress)`
- `Cancel`

Pieces are independently authenticated and may arrive in any transport order.
Their ordered geometry and digests, together with canonical metadata, reduce to
one object commitment. No path owns object truth.

The root entry is zero and names exactly one regular file or directory. Entries
are parent-before-child. A name is one bounded NFC UTF-8 component; separators,
dot entries, Windows device aliases, forbidden or trailing characters,
symlinks, and special files are rejected. Siblings must remain distinct under
portable case equivalence.

Every declaration is charged against the same bounded reconstruction budget on
both endpoints. Geometry is immutable. Conflicting replay is a protocol error,
not last-write-wins behavior.

## Resume negotiation

The QUIC receiver may offer a canonical bounded set of sparse piece ranges. It
first reads every claimed piece from invisible staging and verifies its BLAKE3
digest. Each range commitment binds block, entry, offset, length, and digest.
The sender validates those commitments during its normal one-pass source read;
an invalid range is resent as ordinary pieces.

The WSS fallback retains its contiguous-prefix resume protocol. Neither path
accepts serialized hash internals, unauthenticated lengths, or a resume identity
derived from the human code.

## Completion

The receiver emits `CommitReceipt` only after all of the following:

1. all declared entries and bytes arrived;
2. every block and file seal verified;
3. the canonical object seal verified;
4. path and portable metadata checks passed;
5. staged bytes and required directories were durably flushed;
6. the absent destination root became visible atomically.

The sender reports success only after validating that receipt, then sends an
explicit `CommitAck`. This lets the receiver distinguish sender acceptance from
a transport-level FIN that happened to be acknowledged.
