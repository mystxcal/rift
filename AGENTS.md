# RIFT engineering contract

RIFT is a clean-sheet, live-only, one-sender/one-receiver internet transfer
system. It is not a synchronization product, cloud drive, deferred mailbox, or
compatibility rewrite of SSS or ATP.

## Product invariants

1. The normal interface is one send command and one receive command.
2. Both peers are online. A relay may forward ciphertext but never stores the
   transfer for later receipt.
3. No corrupt or partial object becomes visible at the destination.
4. Relay, rendezvous, and network paths are untrusted for payload correctness
   and confidentiality.
5. Direct, relayed, coded, compressed, sparse, and locally reused information
   all satisfy the same authenticated reconstruction graph.
6. Runtime choices minimize tail completion time under hard correctness,
   congestion-safety, memory, and capability constraints.
7. Cancellation drains owned work. There are no detached transfer tasks.

## Architecture boundaries

- `rift-core`: pure deterministic object, reconstruction, and decision logic.
  No sockets, filesystem, wall clock, ambient randomness, or process state.
- `rift-protocol`: bounded wire and manifest codecs. Parsing untrusted bytes
  must be total, length-bounded, and allocation-bounded.
- `rift-transport`: bounded, policy-free async transport adapters shared by
  endpoints and relays. It does not choose routes or interpret payloads.
- `rift-runtime`: asupersync-native effects, paths, crypto sessions, I/O, and
  lifecycle. Tokio is not permitted.
- `rift-cli`: human and stable JSON interfaces; no transport policy lives here.
- `rift-relay`: ephemeral rendezvous and bounded ciphertext forwarding only.
- `rift-lab`: deterministic simulations, adversarial traces, baselines, and
  performance evidence.

Keep mechanisms behind these boundaries. Do not solve a local problem by
smuggling policy into a lower layer.

## Development rules

- Correctness gates precede performance claims.
- Record the exact benchmark revision, environment, workload, and failed runs.
- Never optimize only against one synthetic link regime.
- Every adaptive mechanism needs a fixed baseline, an ablation, a potency
  check, and a condition under which it disables itself.
- No user-facing mode is added merely because an internal mechanism exists.
- Unsafe code is forbidden until a measured fast-path bottleneck requires a
  narrowly isolated platform implementation and its safety argument is
  documented.
- Pin external research dependencies to immutable revisions.
- Do not publish, push, deploy, or expose the project without an explicit
  privacy review and user authorization.
