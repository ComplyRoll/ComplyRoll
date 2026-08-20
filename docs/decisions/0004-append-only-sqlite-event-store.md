# ADR 0004: Use an append-only SQLite event store

- Status: Accepted
- Date: 2026-08-20

## Context

Phase 1 needs durable vulnerability-case history, reproducible reports, and projections that can
be rebuilt after code or schema changes. Material case changes must remain ordered and auditable,
and two writers must not silently assign different meanings to the same aggregate version.

SQLite provides the local transactions and constraints required by the MVP without adding a
runtime dependency or coupling domain records to a hosted database. SQLite alone does not make a
file tamper-proof, so the storage contract must distinguish protection against application bugs
from later evidence-bundle signing and operating-system access controls.

## Decision

ComplyRoll will persist material changes as immutable event envelopes in SQLite. Each envelope
contains a globally unique event identifier, stream identifier and monotonically increasing
stream version, event type and payload-schema version, occurrence and recording timestamps,
canonical JSON payload and metadata, and a SHA-256 digest of the canonical payload.

Writers append one transactional batch with an expected stream version. A unique
`(stream_id, stream_version)` constraint and the expected-version check provide optimistic
concurrency control. Unique event identifiers make accidental event replay visible. Database
triggers reject updates and deletions from the event log.

Projection tables are disposable. A projection checkpoint records the last global event sequence
applied by one named projection and uses compare-and-swap updates. Projection implementations must
remain rebuildable from sequence zero and must update their rows and checkpoint transactionally
once their concrete schemas are introduced.

Schema changes use explicit, ordered migrations recorded in the database. Event payloads remain
domain-shaped JSON rather than serialized Python objects or SQLite-specific domain types.

## Consequences

Benefits:

- Evaluation revisions, rating changes, response actions, and case transitions can append history
  instead of overwriting earlier decisions.
- Global sequence numbers provide a deterministic input order for report and operational views.
- Stream versions expose concurrent updates rather than silently accepting lost writes.
- Canonical payload digests make accidental corruption and projection-input drift detectable.
- SQLite remains a dependency-free, portable local deployment option.

Costs and limits:

- Event and projection schema evolution requires migrations and replay tests.
- Projection handlers must be idempotent and transactionally checkpoint their work.
- A user with direct write access to the database file can remove triggers or rewrite the file;
  signed export manifests and deployment access controls remain separate future work.
- Each event type needs a documented payload contract as Phase 1 domain events are added.

## Rejected alternatives

A mutable table for only the current case state was rejected because it cannot reproduce earlier
evaluations or reports. One SQLite table per event type was rejected because it couples the event
log to projection concerns and makes ordered replay harder. A hosted database was rejected for
the MVP because local and CI use must remain first-class.
