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

## Amendment 2026-08-21

An audit of the Phase 1 store found that the original decision was implemented in a way that could
not survive an adverse environment. The decision itself stands. The mechanics below correct it.

### Write-ahead logging and explicit full synchronous

The store now sets `PRAGMA journal_mode = WAL` and `PRAGMA synchronous = FULL` when it connects,
and refuses to run if a file database will not accept write-ahead logging. In-memory databases
report journal mode `memory` and are accepted as the one exception.

Under the previous rollback journal, one open reader was enough to make a writer's `COMMIT` fail.
That is not an exotic condition for this system: a report render and an ingest run overlapping is
the normal case. Write-ahead logging lets readers and one writer proceed concurrently, so an
overlapping reader no longer fails a commit, and a second process can open the store while a
writer holds the lock instead of blocking on the header read.

Write-ahead logging alone reduces durability, because its default `synchronous = NORMAL` can lose
recently committed transactions on a power loss or operating-system crash. For an evidence log
that is not an acceptable trade, so `synchronous = FULL` is set explicitly rather than left to the
SQLite default. The store pays a per-commit fsync and keeps the guarantee that a returned
`EventRecord` is on disk.

### A retryable busy error, and no wedged connections

Contention is now a named, retryable outcome rather than a leaked driver exception.
`EventStoreBusyError` extends `EventStoreError` and is raised when SQLite reports the database is
locked or busy. The transaction context wraps `BEGIN IMMEDIATE` and `COMMIT`, rolls back on either
failure, and refuses to start when its connection is already inside a transaction.

This closes a correctness hole, not only an ergonomic one. A failed `COMMIT` previously left the
transaction open, and every later read on that connection returned uncommitted rows as though they
were history. The store reported an event that a reopen proved had never been written, and the
global sequence it claimed was later reissued to a different event. Callers may now retry a busy
append; the connection is always left outside a transaction, and a failed rollback is reported
alongside the original error rather than replacing it.

The busy timeout is a constructor argument (`busy_timeout_ms`, default 5000) so tests can force
contention quickly and deployments can tune it.

### Schema verification when an existing database is opened

Opening a database at the current schema version now compares `sqlite_master` against the object
set derived from the schema definition, and rejects the file if any table, index, or trigger is
missing. Removing the append-only triggers was previously invisible: the store would reopen the
file and then execute `DELETE FROM events` through its own connection without complaint.

Related open-path hardening: a file that is not a SQLite database raises `UnsupportedSchemaError`
instead of a raw `sqlite3.DatabaseError`, and a database at user version zero that already
contains objects is refused rather than having the schema created on top of it.

Verification covers the presence of schema objects, not the integrity of their definitions. A
trigger that is dropped and replaced with an inert one carrying the same name still passes. Adding
`PRAGMA quick_check` on open was considered and deferred, because it scans the whole database and
belongs in an explicit verification command rather than in every open.

### Contiguity checks on read

`read_all` requires the sequences it returns to be contiguous from `after_sequence + 1`, and
`read_stream` requires stream versions to be contiguous from `after_version + 1`. A gap raises
`EventIntegrityError`, which now carries a `sequence` attribute locating the offending row.

This is sound because `sequence` is an `INTEGER PRIMARY KEY AUTOINCREMENT` column and SQLite rolls
`sqlite_sequence` back with an aborted transaction, so a rolled-back batch reuses its sequence
numbers and committed history is gap-free by construction. A gap therefore means a committed row
was deleted out of band. Before this change, deleting a middle row read back clean, and the stream
version reported for the truncated stream was unchanged.

### What the payload digest does and does not cover

`payload_sha256` covers `payload_json` only. It does not cover the rest of the envelope, and no
row commits to the row before it.

Tampering with `metadata_json`, `event_type`, `occurred_at`, `recorded_at`, `event_version`,
`stream_id`, or `event_id` is not detected by the digest. Contiguity checking now catches deleted
rows, but it does not catch a rewritten one. This matters most for timestamps, because a
back-dated `occurred_at` makes an overdue remediation look compliant, and every FedRAMP deadline
is computed from timestamps of that kind.

A full-envelope digest and a `prev_sha256` hash chain, together with a `verify_history()` method
and a command that exposes it, are deferred to a later schema version. They change the row format
and so require a migration, which is out of scope for a fix that does not bump `SCHEMA_VERSION`.
Until that lands, describe this store as append-only with detectable payload corruption and
detectable row deletion, and do not describe it as tamper-evident.

### Follow-up 2026-08-21: error boundary and concurrent first open

A second, cross-vendor review of the amendment above found two gaps, and a multi-process
exercise found a third. All three are corrected in the same change set.

Every public method now runs under one error boundary. SQLite failures are classified by the
symbolic result name SQLite attaches to the exception (`sqlite_errorname`, Python 3.11 and
later): `SQLITE_BUSY` and `SQLITE_LOCKED` become `EventStoreBusyError`, `SQLITE_CORRUPT` becomes
`EventIntegrityError`, `SQLITE_NOTADB` becomes `UnsupportedSchemaError`, and anything else (a
full disk, read-only media, an I/O error) becomes `EventStoreError` carrying SQLite's message.
The earlier message-substring heuristic is only a fallback for exceptions that carry no result
name. A raw `sqlite3` exception no longer crosses the store boundary on any path, including
`SQLITE_FULL` during an insert and corruption discovered while opening or reading.

A rollback that fails after a failed commit, or after a body error, cannot leave a trustworthy
connection behind. The transaction context now closes the connection, the store forgets it and
reports itself closed on the next call, and the raised error names both failures and says the
connection was closed. Callers retry by constructing a new store.

Opening a brand-new file from several processes at the same moment previously failed for every
process but one, because `PRAGMA journal_mode = WAL` needs exclusive access and SQLite does not
apply the busy handler to that switch. The store now reads the journal mode first, which needs no
lock and is the only step an established WAL file ever takes; otherwise it retries the switch
within `busy_timeout_ms`. Schema creation re-reads `user_version` after acquiring
`BEGIN IMMEDIATE`, so a peer that initialized the store first is verified like any reopen rather
than raced. Four processes appending twenty-five events each to a fresh store produce one hundred
contiguous events with no busy failures.

A second independent probe set added two tamper cases the first amendment missed. A database
whose triggers keep their names but carry different bodies passed the object check while
`UPDATE` and `DELETE` succeeded through the store's own connection, and deleting the most recent
rows left no gap for the contiguity check to see while the next append minted a sequence past
the hole and made every later read fail. Opening a store now compares the stored DDL of every
expected table, index, and trigger against the source DDL (whitespace and case normalized), and
both opening and appending require SQLite's AUTOINCREMENT counter for `events` to equal the last
stored sequence; a mismatch is reported as a truncated history with the last intact sequence.
The constructor also maps a path that cannot be opened onto `EventStoreError` rather than a raw
driver exception. Envelope fields outside `payload_json` remain undigested until the hash chain.

## Amendment 2026-10-03: reads apply the append rules to names, versions, the counter, and JSON

`append` has always refused an `event_id`, `stream_id`, or `event_type` that is blank, over 500
characters, or outside `_NAME_PATTERN`, and has always written `stream_version` and
`event_version` as integers. It has always written both JSON columns through
`_canonical_json_object`, which refuses nesting deeper than 64 levels, more than 100000 values,
NaN or infinity, more than 1 MiB, and text that cannot be encoded as UTF-8. Reads checked none
of this. The version columns are declared `INTEGER` in a table that is not `STRICT`, so SQLite
stores whatever an out-of-band edit gives it: `CHECK (stream_version >= 1)` admits the text
`'x'`, because SQLite orders text above every integer, and a numeric text too large for 64 bits is
coerced to a real, which is infinity once it passes the range of a double. The `AUTOINCREMENT`
counter in `sqlite_sequence` has no declared type at all. A row or counter edited that way was
either read as valid or ended the command in a Python traceback. A stream id carrying a parser
version of 4301 digits or more crashed the fold in `int()`, and a payload holding a lone surrogate
escape passed `store verify` and then crashed `report` when it wrote its output.

Reads now apply those rules before they use a row:

- `_event_from_row` refuses a name outside the append grammar and a version column that is not an
  integer before it checks the payload digest, and raises `EventIntegrityError`.
- The open-time and append-time contiguity checks aggregate `stream_version` with raw SQL and
  never pass through `_event_from_row`. They refuse a stream whose aggregate is not an integer and
  name the first offending row. Opening a store refuses a sequence counter that is not an integer.
- After decoding, `_event_from_row` runs both JSON columns through `_canonical_json_object`, the
  same check `append` runs, and raises `EventIntegrityError` when either breaks it. The depth
  limit is therefore 64 levels on every Python version.
- Stored JSON the decoder cannot parse at all, because an integer literal exceeds the
  interpreter's digit limit or the nesting exceeds its recursion limit, is refused like JSON that
  does not parse. Neither error is a `json.JSONDecodeError`, so neither was caught before.
- `store verify` reports `event_name_invalid` and `event_version_invalid` for such rows, the JSON
  cases as `payload_not_json`, and a counter that is not an integer as
  `sequence_counter_mismatch`. It does not count a row whose `stream_version` is not an integer in
  the stream-version contiguity walk.

An integrity error that names a stored event or stream quotes a name inside the append grammar
exactly as before, and describes any other name by its length or storage class, because a name
outside the grammar can be any length.

Two stored values stay outside these checks. `occurred_at` and `recorded_at` are parsed, not
checked against the UTC format `append` writes, so a timestamp with another offset still reads. A
text column that is not valid UTF-8 fails inside the `sqlite3` module before any check runs and is
reported as `store_unavailable`, with the module's message.

This does not make a rewritten envelope detectable in general. A name or version rewritten to
another value `append` could have written still reads, as "What the payload digest does and does
not cover" says. The checks refuse only rows no `append` could have written, so no store written
through `append` is affected. Because every stream id a read accepts is at most 500 characters, a
parser version component in one is at most 425 digits. That is below 640, the lowest limit
`sys.set_int_max_str_digits` accepts other than 0 (unlimited), so version comparison cannot reach
the interpreter's digit limit under any setting.
