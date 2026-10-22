# Security design requirements

ComplyRoll will process sensitive security evidence. Security controls are product requirements,
not deployment documentation to add later.

## Threats

- Malicious or malformed assessment files
- XML entity or resource-exhaustion attacks
- Path traversal through archive contents or evidence references
- Oversized artifacts and decompression bombs
- Formula injection in CSV output
- Untrusted Markdown/HTML evidence
- Evidence tampering or ambiguous provenance
- Exposure of exploit-enabling vulnerability detail
- Credential, PII, customer, or infrastructure leakage
- Unauthorized trust-center access
- Dependency and update-channel compromise
- Automated decisions overstating or understating agency risk

## Input handling

- Treat every imported file and API response as untrusted.
- Bound file size, collection size, nesting depth, and parse time.
- Disable external XML entities and network resolution.
- Never extract an archive member outside a dedicated temporary directory.
- Preserve the source digest before parsing.
- Keep diagnostics separate from report data.
- A parse error cannot become an empty successful assessment. With `--record-failed-imports` it
  becomes a recorded vulnerability instead, never a clean result (ADR 0014).

### Phase 0 enforced bounds

The standard-library ingestion layer currently enforces:

- 32 MiB maximum per artifact, read from regular files only with a bounded read loop (FIFOs and
  devices are refused rather than read to exhaustion)
- 128 levels of JSON nesting and at most 500,000 JSON values
- 128 levels of XML nesting and at most 500,000 XML elements
- UTF-8 JSON (a leading BOM is tolerated) with duplicate keys and non-standard constants such as
  `NaN` rejected
- XML DOCTYPE and ENTITY declarations rejected by the parser's declaration handlers, in any
  encoding expat decodes (UTF-8, UTF-16, and others); external entities are never resolved, and
  expat's own amplification limiter remains as a backstop. Literal `<!DOCTYPE` text inside CDATA or
  comments is ordinary character data and is accepted.
- No archive extraction, XInclude processing, network lookup, or imported-code execution
- For SARIF, at most 50,000 results per run (`max_results_per_run`), 50,000 observations per
  artifact (`max_observations_per_artifact`), and 256 MiB of canonical JSON summed over an
  artifact's observations (`max_observation_bytes_per_artifact`), all `IngestLimits` fields, and at
  most 256 locations per result; exceeding any of them refuses the artifact
- A SARIF observation is capped member by member (512-character identity inputs, 2,048-character
  uris, 512-character titles and scalar metadata values, 4,096-character descriptions, 64 list
  items of 256 characters each, and 64 source identifiers). The caps count characters, not
  bytes, and a character can cost up to four bytes of canonical JSON, so real input can reach
  the ceiling. One folded observation over `MAX_OBSERVATION_JSON_BYTES` (512 KiB of canonical
  JSON) refuses the artifact on the stateless and persisted paths alike, which is why no
  payload the store's `MAX_EVENT_JSON_BYTES` (1 MiB) or `MAX_EVENT_JSON_VALUES` (100,000) would
  refuse is ever built
- For HDF, the same three `IngestLimits` fields apply: `max_results_per_run` bounds one
  profile's controls and one control's results, `max_observations_per_artifact` bounds the
  distinct folded observations, and `max_observation_bytes_per_artifact` bounds their summed
  canonical JSON. A document lists at most 64 profiles (`MAX_PROFILES_PER_DOCUMENT`), which also
  bounds every `parent_profile` chain. An HDF observation takes the same member caps and the same
  512 KiB ceiling as a SARIF one. Exceeding any of them refuses the artifact
- Exactly nine HDF tags are read (`severity`, `severityoverride`, `cci`, `nist`, `gid`, `rid`,
  `stig_id`, `cve`, and `cwe`). Check and fix prose, `code`, `refs`, `source_location`,
  `depends`, `statistics`, and every other tag are never read, so their size costs nothing beyond
  the node bound. A result's `backtrace` is tested for presence and its content is never read
- An HDF `impact` is checked before any arithmetic: an integer outside 0 to 1 is refused before
  `float()` could overflow on it, a float must be finite and within 0 to 1, and a bool is not a
  number. A refused impact is a warning that sets nothing. An integer of more than 4,300 digits
  is refused inside `json.loads` by Python's `int_max_str_digits` limit and fails the artifact
- A bare `.json` file is read as HDF only after its bounded parse has finished, and only when it
  has no `stigs` key, a `profiles` array, and a `platform` object. A bare `.json` document that
  exceeds the depth or node bound is never sniffed, so its failure is attributed to CKLB
- For CycloneDX, at most `max_results_per_run` vulnerabilities per document and 1,024 `affects`
  entries per vulnerability (`MAX_AFFECTS_PER_VULNERABILITY`), both checked before any fold work,
  plus the SARIF observation limits and member caps, with the observation of the subject counted
  toward `max_observations_per_artifact`; a folded package keeps at most 64 installs
  (`MAX_INSTANCES_PER_PACKAGE`). A candidate's fold order is built from one token per carrier, cut
  at 256 characters and followed by a SHA-256 digest of the whole, so memory does not grow with purl
  length times `affects` count. Each distinct bom-ref's carrier facts are built once and shared by
  every `affects` entry that names it, so memory does not grow with components sharing one bom-ref
  times the entries naming it either. Each install's texts are sanitized and capped once per
  document, so CPU does not grow with purl length times the vulnerabilities naming it. The component
  tree is walked with an explicit stack bounded by the parse, never by recursion. Exceeding any
  limit refuses the artifact
- A bare `.json` file is read as CycloneDX only after its bounded parse has finished and the HDF
  sniff has declined it, and only when it has no `stigs` key and `bomFormat` is `CycloneDX`
- SARIF, HDF, and CycloneDX diagnostics are coalesced per code per artifact, and each JSON path
  and detail they carry is sanitized and cut at 512 characters, so one artifact's diagnostics
  stay within about 56,000 characters whatever the input's size
- A lone surrogate code point in any JSON string or object key is refused at parse, for every
  JSON adapter
- For a CISA KEV catalog supplied with `--kev`, 8 MiB maximum (the live feed is about 1.7 MB),
  at most 20,000 entries (the live feed holds about 1,700), and 16 levels of JSON nesting (the
  feed reaches 5), with the standard 500,000-value bound unchanged. The catalog is read through
  the same bounded reader as an artifact and is never fetched: the operator downloads the feed
  from CISA out of band, and ComplyRoll opens no socket for it, bundles no copy, and writes
  nothing about it to the event store
- The catalog is validated field by field before any value is used. Every field is type-checked
  before any regex or parse runs, a JSON `null` in an optional field is refused rather than read
  as absent, all three dates are matched against explicit ASCII patterns before `fromisoformat`
  (which otherwise accepts basic, week, and other non-RFC forms), and every year is held between
  1970 and 9000 so that the next-day due instant and the UTC normalization cannot raise
  `OverflowError` past the CLI's handlers. Any failure refuses the run as `invalid_input` and
  publishes nothing
- Catalog error messages quote only values that have already passed validation, or a `repr` cut
  to 64 characters, so an 8 MiB field cannot become an 8 MiB stderr line. A second `--kev` is
  refused rather than silently applying the last one, and naming the catalog as an output is
  refused as an input overwrite
- For an information resource inventory supplied with `--inventory` (ADR 0015), 8 MiB maximum
  (`MAX_INVENTORY_BYTES`), at most 20,000 resources (`MAX_INVENTORY_RESOURCES`), and 16 levels
  of JSON nesting, with the standard 500,000-value bound unchanged. The inventory is a new
  untrusted input, read through the same bounded reader as an artifact. ComplyRoll never fetches
  it and never writes it to the event store, and a report records its SHA-256, size, and entry
  count, never its bytes. `cases coverage` reads it through the same reader, and each gap record
  it stores carries the clock's resource pair, the entry's `job`, and the inventory's SHA-256,
  never the bytes
- The inventory is validated field by field before any value is used. Unknown keys are refused at
  every level, and every field is type-checked before any pattern runs. Identity text takes the
  adapters' rule and is refused, never repaired: over 512 characters, or holding a control,
  format, surrogate, or line-separator code point, or blank. So an inventory pair can only name
  what an observation can carry. A resource type may not hold a colon, `name`, `sampleGroup`,
  and `job` must be 1 to 128 printable ASCII characters, and every instant is matched against the
  KEV catalog's ASCII pattern and held between 1970 and 9000 UTC before it is used. That pattern
  is an RFC 3339 subset with an uppercase `T` and either an uppercase `Z` or a numeric offset,
  and fractional seconds are truncated to microseconds, so two instants that differ only beyond
  the sixth fractional digit compare equal, `--as-of` included. A JSON `null`
  in an optional field reads as absent. Any failure refuses the run as `invalid_input` with a
  message that starts "inventory", and publishes nothing
- Inventory error messages quote only values that have passed validation, or a `repr` cut to 64
  characters, and an identifier refused for its length or its code points is described, never
  echoed. A second `--inventory` is refused as `invalid_option` rather than silently applying the
  last one, and naming the inventory as an output is refused as an input overwrite

Callers may lower these limits for their environment. Raising them is an explicit caller decision.
Compatibility CSV output neutralizes formula-leading cells, and Markdown table output escapes raw
HTML, delimiters, and embedded line breaks. Markdown link and image syntax is not yet neutralized;
treat rendered roll-ups from untrusted checklists accordingly.

The SARIF adapter refuses identity and degrades evidence (ADR 0011 Decision 10). An identity
input that carries a control, format, surrogate, or line-separator code point, or that exceeds
its cap, fails the artifact, while titles, messages, tags, and metadata values are sanitized and
truncated with the cut members named. Every uri in a log is text: it is validated, recorded, and
never opened, resolved, or fetched. Message placeholders are expanded by a single-pass pattern
substitution, never by `str.format`, with at most 1,024 placeholders substituted and literal
text read only as far as the 4,096-character budget leaves room for, so a result's cost is
bounded by the caps and not by the size of a template or of the descriptor and run data it shares
with other results, and a result's own lists are cut once however many resources it names.
Placeholders, location links, and CVE, GHSA, and CWE identifiers take ASCII letters and digits
only, so another script's digits, or a letter that only folds to an ASCII one, never become one,
and a `security-severity` string must be an ASCII decimal, so `0_9` or another script's digits
never set a severity. A clock outside the years 1970 to 9000 UTC is ignored with a warning, and an
integer `security-severity` outside 0 to 10 is invalid, both checked before any arithmetic that
could overflow on them; a region line or column above 2**31 - 1 is absent, so a region's text stays
short. A very large CodeQL log can exceed the 500,000 JSON value bound while staying under 32 MiB;
it fails closed with a message that names the bound, and raising it is the caller's decision.

The HDF adapter follows the same rule (ADR 0013 Decision 10). Every control id, every profile
name, and `platform.target_id` is an identity input: over 512 characters, or carrying a control,
format, surrogate, or line-separator code point, it is refused whole and the artifact yields no
observations. Titles, descriptions, tag values, result messages, platform strings, and waiver
and attestation texts are evidence, sanitized and cut at the shared caps with the cut members
named. The adapter opens no path and fetches nothing: `depends` entries, profile `url` values,
and `source_location` paths are never read. A `backtrace` or an `exception` never reaches a
shell or an evaluator; an exception is recorded only as the text of a failure message.

The CycloneDX adapter follows the same rule (ADR 0016). The tool names, every vulnerability id, and
every composed scope and package resource id are identity inputs: over 512 characters, or carrying a
control, format, surrogate, or line-separator code point, the reading is refused, never repaired; on
an inventory or an empty BOM (K1, K2) that refusal is a format refusal, never a detection failure. A
purl is parsed by a function that never raises; a malformed escape or non-UTF-8 bytes make it a weak
key with a warning, and a decoded `/` can never add a path segment. Case folding is ASCII only, so a
package key does not depend on the interpreter's Unicode database. Purls, BOM-Links, external
references, and every other URL in a document are text: nothing is opened, resolved, or fetched, and
no other document is joined. A standalone VEX document is refused, and an embedded analysis is
recorded as metadata that never changes a disposition, so a supplier's statement cannot close a
case, and a judged record never counts toward verifying coverage. Component names, versions,
descriptions, and analysis details are evidence, sanitized and cut at the shared caps.

A detection process failure (ADR 0014) is built from a reading that already failed, so everything it
records is treated as hostile. The file name and every diagnostic message and location pass
`diagnostic_text` (sanitized, then cut at 512 characters) before they reach the system observation's
metadata, the `failure.recorded` payload, a demoted diagnostic, or the report's `detectionFailures`.
A diagnostic with no location takes the cleaned file name as its location, and an in-file location
the adapter gave, such as `stigs[0].rules`, is kept. The failure class and `failure.codes` are
decided from diagnostic codes in a closed vocabulary and two structured fields on the result, never
from message text, and an ERROR code outside that vocabulary stops the run as it did before, so a
new adapter error cannot be recorded until someone classifies it. No message text, name, or parser
enters the observation's identity. A failed reading contributes at most `FAILURE_DIAGNOSTIC_CAP`
(62) of its diagnostics, ordered by their own content, plus one `failure_diagnostics_truncated`
notice that names the dropped count and the `detection_failure_recorded` notice, so the list is at
most 64 entries however many the reading produced, and the `failure.recorded` contract refuses a
longer one. Every adapter sets its source type from a literal constant, so no input byte can produce
a `complyroll.` source type, and `Observation` refuses that prefix on an artifact observation as
defense in depth. The guarantee is worded for what it delivers: a reader identifies a system record
by `detectedAtSource` `system`, resource type `artifact`, and membership in `detectionFailures`. A
SARIF driver named `complyroll` yields an artifact record with source type `sarif` that none of
those three match, and a test pins it.

## Evidence integrity

- Use SHA-256 content digests for artifacts.
- Record producer, method version, collection time, and ingest time.
- Preserve append-only material history.
- Make report snapshots reproducible from event and policy snapshots.
- Consider signed manifests after the local evidence bundle format stabilizes.

### Phase 1 local persistence protections

- Event appends use one immediate transaction and an expected stream version. A failed commit
  rolls back and raises `EventStoreBusyError`; the connection is never left inside an open
  transaction.
- The database runs in WAL journal mode with `synchronous=FULL`, so readers do not block commits
  and committed history survives power loss.
- Unique event IDs and stream versions reject accidental replay and lost updates.
- Event payload and metadata JSON are bounded, structurally validated, and serialized canonically.
- `payload_sha256` covers the canonical payload bytes only and is verified on every read. The
  metadata, event type, stream identifier, version, and timestamps are not yet covered by a
  digest; a full-envelope digest with a per-store hash chain is planned for the next schema
  version.
- SQLite triggers reject application-level updates and deletes from event history, and opening a
  store verifies that the expected tables, indexes, and triggers are still present. A schema
  object the store never created, such as an added trigger, is not refused; an insert it aborts
  is refused with SQLite's reason, cut at 200 characters, and only a UNIQUE key reads as a
  conflict with committed history.
- Reads verify that global sequences and stream versions are contiguous, so a deleted event is
  reported as an integrity error instead of being skipped.
- Reads apply the append rules to event names, version columns, and the sequence counter, and the
  canonical-JSON checks to both JSON columns. The metadata key rule is applied at append and by
  `store verify`, not on read (ADR 0008). Event IDs, stream identifiers, and event types must be at
  most 500 characters from the allowed set. The stream version and event version must be stored as
  integers of at least 1, and the sequence counter as one integer in one row. Stored JSON must pass
  the checks `append` runs on it (nesting, value count, size, no NaN or infinity, valid Unicode) and
  be the exact canonical text `append` writes, so reindented, padded or reordered JSON and a
  duplicate object member are refused, and JSON past the decoder's own limits is refused like JSON
  that does not parse. Both timestamp columns must be the exact UTC text `append` writes, with six
  fraction digits and a `Z`, so another offset or spelling of an instant is refused. A row edited in
  place to break any of these is refused with `store_integrity` rather than a traceback, and
  `store verify` reports it (`event_name_invalid`, `event_version_invalid`, `payload_not_json`,
  `event_timestamp_invalid`, `sequence_counter_mismatch`). A text column that is not valid UTF-8 is
  refused as `store_integrity`, naming the column and never its text, and `store verify` reports its
  row as `event_text_invalid` and walks on. A value rewritten to another one `append` could have
  written is not detected. Store integrity errors never quote a name outside the grammar: the
  refusal of the name gives the rule it breaks, and a message that identifies its event or stream
  for another fault, such as a version gap or a digest mismatch, gives its length or storage class.
  A refusal or fault message cuts each stored value it quotes at 200 characters and gives the full
  length: a payload value, the value and unexpected key a contract issue quotes, its JSON pointer,
  the keys a `metadata_breaches` message lists, and a stream identifier a stream-id parse quotes.
  Other messages quote a stream identifier whole, which the name rule holds to 500 characters. A
  contract error lists every issue, so its length still grows with the number of invalid values, up
  to the store's value cap. Some output carries stored text unescaped, newlines and terminal escape
  sequences included: a payload key in a contract issue's JSON pointer, a key in a
  `metadata_breaches` message, and the actor `cases history` prints on stdout, even from a store
  that verifies clean. Treat any output read from an untrusted store as untrusted text.
- A projection checkpoint must hold a non-negative integer count and a time with a timezone. The
  library's checkpoint reader and its compare-and-swap refuse any other row as
  `EventIntegrityError`, and `store verify` reports it as `projection_checkpoint_invalid`. No
  command reads a checkpoint.
- `store verify` holds the migration records to the schema marker: a record the marker needs
  and the table lacks (`migration_missing`), a record whose description is not the one its
  migration writes (`migration_altered`), and, with the marker in the supported range, a record
  it does not reach (`migration_unexpected`), the trace of a marker lowered after the record was
  written. An append that would mark such a store refuses it as `store_unavailable` and names
  the record, rather than failing on SQLite's unique constraint.
- `store verify` reports a case stream whose id names no tracking id
  (`case_tracking_id_mismatch`) and a case that records a disposition and no evaluation
  (`disposition_without_evaluation`). Every report from the store, `cases list`,
  `cases evaluate` and `cases attest-detection` refuse the first as `history_invalid`, and every
  report refuses the second.
- Projection checkpoints are mutable but disposable; durable history remains the rebuild source.
- A failure stream (ADR 0014) is appended in the same transaction that marks the store schema
  version 2, so the marker and the failure commit or roll back together. A hold, a failure stream
  that opens with `failure.held` (ADR 0014, amendment 2026-10-13), marks the store schema version
  3 the same way. A build that predates failure streams refuses a schema 2 store, and a build that
  predates holds refuses a schema 3 store, in `ingest`, `cases`, and `report --db` rather than
  misreading it. Their `store verify` reports a marker they do not open as
  `schema_version_unsupported` (ADR 0004, amendment 2026-10-03); before that amendment it
  reported the failure streams as faults. `store verify` reports a failure stream in a store left
  at version 1, or a hold in a store below version 3 (`failure_schema_unmarked`), a failure
  stream that is not exactly one head and one observation (`failure_incomplete`,
  `failure_overfull`), a head or observation that does not match its stream, an observation whose
  metadata is not what its writer stores (a failure class its codes do not name included), an
  observation carrying a field its writer fixes otherwise (disposition, severity, source
  identifiers, title, description, or an evidence id other than the digest's own), a stream its
  observation opens, or a head and observation that describe two different failures
  (`failure_stream_mismatch`), a hold whose observation no `failure.recorded` stream holds first
  (`failure_hold_orphaned`), and a stream that does not open with `failure.held` holding a system
  observation another failure stream of the digest already holds (`failure_duplicate_observation`).
  The head checks treat `failure.recorded` and `failure.held` alike. Except for the unmarked store,
  `report --db` refuses each of these rather than rendering it.

These controls protect against application mistakes and detectable corruption. They do not make a
database file tamper-proof against a user with direct filesystem write access. File permissions,
encrypted storage, signed export manifests, backup integrity, and retention controls remain
deployment or later bundle requirements. Database files are created with the process umask; set a
restrictive umask or move the file to a protected location on shared hosts.

### Phase 1 policy-source protections

- Runtime policy loading is offline and bounded to an 8 MiB source snapshot.
- SHA-256 is verified against an immutable commit manifest before JSON parsing.
- Dataset version and last-updated metadata must also match the manifest.
- Duplicate JSON keys, non-standard constants, excessive nesting, and excessive values are
  rejected.
- Policy selection uses official structured applicability and class variants; it does not parse
  deadlines from prose.
- Deadline results retain the source rule, profile, commit, version, date, and digest.

### Phase 1 report-schema protections

- Four official schema documents are pinned to one immutable `FedRAMP/schemas` commit.
- SHA-256, `$schema`, `$id`, and `$schemaVersion` are verified before registry construction.
- Every schema is checked as Draft 2020-12 and every `$ref` is pre-resolved.
- The immutable registry contains only bundled resources and has no network retrieval callback.
- Raw report JSON uses byte, depth, and value-count bounds and rejects duplicate keys and
  non-standard constants.
- URI, date, and date-time formats are enforced instead of treated as unchecked annotations.
- Validation issues preserve instance/schema JSON Pointers and exact source provenance.

## Sensitive information

Each evidence artifact requires a sensitivity classification and optional redacted representation.
Reports must disclose sufficient risk information without unnecessarily exposing:

- Credentials or tokens
- Exploit payloads or detailed attack paths
- Internal hostnames and addresses
- Employee PII
- Emergency procedures or bypass mechanisms
- Unnecessary customer or agency identities

Redaction must be explicit and reviewable. It must not silently omit material risk.

A compiled report and its Markdown twin are the provider's and assessor's working record. They
include internal resource identifiers and provider rationale, so redact them before sharing with
an agency. Audience-specific views are a later slice.

A report compiled with `--inventory` carries more of the same: every inventory resource and alias,
the `job` and `sampleGroup` names, the operator's attestation references, and the observed
resources the inventory omits. Redact the coverage block and its Markdown section the same way.

## Authorization and trust-center publishing

The hosted/API phase must include:

- Least privilege and role separation
- Just-in-time access where practical
- Strong non-user authentication
- Access inventory and history
- Tamper-resistant audit events
- Availability independent from the monitored service where required
- Encryption in transit and at rest
- Revocation and access review
- Separate public, agency, assessor, and restricted evidence views

## Automated decisions

ComplyRoll may calculate deterministic rule deadlines and identify missing information. It must not
silently make contextual security decisions.

The following require explicit rationale and actor provenance:

- IRV classification
- LEV classification
- PAIN assignment
- False-positive disposition
- Risk acceptance
- KSI sufficiency conclusion

AI-assisted summaries or suggestions must remain distinguishable from provider or assessor
decisions and must cite their underlying records.

## Dependency policy

- Minimize runtime dependencies.
- Pin and verify dependencies in release automation.
- Generate an SBOM for releases once packaging begins.
- Document why security-sensitive parsers and schema validators are selected.
- Never execute imported validation code without an explicit sandbox and trust decision.

ADR 0006 documents the first runtime dependency: the active, MIT-licensed `jsonschema` Draft
2020-12 implementation with its non-GPL format extra. The extra resolves to roughly nineteen
distributions, of which only `rfc3339-validator` (date-time) and `rfc3986-validator` (uri) back
the formats ComplyRoll requires; narrowing the dependency to those two packages, committing a
hashed lock file, and generating an SBOM are still open. The major version is bounded; release
builds must lock, scan, and inventory the resolved dependency graph. `referencing`, which
`jsonschema` already requires and which the same maintainer publishes, is declared directly
because the schema loader imports it; declaring it adds no distribution to the resolved graph.
ComplyRoll owns the offline registry boundary so the validator never retrieves a schema referenced
by untrusted or mutable content. If a GPL-licensed `rfc3987` package is installed alongside,
`jsonschema` prefers it for the `uri` format; keep it out of deployment environments.

## Reporting and sensitive input

Vulnerability reports go through the channel in the repository's root `SECURITY.md`. Real
assessment artifacts routinely carry Controlled Unclassified Information markings and must never
be attached to issues, pull requests, or advisories; reproduce with synthetic fixtures or
redacted copies that keep only rule identifiers and statuses.
