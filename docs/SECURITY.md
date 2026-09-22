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
- A parse error cannot become an empty successful assessment.

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
- For SARIF, at most 50,000 results per run (`max_results_per_run`) and 50,000 observations per
  artifact (`max_observations_per_artifact`), both `IngestLimits` fields, and at most 256
  locations per result; exceeding any of them refuses the artifact
- A SARIF observation is capped member by member (512-character identity inputs, 2,048-character
  uris, 512-character titles and scalar metadata values, 4,096-character descriptions, and 64
  list items of 256 characters each), and one folded observation over
  `MAX_OBSERVATION_JSON_BYTES` (512 KiB of canonical JSON) refuses the artifact on the stateless
  and persisted paths alike, so no payload the store's `MAX_EVENT_JSON_BYTES` (1 MiB) or
  `MAX_EVENT_JSON_VALUES` (100,000) would refuse is ever built
- A lone surrogate code point in any JSON string or object key is refused at parse, for every
  JSON adapter

Callers may lower these limits for their environment. Raising them is an explicit caller decision.
Compatibility CSV output neutralizes formula-leading cells, and Markdown table output escapes raw
HTML, delimiters, and embedded line breaks. Markdown link and image syntax is not yet neutralized;
treat rendered roll-ups from untrusted checklists accordingly.

The SARIF adapter refuses identity and degrades evidence (ADR 0011 Decision 10). An identity
input that carries a control, format, surrogate, or line-separator code point, or that exceeds
its cap, fails the artifact, while titles, messages, tags, and metadata values are sanitized and
truncated with the cut members named. Every uri in a log is text: it is validated, recorded, and
never opened, resolved, or fetched. Message placeholders are expanded by a single-pass pattern
substitution, never by `str.format`. A very large CodeQL log can exceed the 500,000 JSON value
bound while staying under 32 MiB; it fails closed with a message that names the bound, and
raising it is the caller's decision.

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
  store verifies that the expected tables, indexes, and triggers are still present.
- Reads verify that global sequences and stream versions are contiguous, so a deleted event is
  reported as an integrity error instead of being skipped.
- Projection checkpoints are mutable but disposable; durable history remains the rebuild source.

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
hashed lock file, and generating an SBOM are open items tracked in `CHANGELOG.md`. The major
version is bounded; release builds must lock, scan, and inventory the resolved dependency graph.
ComplyRoll owns the offline registry boundary so the validator never retrieves a schema referenced
by untrusted or mutable content. If a GPL-licensed `rfc3987` package is installed alongside,
`jsonschema` prefers it for the `uri` format; keep it out of deployment environments.

## Reporting and sensitive input

Vulnerability reports go through the channel in the repository's root `SECURITY.md`. Real
assessment artifacts routinely carry Controlled Unclassified Information markings and must never
be attached to issues, pull requests, or advisories; reproduce with synthetic fixtures or
redacted copies that keep only rule identifiers and statuses.
