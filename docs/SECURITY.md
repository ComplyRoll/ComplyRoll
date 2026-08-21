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

- 32 MiB maximum per artifact
- 128 levels of JSON nesting and 500,000 JSON values
- 128 levels of XML nesting and 500,000 XML elements
- UTF-8 JSON with duplicate keys and non-standard constants such as `NaN` rejected
- Complete rejection of XML DTD and entity declarations
- No archive extraction, XInclude processing, network lookup, or imported-code execution

Callers may lower these limits for their environment. Raising them is an explicit caller decision.
Compatibility CSV output neutralizes formula-leading cells, and Markdown table output escapes raw
HTML, delimiters, and embedded line breaks.

## Evidence integrity

- Use SHA-256 content digests for artifacts.
- Record producer, method version, collection time, and ingest time.
- Preserve append-only material history.
- Make report snapshots reproducible from event and policy snapshots.
- Consider signed manifests after the local evidence bundle format stabilizes.

### Phase 1 local persistence protections

- Event appends use one immediate transaction and an expected stream version.
- Unique event IDs and stream versions reject accidental replay and lost updates.
- Event payload and metadata JSON are bounded, structurally validated, and serialized canonically.
- Every payload records a SHA-256 digest that is verified when history is read.
- SQLite triggers reject application-level updates and deletes from event history.
- Projection checkpoints are mutable but disposable; durable history remains the rebuild source.

These controls protect against application mistakes and detectable corruption. They do not make a
database file tamper-proof against a user with direct filesystem write access. File permissions,
encrypted storage, signed export manifests, backup integrity, and retention controls remain
deployment or later bundle requirements.

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
2020-12 implementation with its non-GPL format extra. The major version is bounded; release builds
must lock, scan, and inventory the resolved dependency graph. ComplyRoll owns the offline registry
boundary so the validator never retrieves a schema referenced by untrusted or mutable content.
