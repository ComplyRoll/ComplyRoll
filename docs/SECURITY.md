# Security design requirements

TrustRoll will process sensitive security evidence. Security controls are product requirements,
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

## Evidence integrity

- Use SHA-256 content digests for artifacts.
- Record producer, method version, collection time, and ingest time.
- Preserve append-only material history.
- Make report snapshots reproducible from event and policy snapshots.
- Consider signed manifests after the local evidence bundle format stabilizes.

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

TrustRoll may calculate deterministic rule deadlines and identify missing information. It must not
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
