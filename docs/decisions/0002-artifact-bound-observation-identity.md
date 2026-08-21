# ADR 0002: Bind observation identity to the source artifact

- Status: Accepted
- Date: 2026-08-18

## Context

Reimporting one artifact must be idempotent, but two assessment runs containing the same rule on
the same resource are separate source facts. An identity made only from scanner, rule, and
resource would incorrectly collapse all later observations. An identity based on ingestion time
would create duplicates whenever identical bytes are reimported.

## Decision

The Phase 0 observation fingerprint is SHA-256 over source type, source tool, parser name/version,
source record, resource type, resource identifier, benchmark/profile context, and the exact
artifact SHA-256. Adapter-generated observation IDs are derived from that fingerprint.

The ingestion timestamp, display text, status, and source severity are not identity inputs. Their
exact values remain in the immutable observation.

## Consequences

- Reimporting byte-identical artifacts with the same parser version produces the same observation
  identifiers.
- A parser-version change creates a new normalized observation rather than silently changing an
  existing identifier's meaning.
- A changed artifact produces a new immutable set even when it evaluates the same rules.
- Whitespace-only source changes also create a new artifact and observations; this is intentional
  because ComplyRoll records received evidence, not a lossy semantic reconstruction of it.
- Case correlation in Phase 1 must group related observations without treating fingerprint
  equality as the vulnerability-correlation rule.

## Amendment 2026-08-21

The original decision assumed every observation is bound to a received artifact. That made a
process-failure observation impossible to construct, even though a failed or missing validation is
itself a vulnerability the provider must record. This amendment adds a second identity recipe
rather than weakening the first.

### Origin discriminator

`Observation.origin` is an `ObservationOrigin` and defaults to `ARTIFACT`, so every existing caller
keeps today's contract.

- `ARTIFACT` observations require `source_artifact_name` and a SHA-256 `source_artifact_digest`,
  exactly as before.
- `SYSTEM` observations must leave both artifact fields empty, must supply `observed_at` (the
  detection window is the fact being recorded), and must supply a non-blank `context_key` (the
  identity of the producing validation or job). There are no bytes to hash, so the job identity and
  the window carry the identity instead.

### The SYSTEM identity recipe

SHA-256 over a JSON array, `json.dumps(..., separators=(",", ":"), ensure_ascii=True)`:

`["system", source_type, source_tool, parser_name, parser_version, source_record_id,
resource_type, resource_id, context_key, observed_at in UTC ISO-8601]`

`derived_observation_id` remains `obs-<fingerprint>` for both origins.

The recipe is JSON-encoded because JSON string escaping makes it injective: no combination of field
values can be rearranged to produce the payload of a different observation. The literal `"system"`
prefix keeps the two identity spaces disjoint. `observed_at` is normalized to UTC before
formatting, so the same instant expressed in two offsets yields one identity.

### The ARTIFACT recipe is unchanged, deliberately

The artifact recipe still joins its nine parts with `\x1f` and is **not** injective: the separator
is unescaped and the identity fields still accept NUL and other C0 controls. Making it injective
would re-mint every observation identifier already in existence, so that change is deferred to a
version bump and must be paired with a migration. The defect is recorded here rather than fixed
silently.

### Per-adapter parser versions

`PARSER_VERSION` is replaced by `CKLB_PARSER_VERSION`, `CKL_PARSER_VERSION`,
`XCCDF_PARSER_VERSION`, and `CCI_PARSER_VERSION` (plus `XML_DISPATCH_PARSER_VERSION` for the
pre-dispatch stage that fails before an adapter is chosen). Artifact provenance now records the
version of the adapter that actually ran instead of a shared module default. Because the parser
version is an identity input, one shared constant meant correcting a single parser would re-mint
every unchanged observation from the other three. All values stay `"1"`, so no identity changes
today.

### Digest normalization

`source_artifact_digest` and `EvidenceArtifact.digest_sha256` are stored lowercase. The validator
already accepted mixed case but preserved it, so the same artifact recorded with an uppercase
digest produced a different fingerprint. No shipped adapter emits uppercase, so no existing
identifier changes.
