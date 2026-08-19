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
  because TrustRoll records received evidence, not a lossy semantic reconstruction of it.
- Case correlation in Phase 1 must group related observations without treating fingerprint
  equality as the vulnerability-correlation rule.
