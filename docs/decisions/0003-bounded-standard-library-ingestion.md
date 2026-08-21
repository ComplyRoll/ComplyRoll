# ADR 0003: Use bounded standard-library ingestion for Phase 0

- Status: Accepted, amended 2026-08-21
- Date: 2026-08-18

The Decision section below records the original mechanism. The 2026-08-21 amendment supersedes
how DTD and entity rejection is enforced; read it before relying on that paragraph.

## Context

Assessment artifacts are untrusted and may be malformed or intentionally hostile. ComplyRoll also
needs to run on hardened workstations where adding dependencies may require separate approval.

## Decision

Phase 0 retains a dependency-free runtime and wraps Python's JSON and ElementTree parsers with
explicit file-size, nesting, node, and element bounds. XML DTD and entity declarations are
rejected before parsing. JSON must be UTF-8 and cannot contain non-standard numeric constants.
Parser errors and structurally invalid documents become explicit failed-ingest diagnostics.

Compatibility CSV and Markdown renderers neutralize formula-leading cells and raw markup without
changing normal predecessor output.

## Consequences

- No parser dependency or network access is required to ingest Phase 0 sources.
- Limits are deterministic, testable, and configurable by local callers.
- DTD-dependent XML is rejected even when its entity declarations would be harmless.
- Archive handling remains out of scope; any future archive adapter requires separate traversal,
  expansion, and extraction controls.
- Parser dependencies may still be reconsidered if later formats cannot be handled safely within
  these bounds.

## Amendment 2026-08-21: declaration rejection moved into the parser

### What was wrong

The original implementation rejected prohibited declarations by scanning the raw artifact bytes
for `<!DOCTYPE` and `<!ENTITY` before parsing. A byte scan is the wrong layer for a rule about
XML syntax, and it failed in both directions.

It under-rejected. The scan compared uppercased ASCII, but expat auto-detects UTF-16 from a byte
order mark or from the `<\x00` pattern that opens a UTF-16LE document. A UTF-16 encoded checklist
carrying an internal subset never matched the probe, so expat parsed the DTD and expanded the
declared entities. The expanded text reached observation fields, including `HOST_NAME`, which
feeds resource identity and therefore `derived_observation_id`. An attacker could forge the host
an assessment is attributed to, smuggle whole `VULN` records, or amplify a small artifact into
hundreds of megabytes of resident memory. External `SYSTEM` entities were not resolved, so this
was never a file-read or SSRF path.

It also over-rejected. A well-formed UTF-8 checklist that quotes `<!DOCTYPE` inside a CDATA
section or a comment is ordinary evidence: it is what a finding about a DTD vulnerability looks
like when an assessor writes it down. The scan cannot tell markup from content, so it refused the
whole artifact and produced zero observations, and the affected host silently dropped out of the
compatibility roll-up.

### What changed

`parse_xml_bounded` now drives `xml.parsers.expat` directly and feeds an
`xml.etree.ElementTree.TreeBuilder`. Rejection happens in the parser's own callbacks, where the
question "is this a declaration?" is already answered:

- `StartDoctypeDeclHandler` rejects any DOCTYPE, with or without an internal subset.
- `EntityDeclHandler` rejects any entity declaration, general or parameter.
- `ExternalEntityRefHandler` rejects external entity references as defense in depth.

Because the parser has already decoded the document, the guard is encoding independent, and
character data is never mistaken for markup. Depth and element bounds moved into the start and
end element handlers and keep their existing `InputLimitError` messages. The parser runs with
`namespace_separator="}"`, and names are rewritten to ElementTree's `{uri}local` convention so
adapters and tree output are unchanged.

`read_bounded` now requires a regular file and reads through a bounded loop rather than
`read_bytes`. A FIFO, character device, or directory is refused before the file is opened, so an
artifact path that would otherwise block forever on `open` fails immediately.

### What this does and does not protect

Protected:

- Internal entities are rejected at declaration, before any expansion, in every encoding expat
  accepts. Entity-expansion amplification is therefore unreachable through this entry point.
- External entities are never resolved. Parameter entity parsing is off by default and no
  external reference handler resolves anything, so there is no file read or network fetch.
- Non-regular files cannot stall or exhaust ingestion.

Not protected, and deliberately so:

- DTD-dependent XML is still refused outright, even when its declarations would be harmless.
- Expat's own billion-laughs amplification limiter remains in place as a backstop. It is not the
  control this project relies on; it covers residual paths and future parser configuration
  changes rather than the declared threat.
- Nothing here bounds what a valid document may assert. Content-level trust remains a provenance
  and review question, not a parser question.
