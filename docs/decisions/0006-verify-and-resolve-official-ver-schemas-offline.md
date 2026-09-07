# ADR 0006: Verify and resolve official VER schemas offline

- Status: Accepted
- Date: 2026-08-20

## Context

Phase 1 must validate Vulnerability Detail, Accepted Vulnerability, and Historical VER Activity
documents against FedRAMP's official Draft 2020-12 JSON Schemas. Those schemas reference a shared
Common Definitions document by absolute `https://fedramp.gov` identifiers.

The date-stamped `2026-06-24` files were corrected in place after publication. The three report
schemas changed from version `0.1.0` to `0.1.1`, and Common Definitions is now version `0.2.1`,
without changing the public filenames. The corrected documents are available in the official
`FedRAMP/schemas` repository, where one Git commit can identify their exact bytes.

A complete Draft 2020-12 validator and reference implementation is security-sensitive and too
large to reproduce safely in ComplyRoll. Python's standard library does not provide one.

## Decision

ComplyRoll pins the four schema documents to `FedRAMP/schemas` commit
`ae43ae2952c5dd5c56d54d12e8b92c7db1b3710a`. A package manifest records the repository, commit,
retrieval time, JSON Schema draft, and each document's filename, `$id`, `$schemaVersion`, and
SHA-256. Runtime loading verifies those values before a schema is used.

The loader builds an immutable `referencing.Registry` from only the verified package resources.
It preflights every `$ref`, including JSON Pointer fragments. No retrieval callback or legacy
remote resolver is configured, so an absent resource fails closed instead of reaching the
network. Each document is also checked as a Draft 2020-12 schema before report validation.

ComplyRoll uses `jsonschema[format-nongpl]>=4.23,<5` for Draft 2020-12 validation, modern
`referencing` integration, and the URI, date, and date-time format implementations required by the
official schemas. The dependency is major-version bounded. Release automation must lock and scan
the resolved dependency graph before distribution.

Validation produces deterministic issues with instance and schema JSON Pointers, the failed
validator keyword, and a human-readable message. Results retain the official schema repository,
commit, identifier, schema version, and digest. Callers may inspect all issues or explicitly raise
one domain error.

FedRAMP describes these schemas as minimum structures. ComplyRoll therefore preserves their
default extension-friendly behavior and does not impose `additionalProperties: false` locally.
Raw report JSON is still bounded and rejects duplicate keys, non-standard constants, malformed
UTF-8, excessive nesting, and excessive value counts before schema validation.

## Consequences

Benefits:

- Historical validation is reproducible even if a date-stamped public URL changes again.
- Cross-document references resolve offline using their official identifiers.
- Missing resources, schema tampering, invalid schema definitions, and invalid reports have
  separate fail-closed errors.
- Actionable JSON Pointers can be surfaced by the CLI and projection pipeline without parsing
  validator prose.

Costs and limits:

- Schema validation introduces the first non-standard-library runtime dependency and its format
  checker dependency graph.
- Bundled schemas are snapshots; adopting a later official correction requires a reviewed manifest
  and digest update.
- Schema validity is structural. It does not by itself establish semantic accuracy, report-period
  ordering, correct case state, or compliance with every narrative rule.
- The initial registry contains only the three Phase 1 VER output schemas and their common
  definitions. Later report types must be added through the same manifest process.

## Dependency assessment

`python-jsonschema/jsonschema` is an active, non-archived MIT-licensed implementation of JSON
Schema with explicit Draft 2020-12 and `referencing` support. The non-GPL format extra is selected
to ensure official `uri`, `date`, and `date-time` keywords do not silently become annotations when
optional checkers are absent. Network access remains disabled by application-owned registry
construction rather than delegated to the dependency.

## Rejected alternatives

Fetching public schema URLs during validation was rejected because it would prevent offline and
historical reproduction and would expose validation to mutable content and network failures.
Maintaining a partial in-house JSON Schema evaluator was rejected because incomplete keyword or
reference behavior could incorrectly certify a report. The deprecated `RefResolver` API was
rejected because the modern immutable registry provides an explicit offline resource boundary.

## Amendment 2026-09-04: re-pin to Common Definitions 0.3.0

The bundle now pins `FedRAMP/schemas` commit `5156719aa7d0def16cf66f6197db9d6c0024e0e7`, the
merge of upstream pull request 22 on 2026-09-01. That commit changed only Common Definitions,
from version `0.2.1` to `0.3.0`, SHA-256
`ed810d60584580fb86cda3f846d94504a14e09538122c27c5b5231d41151d6de`. The three report schemas are
byte-identical to the `0.1.1` copies pinned above, so their manifest entries and digests are
unchanged. The manifest process this record describes was followed as written: the manifest
records the new commit, retrieval time, version, and digest, and the loader verifies them before
any schema is used. What changed inside the schema and why ComplyRoll adopted it are in ADR 0009.
