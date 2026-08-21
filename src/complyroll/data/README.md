# Bundled official data

Everything in this directory except the two `*-source.json` manifests is an unmodified copy of a
file published by the FedRAMP Program Management Office (GSA). ComplyRoll pins each file to one
immutable Git commit, records its SHA-256 in the matching manifest, and verifies the digest before
the file is parsed.

| File | Source repository | Pinned by |
|---|---|---|
| `fedramp-consolidated-rules.json` | <https://github.com/FedRAMP/rules> | `fedramp-rules-source.json` |
| `fedramp-common-definitions-schema-2026-06-24.json` | <https://github.com/FedRAMP/schemas> | `fedramp-ver-schemas-source.json` |
| `fedramp-vulnerability-detail-report-schema-2026-06-24.json` | <https://github.com/FedRAMP/schemas> | `fedramp-ver-schemas-source.json` |
| `fedramp-accepted-vulnerability-info-schema-2026-06-24.json` | <https://github.com/FedRAMP/schemas> | `fedramp-ver-schemas-source.json` |
| `fedramp-historical-ver-activity-schema-2026-06-24.json` | <https://github.com/FedRAMP/schemas> | `fedramp-ver-schemas-source.json` |

## License

These files are works of the United States Government and are not subject to copyright protection
in the United States (17 U.S.C. 105). They are not covered by ComplyRoll's Apache License,
Version 2.0, which applies to ComplyRoll's own code. Neither upstream repository currently carries a LICENSE file;
if one is added, it governs.

## Digest basis

Digests are computed over the bytes served by GitHub at the pinned commit. The same schemas served
from `https://fedramp.gov/schemas/` are minified, so their byte digests differ while the parsed
JSON is identical. Compare parsed JSON, not bytes, when checking the fedramp.gov copies.

## Updating

Re-pinning is a reviewed change: fetch the files at a new commit, recompute every SHA-256, update
the manifest (commit, retrieval time, versions, digests), run the test suite, and record the
change in `CHANGELOG.md`. The upstream `CHANGELOG.md` in `FedRAMP/schemas` and the `bun run check`
tooling in `FedRAMP/rules` are the authoritative signals for breaking changes.
