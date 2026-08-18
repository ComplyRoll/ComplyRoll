# TrustRoll

TrustRoll is a local-first evidence compiler for FedRAMP 20x Vulnerability Detection and
Response (VDR).

It is intended to turn scanner observations, validation runs, and operational evidence into
traceable vulnerability cases, class-aware response timelines, and consistent human- and
machine-readable FedRAMP reports.

> **Project status:** pre-alpha planning and architecture scaffold. TrustRoll does not yet
> produce a FedRAMP submission package and must not be represented as FedRAMP approved.

## Product direction

TrustRoll's initial product wedge is deliberately narrower than a full GRC platform:

1. Ingest heterogeneous security observations.
2. Preserve source evidence and provenance.
3. Group observations into stateful vulnerability cases without losing instance detail.
4. Capture internet reachability, likely exploitability, and Potential Agency Impact N-rating
   (PAIN) evaluations.
5. Calculate applicable Class B or Class C clocks from a pinned official rules version.
6. Generate schema-valid FedRAMP VER JSON and matching human-readable reports.
7. Detect failures in the detection and response process itself.

The existing [`stigroll`](https://github.com/ktalons/stigroll) project is the planned first
compatibility adapter. Its CKL, CKLB, XCCDF, and CCI mapping behavior will be preserved while
TrustRoll introduces the broader VDR case model.

## Why this exists

FedRAMP 20x is based on measured outcomes and persistent validation. A failed STIG rule or CVE is
only a source observation. VDR additionally covers drift, failed validation pipelines, stale
security decisions, supply-chain exposures, process failures, and other weaknesses.

TrustRoll therefore separates immutable observations from vulnerability cases:

```mermaid
flowchart TD
    A["STIG, XCCDF, SARIF, SBOM and cloud sources"] --> B["Immutable observations"]
    B --> C["Grouped vulnerability cases"]
    C --> D["IRV, LEV and PAIN evaluation"]
    D --> E["Class-aware deadlines and response history"]
    E --> F["VER JSON, SDR evidence and human reports"]
    G["KSI validation and process health"] --> B
```

## Non-negotiable rules

- Source severity, DISA CAT, CVSS, and PAIN are separate concepts.
- TrustRoll must never infer PAIN solely from source severity or CVSS.
- A scanner pass may support a Key Security Indicator (KSI); it does not prove the complete KSI.
- Grouping observations must not destroy affected-resource or source-level details.
- Rule calculations must identify the exact pinned FedRAMP rules version used.
- Human-readable and machine-readable reports must come from the same normalized records.
- Historical evaluations and evidence must remain reproducible.

## Repository guide

- [`docs/BUILD_PLAN.md`](docs/BUILD_PLAN.md) — phased implementation plan and exit criteria
- [`docs/ARCHITECTURE.md`](docs/ARCHITECTURE.md) — system boundaries and component design
- [`docs/DATA_MODEL.md`](docs/DATA_MODEL.md) — observation, case, evaluation, and evidence model
- [`docs/FEDRAMP_2026_MAPPING.md`](docs/FEDRAMP_2026_MAPPING.md) — current rule and schema mapping
- [`docs/SECURITY.md`](docs/SECURITY.md) — threat model and evidence-handling requirements
- [`docs/decisions/0001-observation-case-separation.md`](docs/decisions/0001-observation-case-separation.md)
  — first architecture decision record

## Current scaffold

The package currently supplies foundational domain types and a small CLI:

```bash
python3 -m trustroll version
python3 -m trustroll plan
```

From a source checkout:

```bash
PYTHONPATH=src python3 -m trustroll version
PYTHONPATH=src python3 -m unittest discover -s tests -v
```

No runtime dependencies are required for this initial scaffold. JSON Schema validation, database
migrations, API support, and source adapters will be added intentionally as their phases begin.

## Authoritative sources

TrustRoll will consume and pin, rather than copy into application constants:

- [FedRAMP Consolidated Rules for 2026](https://www.fedramp.gov/2026/)
- [FedRAMP machine-readable rules](https://github.com/FedRAMP/rules)
- [Vulnerability Detection and Response](https://www.fedramp.gov/2026/reference/vulnerability-detection-and-response/)
- [Vulnerability Evaluation and Reporting](https://www.fedramp.gov/2026/reference/vulnerability-evaluation-and-reporting/)
- [Key Security Indicators](https://www.fedramp.gov/2026/reference/key-security-indicators/)

## License and status

MIT licensed. TrustRoll is an independent open-source project and is not affiliated with,
endorsed by, or approved by GSA or FedRAMP.
