# ADR 0012: CISA KEV enrichment

- Status: Accepted
- Date: 2026-09-25

## Context

`VDR-TFR-KEV` (SHOULD, selected for Class B and Class C) reads: "Providers SHOULD remediate
Known Exploited Vulnerabilities according to the due dates in the CISA Known Exploited
Vulnerabilities Catalog (even if the vulnerability has been fully mitigated) as required by
CISA Binding Operational Directive (BOD) 26-04 or any successor guidance from CISA." It is the
only selected timeframe rule in the FedRAMP rules dataset that carries no structured
timeframe: the deadline lives in someone else's document, published daily, and changes after
publication.

ADR 0005 already decided that KEV due dates are external inputs from the applicable catalog and
are never inferred from FedRAMP prose, and ADR 0007 Decision 6 already said that a KEV clock,
when it arrived, would stop only on remediation. This ADR is the clock those two anticipated.

BOD 26-04 (2026-06-10) supersedes and revokes BOD 22-01. Its Table 1 sets 3-day or 14-day
remediation timelines in calendar days, plus forensic triage, keyed to public exposure,
automatability, and technical impact. CISA computes each catalog `dueDate` from its own view of
those inputs, and its implementation guidance tells agencies to remediate by that published
`dueDate`. ComplyRoll holds none of Table 1's per-asset inputs, so the catalog date is the only
honest deadline it can report.

The catalog itself was measured against the live feed on 2026-09-22 (1,737,207 bytes, 1717
entries, `catalogVersion` 2026.09.21, `dateReleased` 2026-09-21T18:46:35.0873Z):

- Each entry carries twelve keys: `cveID`, `vendorProject`, `product`, `vulnerabilityName`,
  `dateAdded`, `shortDescription`, `requiredAction`, `dueDate`, `knownRansomwareCampaignUse`,
  `forensicTriage` (added in 2026.09.01 and now on every entry), `notes`, and `cwes`. The
  three dates are plain `YYYY-MM-DD` with no zone.
- `catalogVersion` is not unique within a day, and entries change after publication: fifteen
  `dueDate` corrections were observed. Identity therefore has to be the bytes.
- Since BOD 26-04 took effect, every new entry's gap between `dateAdded` and `dueDate` is 3 or
  14 days. Historical catalogs did carry entries whose `dueDate` preceded their `dateAdded`;
  all fifteen observed corrections fixed exactly that.
- 140 entries carry non-ASCII text and two carry U+FFFD, in fields the deadline never reads.

Two definitions pull against each other on what a KEV clock may assert. `FRD-ODV` defines an
overdue vulnerability as one "that the provider intends to fully mitigate or remediate but has
not or will not do so within the time frames recommended or required by FedRAMP"; read
literally, a record already fully mitigated falls outside it. The Common Definitions schema, on
the other side, describes `overdueStatus` only by pointer: "See VER-TFR-EVU and VER-TFR-MAV for
overdue definitions." ADR 0007 Decision 7 already went past that pointer when it added
`VDR-TFR-PVR` to the overdue clauses, so the pointer is a summary of the rules in force, not a
closed list.

`VER-RPT-VDT` asks of every vulnerability whether it "is currently or is likely to become an
overdue vulnerability or not" and, if so, for an explanation. This ADR reads `VDR-TFR-KEV`'s
parenthetical, "even if the vulnerability has been fully mitigated", as the more specific rule
for KEVs, overriding the `FRD-ODV` disjunction for them and only for them.

No bundled FedRAMP report schema has a KEV field, and none sets `additionalProperties: false`,
so everything this slice learns rides in `x-complyroll` except the one official field the rule
forces, `overdueStatus`.

## Decision 1: a per-run input, never fetched, bundled, or stored

`--kev FILE` is accepted by `report vdt`, `report avi`, and `report historical`, with or
without `--db`. The operator downloads the CISA JSON feed out of band; ComplyRoll opens no
socket, ships no copy of the catalog, and writes no catalog event into the store.

This keeps the event log free of a document ComplyRoll does not own and cannot version. The
catalog reaches both compile paths by one route, `ReportOptions.kev_catalog`, and both paths run
the one `compile_record_set`, so the stateless and persisted paths agree by construction rather
than by a second implementation kept in step. `--kev` is deliberately absent from the
`--db`-versus-inputs conflict list for the same reason: no store holds a catalog, so a catalog
is never a second source of truth.

The bundled feed that is not shipped has a cost: a report can only be regenerated if the
operator still has the catalog bytes that were current at its `as_of`. Decision 6 says so
explicitly and the report names the bytes it used.

## Decision 2: bounded and fail-closed, with every message naming the catalog

The catalog is read through `safeio.read_bounded` and `safeio.parse_json_bounded`, which
already refuse non-regular files, oversize files, duplicate keys, NaN and Infinity, lone
surrogates, and excess depth or node count, and which tolerate a BOM. `src/complyroll/reports/kev.py`
adds its own limits on top:

```
MAX_KEV_CATALOG_BYTES = 8 * 1024 * 1024   # the live feed is 1,737,207 bytes
MAX_KEV_ENTRIES       = 20_000            # the live feed holds 1717
KEV_LIMITS            = IngestLimits(max_artifact_bytes=MAX_KEV_CATALOG_BYTES,
                                     max_json_depth=16)
```

The default `max_json_nodes` of 500,000 is kept: an entry is about fifteen nodes, so 20,000
entries is about 300,000, and the nesting reaches depth 5. No `IngestLimits` field was added.

Every field the loader reads is type-checked with `isinstance` before any regex or parse runs,
so no `TypeError` or `AttributeError` can escape a field rule, and a JSON `null` in an optional
field is refused rather than read as absent. Beyond that the loader refuses a root that is not
an object, a `catalogVersion` that is not one to 64 printable ASCII characters, a `dateReleased`
that is not an RFC 3339 instant by an ASCII-class pattern checked before `parse_rfc3339`, a
`count` that is missing or not equal to the number of entries, a `vulnerabilities` list longer
than `MAX_KEV_ENTRIES`, a `cveID` that is not `CVE-[0-9]{4}-[0-9]{4,19}`, a `dateAdded` or
`dueDate` that is not `[0-9]{4}-[0-9]{2}-[0-9]{2}` or is an impossible date, a duplicate
`cveID`, and a `knownRansomwareCampaignUse` or `forensicTriage` that is present but not one to
32 printable ASCII characters.

The date patterns use explicit `[0-9]` classes rather than `\d`, because `\d` without
`re.ASCII` matches other decimal digits, and they run before `fromisoformat`, because on 3.11
through 3.14 `date.fromisoformat` accepts "20260915" and "2026-W38-2" and
`datetime.fromisoformat` accepts basic, week, space-separated, hour-only, and comma-fraction
forms as well as surrounding whitespace. Every one of those would be a date the catalog did not
write.

All three dates are also bounded to the years 1970 through 9000, the same window
`adapters/sarif.py` already guards. A `dueDate` of 9999-12-31 passes `fromisoformat` and then
overflows when the next-day due instant is computed, and a `dateReleased` in year 1 with a
positive offset overflows `.astimezone(UTC)`. `OverflowError` is not a `ValueError`, so without
that bound it would escape `_run_report`, `_persisted_run`, and `main` as a traceback.

Every failure is a `ReportInputError` whose message starts "KEV catalog", which the CLI reports
as `invalid_input`. Loader failures are never report diagnostics: a catalog that cannot be
trusted stops the run before a record set exists. Messages quote only values that have already
passed validation, or a `repr` cut to 64 characters, so an 8 MiB field cannot become an 8 MiB
stderr line; `dateReleased` is length-checked first for exactly this reason, because
`parse_rfc3339` quotes its whole input.

`parse_kev_catalog(content, *, name)` is exported and bounds itself, checking `len(content)`
against `MAX_KEV_CATALOG_BYTES` because `parse_json_bounded` never checks size. It converts
`ValueError`, `InputLimitError`, `RecursionError`, and `OverflowError` into `ReportInputError`,
and the UTC normalization and every entry's due instant are computed inside that wrapped block
so the year bound has a backstop. `TypeError` and `AttributeError` are deliberately not
wrapped: the type checks make them unreachable, and a blanket catch would turn a loader bug
into a misleading input error.

The catalog is tolerant where tolerance costs nothing: unknown keys at root and entry level,
absent or non-ASCII free text in fields the loader never reads, a `dueDate` before its
`dateAdded`, and a BOM.

## Decision 3: identity is the raw-byte SHA-256

`catalogVersion` is not unique within a day and entries change after publication, so neither
the version nor the release instant can identify a catalog. The digest is taken over the raw
bytes as read, before any BOM is stripped, and published as `x-complyroll.kevSource`:

```
"kevSource": {"name": "kev-catalog.json", "sha256": "<64 hex>", "sizeBytes": 8753,
              "catalogVersion": "2026.09.14", "dateReleased": "2026-09-14T17:00:00.123400Z",
              "count": 12, "entriesConsidered": 11}
```

with a Provenance row carrying the same digest in the Markdown twin. `dateReleased` there is
the normalized instant, while the digest pins the verbatim bytes. `count` is what the catalog
declares; `entriesConsidered` is what this run applied after the `dateAdded` filter.

Given the same bytes under the same file name, the stateless and persisted paths produce
byte-identical documents. The same bytes under a different file name move exactly two things,
`kevSource.name` and the Provenance label. A catalog whose entries are in a different order is
different bytes, and its report is identical except for the digest, which appears in
`kevSource.sha256`, the Provenance row, and every catalog-level diagnostic location, and except
for `sizeBytes` if the whitespace differs too.

## Decision 4: matching is exact, on `CVE-` identifiers only

A record is a KEV when one of its `source_identifiers` entries beginning `CVE-` equals an
entry's `cveID` exactly. There is no alias, GHSA, vendor and product, or leading-zero
equivalence.

Both sides are already canonical, with one normalization point each. The SARIF adapter's `_CVE`
pattern is ASCII and case-blind with the same 4 to 19 digit sequence, and `_extract_identifiers`
rebuilds `CVE-{year}-{sequence}` in uppercase; the catalog side is strict uppercase through the
loader regex. The identifier sources are the ones ADR 0011 Decision 5 lists, which includes tag
prose; description prose never is. The STIG adapters yield no CVE identifiers at all, so a
STIG-only run is told so rather than silently matching nothing.

## Decision 5: the clock

1. **Membership.** An exact `cveID` match whose entry's `dateAdded` is on or before the UTC
   date of `as_of`. An entry added later is not applied, because at `as_of` it was not yet a
   KEV.
2. **Due date.** The entry's `dueDate`, used literally. Table 1 is not recomputed: the rule
   names "the due dates in the CISA ... Catalog", and ComplyRoll has none of Table 1's inputs.
3. **Due instant.** The end of the due date in UTC, which is the midnight that begins the next
   UTC day: `datetime.combine(due + timedelta(days=1), time(0), UTC)`. It does not read
   `--calendar-tz`. The loader computes it once per entry, so the compile path does no date
   arithmetic on catalog input.
4. **Start.** `dateAdded` at 00:00:00Z, anchor `"catalog"`, timeframe null. It is
   informational: the due instant never derives from it, which is why an entry whose `dueDate`
   precedes its `dateAdded` is tolerated rather than refused.
5. **Stop.** `satisfied = resolved_status in KEV_STOPS`, where `KEV_STOPS` is
   `{REMEDIATED, FALSE_POSITIVE}`, so a `CLOSED` record with either as its closed disposition
   counts through `resolved_status`. Partial and full mitigation do not stop it, which is what
   "even if the vulnerability has been fully mitigated" requires. Acceptance does not stop it
   either. Satisfied means as recorded when the report runs, the same limit `VDR-TFR-PVR` and
   `VER-TFR-MAV` already have.
6. **Past due.** `past_due = (not satisfied) and as_of > due_at`, the strict comparison every
   existing clock uses. A remediated or false-positive record is never past due. An accepted
   one can be.
7. **Status**, first match wins: `remediated` or `falsePositive` when satisfied, `accepted`
   when the resolved status is `ACCEPTED`, `pastDue` when past due, otherwise `open`. Every
   count of records past a KEV due date counts the `pastDue` boolean and not
   `status == "pastDue"`, so an accepted past-due record is counted.
8. **One clock per record**, bound to the earliest `dueDate` and, on a tie, the lowest `cveID`.
   Every matched entry is still listed. One CVE on two records flags both.
9. **No LEV.** KEV membership never sets `isLikelyExploitable`. `FRD-LEV` is the evaluator's
   call and a catalog listing is not an evaluation.

## Decision 6: a catalog released after `as_of` is an error

When `dateReleased` is after `as_of`, compilation raises `ReportCompileError` carrying ERROR
`kev_catalog_after_as_of`, and the run publishes nothing.

Entries change after publication, so a catalog released later cannot show that the `dueDate` it
carries was the one in force at `as_of`; a report built that way would assert a deadline that
did not exist when it claims to be measuring. Regenerating an old report needs the catalog that
was current then, and the digest of that catalog is in the old report's `kevSource`. CISA
publishes its catalog history, so the operator has somewhere to go.

The refusal reaches the operator as a diagnostic line rather than a traceback because it is
raised inside the block `_persisted_run` wraps, which is the same handler the store commands
use. That holds on the stateless path too, where no store is opened at all.

## Decision 7: the Vulnerability Detail Report keeps open KEV work

A record stays in the VDT with no activity in the period when it is not accepted, its clock is
matched and not satisfied, its detection is on or before the period end, and some matched entry
was listed on or before the UTC date of the period end.

Under `VDR-TFR-KEV` a mitigated KEV is unresolved, and the ADR 0007 period rule already treats
an unresolved weakness as activity in every period. Without this the rule would be
unenforceable in exactly the case it was written for: a provider who fully mitigates a KEV and
then lets the catalog date pass would see the record drop out of the next quiet period's report.

The listing bound is what keeps the rule honest in the other direction. Nothing orders `as_of`
against the period end, and `--as-of` defaults to now, so an August report compiled on
3 September must not pull in a record that was quiet through August and became a KEV on
2 September. AVI and historical selection do not change.

## Decision 8: KEV sets `isOverdue` except on accepted records

A past-due clock sets `overdueStatus.isOverdue` and adds a clause, for records that are not
accepted. An accepted record keeps exactly `{"isOverdue": false}` and shows the missed date in
`x-complyroll` and in its Known exploited line.

`FRD-ACV` and `FRD-ODV` partition the population: an accepted vulnerability is one the provider
does not intend to remediate, so it cannot be one the provider "intends to ... but has not"
remediated. That partition is a definition, not a judgment about whether the date was missed,
so the date is still reported; it is simply not reported as an official overdue. The authority
is the amendment this slice writes to ADR 0007 Decision 7.

The clause, when it fires, names the catalog by version and release instant and says what was
not done. A mitigated record's clause carries one extra sentence saying the mitigation does not
stop the clock, and a record whose due date had already passed at detection carries one saying
so, because otherwise "no remediation recorded" reads as an accusation about a window the
provider never had.

## Decision 9: two output shapes, both pinned by goldens

With a catalog, every record's extension gains a `kev` key, null when the record matched
nothing, and the report extension gains `kevSource`. Without a catalog, neither key exists
anywhere and every byte of every output is what it was before this slice.

Emitting `"kev": null` unconditionally was rejected: it would move all fourteen existing
goldens and every consumer's parse for a field that is absent information, not a null value.
The two shapes are pinned by the three new golden pairs and by the fourteen existing ones,
which all compile without a catalog.

## Decision 10: `VDR-CSO-AKE` is out of scope

`VDR-CSO-AKE` says a provider SHOULD NOT deploy a service with a known exploited vulnerability.
ComplyRoll models no deployment state: it knows what a scanner found, not what was shipped or
when. Reading AKE from first detection would assert a deployment event the evidence does not
carry. The rule is recorded here as unimplemented rather than approximated.

## Worked examples

Compiled from `tests/fixtures/kev-image-web.sarif`, `tests/fixtures/kev-image-worker.sarif`,
`examples/evaluations-kev.json`, and `tests/fixtures/kev-catalog.json` at Class C with `as_of`
2026-09-15T12:00:00Z. Every identifier in the fixture catalog is `CVE-2099-*`; no CISA content
is carried in this repository. The tracking ids are the ones `tests/golden/vdt-kev.md` and
`tests/golden/avi-kev.md` carry.

- **A due date at the boundary.** `case-d71ea9b36c49f957` carries `CVE-2099-0001`, added
  2026-08-27 and due 2026-09-10. The due instant is 2026-09-11T00:00:00Z, so a remediation
  recorded at 2026-09-10T23:59:59Z would have been in time and one at 2026-09-11T00:00:00Z
  would not. At `as_of` nothing is recorded, so the status is `pastDue` and the clause reads
  "lists CVE-2099-0001 with due date 2026-09-10, which ended 2026-09-11T00:00:00Z with no
  remediation recorded." The same CVE on the worker image is `case-bfcbac2c7be88a19`, a second
  record with its own clock: one catalog entry, two flagged records, no deduplication.
- **A mitigated past-due record.** `case-c4a0253c9a9ff48b` carries `CVE-2099-0004`, due
  2026-09-03, and is evaluated `fully_mitigated`. Mitigation is not in `KEV_STOPS`, so the
  clock runs and the record is officially overdue. Its clause adds "A recorded mitigation does
  not stop this clock." This is the case `VDR-TFR-KEV`'s parenthetical exists for, and it is
  the one that makes `--kev` change a provider's overdue count.
- **An accepted past-due record.** `case-94c71266d391144a` carries `CVE-2099-0006`, due
  2026-08-31, and is accepted with a rationale. It appears in the AVI report, where the Summary
  reads "Overdue 0" beside "Past a CISA KEV due date 1" and its Known exploited line ends
  "accepted, past due". Its `overdueStatus` is `{"isOverdue": false}`, its `kev.status` is
  `accepted`, and its `kev.pastDue` is true. That pair of numbers on one Summary is the
  `FRD-ACV` and `FRD-ODV` partition made visible.
- **Due before detection.** `case-9d2c5885ea234bd0` carries `CVE-2099-0009`, added 2026-06-01
  and due 2026-06-15, first detected 2026-09-02T10:15:00Z. The clock was already past due when
  the scanner first saw it, so its clause adds "The due date had passed before detection at
  2026-09-02T10:15:00Z." The record is overdue from its first report, which is what a legacy
  KEV found late honestly is.
- **Two CVEs on one record.** `case-47c219a4b195f33c` carries `CVE-2099-0002` (due 2026-09-22)
  and `CVE-2099-0003` (due 2026-09-24), the second read from a SARIF tag. Both are listed in
  the Known exploited line; the clock binds to the earlier due date, so it follows
  `CVE-2099-0002` and the line reads "due date 2026-09-22 ends 2026-09-23T00:00:00Z; open".
  The verb is "ends" rather than "ended" because the instant is still ahead of `as_of`. The
  record is overdue, but on `VER-TFR-EVU` and not on KEV, so its explanation carries only the
  evaluation clause. `case-154434fe3008eee7` is the same shape with both clocks run out: its
  one explanation carries the `VER-TFR-EVU` clause followed by the `VDR-TFR-KEV` clause, which
  is the clause order in text and not only in the deadline list.
- **A record the catalog does not cover yet.** `case-1a88bd335ba6c185` carries
  `CVE-2099-0008`, which the fixture catalog lists with `dateAdded` 2026-09-20, after `as_of`.
  Its `kev` is null and its Known exploited line reads "no entry in the supplied CISA KEV
  catalog dated on or before 2026-09-15", which stays true where "not listed" would be false.
  The run also carries INFO `kev_entries_after_as_of` saying one entry was not applied and one
  compiled record carries it.

## Consequences

- Adding `--kev` to an existing run can raise the overdue count, because a fully mitigated KEV
  past its catalog date becomes officially overdue. That is the rule working, and it is in the
  changelog so no one meets it by surprise in a report they already published.
- ADR 0010's Consequences reasoned that an accepted record publishes `{"isOverdue": false}`
  because acceptance satisfied every deadline its golden record had. A KEV clock is the first
  deadline acceptance does not satisfy, so that reasoning does not cover KEV: the conclusion
  survives for a different reason, the `FRD-ACV` and `FRD-ODV` partition of Decision 8. ADR
  0010 Decision 2 does not change, and neither does ADR 0008.
- The report is invariant to the order of the catalog's entries except for the digest. Entries
  are sorted by `cveID` on load, so the same set of entries in another order produces the same
  document apart from `kevSource.sha256`, the Provenance row, the catalog-level diagnostic
  locations, and `sizeBytes` if the whitespace also moved.
- The literal catalog `dueDate` can differ from what Table 1 would give for a particular asset,
  because CISA computes it from its own exposure view. The ADR says so and every clause names
  the catalog, so a reader can tell whose deadline they are looking at.
- No remediation instant exists in the model, so a remediation recorded late shows as satisfied
  and never as late. This is the same "as recorded at run time" limit `VDR-TFR-PVR` and
  `VER-TFR-MAV` carry. A `remediatedAt` input is future work.
- Regenerating an old report needs the catalog that was current at its `as_of`, and Decision 6
  refuses anything later. The ERROR names the release instant so the operator knows which
  catalog to find.
- The shown `dueAt` reads as the following day, 2026-09-11T00:00:00Z for a due date of
  2026-09-10. The clause and the detail line both print the date and say the instant it
  "ended", or "ends" when it is still ahead, so the extra day is never silent.
- The SARIF adapter caps every folded list at `MAX_LIST_ITEMS`, 64 members, so a CVE can be
  among the identifiers it dropped. WARNING `kev_match_incomplete` fires per record when that is possible and a
  match therefore cannot be ruled out. The check depends on the adapter's smallest-first cut; a
  future adapter that cuts differently has to be re-checked against it.
- A CVE written into a SARIF tag attaches to the observation under ADR 0011 Decision 5, so a
  tag citing a related KEV matches. The identifier list is extracted, not curated.
- Two tools reporting the same CVE are two cases until cross-source correlation exists, so each
  gets its own clock and the KEV counts can look inflated relative to distinct CVEs.
- The store records nothing about which catalog a persisted report used. `kevSource` in the
  published document is the only record, which is why the digest is over the raw bytes.
- The three-day staleness threshold is the shortest BOD 26-04 timeline, so a catalog old enough
  to warn is old enough to have missed an entry whose whole clock has since run. It is a
  WARNING and never a refusal, because a slightly old catalog still reports real deadlines.
- Seven codes are the whole KEV surface. Two raise and stop the run,
  `kev_catalog_after_as_of` and `kev_rule_unavailable`; two warn, `kev_catalog_stale` and
  `kev_match_incomplete`; three inform, `kev_entries_after_as_of`, `kev_no_cve_identifiers`,
  and `kev_no_matches`. Catalog-level ones are located at `sha256:<hex>` and per-record ones
  at the record's source record id.
- `vdt.py` grows by about ninety lines ahead of its planned split. The loader and the clock
  live in `reports/kev.py`, so the split has less to move, not more.

## Rejected alternatives

- Recomputing BOD 26-04 Table 1: ComplyRoll holds none of its per-asset inputs, and the rule
  names the catalog's dates, not the table's method.
- 23:59:59Z as the due instant: it leaves a one-second hole at the end of the due date and
  invites a rounding argument the midnight boundary does not have.
- Reading `--calendar-tz` for the due instant: the catalog is a single global document with one
  date per entry, so a zone-dependent deadline would make the same catalog mean different
  things in different reports.
- A `--remediated-at` input so a late remediation could be shown as late: real, and out of
  scope here. It is future work, recorded with the PVR and MAV limit it shares.
- Mitigation stopping the clock: the rule's parenthetical forbids exactly this.
- `isOverdue` true on accepted records: `FRD-ACV` and `FRD-ODV` partition the population, and
  an accepted record is not one the provider intends to remediate.
- One deadline row per matched CVE: the deadline table is keyed by rule, and several rows for
  one rule would break the Markdown parity check for no gain over listing every entry in the
  Known exploited line.
- KEV membership setting `isLikelyExploitable` or LEV: `FRD-LEV` is the evaluator's judgment
  and a catalog listing is not an evaluation.
- Alias, GHSA, vendor and product, or leading-zero matching: each is a second normalization
  rule that would need its own version and its own failure mode.
- CSV catalog input: one format, one parser, one set of bounds.
- Fetching the feed, or bundling a copy: Phase 0 opens no socket, and a bundled catalog would
  be stale the day it shipped and would look authoritative anyway.
- Storing catalog events: the catalog is not ComplyRoll's document, and the store would then
  need a policy for a catalog that changed under an unchanged version string.
- A new keyword on the compile functions: `ReportOptions` already carries the per-run inputs,
  and one route to both paths is what makes them agree by construction.
- A hard staleness gate: a three-day-old catalog still carries real deadlines, and an operator
  compiling on a Monday would be blocked for no defect.
- The due instant as an activity instant for period selection: it would pull a record into a
  period on a date nothing happened in. Decision 7 uses detection and the listing date instead.
- Emitting `"kev": null` with no catalog: it moves all fourteen existing goldens for a key that
  means "not asked", not "no value".
- Reusing `trivy-image.sarif` for the fixtures: its CVEs are real identifiers, and the KEV
  fixtures had to be synthetic in every field a catalog touches.
- Hardcoding the rule's force or name: they come from the selected policy, so a rules dataset
  that changes either is reported as it is written. A policy with no `VDR-TFR-KEV` raises
  `kev_rule_unavailable` rather than inventing one.
- Reading `VDR-CSO-AKE` from first detection: it would assert a deployment the evidence does
  not carry.
