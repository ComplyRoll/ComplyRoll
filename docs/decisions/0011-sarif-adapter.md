# ADR 0011: SARIF adapter

- Status: Accepted
- Date: 2026-09-20

## Context

Phase 2 of the build plan opens with a SARIF adapter, so that code scanners, image scanners,
and infrastructure-as-code scanners feed the same observation ledger, correlation, and reports
that the STIG adapters feed today. SARIF 2.1.0 is the one interchange format that Trivy, Grype,
Semgrep, CodeQL, and Checkov all write and that GitHub code scanning consumes, so one adapter
covers the scanners a provider is most likely to run already, and any other conforming 2.1.0
producer comes along with them.

Two things were frozen before this work started. ADR 0002 fixed observation identity as a
SHA-256 over nine inputs (source type, source tool, parser name and version, source record id,
resource type and id, context key, and the artifact digest), and ADR 0007 fixed the vulnerability
group key as `(source_type, source_record_id, context_key)` and deferred cross-source
correlation. SARIF has to supply those inputs without adding a tenth, from a format whose
producers disagree with each other about what a finding's identity is: Grype's
`partialFingerprints` hash package identity, CodeQL's hash a source line, Trivy and Checkov emit
none, and Semgrep writes a literal placeholder. A producer-owned identifier cannot be the
identity of a ComplyRoll observation.

The adapter also inherits the Phase 0 posture: no path is opened, no network is touched, every
bound is enforced before anything is trusted, and an artifact that cannot be read honestly fails
closed rather than producing a partial success. The event store adds a bound the STIG adapters
never approached, `MAX_EVENT_JSON_BYTES` at 1 MiB and `MAX_EVENT_JSON_VALUES` at 100,000 per
event, and a SARIF log can carry thousands of results that fold into one observation, so the
adapter has to bound what one observation can grow to.

## Decision 1: one adapter on the Phase 0 contract, dispatched by suffix only

`SarifAdapter` in `src/complyroll/adapters/sarif.py` implements the `SourceAdapter` contract
with `name = "complyroll.sarif"`, `version = SARIF_PARSER_VERSION` (`"1"`), and
`media_type = "application/sarif+json"`. `ingest_stig_artifact` dispatches a `.sarif` suffix,
or a name ending in `.sarif.json`, to it; every other suffix keeps its existing behavior, and
the dispatcher keeps its name because renaming it is a separate refactor. A bare `.json` file
is never sniffed for SARIF content: that would change CKLB dispatch and the compat path for
every existing `.json` checklist, and nothing in the suite pins CKLB attribution of a malformed
`.json` yet. The adapter accepts only an object root whose `version` is exactly `2.1.0` with
`runs` as an array; anything else is an `AdapterParseError` and the artifact fails.

`SARIF_PARSER_VERSION` is its own constant so a SARIF bump can never re-mint CKLB, CKL, or
XCCDF observations. The `stigroll` compatibility command recognizes an artifact attributed to
the SARIF parser, prints a warning that it rolls up STIG checklists only, and skips it, so a
SARIF log passed to the predecessor CLI never becomes a row in a STIG roll-up.

## Decision 2: identity reuses the ADR 0002 recipe unchanged

SARIF supplies the nine inputs and adds nothing. `source_type` is the literal `sarif`, never
read from `$schema` or `version`. `source_tool` is `tool.driver.name`, verbatim: never the
version, `semanticVersion`, `fullName`, or `organization`, because a scanner upgrade is not a
new vulnerability, and never case-folded or normalized, because a normalization rule would be
a second identity input needing its own version. Versions go to metadata.

`context_key` is the driver name, followed by `|` and the automation category when
`runAutomationDetails.id` contains a slash. The category is everything before the last slash;
the last component is the run instance that GitHub and CodeQL fill with a build number or a
date, and it is dropped so a per-run id cannot re-mint cases. An id with no slash is a bare run
id and is ignored. The driver name is the namespace that gives a rule id its meaning, the role
the STIG name plays for a V-id, and because the correlation key never sees `source_tool`, it
is also what keeps Trivy and Grype reporting the same CVE as separate cases until cross-source
correlation lands. `versionControlProvenance.repositoryUri` is not in the key: its spellings
(https, ssh, a trailing `.git`) would split cases, and the category is what users control.

Producer-owned identifiers are recorded and never trusted. `fingerprints` and
`partialFingerprints` are each stored as one compact-JSON value of sorted name and value pairs
under a fixed metadata key, so a producer can never mint a key of its own; `guid`,
`correlationGuid`, and rule `deprecatedIds` go to metadata under fixed keys the same way.
Region, line, column, snippet, and message text are metadata and never identity: line churn
would re-mint resources, and a case's affected-resource list never shrinks. The metadata
vocabulary is fixed at 38 keys, and a key outside it raises `RuntimeError`, which is an adapter
bug and never an input condition.

## Decision 3: the resource is the located thing, scoped by what the run says it scanned

Four `resource_type` values, all permanent identity inputs, rendered in the Markdown
affected-resource column beside `host`:

- `image` when the run declares an image (`run.properties.imageName`, else
  `run.properties.repoDigests[0]`) and the location has a physical uri; `resource_id` is
  `<image>/<uri>`.
- `file` when the location has a physical uri and the run declares no image; `resource_id` is
  `<repositoryUri>/<uri>` when `versionControlProvenance[0].repositoryUri` is present (one
  trailing slash removed), else the uri alone.
- `logical` when the location has only `logicalLocations`; `resource_id` is the image name or
  the repository uri when either is present, then `/`, then the first logical location's
  `fullyQualifiedName` or `name`.
- `scan` when a result has no usable location at all; `resource_id` is the driver name, with
  WARNING `resource_identity_fallback`, so the result still yields exactly one observation and
  the same bytes under two filenames keep one identity. The STIG adapters use the filename
  stem for this fallback; SARIF does not, because a renamed log would re-mint the observation.

One observation is produced per distinct resource among `result.locations`.
`relatedLocations`, `codeFlows`, `threadFlows`, `stacks`, `graphs`, `fixes`, and
`attachments` never produce observations, and a result with more than
`MAX_LOCATIONS_PER_RESULT` (256) locations refuses the artifact. When `artifactLocation.uri`
is absent and `artifactLocation.index` names an entry of `run.artifacts` with a
`location.uri`, that uri is used, which is the index-only form CodeQL writes. The uri is used
as written: never resolved against `uriBaseId` or `originalUriBaseIds`, never percent-decoded,
never normalized, so a repository-relative path is identical on every CI runner. `uriBaseId`
and the one-level `originalUriBaseIds[uriBaseId].uri` go to metadata; the chain is not walked,
so there is nothing to cycle. A uri that is whitespace only counts as no physical location; one
containing a `..` segment or starting with `//` is kept verbatim with WARNING `uri_suspicious`.
No path is ever opened, so this is hygiene, not traversal.

## Decision 4: the rule identifier is resolved in the spec's order and kept whole

The component comes first (spec 3.54.2): `result.rule.toolComponent.index` names
`tool.extensions[index]`; else `result.rule.toolComponent.guid` names whichever of
`tool.driver` and `tool.extensions[]` carries that guid; else the component is `tool.driver`.
The descriptor is `component.rules[result.rule.index]`, else
`component.rules[result.ruleIndex]` (3.52.5 and 3.27.6, so an extension's `ruleIndex` reads
the extension's own rules, never the driver's); else, with no index at all, the descriptor in
that component whose `id` equals the string id, when exactly one matches (3.52.3). That last
step was added during the build: Semgrep and Grype write `ruleId` with no `ruleIndex`, and
without it their results came out with empty titles, no tags, no CWE identifiers, and Grype at
MEDIUM instead of HIGH. Identity was never affected by it.

`source_record_id` is `result.ruleId`, else `result.rule.id`, else the resolved descriptor's
`id`; the first string wins. Hierarchical ids (`CA2101/1`) are not truncated and composite ids
(Grype's `CVE-2024-0001-openssl`) are not parsed. That one descriptor also supplies the title,
`defaultConfiguration.level`, the rule-level `security-severity`, `messageStrings`, and its
component's `globalMessageStrings`, so identity and evidence never read two different rules.
When a string id is present and the descriptor's `id` is not a component-wise prefix of it
(3.52.4, so `CA5350/md5` against descriptor `CA5350` is not a conflict), the string is the
identity and WARNING `rule_reference_conflict` is emitted. Indexes never cross runs. A result
with no resolvable id is ERROR `rule_id_missing` and the artifact fails closed: skipping it
would drop a finding from the evidence, and keying it on a placeholder would merge unrelated
findings into one case.

## Decision 5: messages are expanded by pattern, never by `str.format`, and identifiers are extracted, not curated

The description is `result.message.text`, else `descriptor.messageStrings[message.id].text`,
else the resolved component's `globalMessageStrings[message.id].text` (3.11.7 scopes the
lookup to the component that defines the rule), else `descriptor.fullDescription.text`, else
empty. `[label](n)` link syntax is flattened to `label` on the template first; then `{n}`
placeholders are replaced from `message.arguments[n]` in one left-to-right pass with an output
budget of `MAX_DESCRIPTION_CHARS`, at most `MAX_MESSAGE_ARGUMENTS` (32) arguments read, a
missing or non-string argument left as the literal placeholder, and `{{` and `}}` unescaped in
the same pass. `message.markdown` is never read: the spec requires `text` beside it, and
Markdown must not reach the twin unescaped. The title is `descriptor.shortDescription.text`,
else `descriptor.name`, else empty.

`source_identifiers` come from three fixed anchored regexes (CVE, GHSA, and CWE, the last
reading both Semgrep's `CWE-78: ...` tag and CodeQL's `external/cwe/cwe-078` form) run over
the rule identifier, the descriptor's `id` and `name`, its `properties` texts and
`relationships[].target.id`, the result's `properties` texts, and `result.taxa[].id`, unique
and sorted. They feed the group's `source_identifiers` and the later KEV enrichment and are
never identity. Because they read tag prose, a CWE mentioned in a tag attaches to the
observation.

## Decision 6: every result becomes an observation, and `kind` maps to disposition

`fail` or absent is OPEN; `pass` is PASS; `notApplicable` is NOT_APPLICABLE; `review` is
NOT_REVIEWED; `informational` is NOT_REVIEWED (the spec says it reports no problem, but it is
not a pass claim either, and the STIG status aliases already map the same word the same way);
`open` is UNKNOWN (the spec's "inconclusive, a problem might exist": UNKNOWN is one of the two
unresolved dispositions, so it surfaces in every report as an `unresolved_observation` warning
instead of vanishing the way NOT_REVIEWED does); any other value is UNKNOWN with WARNING
`invalid_result_kind`.

`baselineState` is metadata only and never moves a disposition, with INFO
`baseline_state_ignored` when it is present: a producer's baseline diff is producer-owned
state, and letting `absent` close a finding would be the adapter accepting risk. Suppressions
never change disposition either. A suppression whose `status` is absent or `accepted` counts as
accepted (3.35.4); `suppressed` is `true` in metadata when any suppression is accepted and
`false` when only `rejected` or `underReview` ones remain; `suppression_kinds` and
`suppression_statuses` record the rest; WARNING `results_suppressed` is emitted for the
accepted ones; and the observation stays OPEN in every case, because a developer's `nosemgrep`
comment is exactly what an evaluator must see.

## Decision 7: severity is evidence, read from `security-severity` first and the level chain second

The effective level follows spec 3.27.10: `none` when `kind` is present and not `fail`; else
`result.level`; else, when the result's invocation (`provenance.invocationIndex`, defaulting
to 0 when the run has exactly one invocation, per 3.48.6) carries a `ruleConfigurationOverrides`
entry whose descriptor resolves to the result's own component and rule, that override's
`configuration.level`; else the descriptor's `defaultConfiguration.level`; else `warning`.
Then `security-severity` is read from the first holder that declares it, the result's
`properties` before the descriptor's. A value that is a JSON number (bool excluded) or a numeric
string, finite, greater than 0 and at most 10, sets severity by the GitHub bands: 9.0 and above
CRITICAL, 7.0 and above HIGH, 4.0 and above MEDIUM, below 4.0 LOW. Exactly `0.0` means unset in
GitHub's own reading and falls through silently to the level chain (Trivy writes `0.0` for
UNKNOWN); because the first holder wins, a result-level `0.0` falls through without reading the
descriptor's value. A value that is present but unusable (negative, above 10, NaN, a bool,
non-numeric text) is WARNING `security_severity_invalid` and falls through. The level then maps
`error` HIGH, `warning` MEDIUM, `note` LOW, `none` INFORMATIONAL; an unknown level is WARNING
`invalid_level` and UNKNOWN. Metadata records `level`, `level_source` (`forced_none`,
`result`, `invocation_override`, `rule_default`, or `default`), `security_severity` verbatim,
and `severity_source` (`security-severity` or `level`).

None of this touches PAIN. `source_severity` is the scanner's opinion recorded as evidence; the
evaluator sets PAIN, and no report reads scanner severity into a deadline.

## Decision 8: `observed_at` comes only from the log's own clocks, earliest first

Per result, `provenance.firstDetectionTimeUtc`, else `provenance.lastDetectionTimeUtc`; else
per run, the earliest parsable `invocations[].startTimeUtc`, which is the default the spec
itself gives a missing detection time in 3.48.3, else the earliest `endTimeUtc`; else none,
with the existing `source_timestamp_missing` warning once per artifact. Earlier is the
conservative reading for a detection clock: a VDR deadline that starts sooner is never the
lenient mistake. Never file mtime, never `ingested_at`, never a date parsed out of an automation
id. A JSON null clock member is absent; a present but unparsable value is WARNING
`source_timestamp_invalid` and counts as absent.

Parsing goes through the shared `parse_timestamp` (trailing `Z` to `+00:00`,
`datetime.fromisoformat`, must be aware; fractions longer than six digits are truncated, which
is what makes CodeQL's seven-digit clocks round-trip canonically) and then a SARIF-local check
that the UTC offset is a whole number of minutes, because the canonical timestamp and the event
contract both refuse `+05:30:15`. The plan put that check in the shared helper; the build kept
it in `sarif.py`, because five CLI tests use an XCCDF end time with a seconds-bearing offset as
their fixture for a payload the contract refuses at `record_ingest`, and moving the guard would
have turned that payload into a missing timestamp. So SARIF never produces an `observed_at` the
contract refuses, the STIG adapters keep today's behavior, and closing the same divergence for
CKLB and XCCDF is on the Phase 2 cleanup list.

## Decision 9: results that share an identity fold into one bounded observation

Inside one artifact, results that share the fold key (driver name, rule identifier, resource
type, resource id, and context key, which together with the artifact's constant inputs is the
fingerprint itself) fold into one observation, across runs. Two runs of the same driver and
category fold; two drivers never do. The folded observation keeps `occurrence_count` (one
uncapped integer) and, in metadata, the regions with their paired location messages and the
run indexes, ordered by region tuple and deduplicated, each list cut at `MAX_LIST_ITEMS` (64)
with the cut member named under `truncated`. The worst disposition wins (OPEN, then UNKNOWN,
NOT_REVIEWED, NOT_APPLICABLE, PASS), the strongest severity wins, the earliest `observed_at`
wins, and the title, description, and kept regions come from the candidates with the smallest
`(startLine, startColumn, endLine, endColumn, message text)` tuples, so the fold is independent
of result order. INFO `results_collapsed` names each folded result. The dispatcher's
`duplicate_observation_identity` check stays as a backstop and a test asserts it never fires
for SARIF.

The bound is arithmetic, not hope. The metadata vocabulary is fixed, so a producer cannot add a
key. List-valued members hold at most `MAX_LIST_ITEMS` items of `MAX_LIST_ITEM_CHARS` (256)
each, uri-valued scalars at most `MAX_URI_CHARS` (2,048), other scalars
`MAX_METADATA_VALUE_CHARS` (512), the title `MAX_TITLE_CHARS` (512), and the description
`MAX_DESCRIPTION_CHARS` (4,096), which puts a fully saturated observation near a quarter of a
megabyte and under one hundred values. The adapter enforces a ceiling anyway: after folding,
an observation whose canonical JSON exceeds `MAX_OBSERVATION_JSON_BYTES` (512 KiB) raises
`InputLimitError`, so `report vdt` and `ingest --db` refuse the same input the same way instead
of diverging at the store's `MAX_EVENT_JSON_BYTES` (1 MiB) and `MAX_EVENT_JSON_VALUES`
(100,000). Neither the artifact byte bound nor `max_json_nodes` bounds a string's length, which
is why these caps exist: without them, 2,000 same-identity results with distinct 600-character
location messages, or one result with 300 producer fingerprint names of 4,096 characters, pass
every input bound, compile on the stateless path, and fail `ingest --db` inside the store with a
bare `ValueError`. Both are reproduced in the tests, along with a log that fills every metadata
key at its cap, and all three fold to observations under the ceiling.

Diagnostics are coalesced per code per artifact, each carrying an occurrence count and the
first `MAX_DIAGNOSTIC_PATHS` (5) JSON-path locations in its message, because the report copies
every non-ERROR diagnostic and the `artifact.ingested` event embeds them, so the diagnostics
payload is bounded by the number of codes and not by the size of the input.

## Decision 10: refuse identity, degrade evidence

An identity input (driver name, rule identifier, uri, logical name, image name, repository uri,
automation id) that contains a code point in categories Cc, Cf, Cs, Zl, or Zp, or exceeds
`MAX_IDENTITY_CHARS` (512) for names and ids or `MAX_URI_CHARS` for uris, is ERROR
`identity_input_invalid` and the artifact fails closed; nothing is stripped or truncated on the
way into a fingerprint, and a tab or newline inside an identity input is refused as the Cc code
point it is. Every uri goes through that refusal, the evidence uris (`informationUri`,
`helpUri`, and the original uri base) included, so a uri is never cut. Evidence (titles,
messages, tags, help text, metadata values) has Cc other than tab and newline, Cf, and Cs
removed, Zl and Zp mapped to newline, and is truncated at its cap with a trailing
`...[truncated]` marker; the metadata key `truncated` holds the compact-JSON list of member
names that were cut, and one coalesced WARNING `evidence_sanitized` and one
`evidence_truncated` per artifact carry the counts.

Separately, `parse_json_bounded` now refuses a lone surrogate code point in any JSON string or
object key during the walk it already does, raising `ValueError` so the dispatcher reports
`artifact_parse_failed`. Before this, `{"a":"\ud800"}` parsed and then the report writer and
the store both failed on `.encode("utf-8")`; that was a CKLB bug too, and the check covers
every JSON adapter.

## Decision 11: two `IngestLimits` fields, exceeded means refused, reaching the adapter through its constructor

`max_results_per_run = 50_000` (SARIF only for now) and `max_observations_per_artifact =
50_000` (a generic name so CKLB can adopt it later) join `IngestLimits`.
`SarifAdapter.__init__(self, limits: IngestLimits = DEFAULT_LIMITS)` stores them on the
instance; `name`, `version`, and `media_type` stay class attributes so the attribution block
reads them as it does for `CklbAdapter`; the dispatch branch constructs `SarifAdapter(limits)`
from the dispatcher's own `limits` argument, and `SourceAdapter.parse` and the three STIG
adapters are untouched. Exceeding either field, or `MAX_LOCATIONS_PER_RESULT` on one result, or
`MAX_OBSERVATION_JSON_BYTES` after folding, raises `InputLimitError`, which the dispatcher
already reports as `artifact_parse_failed`. `DEFAULT_LIMITS` keeps every existing value.

## Decision 12: the shared helpers move to `adapters/common.py`

`_text`, `_unique`, `_parse_timestamp`, `_make_observation`, and `_missing_time_diagnostic`
leave `stig.py` and become `text_of`, `unique`, `parse_timestamp`, `make_observation`, and
`missing_time_diagnostic` in a new module; `make_observation` gains
`resource_type: str = "host"`. `stig.py` imports them; `sarif.py` imports from `common.py` and
never from `stig.py`, so there is no cycle. Every existing golden stayed byte-identical through
the move, which is the proof that it changed nothing.

## Decision 13: empty and failed runs are diagnosed, and a clean scan is not yet evidence

A run that is not an object, or whose driver has no name, is ERROR `invalid_run`, and so is a
`results` member that is present but not an array. `results` absent or null is WARNING
`results_unknown` (the spec's results-unknown state) and the run is skipped; `results: []` is
INFO `run_clean`; a run whose `invocations[].executionSuccessful` is false is WARNING
`execution_unsuccessful` and its results are still read; a log with
`externalPropertyFileReferences` is WARNING `external_properties_ignored`, because results or
rules may live in files that are never opened. When no run yields an observation the artifact
is the existing ERROR `no_observations`, because `IngestResult.successful` requires
observations and `record_ingest` refuses anything else. Turning a clean scan or a failed
invocation into a system-origin coverage observation is backlog item 9, not this slice.

## Worked examples

The tracking ids below are the ones `tests/golden/vdt-sarif.md` carries, compiled from
`trivy-image.sarif`, `semgrep-code.sarif`, and `codeql-repo.sarif` with
`--detected-at 2026-09-01T00:00:00Z`.

- `case-10f5974d95a33fdf` is `tracking_id_for("sarif", "CVE-2024-0001", "Trivy")`. The Trivy
  run declares `ghcr.io/example/app:1.4.2` in `properties.imageName` and no automation id, so
  the context key is the bare driver name and every located file is an `image` resource scoped
  by the image. Three results carry the rule: two locate `app/requirements.txt` and fold into
  one observation with `occurrence_count` 2 and an INFO `results_collapsed`, and the third
  locates the installed `requests` package metadata, so the case shows two resources. The
  rule's `security-severity` of 9.8 makes both observations CRITICAL with `severity_source`
  `security-severity`. Trivy writes no invocation clock, so neither observation has an
  `observed_at` and the case's detection time comes from the attestation.
- `case-889c19760e425785` is `tracking_id_for("sarif", "CVE-2024-0002", "Trivy")`: the same
  run, two results on `library/alpine` folded into one observation on one `image` resource,
  MEDIUM from the rule's `security-severity` of 5.5.
- `case-5cfbebe8d4b91c27` is
  `tracking_id_for("sarif", "python.lang.security.audit.exec-detected.exec-detected", "Semgrep OSS")`.
  Semgrep writes `ruleId` with no `ruleIndex`, so the descriptor is found by the 3.52.3 id
  match, which is where the title, the `warning` default level (MEDIUM, `level_source`
  `rule_default`), and the `CWE-95` identifier read from the rule's tag come from. The run
  declares no image and no `versionControlProvenance`, so the two results on
  `src/app/runner.py` fold into one `file` resource whose id is the bare path. The sibling
  `subprocess-shell-true` result on `src/app/tasks.py` carries an `inSource` suppression with
  no status; it is reported as `case-0e3754ea1c369285` all the same, with `suppressed` `true`
  in its metadata and WARNING `results_suppressed` on the artifact.
- `case-d2b9f5abf1fe44ac` is
  `tracking_id_for("sarif", "js/xss-through-dom", "CodeQL|nightly/lint")`. The CodeQL run's
  automation id is `nightly/lint/2026-09-01`, so the category `nightly/lint` joins the driver
  name and the dated instance is dropped. Its rules live in a `tool.extensions` entry and its
  locations name `run.artifacts` entries by index, so the component and the uri are both
  resolved indirectly; `versionControlProvenance` names `https://github.com/example/webapp/`,
  so the `file` resource is `https://github.com/example/webapp/src/ui/render.js`. The tags
  `external/cwe/cwe-079` and `external/cwe/cwe-116` become `CWE-79` and `CWE-116`. The
  invocation's `startTimeUtc` supplies `observed_at`, so the case needs no attestation. The
  same rule's result on `src/ui/legacy.js` has `kind` `open`, so its disposition is UNKNOWN:
  it is not a vulnerability in the report, and the report says so with an
  `unresolved_observation` warning, which is the loud behavior Decision 6 chose.

## Consequences

- The four resource type strings `image`, `file`, `logical`, and `scan` are permanent identity
  inputs beside `host` from the first release that carries them.
- A driver rename (Semgrep OSS to Semgrep PRO, or a fork) re-mints every tracking id, because
  the driver name is in `context_key`. Cross-source correlation and manual merges are the
  scheduled mitigation.
- A clean scan is not yet evidence: `results: []` is INFO `run_clean` and, with no other run
  yielding an observation, ERROR `no_observations`, which fails ingest. Because the CLI parses
  every artifact before opening the store, a clean log fails the whole `complyroll ingest` run
  that includes it, so operators drop clean logs until the coverage observation of backlog
  item 9 lands.
- Cross-tool CVE merging waits for cross-source correlation: Trivy and Grype reporting the
  same CVE are two cases with two tracking ids today.
- `informational` and `review` observations are recorded as NOT_REVIEWED and stay silent in
  reports; `open` ones are loud, recorded as UNKNOWN with an `unresolved_observation` warning
  in every report.
- Folding by identity means Trivy's two vulnerable packages in one `requirements.txt` share
  one observation: the count, both location messages, and the chosen description are
  preserved, but the case shows one resource. Package-level identity is deferred to the SBOM
  adapter.
- Absolute `file:///` uris from tools that resolve paths before writing differ per runner and
  split resources. Metadata records the uri base; repository-relative output is the
  recommendation.
- `file` resources scoped by `repositoryUri` re-mint when the same tool runs with and without
  `versionControlProvenance`. GitHub code scanning always emits it.
- `source_identifiers` reads tag prose, so a CWE mentioned in a tag attaches to the
  observation; the list is extracted, not curated.
- The 500,000 JSON value bound refuses very large CodeQL logs below 32 MiB; raising
  `max_json_nodes` is an explicit caller decision and the message says so. Neither that bound
  nor the byte bound limits a string's length, so the per-observation caps and the 512 KiB
  ceiling are the only thing between a 32 MiB artifact and the 1 MiB event cap, and the
  saturated-caps test is what keeps the arithmetic honest when a cap is raised later.
- Outside this slice: the store raises a bare `ValueError` for a payload over its caps and the
  persisted CLI run catches no bare `ValueError`, so an oversized payload from a future adapter
  would surface as a traceback. The adapter ceiling makes it unreachable for SARIF. The CLI
  clause joins the Phase 2 cleanup list beside the bare assert in `compat/stigroll.py`, the
  CKLB and XCCDF timestamp divergence of Decision 8, and a one-line formatter run on a
  pre-existing expression in `stig.py`.
- Six fixtures (Trivy, Grype, Semgrep, CodeQL, Checkov, and a spec-corners log), the two
  goldens `tests/golden/vdt-sarif.json` and `tests/golden/vdt-sarif.md`, and the
  persisted-path, replay, and saturated-caps tests hold the behavior above; the eight existing
  goldens are byte-identical.

## Rejected alternatives

- Normalizing the driver name: a normalization rule is a second identity input that needs its
  own version.
- Producer fingerprints as identity: they mean a different thing in each tool and two of the
  five emit none.
- Region in `resource_id`: line churn would re-mint resources on every edit.
- Package identity (`name@version`) as the Trivy resource: package-level identity belongs to
  the SBOM adapter, and it is not what the location says.
- Dropping the driver from `context_key`: Trivy and Grype would merge on a CVE before
  cross-source correlation exists to say so.
- `repositoryUri` in `context_key`: its spellings split cases.
- Suppressed results to NOT_REVIEWED or NOT_APPLICABLE: a developer's suppression would close
  a finding the evaluator never saw.
- `baselineState` `absent` to PASS: the adapter would be accepting risk on a producer's diff.
- `informational` to PASS: an informational rule makes no compliance claim.
- A diagnostic per result: the artifact event would grow with the input and reach the store
  cap.
- A bare `.json` sniff: it changes CKLB dispatch for every existing `.json` checklist, and
  nothing pins that attribution yet.
- The `?` placeholder for a missing rule id: it merges unrelated findings into one case.
- The filename stem as the `scan` resource id: a renamed log would re-mint the observation.
- Percent-decoding or resolving uris: a repository-relative path would stop being identical
  across runners, and resolving walks a chain the log controls.
- Reading `message.markdown`: Markdown must not reach the twin unescaped.
- `str.format`: it interprets attribute and index syntax inside the braces, so producer text
  would steer Python lookups.
- An `ingest_artifact` alias: the rename touches over a hundred references and is its own
  refactor.
- Relaxing `IngestResult.successful` for empty logs: a parse of nothing would become a
  successful assessment, which the security posture forbids.
- Seven limit fields: two suffice, and each field is a promise to keep.
- A `sarif_` prefix on diagnostic codes: the codes already name their condition and the
  artifact names the parser.
- Refusing `|` in a driver name: the CKLB and XCCDF context keys use the same join unguarded,
  and a collision surfaces both tools in `detection_sources`.
- Ignoring `ruleConfigurationOverrides`: the spec's level chain names them, so a log that
  carries one would be read at the wrong level.
- Treating `security-severity` `0.0` as LOW: GitHub reads `0.0` as unset and Trivy writes it
  for UNKNOWN.
- Reading the latest clock instead of the earliest: a deadline that starts later is the
  lenient mistake.
