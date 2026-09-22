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
that component whose `guid` equals `result.rule.guid` (3.52.6); else the descriptor whose `id`
equals the string id (3.52.3). The guid and id steps count only a lone exact match: a value no
descriptor carries, or one that two descriptors carry, names nothing, and a guid that names
nothing falls through to the id. Guids and ids compare with surrounding whitespace trimmed and
otherwise code point for code point, so a guid in other letter case names nothing. That is the
adapter's reading, not a spec requirement: 3.5.3 lets a guid's hex digits take either case, and
a result whose only rule reference is such a guid ends in `rule_id_missing` below rather than in
a guessed match. There is no prefix matching, because 3.52.4 keeps a hierarchical id out of the
lookup, so `CA5350/md5` never finds descriptor `CA5350` by its id. Each component's descriptor
positions by id and by guid are indexed once per run, so the lookup costs the same for every
result that makes it. The id step was added during the build: Semgrep and Grype write `ruleId`
with no `ruleIndex`, and without it their results came out with empty titles, no tags, no CWE
identifiers, and Grype at MEDIUM instead of HIGH. Identity was never affected by it, and a
result that carries only `rule.guid` takes its identity from the descriptor the guid names.

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
empty. `[label](n)` link syntax is flattened to `label` on the template first, in one
left-to-right pass over the escapes of 3.11.6: inside link text, `\\`, `\[`, and `\]` are
unescaped in the kept label, a backslash before any other character stays as written because
producers write Windows paths, and an unescaped `[` abandons the link at that bracket. Only link
text followed by `](`, one to nine ASCII digits, and `)` is flattened, so a uri link and
unterminated text stay as written, and nothing outside link text is unescaped. The spec's
example 1 is printed without the `]` that closes its link text, so as printed it stays as
written; with that bracket it renders as the spec says, `para[0]\spans[2]`. Then `{n}`
placeholders are replaced from `message.arguments[n]` in one left-to-right pass with an output
budget of `MAX_DESCRIPTION_CHARS`, at most `MAX_MESSAGE_ARGUMENTS` (32) arguments read, a
missing or non-string argument left as the literal placeholder, and `{{` and `}}` unescaped in
the same pass. A placeholder and a link index are ASCII digits only, so another script's digit
never becomes one. The pass substitutes at most `MAX_MESSAGE_PLACEHOLDERS` (1,024) placeholders,
whether or not an argument fills them, and reads a run of literal text only as far as the room
left in the budget, so one expansion costs the budget and never the size of the template. An
expansion that stops at the placeholder cap, or that leaves template text unread when the budget
runs out, is marked cut with the `...[truncated]` marker, `description` in `truncated`, and the
`evidence_truncated` warning, even when stripping or sanitizing brings what was read back under
the cap: text went unread either way. `message.markdown` is never read: the spec requires `text`
beside it, and Markdown must not reach the twin unescaped. The title is
`descriptor.shortDescription.text`, else `descriptor.name`, else empty.

`source_identifiers` come from three fixed anchored regexes (CVE, GHSA, and CWE, the last
reading both Semgrep's `CWE-78: ...` tag and CodeQL's `external/cwe/cwe-078` form) run over
the rule identifier, the descriptor's `id` and `name`, its `properties` texts and
`relationships[].target.id`, the result's `properties` texts, and `result.taxa[].id`, unique
and sorted. Every pattern reads ASCII letters and digits only, since a case-blind Unicode letter
class also matches the dotted and dotless i, the long s, and the Kelvin sign. A CVE sequence
number is 4 to 19 digits, the bound of the `cveId` pattern in the CVE record format. So a
lookalike letter or digit, or an overlong number, never becomes an identifier. At most
`MAX_LIST_ITEMS` (64) identifiers are kept per observation, the first 64 in sorted order, cut
the same way per result and again per fold; a cut adds `source_identifiers` to `truncated` with
the `evidence_truncated` warning. They feed the group's `source_identifiers` and the later KEV
enrichment and are never identity. Because they read tag prose, a CWE mentioned in a tag
attaches to the observation.

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
`result.level`; else, when the result's invocation carries a `ruleConfigurationOverrides` entry
whose descriptor reference resolves to the result's own descriptor, that override's
`configuration.level`; else the descriptor's `defaultConfiguration.level`; else `warning`.

The invocation is `provenance.invocationIndex` when that is a JSON integer. An absent index, or
one that is null, a bool, text, or any other non-integer, takes the spec default of 3.48.6: 0
when the run has exactly one invocation, else none. An explicit negative index is the spec's
unknown invocation, and neither it nor an index past the end of `invocations` applies an
override. A result whose descriptor does not resolve takes no override either, whatever index it
carries. Each invocation's entries are resolved once per run, in list order, skipping any entry
that is not an object, whose `descriptor` is not an object, or whose `configuration.level` is
absent or empty (an entry with no level never decides, so a later one can). An entry's
descriptor reference resolves the way a result's rule reference does in Decision 4, with no
`ruleIndex` beside it: its component by `toolComponent.index`, else `toolComponent.guid`, else
the driver, and then its descriptor by `index`, else `guid`, else a lone exact `id`. An entry
that resolves to no descriptor, an index past the end of the rules included, never applies. An
entry applies to a result when both resolve to the same descriptor, at the same position in the
same component. Spec 3.52.4 keeps a reference's `id` out of the lookup, and the id step above
counts only a lone exact match, so when two descriptors share the id `CA1711`, an entry naming
`{index: 1, id: CA1711}` sets the level of `rules[1]` alone, and an entry naming only the id
resolves to neither. When several entries resolve to one descriptor, the first in list order
wins.

Then `security-severity` is read from the first holder that declares it, the result's
`properties` before the descriptor's. A value that is a JSON number (bool excluded) or a string
that, once trimmed, is an ASCII decimal (digits, then optionally a point and more digits),
finite, greater than 0 and at most 10, sets severity by the GitHub bands: 9.0 and above
CRITICAL, 7.0 and above HIGH, 4.0 and above MEDIUM, below 4.0 LOW. A JSON integer is
range-checked as an integer before it is converted, so an integer above about 1.8e308, which the
loader's integer digit limit admits and a float cannot hold, is invalid rather than an overflow.
Exactly `0.0` means unset in GitHub's own reading and falls through silently to the level chain
(Trivy writes `0.0` for UNKNOWN); because the first holder wins, a result-level `0.0` falls
through without reading the descriptor's value. A value that is present but unusable (negative,
above 10, NaN, a bool, or any other text, such as `0_9`, `1e1`, `.5`, or another script's
digits, which `float()` would read) is WARNING `security_severity_invalid` and falls through.
The level then maps `error` HIGH, `warning` MEDIUM, `note` LOW, `none` INFORMATIONAL; an unknown
level is WARNING `invalid_level` and UNKNOWN. Metadata records `level`, `level_source`
(`forced_none`, `result`, `invocation_override`, `rule_default`, or `default`),
`security_severity` verbatim, and `severity_source` (`security-severity` or `level`).

None of this touches PAIN. `source_severity` is the scanner's opinion recorded as evidence; the
evaluator sets PAIN, and no report reads scanner severity into a deadline.

## Decision 8: `observed_at` comes only from the log's own clocks, earliest first

Per result, `provenance.firstDetectionTimeUtc`, else `provenance.lastDetectionTimeUtc`; else
per run, the earliest parsable `invocations[].startTimeUtc`, which is the default the spec
itself gives a missing detection time in 3.48.3, else the earliest `endTimeUtc`; else none,
with the existing `source_timestamp_missing` warning once per artifact. Earlier is the
conservative reading for a detection clock: a VDR deadline that starts sooner is never the
lenient mistake. When the earliest instant is written under two offsets, as
`2026-09-01T00:00:00Z` and `2026-08-31T17:00:00-07:00` are, the one whose canonical text sorts
first is kept, so no order of results, runs, or invocations changes the observation's
`observed_at`. Never file mtime, never `ingested_at`, never a date parsed out of an automation
id. A JSON null clock member is absent; a present value that fails the checks below is WARNING
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

A second SARIF-local check keeps only an instant whose UTC year is 1970 through 9000
(`MIN_CLOCK_YEAR` and `MAX_CLOCK_YEAR`). Year 1 with a positive offset overflows the conversion
to UTC, and year 9999 overflows the deadline arithmetic that later adds a policy timeframe to
the clock, so a clock outside those years is refused at ingest rather than raising
`OverflowError` downstream. The kept value keeps its own offset; only the check reads it in UTC.
The check is SARIF-local like the offset check, so the downstream sites that overflow stay on
the Phase 2 cleanup list for the other adapters' clocks. The diagnostic's summary names the
whole rule: "clock value is not an aware timestamp with a whole-minute offset in the years 1970
to 9000 UTC; ignored".

Spec 3.9 lets hour 24 name the midnight that ends a day, and `fromisoformat` reads hour 24 only
from Python 3.14, in every spelling it accepts. So the spec's form, `T24:00` or `T24:00:00` with
an optional all-zero fraction, under any valid offset, is read as 00:00 of the next day on every
interpreter, and any other hour 24 is `source_timestamp_invalid` on every interpreter, as are
`9000-12-31T24:00:00Z`, whose next midnight falls in 9001 and fails the year check, and
`9999-12-31T24:00:00Z`, whose next midnight no `datetime` can hold, so the overflow is caught
and refused rather than raised. Two forms 3.9 allows are refused on every interpreter as
deliberate deviations: a leap second (`:60`), which no `datetime` can hold, and a date with no
time, which is not an aware instant. Neither is a clock the event contract can carry.

## Decision 9: results that share an identity fold into one bounded observation

Inside one artifact, results that share the fold key (driver name, rule identifier, resource
type, resource id, and context key, which together with the artifact's constant inputs is the
fingerprint itself) fold into one observation, across runs. Two runs of the same driver and
category fold; two drivers never do. The folded observation keeps `occurrence_count` (one
uncapped integer) and, in metadata, the regions with their paired location messages and the
run indexes, ordered by region tuple and deduplicated, each list cut at `MAX_LIST_ITEMS` (64)
with the cut member named under `truncated`. The worst disposition wins (OPEN, then UNKNOWN,
NOT_REVIEWED, NOT_APPLICABLE, PASS), the strongest severity wins, the earliest `observed_at`
wins with Decision 8's tie-break between offsets, and the title and description come from the
candidate that sorts first by its smallest region's `(startLine, startColumn, endLine,
endColumn)`, where a missing member or region counts as zero, and then by its description (the
result's expanded message), with the rest of its content breaking any tie left, so the fold is
independent of result order. INFO `results_collapsed` names each folded result. The dispatcher's
`duplicate_observation_identity` check stays as a backstop and a test asserts it never fires for
SARIF.

The bound is arithmetic, not hope, and the arithmetic counts characters. The metadata
vocabulary is fixed, so a producer cannot add a key. List-valued members hold at most
`MAX_LIST_ITEMS` items of `MAX_LIST_ITEM_CHARS` (256) each, uri-valued scalars at most
`MAX_URI_CHARS` (2,048), other scalars `MAX_METADATA_VALUE_CHARS` (512), the title
`MAX_TITLE_CHARS` (512), the description `MAX_DESCRIPTION_CHARS` (4,096), and
`source_identifiers` at most 64 entries, so a fully saturated observation is at most 126 JSON
values. A region line or column above `MAX_REGION_INTEGER` (2**31 - 1) is absent, and a start
line above it leaves no region at all, so a region's text stays short; a location message is
cut to leave room for its region prefix, so the joined item stays within `MAX_LIST_ITEM_CHARS`
with one marker. A character is not a byte, though. Canonical JSON spends one to four bytes on
each character: four on a four-byte UTF-8 character, and four on an ASCII quote or backslash
inside a list-valued member, which is escaped once in the list's compact JSON and again in the
observation's. The log that fills every cap with ASCII letters (`saturated_log` in the tests)
folds to an observation of 263,694 bytes of canonical JSON, and the same log in four-byte text
folds to 981,747 bytes.

So the adapter enforces a ceiling, and real input reaches it: after folding, an observation
whose canonical JSON exceeds `MAX_OBSERVATION_JSON_BYTES` (512 KiB) in UTF-8 raises
`InputLimitError`, which the dispatcher reports as `artifact_parse_failed`, so `report vdt` and
`ingest --db` refuse the same input the same way instead of diverging at the store's
`MAX_EVENT_JSON_BYTES` (1 MiB) and `MAX_EVENT_JSON_VALUES` (100,000). The four-byte saturated
log fails closed that way on both paths, and a four-byte observation of 507,381 bytes, just
under the ceiling, records and replays. Neither the artifact byte bound nor `max_json_nodes`
bounds a string's length, which is why the caps exist: without them, 2,000 same-identity
results with distinct 600-character location messages, or one result with 300 producer
fingerprint names of 4,096 characters, pass every input bound, compile on the stateless path,
and fail `ingest --db` inside the store with a bare `ValueError`. Both are reproduced in the
tests, along with the ASCII log that fills every metadata key at its cap, and all three fold to
observations under the ceiling. An artifact's observations are bounded together as well. A fold
copies each capped list it keeps, so a result that names 256 resources carries its own lists
into 256 observations and a descriptor's lists reach every observation whose results name it:
50,000 observations under the ceiling could reach about 26 GB, and an admissible 3 MB log folds
into about 1.9 GB of canonical JSON. `max_observation_bytes_per_artifact` (256 MiB, eight times
`max_artifact_bytes`) caps the canonical JSON of every observation one artifact yields, summed
as each is built, so the artifact fails closed with `InputLimitError` before its observations
grow much past the budget, on both paths alike. The six fixtures fold to between 0.51 and 1.41
times their own size. The budget bounds observations, not the candidates they fold from, which
are all held until the last run is read; the input bounds limit those instead. A candidate is
one result at one resource and costs the log at least two JSON values, so `max_json_nodes`
allows about 250,000 of them, and 245,000 results with no location, a 3.7 MB log, hold about 300
MiB before the first observation is built, or about 550 MiB when each run also carries a full
tool, automation, and provenance block, since every candidate keeps its own copy of its run's
metadata. Both grow linearly with the count.

Diagnostics are coalesced per code per artifact, each carrying an occurrence count and the
first `MAX_DIAGNOSTIC_PATHS` (5) JSON-path locations in its message, because the report copies
every non-ERROR diagnostic and the `artifact.ingested` event embeds them. A path can embed a
producer's object key and a detail quotes a producer's value, so every path and detail is
sanitized like evidence and cut at `MAX_METADATA_VALUE_CHARS` (512) with the marker, and a
detail is built from a bounded part of the value: at most the first 513 characters of a string,
a bounded `reprlib` rendering of an array or object, which reads only its first few members in
their own order and never sorts an object's keys, and the repr of a number, which the loader's
integer digit limit already bounds. Each code keeps its first summary and its first detail. One
code's message is then at most its summary; a 17-character frame plus the digits of its count;
five paths of 512 characters with their separators and a trailing `, ...`, which is 2,573
characters; and, for the five codes that carry a detail (`identity_input_invalid`,
`invalid_level`, `invalid_result_kind`, `rule_reference_conflict`, and
`security_severity_invalid`), `; first: ` and the detail, 521 more. Twenty codes can reach the
coalescer and their longest summaries total 1,322 characters, so the diagnostics of one artifact
come to at most 55,727 characters plus the decimal digits of the twenty counts, and 117 more for
the two fixed messages (`no_observations` and `source_timestamp_missing`), whatever the size of
the input. These are characters; the store's UTF-8 spends at most four bytes on each.

The work per result is bounded the same way. A run's shared tool data is read once: the
component guid map and each component's rule positions are indexed on first use, each
invocation's overrides are resolved to descriptors on first use, so a result finds its override
by position and never compares a shared id or guid, and a descriptor's or a component's evidence
(its title, tags, message templates, identifiers, `security-severity` and the detail a
diagnostic quotes from it, and default level) is resolved once and shared by every result that
names it. A shared text is cleaned once, and its cleaning is reported at each result's own path,
with the same counts and in the same first-seen order that cleaning it again there would give. A
shared uri, a run artifact's, a uri base's, or a descriptor's `helpUri`, is checked once per
run, and so is a descriptor's id where it stands as a result's rule identifier. Each use of one
that is refused is still refused at its own path, and a run artifact's uri with a `..` segment
or a `//` prefix is still warned about at each location that names it. A shared list, a
descriptor's tags or `deprecatedIds` or a run's `repoDigests`, is cut once too, where it is
cleaned, to its `MAX_LIST_ITEMS` + 1 smallest distinct items in sorted order, and so is each of
a result's own lists and fingerprints (taxa, suppression kinds and statuses, `fingerprints`, and
`partialFingerprints`), which join one fold for each resource the result names. Each of a fold's
first 64 items is among the first 64 of the list it came from, and the item past them keeps the
cut flag, so every fold keeps the items and the cut the whole list would have given it, and
never sorts more than 65 items of any one of these lists. A location's regions, messages, and
logical names are left whole, since each joins only the fold of the resource that location
names. A result's cost is therefore its own bytes read once plus a bounded amount for each fold
it joins, and never the size of a template or a descriptor it shares with every other result in
the run, or the size of its own lists once for each resource it names.

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
`evidence_truncated` per artifact carry the counts. Whitespace at either edge of a text is
trimmed before the text is sanitized, CR, VT, FF, U+001C to U+001F, U+0085, U+2028, and U+2029
included, so such a character at an edge is not counted in `evidence_sanitized`, while the same
character inside the text is. Every character that matters for security, Cf, Cs, and Cc other
than whitespace, is counted wherever it sits in the text that is read.

Separately, `parse_json_bounded` now refuses a lone surrogate code point in any JSON string or
object key during the walk it already does, raising `ValueError` so the dispatcher reports
`artifact_parse_failed`. Before this, `{"a":"\ud800"}` parsed and then the report writer and
the store both failed on `.encode("utf-8")`; that was a CKLB bug too, and the check covers
every JSON adapter.

## Decision 11: three `IngestLimits` fields, exceeded means refused, reaching the adapter through its constructor

`max_results_per_run = 50_000` (SARIF only for now), `max_observations_per_artifact = 50_000` (a
generic name so CKLB can adopt it later), and `max_observation_bytes_per_artifact` at 256 MiB
(Decision 9) join `IngestLimits`. `SarifAdapter.__init__(self, limits: IngestLimits =
DEFAULT_LIMITS)` stores them on the instance; `name`, `version`, and `media_type` stay class
attributes so the attribution block reads them as it does for `CklbAdapter`; the dispatch branch
constructs `SarifAdapter(limits)` from the dispatcher's own `limits` argument, and
`SourceAdapter.parse` and the three STIG adapters are untouched. Exceeding any of the three, or
`MAX_LOCATIONS_PER_RESULT` on one result, or `MAX_OBSERVATION_JSON_BYTES` after folding, raises
`InputLimitError`, which the dispatcher already reports as `artifact_parse_failed`.
`DEFAULT_LIMITS` keeps every existing value.

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
  saturated-caps tests, in ASCII and in four-byte text, are what keep the arithmetic honest
  when a cap is raised later.
- Because the caps count characters, a log that fills them with multi-byte text, or with the
  quotes and backslashes a list member escapes twice, can be refused whole at the ceiling where
  the same log in ASCII letters is accepted: the saturated log passes in ASCII letters and fails
  in four-byte text. That is the ceiling doing its job, failing the artifact closed with
  `artifact_parse_failed` on both paths before the store sees it.
- Outside this slice: the store raises a bare `ValueError` for a payload over its caps and the
  persisted CLI run catches no bare `ValueError`, so an oversized payload from a future adapter
  would surface as a traceback. The adapter ceiling is what makes that unreachable for SARIF:
  no observation over 512 KiB leaves the adapter, whatever the caps allow, and the caps alone
  allow more, since the four-byte saturated observation is 981,747 bytes, within 7 percent of
  the 1 MiB event cap. The CLI clause joins the Phase 2 cleanup list beside the bare assert in
  `compat/stigroll.py`, the CKLB and XCCDF timestamp divergence of Decision 8, and a one-line
  formatter run on a pre-existing expression in `stig.py`.
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
