# ADR 0013: HDF adapter

- Status: Accepted
- Date: 2026-09-29

## Context

Phase 2 continues with an adapter for the Heimdall Data Format (HDF), which is what InSpec's
`json` reporter writes (exec-json) and what MITRE's SAF CLI writes when `saf convert` turns
Nessus, Trivy, Burp, and other scanner output into the same shape. One adapter therefore covers
native InSpec and CINC Auditor runs, including the STIG baselines published as InSpec profiles,
and every converted scanner report, and feeds them into the observation ledger, correlation, and
reports the STIG and SARIF adapters already feed.

The document is one run. The root is an object with `platform` (`name`, `release`, and an
optional `target_id`), `profiles` (an array), `statistics`, and `version` (the producer's
version string; there is no schema version member). A profile carries `name`, `title`,
`version`, `sha256`, `status` with `status_message`, `controls`, and, for overlays, `depends`
and `parent_profile`. A control carries `id`, `title`, `desc` and `descriptions`, `impact` (a
number from 0 to 1), free-form `tags`, `results`, `waiver_data`, and, after `saf attest apply`,
`attestation_data`. A result carries `status`, `code_desc`, `start_time`, `message`,
`exception`, and `backtrace`. InSpec's own statuses are `passed`, `failed`, and `skipped`; it
never writes `error`. A check that raised keeps its RSpec status, which is often `passed`, and
gains `exception` and `backtrace` (InSpec `lib/inspec/formatters/base.rb:47-58` sets both
unless the exception is an expectation failure, and 232 copies the RSpec status). Converters do
write `status "error"`.

Overlays are the shape that decides the design. In real InSpec output the wrapper profile has no
`parent_profile`, carries `depends`, and lists every control with `results: []`; the profile it
pulls in names the wrapper in `parent_profile`, and only the profile at the bottom of that chain
holds results. A three-layer sample checked while designing this (InSpec 4.18.100, an Oracle
database baseline) has exactly that shape, and its middle layer's `depends` entry names the leaf
by a local alias that matches no profile `name` in the document, so `depends` cannot be used to
walk the chain.

Converted documents follow conventions that are observed, not specified: `platform.name` is the
constant `Heimdall Tools`, every `start_time` is `""`, a control id carries the finding
identifier (a Trivy conversion's id is the CVE), and `tags.cve` and `tags.cwe` carry lists.

The two upstream readers roll a control up differently from each other and from what a
vulnerability report needs. Heimdall's `compute_status` (mitre/heimdall2
`libs/inspecjs/src/compat_inspec_1_0.ts:235-262`) reads any error first as Profile Error, then a
waived or impact-0 control as Not Applicable, then no results as Profile Error, then any failure as
Failed, any pass as Passed, and the rest as Not Reviewed; a result with a truthy `backtrace` is an
error whatever its status (283-286). InSpec's enhanced outcomes
(`lib/inspec/enhanced_outcomes.rb:6-16`) read an exception with a backtrace as error, except on a
`noop` resource, then impact 0 as not applicable, then all skipped as not reviewed, then any
failure as failed, and the rest as passed. InSpec's severity table is `IMPACT_SCORES`
(`lib/inspec/impact.rb:5-19`): none 0.0, low 0.1, medium 0.4, high 0.7, critical 0.9.

Two things were frozen before this work started. ADR 0002 fixed observation identity as a
SHA-256 over nine inputs, and ADR 0007 fixed the vulnerability group key as `(source_type,
source_record_id, context_key)`. ADR 0011 set the posture this adapter inherits: suffix
dispatch, refuse identity and degrade evidence, fold by identity with a byte ceiling per
observation and a byte budget per artifact, and fail closed on any error.

Three designs were written and scored before this one: a checklist-shaped design, a
SARIF-shaped design, and a compliance-semantics-first design. The checklist-shaped design was
fatal, because it read the overlay inverted: it would have emitted the wrapper's empty controls
as ERROR observations and dropped the leaf's failed results. Both of the others shared one
hazard, `float()` on an arbitrary-precision JSON integer, which raises `OverflowError` where the
dispatcher does not catch it. This ADR takes the third design's semantics with the second
design's guards, and a skeptic pass over the result changed the backtrace rule, the attestation
handling, and the overlay walk before anything was built.

## Decision 1: one adapter on the Phase 0 contract, dispatched by name and by a key check

`HdfAdapter` in `src/complyroll/adapters/hdf.py` implements the `SourceAdapter` contract with
`name = "complyroll.hdf"`, `version = HDF_PARSER_VERSION` (`"1"`, `hdf.py:57`), and
`media_type = "application/json"`. The parser version is its own constant, so an HDF correction
can never re-mint a CKLB, CKL, XCCDF, or SARIF observation. The limits reach the adapter
through its constructor, as they reach SARIF's.

`ingest_stig_artifact` sends a name ending `.hdf.json`, compared case-insensitively, to
`HdfAdapter(limits)` (`stig.py:598`). That arm sits after the SARIF arm and before the
`.cklb`/`.json` arm. A bare `.json` file parses exactly as before, and then the already-parsed
value is looked at once (`stig.py:609-613`): `looks_like_hdf` (`hdf.py:215-222`) accepts an
object with no `stigs` member, a `profiles` array, and a `platform` object, and everything else
goes to `CklbAdapter` as before. `stigs` is tested first, so a document that claims to be a
checklist stays a checklist. A `.cklb` file is never sniffed. This is the `.xml` and `.arf`
root-element precedent applied to JSON.

It is a recorded carve-out from ADR 0011 Decision 1, which refused a bare `.json` sniff for two
reasons. The first, that a sniff would change dispatch for every existing `.json` checklist,
does not reach HDF: a checklist carries `stigs`, and the key check requires its absence. The
second, that nothing pinned CKLB attribution of a malformed bare `.json`, is closed here.
`test_adapters.py:684` pins that `{` saved as `scan.json` still fails as CKLB, and
`test_adapters.py:694` pins that an HDF document saved as `scan.json` and refused by the node
bound is attributed to CKLB too, because the sniff reads only a document that parsed within the
bounds. `test_adapters.py:487` still pins that a SARIF log saved as `scan.json` fails as CKLB on
its shape; it has no `profiles` member. What moves is the one class the carve-out is for: an
HDF-shaped bare `.json` that used to fail as CKLB now ingests as HDF. SARIF stays unsniffed,
since every SARIF producer can write its own suffix and HDF has none: InSpec's reporter and
`saf convert` both write `.json`. There is no bare `.hdf` suffix, because `.hdf` means HDF5 to
everyone outside MITRE.

The parse-failure ladder gains one arm (`stig.py:671`): a `.hdf.json` document that fails to
parse, the depth and node bounds included, is attributed to `complyroll.hdf 1
application/json`, and a bare `.json` one stays with CKLB (`stig.py:674`). The adapter wrapper's
catch of `(AdapterParseError, ValueError, TypeError)` (`stig.py:704`) is unchanged. It does not
catch `OverflowError`, so the impact guard range-checks an integer before any float arithmetic
(Decision 7).

The `stigroll` compatibility command skips an artifact attributed to the HDF parser
(`compat/stigroll.py:315-322`) with `warning: <name> is an HDF document; stigroll rolls up STIG
checklists only, skipping`, after the SARIF skip. A lone HDF input ends with `error: no
findings parsed from any input`. A bare `.json` HDF document that used to draw the "no 'stigs'
key" warning draws the skip line instead; both are warnings with no rows.

## Decision 2: identity reuses the ADR 0002 recipe unchanged

HDF supplies the nine inputs and adds nothing.

| Input | Value |
|---|---|
| `source_type` | `hdf` |
| `source_tool` | `inspec` for a native document; `heimdall-tools` when `platform.name` is exactly `Heimdall Tools` (`hdf.py:60-63`) |
| `parser_name`, `parser_version` | `complyroll.hdf`, `1` |
| `source_record_id` | the control `id`, with surrounding whitespace stripped and nothing else changed |
| `resource_type` | `target`, or `scan` under the fallback (Decision 3) |
| `resource_id` | `platform.target_id`, or the root profile name under the fallback |
| `context_key` | the name of the root profile the control's profile hangs under |
| artifact digest | the SHA-256 of the bytes read, as for every adapter |

`context_key` is found by walking `parent_profile` upward (Decision 9). It is never the profile
version or `sha256`, so a profile patch does not re-mint the tracking id of an unchanged
weakness, which is the reason ADR 0011 Decision 2 dropped the run instance. For a converted
document the root profile is the converter's, so the Trivy fixture's context key is
`Trivy Vulnerability Scan`. CINC Auditor writes the same format and is read as `inspec`.

`source_tool` for converted output is a normalized token rather than the verbatim platform
name: it is never a space-bearing display string, and it never claims that InSpec ran. A CKLB
and an HDF document of the same STIG rule are two cases, as Trivy and Grype reporting the same
CVE are (ADR 0011); the `group_id`, `rule_id`, and `stig_id` metadata are the bridge for
cross-source correlation later.

## Decision 3: the resource is the declared target

`resource_type` is `target` and `resource_id` is `platform.target_id` when that is a non-blank
string. InSpec writes a node uuid for a local or ssh run, a container id for a docker target,
and an account for a cloud target, and a converter writes the scanned host, image, or URL, so
`host` would be a claim the document does not make.

When `target_id` is absent, blank, or not a string, `resource_type` is `scan` and
`resource_id` is the root profile name, with WARNING `resource_identity_fallback` ("platform.
target_id is absent or blank; the root profile name is the resource"), emitted once per
document at the path `platform` (`hdf.py:400-406`). This is the SARIF Decision 3 fallback: the
same bytes under two filenames keep one identity (`test_hdf.py:2651`), and a rename never
re-mints an observation. The filename stem is not used, for the reason ADR 0011 Decision 3
gave.

A `target_id` that is present but refused as an identity input (Decision 10) stops the scan
before any profile is read (`hdf.py:390-399`): the document yields that ERROR and
`no_observations`, and nothing else (`test_hdf.py:2965`).

## Decision 4: a failed control is a vulnerability, and the roll-up is a rank table

Each result reads one disposition, first match wins (`hdf.py:287-292`):

| Result | Disposition |
|---|---|
| any `status`, with a `backtrace` present and not `null`, `false`, or `""` | ERROR |
| `status` exactly `failed` | OPEN |
| `status` exactly `error` (the converters' spelling) | ERROR |
| `status` exactly `passed` | PASS |
| `status` exactly `skipped` | NOT_REVIEWED |
| anything else, absent or not a string included | UNKNOWN, WARNING `invalid_result_status` |

The backtrace rule follows both upstream readers. InSpec writes a check that raised as its RSpec
status plus `exception` and `backtrace` (`lib/inspec/formatters/base.rb:47-58`, 232); Heimdall
reads a truthy `backtrace` as an error whatever the status (`compat_inspec_1_0.ts:283-286`), and
InSpec's enhanced outcomes read an exception with a non-nil backtrace as an error
(`lib/inspec/enhanced_outcomes.rb:6-7`). As built, only an absent member, `null`, `false`, and
`""` count as no backtrace (`hdf.py:272-279`), so `0`, `[]`, `{}`, `true`, and any non-empty
string read ERROR (`test_hdf.py:1605`). `[]` reads as an error in both readers: Heimdall by
JavaScript truthiness and InSpec because it is not nil. Like Heimdall, and unlike InSpec, the
rule does not also require an `exception`. The backtrace is read for presence only;
its content is never read or recorded. An `exception` with no backtrace keeps its status, as
both readers keep it.

Status matching is exact. `"Passed"`, `" passed"`, and `"FAILED"` read UNKNOWN with the
warning, because the four spellings are the producers' own and anything else is not one of
them.

Each control then reads one disposition, recorded in `disposition_source` (`hdf.py:295-308`):

| Control (first match) | Disposition | `disposition_source` |
|---|---|---|
| a valid `impact` equal to 0 | NOT_APPLICABLE, INFO `impact_zero_not_applicable` (Decision 6) | `impact_zero` |
| `results` empty | ERROR | `no_results` |
| otherwise | the highest-ranked result by `HDF_DISPOSITION_RANK` | `results` |

`HDF_DISPOSITION_RANK` (`hdf.py:118-125`) is OPEN 5, ERROR 4, UNKNOWN 3, PASS 2,
NOT_REVIEWED 1, NOT_APPLICABLE 0. The order follows the upstream roll-ups, where a failure
wins, a pass beats a skip, and not applicable ranks lowest. It is not ADR 0011 Decision 9's
worst-wins table (`sarif.py:153-160`, OPEN 5, UNKNOWN 4, NOT_REVIEWED 3, NOT_APPLICABLE 2,
PASS 1, ERROR 0), which stays untouched, and it departs from that table in two places. PASS
ranks above NOT_REVIEWED and NOT_APPLICABLE, which is what lets an attested pass beat the
skipped result it answers (Decision 5). ERROR ranks above UNKNOWN, second only to OPEN, because
both upstream readers put an error ahead of every outcome that is not a failure. SARIF never reads a
result as ERROR, so its table's place for ERROR was never exercised. The duplicate-id fold of
Decision 9 takes SARIF's fold mechanics and this order.

Three deviations from Heimdall and InSpec are deliberate and pinned:

- (a) A failure beside an error reads OPEN, not Profile Error (`compat_inspec_1_0.ts:246`) or
  InSpec's error. A failure the runner observed starts a clock, and an inconclusive sibling never
  hides it; this is the conservative reading ADR 0011 Decision 8 gives a detection clock
  (`test_hdf.py:1483`).
- (b) A waiver never moves the disposition, where Heimdall reads a control skipped under a waiver
  as Not Applicable (`compat_inspec_1_0.ts:190-194`, 248-250). Decision 5 gives the reason
  (`test_hdf.py:1494`).
- (c) Impact 0 beside an error reads NOT_APPLICABLE, where both readers test the error first.
  The profile author's declaration covers an error in a check that carries no risk
  (`test_hdf.py:1500`).

A control with no results reads ERROR, not InSpec's not reviewed (`enhanced_outcomes.rb:10`,
where `all?` over an empty list is true), because an ERROR surfaces as
`unresolved_observation` in every report and a NOT_REVIEWED observation vanishes
(`test_hdf.py:1517`). Heimdall reads it as Profile Error too (`compat_inspec_1_0.ts:251`).
InSpec's `noop` exemption is not copied: the only `noop` exception comes from
`only_applicable_if`, which sets impact 0.0 and freezes it (`lib/inspec/rule.rb:170-180`), and
the impact-0 rule decides first.

## Decision 5: waivers and attestations are recorded and never move a disposition

Only results decide a disposition. The `waiver_data` and `attestation_data` members never do;
the result `saf attest apply` appends is a result, and it counts as one.

A waiver (`waiver_data`) is a risk acceptance made outside ComplyRoll's evaluation record. ADR
0007's evaluations file and the AVI report are where acceptance lives, and ADR 0011 Decision 6
refused the same move for SARIF suppressions. With `run: false` InSpec writes one `skipped`
result, which reads NOT_REVIEWED; with `run: true` and a failure the control is OPEN. Every
waived control draws WARNING `control_waived` ("control carries waiver data; the disposition
comes from its results and the waiver is recorded as metadata") and records `waived "true"`,
`waiver_justification`, and `waiver_expiration` from `expiration_date` (`hdf.py:739-760`).
`waiver_run` is recorded only when `run` is a JSON bool. `skipped_due_to_waiver` is a bool in
InSpec's output and a string in its schema: a bool records `"true"` or `"false"`, a string is
recorded as cleaned text, and `null` or absent records nothing. The waiver `message` is
dropped on purpose: InSpec generates it, as `""` or "Waiver expired on X, evaluating control
normally" (`lib/inspec/rule.rb:410-445`), and it restates the expiration date and the run flag,
which are recorded.

A `waiver_data` or `attestation_data` member counts only when it is a non-empty object. Absent,
`null`, `{}`, and any value that is not an object mean no waiver or attestation: no WARNING, and
no `waived` or `attested` key. InSpec writes `{}` on every unwaived control
(`lib/inspec/reporters/json.rb:140`), so anything stricter would warn on every control of every
native document.

An attestation comes from `saf attest apply` (mitre/saf `src/utils/attestations.ts`). It applies
only to a control whose results are non-empty and whose first result is `skipped`
(`attestations.ts:201-224`), and only with the status `passed` or `failed` (139-165). It sets
`attestation_data` and appends one result (108-137): `code_desc` "Manually verified status
provided through attestation" with the attested status, or, when the attestation had expired at
apply time, "Manual verification status provided through attestation has expired" with
`skipped`. The appended result's `start_time` is the instant `saf attest apply` ran, and its
`message` names the person who attested (`Updated By`, 85-106).

On a control with a non-empty `attestation_data`, a result whose `code_desc` is either marker is
an attestation result (`hdf.py:160-162`, 282-284). It takes part in the disposition and the
counts like any result, and it contributes no clock (Decision 8) and no failure text
(`hdf.py:694-697`). The attestation's content is recorded from `attestation_data` instead:
`attestation_status`, `attestation_explanation`, `attestation_frequency`, and
`attestation_updated`, never `updated_by` and never the appended result's message. `attested`
is `"true"`, or `"expired"` when the expired marker is present. So an attested `passed` reads
PASS over the skipped result it answers, an attested `failed` reads OPEN, and an expired one
reads NOT_REVIEWED. Every attested control draws WARNING `control_attested`, with the detail
`expired` for an expired one (`hdf.py:597-606`), so an attestation is never silent. The status
check runs before the marker check, so an attestation result whose status is outside the four
spellings still warns `invalid_result_status` and reads UNKNOWN.

## Decision 6: impact 0 is honored as not applicable

`impact` is profile content: authored, versioned, and carried in the profile `sha256`, the same
trust level as a CKLB status. MITRE baselines set impact 0 on controls that do not apply to a
platform; Heimdall renders them Not Applicable (`compat_inspec_1_0.ts:248-250`) and InSpec's
enhanced outcomes read them as not applicable (`enhanced_outcomes.rb:8`).

Every impact-0 control emits INFO `impact_zero_not_applicable` ("impact is 0, so the control is
not applicable whatever its results say"), whose detail names what its results would otherwise
have read, such as `results would read OPEN`, or `results would read ERROR` for a control with no
results (`hdf.py:608-616`). A set-aside failure is therefore findable in the diagnostics. The
rule fires on a valid number equal to zero only (`0`, `0.0`, or `-0.0`), never on a string, a
bool, or a small positive impact.

## Decision 7: severity is evidence, never PAIN

Severity is `tags.severityoverride`, else `tags.severity`, else the impact band, else UNKNOWN,
and `severity_source` records which one decided: `severityoverride`, `severity`, `impact`, or
`none` (`hdf.py:256-269`, 709-737). Like every adapter's severity, it is source evidence and
never sets PAIN.

The tag vocabulary is the five names of InSpec's `IMPACT_SCORES` (`lib/inspec/impact.rb:5-19`)
and Heimdall's `severities` (`libs/inspecjs/src/compat_wrappers.ts:53-59`): `none` is
INFORMATIONAL, then `low`, `medium`, `high`, and `critical`. Matching lowercases the tag as
Heimdall does (`compat_inspec_1_0.ts:166-178`); InSpec itself places no constraint on tag
values. Stripping surrounding whitespace before matching is a small recorded deviation. A tag
must be a string. A `null` tag is silent. Any other value, a blank string and a non-string
included, draws WARNING `invalid_severity_tag` ("severity tag is not none, low, medium, high, or
critical; ignored") and falls through. A string tag is recorded as `severity_tag` or
`severity_override`, cleaned but not lowercased, whether or not it matched.

The impact bands are InSpec's table read from the top: at least 0.9 is CRITICAL, 0.7 HIGH, 0.4
MEDIUM, 0.1 LOW, and anything below 0.1 is INFORMATIONAL (`hdf.py:152-158`). Heimdall reads the
same thresholds.

`impact` goes through a guard before any arithmetic (`hdf.py:238-248`). A bool is refused. An
`int` is range-checked from 0 to 1 before any conversion (the WARN comment at `hdf.py:243-244`),
because `float()` raises `OverflowError` on an integer of 310 or more digits, which a JSON
number can carry and the dispatcher does not catch. A `float` must be finite and within 0 to 1,
because `1e400` parses to infinity. An absent or `null` impact is silent: no warning, and
severity comes from the tags or is UNKNOWN. A present impact that fails the guard draws WARNING
`invalid_impact` ("impact is not a number from 0 to 1; it sets neither applicability nor
severity"), the impact-0 rule does not fire, and severity falls through to the tags. The
`impact` metadata is the JSON text of the valid value, with a float normalized by adding 0.0,
so `-0.0` records `0.0`.

`test_hdf.py:1811` feeds `1e400`, `-1e400`, a 400-digit integer and its negative, and a 4,300-digit
integer through the dispatcher and gets `invalid_impact` for each; `test_hdf.py:1848` runs the CLI
on a huge integer impact and gets the warning, exit 0, and no traceback. An integer of 4,301 digits
is refused inside `json.loads` by Python's `int_max_str_digits` limit, so it is
`artifact_parse_failed` attributed to HDF, not a warning (`test_hdf.py:1841`).

## Decision 8: `observed_at` comes from `results[].start_time` only

A result's `start_time` that is absent, `null`, `""`, or whitespace only is silently absent,
because converters write `""` by design (`hdf.py:698-702`). Any other value goes through the
shared clock guard, `parse_clock` (`common.py:325`) reached through `EvidenceParse._clock`
(`common.py:571`): aware, a whole-minute offset, a UTC year from 1970 to 9000, and `24:00`
handled. A value that fails is WARNING `source_timestamp_invalid` and counts as absent.

`observed_at` is the earliest kept clock over the control's results, attestation results
excepted, since their `start_time` is the instant `saf attest apply` ran and not an instant the
check observed anything. Earlier is the conservative detection instant, as ADR 0011 Decision 8
says. A fold keeps the earliest over its candidates. With no kept clock `observed_at` is absent,
and the existing `source_timestamp_missing` warning is emitted once per artifact, from the fold
(`hdf.py:820-823`). A converted control that was later attested therefore stays clockless rather
than taking the apply instant.

There is no document-level fallback. Another control's clock is not this control's detection
time, and ADR 0007 Decision 2 says a detection time is attested, never substituted. A converted
document needs `--detected-at` on the stateless path or `cases attest-detection` on the
persisted path, as a clockless SARIF log does.

## Decision 9: overlay copies resolve to the copy with results, and the rest fold bounded

Profiles are indexed by name in document order (`hdf.py:417-443`). A profile that is not an
object, has no string name, or repeats a name is ERROR `invalid_profile`. A name refused as an
identity input (Decision 10) is remembered, and a profile hanging under it is skipped silently,
since the refusal is already reported (`test_hdf.py:2524`). `parent_profile` absent or `null`
makes a root (`test_hdf.py:2488`); any other value is read as text, so a blank or non-string
parent names no profile. Each profile's root is found by following `parent_profile` upward with
a visited set, and every profile the walk passes shares the answer (`hdf.py:445-476`). A parent
that names no profile is ERROR `invalid_profile` "parent_profile names no profile in this
document", which withholds every observation (`test_hdf.py:2467`), and a cycle is the same ERROR
with "parent_profile links form a cycle" at the profile that closes it (`test_hdf.py:2444`).
`depends` is never read, because its entries name a dependency by a local alias that need not
equal its `name`.

Each control entry becomes one candidate keyed by `(context_key, control id, resource_type,
resource_id)`; `source_tool` is constant per artifact. The shadow rule (`hdf.py:787-805`): within
a key, if any candidate has one or more results, every candidate with empty results is dropped
with INFO `profile_control_shadowed` at its own path. That is the overlay case, with no tree
depth logic. A wrapper's own control that carries results is an ordinary leaf. If every
candidate under a key is empty, one ERROR observation results, which is Heimdall's Profile
Error and never silence.

Remaining duplicates, the same id twice with results or two leaves under one root carrying the
same id, fold as SARIF folds (`hdf.py:807-884`). The primary candidate is the first by content,
`(title, description, sorted scalars, sorted lists)`, so document order never reaches the
observation. The disposition is the highest by `HDF_DISPOSITION_RANK` and carries that
candidate's `disposition_source`; the severity is the highest by the shared `SEVERITY_RANK` and
carries that candidate's severity metadata; the clock is the shared `earliest`; counts are
summed; lists are merged sorted and unique and cut at 64; `occurrence_count` counts the
candidates; and INFO `results_collapsed` names each extra candidate. Every other scalar value
comes from the primary candidate. Each fold key yields one observation, and they are emitted in
fold-key order, so output order is a function of content and `duplicate_observation_identity`
cannot fire.

A profile whose `status` is present and not `loaded` draws WARNING `profile_not_loaded`
("profile status is not loaded; its controls carry no results and yield error observations"),
with the status and `status_message` as detail (`hdf.py:481-491`). Its empty controls become
ERROR observations unless shadowed.

Worked against the real three-layer shape: wrapper W (`depends` on B, five controls, all empty),
middle B (`parent_profile` W, a `depends` entry naming L by an alias that is not L's `name`,
five controls, all empty), and leaf L (`parent_profile` B, the same five ids with results).
Every control's root is W, so every id has three candidates under one key; the two empty ones
are shadowed; five observations result, with `context_key` W, `profile_name` L, and
`profile_parent` B. The control with a `passed` and a `failed` result is OPEN, and the impact-0
control is NOT_APPLICABLE with its INFO trail.

## Decision 10: refuse identity, degrade evidence, and bound through the existing limits

Every control `id`, every profile `name`, and `platform.target_id` is an identity input. Over
`MAX_IDENTITY_CHARS` (512, `common.py:30`) or carrying a code point in categories Cc, Cf, Cs,
Zl, or Zp, it is refused whole with ERROR `identity_input_invalid`, and the artifact fails
closed (`common.py:209`, 485). Titles, descriptions, tag values, result texts, platform strings,
and waiver and attestation texts are evidence: sanitized, cut at the shared caps, and named in
`truncated` when cut, exactly as ADR 0011 Decision 10 describes.

The adapter refuses a document whose root does not have the exec-json shape before it reads a
control, and names the shape it found where it can (`hdf.py:912-933`). Each refusal is an
`AdapterParseError` or `InputLimitError` that the dispatcher reports as `artifact_parse_failed`:

| Condition | Message |
|---|---|
| the root is not an object | `HDF root must be a JSON object` |
| `baselines` and no `profiles` | `hdf-libs v3 'baselines' root is not supported` |
| `controls` and no `profiles` | `'controls' root (json-min or profile export) is not supported` |
| `profiles` missing, not an array, or empty | `HDF profiles must be a non-empty array` |
| more than 64 profiles | `HDF document lists N profiles; maximum is 64` |
| `platform` not an object | `HDF platform must be an object` |
| `version` not a non-empty string | `HDF version must be a non-empty string` |

A `controls` root is both InSpec's `json-min` reporter and the `inspec json` profile export, so
one message names both. A checklist renamed `.hdf.json` fails on the `profiles` line.

Structural faults are ERROR and withhold every observation (`hdf.py:371-373`): `invalid_profile`
("profile must be an object", "profile name is missing, not a string, or empty", "profile name
is carried by two profiles", "parent_profile names no profile in this document",
"parent_profile links form a cycle", "profile controls must be an array"), `invalid_control`
("control must be an object", "control id is missing, not a string, or empty", "control results
must be an array", "result must be an object"), and `no_observations` ("HDF document contains
no usable controls").

No `IngestLimits` field is added. The bounds fall in three attributions:

- `max_artifact_bytes` is a read failure: `read_bounded` refuses the file before any suffix
  test, so every format fails alike with `artifact_read_failed` and no artifact.
- `max_json_depth` and `max_json_nodes` are enforced inside the parse, so the failure ladder
  attributes them by suffix: to HDF for a `.hdf.json` name, and to CKLB for a bare `.json` HDF
  document, because nothing that failed to parse is ever sniffed (`test_adapters.py:694`).
- The bounds the adapter raises are attributed to HDF on both names, since the adapter was
  already chosen: `max_results_per_run` on one profile's controls and on one control's results
  (`hdf.py:505-509`, 539-543), `max_observations_per_artifact` on distinct fold keys
  (`hdf.py:667-671`), and the per-observation `MAX_OBSERVATION_JSON_BYTES` ceiling (512 KiB)
  and per-artifact `max_observation_bytes_per_artifact` budget, both checked by the shared
  `observation_bytes` (`common.py:449`, called at `hdf.py:877-883`), exactly as for SARIF.

One module constant is new: `MAX_PROFILES_PER_DOCUMENT` (64, `hdf.py:67`). A `parent_profile`
chain cannot outgrow the profile count without a cycle, and the walk keeps a visited set, so it
also bounds every chain. Tag lists go through the shared 64-item cut, so no tag-count constant
is needed.

Exactly nine tags are read: `severity`, `severityoverride`, `cci`, `nist`, `gid`, `rid`, `stig_id`,
`cve`, and `cwe`. Each value is a string (one item) or an array of items, and anything else is
ignored (`hdf.py:229-235`). Every other tag, `check` and `fix` prose included, and `code`, `refs`,
`source_location`, `attributes`, `groups`, `supports`, `passthrough`, `depends`, and `statistics`
are never read, so their size costs nothing beyond the node bound. A result's `backtrace` is tested
for presence only (Decision 4); its `exception` is read as text for the failure message of a result
whose `message` is empty.

The metadata vocabulary is `HDF_METADATA_KEYS`, 38 fixed keys (`hdf.py:73-114`), and a key
outside it raises `RuntimeError` (`hdf.py:854-856`), which is an adapter bug and never an input
condition.

- Document and profile: `platform_name`, `platform_release`, `producer_version` (the root
  `version`), and `profile_name`, `profile_title`, `profile_version`, `profile_sha256`,
  `profile_parent`, and `profile_status` of the profile that carried the control.
- Control: `impact`, `severity_tag`, `severity_override`, `severity_source`,
  `disposition_source`, `group_id`, `rule_id`, `stig_id`, `nist_tags`, `waived`,
  `waiver_justification`, `waiver_expiration`, `waiver_run`, `waiver_skipped`, `attested`,
  `attestation_status`, `attestation_explanation`, `attestation_frequency`, and
  `attestation_updated`.
- Results, summed over a fold: `result_count`, `passed_count`, `failed_count`, `skipped_count`,
  `error_count`, and `unknown_count`, each result counted once under the disposition it read;
  `failed_results` and `failure_messages`, the `code_desc` and the `message` (else the
  `exception`) of every OPEN and ERROR result that is not an attestation result;
  `occurrence_count`; and `truncated`.

The title is the control `title`. The description is `desc` when it is non-empty text, else the
`descriptions` entry labelled `default`, else empty (`hdf.py:311-321`).

Identifiers (`source_identifiers`) are unique, sorted, and cut to 64 by the shared
`first_identifiers` (`common.py:386`), with `truncated` naming `source_identifiers` and WARNING
`evidence_truncated` on a cut:

| Input | Rule |
|---|---|
| `tags.cci` items | matched whole against `CCI-[0-9]{6}`, ASCII only (`hdf.py:166`); any other item is WARNING `invalid_cci_list` |
| the control `id` and `title`, `tags.cve`, `tags.cwe` | the shared `extract_identifiers` (`common.py:368`): CVE, GHSA, and CWE ids |
| `tags.nist` | metadata `nist_tags` only |
| `tags.gid`, `tags.rid`, `tags.stig_id` | metadata only |

NIST tags are metadata, never identifiers. A NIST SP 800-53 control id names a member of a
control family, not a weakness or a finding, so it is not a namespace a case can correlate on.
CCIs stay identifiers, as the STIG adapters keep them. CCIs sort before `CVE-`, though, so a
control carrying 64 or more CCIs and a CVE loses the CVE to the 64-smallest cut
(`test_hdf.py:2290`). That is reported, not missed: `cve_may_be_missing` (`kev.py:232-238`)
reads the cut, and a KEV run names the record with INFO `kev_no_cve_identifiers` and WARNING
`kev_match_incomplete` (`vdt.py:1196`, 1221) instead of a match (`test_kev.py:1639`). No
converter produces that shape: the NIST-to-CCI table maps each NIST id to one to three CCIs,
Trivy writes none, and Nessus writes CCIs only on compliance items, which carry no CVE.

Diagnostics are coalesced by the shared `Diagnostics` (`common.py:122`): one line per code with
a count, up to five paths, and the first detail, all located at the artifact name. A document
with a thousand waived controls produces one `control_waived` line.

## Decision 11: the evidence hygiene helpers move to `common.py` behind public names

The pure functions, the constants, and the `Diagnostics` coalescer that SARIF's parser used left
`sarif.py` for `common.py` under public names, beside the helpers ADR 0011 Decision 12 moved
there: the caps (`common.py:30-36`), `TRUNCATION_MARKER`, `MAX_DIAGNOSTIC_PATHS`,
`MIN_CLOCK_YEAR` and `MAX_CLOCK_YEAR`, `SEVERITY_RANK`, the two evidence summaries, the `CVE`,
`GHSA`, and `CWE` patterns (`common.py:69-73`) with `END_OF_DAY` and `HOUR_24`,
`IdentityRefused`, `Cleaned`, `DiagnosticEntry`, `Diagnostics`, `identity_problem`, `sanitize`,
`truncate`, `clean`, `encode_list`, `diagnostic_text`, `DetailRepr`, `quoted`, `parse_clock`
(formerly `_sarif_timestamp`), `earliest`, `extract_identifiers`, and `first_identifiers`. Four
module-level names the moved code reads stay private in `common.py`, since only `common.py`
reads them after the move.

Two things are new. `observation_bytes` (`common.py:449`) holds the two checks from the tail of
SARIF's `_assemble`, the per-observation ceiling and the per-artifact budget, with the same
messages; it compares the running sum plus the new size with the budget before the caller adds
the size, where `_assemble` used to add first, and only the counter's value after a raise
differs, which nothing reads. `EvidenceParse` (`common.py:471`) is a base class carrying the
eight evidence methods both parsers need: `_require_identity`, `_evidence`, `_evidence_list`,
`_scalar`, `_keep_scalar`, `_replay`, `_cut`, and `_clock`. SARIF's `_ArtifactParse` and HDF's
`_HdfParse` both subclass it, and the methods stay instance methods, so the class-level patch
of `_ArtifactParse._cut` at `test_sarif.py:5680` still intercepts the inherited method.

`sarif.py` keeps every name its own code and its tests read, with no `noqa`. It imports the
moved names its surviving code calls under their old private spelling as used aliases
(`clean as _clean`), binds by plain assignment the three private names only tests read
(`_sanitize`, `_sarif_timestamp`, and `_identity_problem`, `sarif.py:66-68`), and re-exports as
`X as X` the four public constants other modules import from it (`kev.py:29` reads two).
`test_adapters.py:877` asserts every one of those bindings with 27 `assertIs` checks. A module
patch intercepts only calls made from that module, so the five spies whose callers moved were
re-pointed at `common`: `test_sarif.py:5504` for `sanitize`, whose caller `clean` moved, and
5704, 5726, 5756, and 5812 for `identity_problem`, whose caller `_require_identity` moved into
the base class. Apart from the `common_module` import those five sites need, nothing in
`tests/test_sarif.py` changed.

As with ADR 0011 Decision 12, every golden stayed byte-identical through the move. The AST dumps of
the 48 moved definitions and the 8 moved methods also equal the originals under the renames, and
the suite ran 1,333 tests green on Python 3.11, 3.13, and 3.14 with the move alone. The docstrings
that said "SARIF" where HDF now shares the code were generalized, such as "Parse one source clock".

## Decision 12: a clean HDF run is evidence

Every control that survives shadowing yields exactly one observation, PASS included, so a
document whose every control passed ingests successfully and its observations carry the pass
claims. This differs from an empty SARIF log (ADR 0011 Decision 13) because an HDF control with
results is a check that ran, and a control with no results is an ERROR observation rather than
nothing. A document with no usable control at all is ERROR `no_observations`
(`hdf.py:361-369`). Backlog item 9, the coverage observation, is unchanged for SARIF and not
needed for HDF.

## Worked examples

The tracking ids below are the ones `tests/golden/vdt-hdf.md` carries, compiled from
`inspec-linux-host.hdf.json`, `saf-trivy-image.hdf.json`, and `inspec-overlay.json` with
`--as-of 2026-09-15T12:00:00Z` and `--detected-at 2026-09-01T00:00:00Z`.

- `case-181b4b18c88fe895` is `tracking_id_for("hdf", "SYN-LNX-0001", "synthetic-linux-baseline")`.
  The native run (InSpec 5.22.3 on ubuntu 22.04) declares a `target_id`, so the resource is
  `target 3f0c9a2e-6d4b-4c1e-9a7b-2f1e8d5c4b3a`. The control's one result failed, so it is
  OPEN, MEDIUM from its `severity` tag over an impact of 0.5, with the identifier `CCI-000366`.
  Its `start_time` of 2026-09-10T14:02:11-07:00 is the detection time, so the case needs no
  attestation, and its `VER-TFR-EVU` window closes at 2026-09-15T21:02:11Z, after the as-of.
  The same document shows the other rules. `SYN-LNX-0002` passed and reads PASS, HIGH from
  impact 0.7. `SYN-LNX-0003` was skipped and reads NOT_REVIEWED. `SYN-LNX-0004` has impact 0
  and a failed result, so it reads NOT_APPLICABLE, INFORMATIONAL from the impact band, with the
  INFO detail `results would read OPEN`. `SYN-LNX-0005` has a `passed` result carrying an
  `exception` and a `backtrace`, so it reads ERROR, and the report names it in an
  `unresolved_observation` warning rather than as a vulnerability. `SYN-LNX-0006` carries a
  waiver with `run: false`, so InSpec wrote one skipped result: it reads NOT_REVIEWED with
  `waived`, `waiver_run "false"`, and `waiver_skipped "true"`, and WARNING `control_waived`.
- `case-1706b7990cce1346` is
  `tracking_id_for("hdf", "CVE-2099-0001", "Trivy Vulnerability Scan")`. The converted document's
  `platform.name` is `Heimdall Tools`, so the source tool is `heimdall-tools` and INFO
  `converted_document` fires once; the resource is `target registry.example.test/web:1.4.2`.
  The identifiers are `CVE-2099-0001` from the id and `CWE-79` from `tags.cwe`, and the
  severity is HIGH from the tag. Every `start_time` is `""`, so none of the three controls has
  an `observed_at`, `source_timestamp_missing` fires once, and the detection time comes from the
  attestation. `case-057bbe4ee9dde990` (`CVE-2099-0102`) is CRITICAL from its tag and
  `case-71446ac59461edb8` (`CVE-2099-0103`) is CRITICAL from its tag over an impact of 0.5, which
  alone would read MEDIUM. All three `VER-TFR-EVU` windows closed at 2026-09-06T00:00:00Z, so all
  three are overdue.
- `case-db1a983f4e0a849a` is `tracking_id_for("hdf", "SYN-RHL-0001", "synthetic-rhel-overlay")`.
  `inspec-overlay.json` is a bare `.json` name, so it reaches the adapter through the key check.
  Its wrapper profile `synthetic-rhel-overlay` lists `SYN-RHL-0001` and `SYN-RHL-0002` with
  empty results plus its own `SYN-RHL-0100`, which passed; the child `synthetic-rhel-baseline`
  names the wrapper in `parent_profile` and carries the two ids with results. Both copies of each
  id share one key under the root, so the wrapper's empty copies are shadowed (two INFO
  `profile_control_shadowed`). `SYN-RHL-0001` failed and reads OPEN HIGH with `CCI-000048`,
  `profile_name` `synthetic-rhel-baseline`, and `profile_parent` `synthetic-rhel-overlay`,
  detected at 2026-09-08T16:01:30Z and overdue since 2026-09-13T16:01:30Z. `SYN-RHL-0002` was
  skipped and then attested as passed: it reads PASS with `attested "true"` and
  `attestation_status "passed"`, its clock comes from the skipped result, and the attester's
  name and the apply instant appear nowhere. WARNING `control_attested` fires on it, and as a
  PASS it is not a vulnerability. `SYN-RHL-0100` reads PASS, LOW from impact 0.3.

The report lists five vulnerabilities, four of them overdue.

## Consequences

- `target` is a permanent identity input beside `host`, `image`, `file`, `logical`, and `scan`
  from the first release that carries it.
- An HDF-shaped bare `.json` that used to fail as CKLB now ingests, and `stigroll` names it with
  the HDF skip line instead of the "no 'stigs' key" warning. A depth or node refusal of such a
  document stays attributed to CKLB, the documented cost of never sniffing what failed to parse.
- The converter conventions are observed, not specified. A converter that writes its own
  platform name reads as native (`inspec` and `target`): a stable identity with an imprecise
  tool name.
- An assessor comparing Heimdall with ComplyRoll sees the three deviations of Decision 4. Under
  (a) a control Heimdall shows as Profile Error reads OPEN here, so more open items. Under (b) a
  control skipped under a waiver reads NOT_REVIEWED here where Heimdall shows Not Applicable, and
  a waived control whose results include a failure reads OPEN here. Under (c) a control Heimdall
  shows as Profile Error reads NOT_APPLICABLE here, so one fewer unresolved item.
- Impact 0 sets a failure aside on the profile author's word. The INFO trail with its detail is
  the visibility.
- A converted document carries no clock. The stateless path needs `--detected-at`, and the
  persisted path needs `cases attest-detection`, because `report vdt --db` refuses
  `--detected-at` beside `--db` (`cli.py:869`); without the attestation it stops with
  `detection_time_missing` (`vdt.py:689`) naming the clockless cases and writes nothing.
- The attestation markers are `saf attest apply` behavior, not a specification. A future
  wording change would read the appended result as an ordinary one, so its apply instant would
  become a clock. The fixture pins today's literals, and WARNING `control_attested` still fires
  on the member, so the attestation is never silent.
- Backtrace presence decides ERROR. A producer that writes a `backtrace` on a genuine pass reads
  ERROR, which is the visible side of the mistake.
- A `waiver_data` or `attestation_data` that is not an object is read as absent, with no
  warning. When a fold has more than one candidate, the waiver and attestation metadata come
  from the primary candidate only, so another candidate's are not recorded, while its WARNING
  still fires.
- A converted title that already leads with its id repeats it in the report's description
  (`CVE-2099-0001: CVE-2099-0001: synthlib: ...`), because the report writes the source record
  id before the title and the adapter keeps the source's title as written.
- A large Nessus or Burp conversion can exceed the 500,000-value node bound. It is refused with
  the bounded-parse message, and raising the bound is the caller's decision.
- Free-text severity tags beyond the five names fall through to the impact band, with one
  coalesced warning line per artifact.
- An HDF observation with every cap saturated measures 259,017 bytes of canonical JSON in
  four-byte text and 225,825 in quotes and backslashes, about half the 512 KiB ceiling, and
  `test_hdf.py:3153` pins that it fits under both ceilings. The ceiling and the per-artifact
  budget still apply to every HDF observation.
- Cross-source correlation stays out of scope: a CKLB and an HDF document of the same rule are
  two cases until it lands.
- Two items join the Phase 2 cleanup list: `OverflowError` in the dispatcher's catch, which the
  adapter makes unreachable for HDF, and the missing clock guards in `common.parse_timestamp`
  for CKLB and XCCDF, which HDF does not widen because it uses the shared guard.
- Four fixtures (`inspec-linux-host.hdf.json`, `saf-trivy-image.hdf.json`,
  `inspec-overlay.json`, and `hdf-spec-corners.hdf.json`), the two goldens
  `tests/golden/vdt-hdf.json` and `tests/golden/vdt-hdf.md`, and the 173 tests in
  `tests/test_hdf.py` hold the behavior above; the twenty existing goldens are byte-identical.

## Rejected alternatives

- Sniffing SARIF too: every SARIF producer can write `.sarif`, and HDF is the format that has no
  suffix of its own.
- A `.hdf` suffix: it means HDF5 to everyone outside MITRE.
- The filename stem as the fallback resource: a renamed document would re-mint its
  observations.
- `host` for native output: a native `target_id` is a node uuid, a container id, or a cloud
  account.
- A `root|leaf` context key: a leaf rename or a re-layered overlay would re-mint every tracking
  id, and it gains nothing, since a direct run of the dependency is a different context under
  either key.
- The profile version or `sha256` in the context key: a profile patch would re-mint the tracking
  id of an unchanged weakness.
- Heimdall's status order verbatim: an error sibling would hide an observed failure, and a
  waiver would read Not Applicable.
- ADR 0011 Decision 9's worst-wins order: it ranks PASS below NOT_REVIEWED, so an attested pass
  could not beat the skipped result it answers.
- InSpec's not reviewed for a control with no results: NOT_REVIEWED vanishes from every report.
- A waived control as NOT_APPLICABLE: the adapter would be accepting risk that belongs in the
  evaluations file.
- Impact 0 as OPEN INFORMATIONAL: a profile author's declaration that a control does not apply
  would open a case.
- NIST tags as identifiers: no case can correlate on a control family member, and they would
  crowd CVEs out of the 64-smallest cut.
- A vendor media type such as `application/vnd.inspec.exec+json`: no registration exists to
  cite, and CKLB already uses `application/json`.
- A document-clock fallback: another control's clock is not this control's detection time.
- Reading `code`, `refs`, or `passthrough`, or the content of `backtrace`: none of them decides
  identity or disposition, and their size would reach the store.
- Reading `depends`: its entries name a dependency by an alias that need not match any profile.
- WARNING `profile_dependency_missing`: the middle layer of a well-formed overlay would raise
  it, because `depends` names by alias.
- Recording the attestation's `updated_by` or the apply instant: the first names a person, and
  the second is when a tool ran, not when anything was observed.
- `Heimdall Tools` verbatim as the `source_tool`: a display string with a space in it would
  become an identity literal.
- A new `IngestLimits` field: the existing fields already bound every count the format has.
- A `MAX_PARENT_CHAIN` constant: the profile cap and the visited set already bound every chain.
- Importing `sarif.py`'s private helpers from `hdf.py`: one adapter would depend on another's
  internals.
- Duplicating the eight evidence methods in `hdf.py`: duplicated hygiene code drifts, and
  `test_sarif.py:5504` changes anyway, because `clean` moves.
- `OverflowError` in the dispatcher's catch now: a broad catch would also report adapter bugs
  as parse failures, and the impact guard already runs before any arithmetic.
- Rolling HDF into `stigroll`: the roll-up is locked to its original bytes and reads checklist
  rows.
