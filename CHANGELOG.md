# Changelog

All notable project changes will be documented here.

## Unreleased

### Fixed

- A compiled Vulnerability Detail Report is now byte-identical across any argument order, on the
  stateless path and the persisted path alike. Four things echoed the order the operator named
  files in: the artifact manifest, the ingest diagnostics and the unresolved-observation
  diagnostics, the members of a vulnerability that spans several files, and the election of the
  surviving reading when two files carry identical bytes under different names. The last two
  reached the report's content rather than only the order of a list, since a group's `title` and
  `description` take the first non-empty value found while walking its members. Each list is now
  ordered by its own content: artifacts by `(name, sha256)`, diagnostics by
  `(code, location, message, level)`, and group members by
  `(resource_type, resource_id, source_artifact_name, observation_id)`. Verified by a randomized
  permutation audit over a deliberately hostile artifact set, across the stateless path, the
  persisted path, and the two compared against each other. The goldens moved by permutation only.
  The event log is deliberately not order-independent: two stores built by ingesting the same
  files in opposite orders differ in bytes and in sequence, both verify clean, and both rebuild
  the identical report.
- A store edited in place so a name, a version, or the sequence counter holds something `append`
  never writes, or so a JSON column breaks a rule `append` applies to JSON, is now refused with a
  coded error (`store_integrity` for those columns) instead of crashing or reading as valid. Every
  command but `store verify` checks `stream_version` and the sequence counter when it opens the
  store. `ingest` without `--record-failed-imports` and
  `cases history` read only the streams they append to or show, so that `ingest` can still
  append, and `cases history` can still show a case, while a name, `event_version`, or JSON value
  of this kind sits on another stream; `store verify` checks every row. A stream id carrying a
  parser version of 4301 digits or more, an integer in stored JSON past the
  interpreter's 4300-digit limit, JSON nested past the recursion limit, text in `stream_version`
  or `event_version` or a number there past the range of a double, and text in the sequence
  counter each ended `report --db`, `cases correlate`, and `ingest` whenever it read the row
  (every run for the counter and `stream_version`) in a Python traceback, and all but the parser
  version crashed `store verify` too. A lone surrogate escape in a stored payload ended
  `report --db` in a traceback while `store verify` reported nothing wrong. A stored name over 500
  characters that broke nothing else used to read as valid. So did an `event_version` below 1 in
  `cases list`, which decodes only case streams, on any other stream. On a case stream, and in
  `report --db` and `store verify` on any stream, such a version was caught only as an
  unpublished contract version; the table's `CHECK` refuses such a version unless the writer
  turned on `PRAGMA ignore_check_constraints`. A second `sqlite_sequence` row for `events`, added
  after SQLite's own, read as valid in every command and in `store verify` whatever it held,
  because each check read only the first row. `store verify` now reports
  `event_name_invalid` and `event_version_invalid`, and reports the JSON and counter cases as
  `payload_not_json` and `sequence_counter_mismatch`. A text column that is not valid UTF-8 is
  refused as `store_unavailable`, and that message can quote the stored text. Store integrity
  errors never repeat a name outside the append grammar: the refusal of the name gives the rule
  it breaks, and a message that identifies its event or stream for another fault, such as a
  version gap or a digest mismatch, gives its length or storage class. The artifact and failure
  identity checks cut a quoted payload value at 200 characters. Stored timestamps are still
  parsed rather than checked against the format `append` writes. A schema marker rewritten to a
  negative number ended `ingest`, `cases correlate`, `cases attest-detection`, and
  `cases evaluate` in a Python traceback (`KeyError`) when they had work to append, and read as
  valid in `report --db`, `cases list`, and `cases history`; each now refuses it with
  `store_unavailable`. `store verify` passed a store with a foreign application id. It passed a
  negative marker or a marker of 0 unless the store held a failure stream, which failed only as
  `failure_schema_unmarked`. It passed a marker above the supported range unless the store was
  still at schema 1, which failed only as `migration_missing`. It now reports a marker outside
  the schemas this build opens as `schema_version_unsupported` and a foreign application id as
  `application_id_mismatch`. It also passed a store holding a row numbered below 1, which every
  other command refused at open. It ended in a traceback on an `events` table rebuilt so
  `sequence` held text (`ValueError`) or without a column the walk reads (`IndexError`), and on a
  migration table rebuilt to hold a version such as `'1x'` at schema 2 (`ValueError`). Without its
  `version` column, the migration table ended it in a store error that dropped the schema faults
  already found. It now reports the row as `sequence_gap`, and reports a table rebuilt without a
  column `append` writes or with text in `sequence` as `schema_object_altered` without walking
  it. It reads the migration table only when it has its `version` column, and counts a record
  only when that version is an integer. Stored JSON is checked against the 1 MiB cap `append`
  applies as the text it stores, and against the other rules as the value it decodes to rather
  than as the text `append` writes, so whitespace under the cap and duplicate object members
  still read, the decoder keeping the last one.
- `.arf`, the suffix OpenSCAP gives its ARF output, was refused unread while the CLI help text on
  the same argument promised ARF support. It now dispatches by root element exactly as `.xml`
  does, so a valid ARF is accepted under either suffix and a misnamed CKL still reaches the CKL
  adapter. Observation identity hashes the artifact digest and not its name, so anyone who worked
  around this by renaming a file will not get duplicate cases when they stop.
- A lone surrogate code point in a JSON string or object key (`"\ud800"`) passed the bounded JSON
  parser and then crashed the report writer and the event store on `.encode("utf-8")`, for any
  JSON artifact. `parse_json_bounded` now refuses it during the walk it already does, and the
  dispatcher reports `artifact_parse_failed` with the code point named. Verified by parser tests
  in `tests/test_safeio.py`.
- A CVE or CWE id run straight into an ASCII letter or digit was cut out of its token rather than
  refused: `CVE-2024-1234evil` named `CVE-2024-1234`, and `CWE-79suffix` named `CWE-79`. The two
  patterns in `adapters/common.py` ended on a digit boundary while the comment above them promised
  a token boundary, which the GHSA pattern beside them already kept. Both now end as GHSA does, so
  a letter or digit after the number names no identifier, and punctuation, an underscore, or a
  character outside ASCII still ends the token. This changes the `source_identifiers` the SARIF
  adapter reads (ADR 0011 Decision 5, recorded in its 2026-09-29 amendment), and the HDF adapter
  shares the patterns. The KEV clock reads the same identifiers, so such a token no longer matches
  a catalog entry either. Verified by `tests/test_sarif.py`; no fixture carries such a token, and
  every golden is byte-identical.
- The `duplicate_artifact` WARNING embedded both file names exactly as supplied, so a control or
  format character in a name reached the report's diagnostics and its Markdown twin, and neither
  name was capped. Both names now pass through `diagnostic_text`, which the adapters' diagnostic
  paths and the failure diagnostics already use. A plain file name comes back unchanged, so every
  golden is byte-identical. Verified by `tests/test_reports.py` with a name holding a control
  character and a name past the 512-character cap.
- An `evaluation_ambiguous` refusal always ended "add contextKey or sourceType", even for an entry
  that already gave one of them. It now names only the keys the entry leaves out: "add
  contextKey" when it gives `sourceType`, "add sourceType" when it gives `contextKey`, and both
  when it gives neither. The stateless report and `cases evaluate` share the text
  (`EvaluationMatch.ambiguity_remedy`). Every golden is byte-identical. Verified by
  `tests/test_reports.py` and `tests/test_history.py`, each with all three shapes.
- A SARIF run with no usable driver, or with a driver name the identity rules refuse, returned
  before its invocations were read, so its failed invocation was never seen. Under
  `--record-failed-imports` a log whose only failed invocation sat in such a run was recorded as
  a `content` failure at the as-of instead of an `execution` failure at the invocation's own
  clock, and a log with a failed invocation in another run took that run's clock even when this
  one was earlier. The `external_properties_ignored` warning, the invocations and the failed
  invocation's clock are now read before the driver check (ADR 0014 amendment 2026-10-14,
  second), so a run refused at its driver also reports `execution_unsuccessful` when an
  invocation failed, any `source_timestamp_invalid` for its invocations, and
  `external_properties_ignored` when it carries external references. When no failed invocation
  declares a usable clock, the `execution` failure is at the as-of. A run with a usable driver
  reports the same diagnostics in the same order as before, and every golden is byte-identical.
  Verified by `tests/test_failures.py`, with eight driver shapes and a two-run log, and by
  `tests/test_cli.py` on the stateless and persisted paths.

### Added

- Coverage and freshness evidence against an information resource inventory (ADR 0015, PR 2).
  `complyroll report vdt`, `report avi`, and `report historical` take `--inventory FILE`, a
  `complyroll.inventory` JSON document listing the resources the provider expects its detection
  processes to reach. It is read locally through a bounded reader (8 MiB, 20,000 resources, JSON
  depth 16, every field checked, a JSON null read as absent), never stored, allowed beside
  `--db`, and named in the report by its raw-byte SHA-256, size, and entry count. Each entry's
  attributes select its clocks from the pinned dataset: `VDR-TFR-MVX` for a machine entry,
  `VDR-TFR-NMV` for a non-machine entry, which only operator attestations verify, `VDR-TFR-PDD`
  or `VDR-TFR-PCD` by `driftLikely`, and `VDR-TFR-PSD` per sample group. A clock anchors on the
  latest verification at or before `--as-of`, else on the entry's `expectedSince`, and a lapse
  is one window. Examined is not verified: NOT_REVIEWED, ERROR, and UNKNOWN never verify, and
  untimed evidence, which includes every CKL and STIG Viewer CKLB observation, never anchors a
  clock. Each clock reads `unanchored`, `missing`, `undetermined`, `stale`, or `current`, the
  first that applies, and observed resources the inventory omits are listed as unregistered.
  Every report gains the `x-complyroll.coverage` block and a Markdown `## Coverage` section after
  Inputs, with fixed text saying a current status is not a compliance finding, and the persisted
  report is byte-identical to the stateless one. An unknown drift likelihood takes
  `VDR-TFR-PDD` with WARNING `drift_likelihood_unknown`, once per entry. A second `--inventory`
  (`invalid_option`), a refused file (`invalid_input`), and a pinned dataset that lacks a
  coverage rule (`coverage_rule_unavailable`) each exit 1 and write nothing. A lapsed window
  opens no case and changes no exit code yet; that is ADR 0015's next pull request. New
  `examples/inventory.json` and four goldens: `tests/golden/vdt-coverage.{json,md}` on the
  official fixture set, and `tests/golden/vdt-coverage-timed.{json,md}` on two clocked SARIF
  logs and `tests/fixtures/inventory-timed.json`. Every existing golden is byte-identical.
- A SARIF run that reports no results is now evidence instead of an error (ADR 0015 decision 1,
  backlog item 9). A run with `results: []` whose every invocation declares
  `executionSuccessful: true` yields one artifact-origin PASS observation of the scope it names
  (`image:<name>` when the run declares an image, `scan:<repository uri>` when it names a
  repository and no image, else `scan:<driver>`), with record id
  `sarif.run`, the driver's automation key as its context, the run clock as `observed_at` or the
  usual missing-timestamp warning, and a fixed description saying the tool ran and found nothing
  it was configured to report, which is not evidence that the scope is clean. The observation's
  identity is the ordinary artifact fingerprint, so the same bytes re-ingest as
  `already_recorded`, it rides the artifact stream with no contract or schema change, and
  correlation never turns it into a case. A clean log therefore ingests on both paths and exits
  0, with or without `--record-failed-imports`, instead of failing the whole run with
  `no_observations`; the `clean_scan` refusal of ADR 0014 Decision 2 is unreachable and retired.
  A run with no results whose invocation failed still mints nothing and stays the execution
  failure ADR 0014 records; one whose invocation never declares `executionSuccessful: true` is
  WARNING `execution_unverified`, mints nothing, and stays `no_observations`. A result whose rule
  id spells `sarif.run` takes its observation over the clean candidate (INFO
  `clean_run_superseded`). Every existing golden is byte-identical. New fixture
  `tests/fixtures/clean-run.sarif`; ADR 0011 Decision 13 and ADR 0014 Decision 2 carry dated
  amendments.
- An ARF fixture and adapter tests. ARF was advertised in the README, the help text, and the
  adapter docstring with no fixture and no parse-level test behind it. The fixture nests its
  `TestResult` five levels down behind a sibling OVAL report, splits the asset identity between
  the ARF assets block and the XCCDF target, and carries an unevaluated rule in an embedded
  benchmark, so a document-scoped identity or identifier sweep fails the tests rather than
  passing them quietly.
- The Accepted Vulnerability Information report and the Historical VER Activity report
  (ADR 0010). The record compiler now builds one period-agnostic `CompiledRecordSet` from
  either path, and three projections read it: `project_vdt`, `project_avi`, and
  `project_historical`. `complyroll report avi` and `complyroll report historical` compile
  each report from scanner artifacts and an evaluations file or, with `--db`, from a store;
  the historical command takes no `--from` or `--to`, and each writes the JSON document and an
  optional Markdown twin. The accepted-vulnerability report selects accepted records by their
  activity instants in the period, counts the rest in `excludedByPeriod` and the active
  records in `activeNotReported`, and takes the acceptance instant from the evaluation's
  `completedAt`. The historical report is a periodless snapshot of every record as of
  `--as-of`, split on acceptance, with `finalDisposition` distinguishing a disposed record from
  an open one. `examples/evaluations-accepted.json` adds one accepted entry to the shipped
  evaluations file, and four goldens, `tests/golden/avi-fixtures.{json,md}` and
  `tests/golden/historical-fixtures.{json,md}`, pin the bytes. Verified by schema validation
  against the bundled `0.1.1` documents, by the goldens on both the stateless and the rebuilt
  path, by agreement between the two paths across reversed ingest order and every ingest
  permutation of a shared fleet case, and by a test that records the same evaluations in two
  stores eleven days apart and proves the report bytes are identical, so the store's
  `recordedAt` never reaches a report.
- A SARIF 2.1.0 adapter (ADR 0011). `report vdt`, `report avi`, `report historical`, and `ingest`
  now accept `.sarif` files, and names ending `.sarif.json`, from Trivy, Grype, Semgrep, CodeQL,
  Checkov, or any conforming producer, beside the STIG checklists. Each result becomes one
  observation per located resource: the driver name is the source tool, the rule identifier
  resolved in the spec's order (an index, then `rule.guid`, then a lone exact id match, never a
  prefix) is the source record id, the located file, image path, or logical name is the
  resource, scoped by the image or repository the run declares, and the driver name plus the
  automation category is the context key, through the unchanged nine-input identity of ADR 0002.
  Results that share an identity inside one artifact fold into one observation with an
  occurrence count and capped region lists. The caps count characters, not bytes, so a log that
  fills them with four-byte text, or with quotes and backslashes that JSON escapes twice inside a
  list, reaches the 512 KiB ceiling on one folded observation's canonical JSON, and that artifact is
  refused on both paths, before the event store's own cap can. A suppressed result stays open with
  its suppression recorded in metadata and a warning on the artifact, `baselineState` never moves a
  disposition, `kind: open` is recorded as unknown so every report flags it, and scanner severity is
  recorded as evidence and never sets PAIN. An integer `security-severity` is range-checked before
  conversion, so an integer too large for a float is invalid rather than an overflow, and a string
  must be an ASCII decimal, so `0_9` or another script's digits never band as CRITICAL. A
  `ruleConfigurationOverrides` level applies from the result's own invocation when the entry's
  descriptor reference resolves, by the same rules as a result's, to the result's own descriptor,
  the first such entry winning; the reference's id counts only when it has no index and no guid that
  names a descriptor, and then only if one descriptor alone has it, so descriptors that share an
  id each keep their own level. Clocks are kept only from 1970 through 9000 UTC, the spec's hour 24
  is read as the next midnight on every interpreter, a leap second or a date alone is refused, and
  of two spellings of the earliest instant under different offsets the one whose text sorts first is
  kept, so no order of results, runs, or invocations changes an observation's `observed_at`. Message
  placeholders, location links, and CVE, GHSA, and CWE identifiers take ASCII letters and digits
  only, and link text reads the spec's escaped brackets and backslashes in one linear pass; a
  message substitutes at most 1,024 placeholders, an observation keeps at most 64 identifiers, and a
  region line or column above 2**31 - 1 is absent. Diagnostics are coalesced per code per artifact
  with occurrence counts and the first JSON paths, each path and detail sanitized and cut at 512
  characters and each detail read from a bounded part of the value without sorting it, so one
  artifact's diagnostics stay within about 56,000 characters whatever the input's size. A run's
  shared rule and component data is resolved once, each shared tags, `deprecatedIds`, or
  `repoDigests` list and each of a result's own lists and fingerprints is cut once to the items a
  fold can keep, each shared uri and each descriptor id a result takes as its rule identifier is
  checked once, and each override entry is resolved to its descriptor once, so a result's cost is
  bounded by the caps rather than by the size of a template, list, or value it shares, or by the
  size of its own lists once for each resource it names. An artifact's observations are capped
  together at 256 MiB of canonical JSON, the same way on both paths. Six synthetic fixtures
  (`trivy-image`, `grype-image`, `semgrep-code`, `codeql-repo`, `checkov-iac`, and
  `sarif-spec-corners`) and two goldens (`tests/golden/vdt-sarif.json` and `vdt-sarif.md`) hold the
  behavior. Verified by the 271 tests in `tests/test_sarif.py`, by the goldens on the stateless
  path, and by the persisted path and the replay reader rebuilding the same report from history byte
  for byte.

- CISA KEV enrichment (ADR 0012). `complyroll report vdt`, `report avi`, and `report
  historical` take `--kev FILE`, a CISA Known Exploited Vulnerabilities catalog JSON feed the
  operator downloads out of band; it is read locally, never fetched, never bundled, and never
  written to the store, so it applies to the stateless path and the `--db` path the same way and
  the two paths stay byte-identical. A record is a KEV when one of its `CVE-` source identifiers
  equals a catalog `cveID` exactly and that entry's `dateAdded` is on or before the UTC date of
  `--as-of`. The clock uses the catalog's `dueDate` literally, ends at the midnight that begins
  the following UTC day, ignores `--calendar-tz`, starts at `dateAdded` under the new `catalog`
  anchor, and stops only on a remediated or false-positive record, so a fully mitigated KEV keeps
  running, which is what `VDR-TFR-KEV` requires. One clock per record binds to the earliest due
  date and, on a tie, the lowest `cveID`, while every matched entry is listed. Each record's
  `x-complyroll` gains a `kev` block, null when nothing matched, with the bound CVE, the due date
  and instant, `satisfied`, `pastDue`, a status of `open`, `pastDue`, `accepted`, `remediated`, or
  `falsePositive`, and the matched entries; the report extension gains `kevSource`, naming the
  catalog's file name, raw-byte SHA-256, size, version, release instant, declared count, and the
  entries this run considered. The Markdown twin gains a Provenance row carrying the digest, the
  Summary rows `Known exploited, CISA KEV` and `Past a CISA KEV due date`, a `Known exploited`
  detail line per record, and the `VDR-TFR-KEV` deadline row. Seven diagnostics report what the
  catalog did: a catalog released after `--as-of` and a policy with no `VDR-TFR-KEV` stop the run,
  a catalog more than three days old and a record whose identifier list may have been truncated
  warn, and entries dated after `--as-of`, a run with no CVE identifiers at all, and a run where
  none matched are reported as information. The catalog is read through the bounded reader at 8
  MiB, 20,000 entries, and JSON depth 16, validated field by field with every date checked against
  an ASCII pattern before it is parsed and every year held between 1970 and 9000, and any failure
  refuses the run as `invalid_input` with a message that starts "KEV catalog". A second `--kev` is
  refused rather than silently applying the last one, and naming the catalog as an output is
  refused as an input overwrite. Six goldens, `tests/golden/vdt-kev.{json,md}`,
  `avi-kev.{json,md}`, and `historical-kev.{json,md}`, and two synthetic SARIF fixtures with a
  synthetic catalog whose every identifier is `CVE-2099-*` hold the behavior; the fourteen
  existing goldens are byte-identical, which is the proof that a run without `--kev` changed
  nothing.

- InSpec HDF adapter (ADR 0013). `complyroll ingest` and every `report` command read the Heimdall
  Data Format that InSpec's `json` reporter writes and that `saf convert` writes from Nessus, Trivy,
  and other scanners. A name ending `.hdf.json`, in any case, goes to the new adapter; a bare
  `.json` file parses as before and goes to it only when the parsed root has no `stigs` member, a
  `profiles` array, and a `platform` object, so every checklist keeps its dispatch and a bare
  `.json` that fails to parse is still attributed to CKLB. A checklist saved under a `.hdf.json`
  name is refused with a message that names its `stigs` member and says to read it under a `.cklb`
  or `.json` name, since the name alone decides the adapter. Each control that survives overlay
  shadowing is one observation of source type `hdf`, keyed by its id under the name of the root
  profile it hangs under, on `target` `platform.target_id`, or on `scan` and the root profile name
  when the document declares no target. A result reads OPEN when it failed, PASS when it passed,
  NOT_REVIEWED when it was skipped, and ERROR when it errored or carries a backtrace whatever its
  status, since InSpec writes a check that raised as its RSpec status plus a backtrace. A control
  takes its highest-ranked result, OPEN first and then ERROR, so an observed failure is never hidden
  by an errored sibling; a control with no results is ERROR, and a control with impact 0 is
  NOT_APPLICABLE with an INFO line naming what its results would have read. That line counts only
  copies that survive shadowing, so an overlay's empty wrapper copies add nothing to it, and each
  copy it names yields an observation unless the artifact fails closed. Impact 0 decides before
  the rule that reads a control under a profile that did not load as ERROR.
  A waiver and a `saf attest apply` attestation are recorded as metadata with a warning and never
  move a disposition by themselves; the attestation's appended result counts, but its clock and its
  author do not. Either member counts when it is present and non-empty, whether or not it is an
  object: a list, a string, `true`, or a number records `waived` or `attested` without the scalars
  only an object can carry, and the warning names the member as not an object rather than reading
  the attestation's marker result as an ordinary one. Severity comes from the `severityoverride`
  tag, the `severity` tag, or InSpec's impact bands, and an impact that is not a number from 0 to 1
  is warned about and ignored before any arithmetic, so a 400-digit integer cannot crash the run.
  `observed_at` is the earliest result `start_time`, and a converted document, which writes `""`,
  needs `--detected-at` or `cases attest-detection` like any clockless artifact. An overlay's empty
  wrapper copies are shadowed by the copy that carries results, found by walking `parent_profile`
  rather than `depends`; a dangling parent or a cycle refuses the artifact. A waiver or an
  attestation on a shadowed wrapper copy passes whole to the copies that carry results when none of
  them carries its own, the outermost wrapper first, so the warning that says it is recorded stays
  true; a leaf result that spells the attestation marker is still read as an ordinary result,
  because the marker rule reads only the leaf's own member. When copies fold into one observation,
  the waiver fields come whole from the first copy in content order that carries a waiver and the
  attestation fields whole from the first expired attestation, else the first attestation, so no
  observation mixes two copies' fields, and `truncated` names only a cut in a value the observation
  keeps. CCIs, CVEs, GHSA ids, and CWEs are identifiers, and NIST tags are metadata. A JSON object
  key that repeats, in this or any other JSON artifact, is now quoted and cut in the refusal
  message, so an untrusted key can no longer write a control character to the terminal. Four
  synthetic fixtures (`inspec-linux-host.hdf.json`, `saf-trivy-image.hdf.json`,
  `inspec-overlay.json`, and `hdf-spec-corners.hdf.json`) and two goldens
  (`tests/golden/vdt-hdf.json` and `vdt-hdf.md`) hold the behavior. Verified by the 215 tests in
  `tests/test_hdf.py`, by the goldens on the stateless path and from the store's history in all six
  ingest orders of the three golden fixtures, and by 1,581 tests on Python 3.11, 3.13, and 3.14; the
  twenty existing goldens are byte-identical.
- System-generated observations for detection process failures (ADR 0014, `VDR-CSO-FAV`).
  `--record-failed-imports` on `report vdt`, `report avi`, `report historical`, and `ingest` turns
  each failed reading into one system observation instead of stopping the run. The system
  observations of one failing digest correlate into one vulnerability case, which a report compiles
  directly and which `cases correlate` opens in a store, as for any other observation. The class is
  decided from a closed vocabulary of diagnostic
  codes and never from message text: `parse` for truncated or corrupt bytes or an input bound
  exceeded, `content` for a well-formed file with no usable content, such as a CKLB STIG with no
  rules array, and `execution` for a SARIF invocation with `executionSuccessful: false`, recorded
  beside the log's own observations when the log still imports. A file that could not be read,
  an unsupported or rejected format, a partial reading, a duplicate observation identity, an
  unclassified error code, and a clean scan stay fatal with the flag. The observation's id comes
  from the ADR 0002 SYSTEM recipe over the digest and the observed instant, which is the failed
  invocation's own clock or else the run's as-of, so a rename, a re-ingest, or another parser
  failing the same bytes at the same instant derives the same id. The record's detection-time
  source is `system`, `cases attest-detection` never attests it, and PAIN comes only from an
  evaluation that names it by source type, record id, and digest; an entry without the digest is
  refused, on the stateless report as `evaluation_ambiguous` when it matches several failures and
  as `evaluation_context_key_required` when it matches one, and by `cases evaluate` under
  `evaluation_unmatched` either way. A report gains
  `x-complyroll.detectionFailures`, a `complyroll.detection-failures` parser version, and a
  Markdown "Detection process failures" table only when its record set holds a failure. A run that
  records a failure writes its report or store and then exits 3 (`EXIT_DETECTION_FAILURES`), and so
  does an `ingest` rerun that finds it already recorded; `report --db` keeps 0 and 1 and refuses
  the flag. On the persisted path each failure is a `failure/<sha256>/<parser>/<version>` stream
  holding a `failure.recorded` v1 head and then its observation. The repository refuses a stream an
  observation opens and an observation whose metadata is not what the writer stores, and the fold
  and `store verify` also refuse a head and an observation that describe two failures. With the
  flag, `ingest` exits 1 with `failure_read_elsewhere` and records nothing when history holds a
  reading of the same bytes that would supersede the failure. A failure whose system observation
  another failure stream of its bytes already holds is recorded as a `failure.held` hold on its own
  stream, and the fold reports one record per observation, the earliest no reading supersedes (R6),
  so a later ingest that supersedes the holder hands the failure to the hold. A failure that a build
  of `main` before this change refused, or a held side record it lost, is recorded by ingesting the
  same file again with the flag at the same instant. A lost pure failure has no recording path once
  a current reading of its bytes is under another parser, or under the same parser at its version or
  later: `failure_read_elsewhere` refuses it before the writes. Rules R1 to R6 decide per digest
  which readings and failures are current, `store verify` gains six audit codes, and reports print
  INFO lines for a superseded reading, a superseded failure, and a stale case. The stored-diagnostic
  contract of `artifact.ingested`, `failure.recorded`, and `failure.held` admits INFO and WARNING
  alone, so `store verify` refuses a head edited to carry an ERROR. The first failure stream marks
  the store schema version 2 in the same transaction, the first hold marks it version 3, and a store
  that never records a failure stays at version 1. A store that recorded a failure cannot be opened
  by an earlier build: its `ingest`, `cases`, and `report --db` exit 1 with
  `store_unavailable: database schema 2 is newer than supported schema 1`, and its `store verify`
  reports each failure stream as faults. A store that recorded a hold is refused the same way by a
  build that knows only version 2, with `database schema 3 is newer than supported schema 2`, and
  its `store verify` reports the marker as `schema_version_unsupported`. Stateless and persisted
  reports stay byte-identical under
  the conditions ADR 0014 Decision 15 names, recorded as an amendment to ADR 0008. Response-process
  failures, missing attestations, stale coverage, missing resources, and the clean scan are not
  built; `docs/BUILD_PLAN.md` records the scope change. Three synthetic fixtures
  (`failed-truncated.sarif`, `failed-invalid-rules.cklb`, and `failed-invocation.sarif`),
  `examples/evaluations-failed.json`, and four goldens (`tests/golden/vdt-failed.json`,
  `vdt-failed.md`, `historical-failed.json`, and `historical-failed.md`) hold the behavior. Verified
  by 2,065 tests on Python 3.11, 3.13, and 3.14, by the four goldens on the stateless path and from
  the store's history, and by a test that recompiles the sixteen report goldens of runs without a
  failure with the flag on, byte for byte; none of the 22 existing goldens moved.

### Changed

- A SARIF log that yields nothing and has a run with no results under an unverified invocation
  (an `executionSuccessful` that is absent, null or not a boolean, or an `invocations` member
  that is not an array) now raises ERROR `clean_run_unverified` beside `no_observations`. The
  content-class failure `--record-failed-imports` records lists both codes, so the record names
  its cause instead of reading like a log with no runs. A productive run beside such a run still
  imports, and a failed invocation never raises the code. ADR 0014 carries a second dated
  amendment of 2026-10-15 and ADR 0015 opens its PR 2 section with it.
- Repositioned the one-line description. "Evidence automation for continuous authorization" used
  Rev5 and continuous-monitoring vocabulary for a tool that implements the 2026 Vulnerability
  Detection and Response and Vulnerability Evaluation and Reporting rules. The package, the
  repository, and the project page now all read "Compiles STIG and SCAP output into schema-valid
  FedRAMP 20x vulnerability reports, with every response clock read from FedRAMP's published rules
  dataset." The PyPI summary is baked in at build time, so it carries the old line until the next
  release.
- The report-schema bundle now pins `FedRAMP/schemas` commit `5156719a` (ADR 0009), which
  carries Common Definitions `0.3.0`. FedRAMP merged it on 2026-09-01 as upstream pull request
  22, closing three issues: `finalDisposition` gains `Remediated` (issue 3),
  `vulnerabilityDetail` gains an optional `painReductionEvents` array (issue 7), and the
  `painReductionEvent` definition now cites `VER-RPT-VDT` instead of a rule that does not exist
  ([issue 16](https://github.com/FedRAMP/schemas/issues/16), which ComplyRoll raised). The
  three report schemas are byte-identical to the `0.1.1` copies already bundled, and the rules
  dataset pin is unchanged. Report provenance in the JSON and the Markdown cites the new commit,
  so the two VDT goldens moved: the commit in both, and in the JSON the relocated key and the
  empty extension lists that are no longer emitted. The schema-examples golden gained a
  `Remediated` example and a `painReductionEvents` example, and new tests prove that the
  `0.3.0` bundle refuses an unknown disposition and a malformed reduction event.
- A `remediated` case now emits `finalDisposition: "Remediated"` instead of `Fully Mitigated`.
  Every other disposition mapping is unchanged, and `x-complyroll.remediated` stays.
- Completed PAIN reductions moved from `x-complyroll.painReductionEvents` to the official
  `painReductionEvents` slot on the vulnerability record, emitted only when a case has at least
  one. A consumer that read the extension key must read the official key instead and treat it as
  optional; the extension no longer carries an empty list for cases with no reductions. This is
  a breaking change to the pre-1.0 extension.
- `ReportOptions` is keyword-only and its period is optional (ADR 0010). `period_from` and
  `period_to` default to `None`, must be given together, and keep the ordering check;
  `has_period` and the `period` property replace direct reads, and a projection that needs a
  period and gets none fails with the compile error `report_period_missing` named after the
  report. Positional construction of `ReportOptions` no longer works. `_period_exclusion_reason`
  takes a `state` argument so the accepted-vulnerability report's `excluded_by_period`
  diagnostic reads "is accepted and no recorded activity between" the bounds instead of
  "has disposition None". `_require_acceptance_rationales` fails the accepted-vulnerability and
  historical projections with `acceptance_rationale_missing` when an accepted record's
  evaluation has no rationale; the detail report keeps setting accepted records aside without
  one. The detail report's bytes are unchanged by this work.
- The rules dataset now pins `FedRAMP/rules` commit `58487bda`, dataset version `2026.09.13.02`
  (ADR 0005 amendment). It closes
  [FedRAMP/community discussion 164](https://github.com/FedRAMP/community/discussions/164),
  which ComplyRoll raised on 2026-08-24 because five rules stated a cadence in prose and carried
  no `timeframe_type` or `timeframe_num`. FedRAMP answered on 2026-09-13 that the timeframes had
  been entered mostly by hand, added the pair to those rules in `2026.09.13.01` (upstream pull
  request 28), and gave the schema optional `timeframe_num_min` and `timeframe_num_max` for the
  one rule that states a range; `2026.09.13.02` (pull request 29) changed only glossary terms and
  definitions. In the VDR and VER scope ComplyRoll selects, the only change is `VDR-TFR-NMV`,
  which now carries a three-month `MUST` timeframe, so `SelectedRule.timeframe` and
  `deadline_for_rule` return it for both classes. No report deadline is computed from it: the
  rule is a recurrence clock per non-machine-based information resource, which ComplyRoll does
  not record yet. Verified by loading and selecting both classes against the new bytes (36 rules
  each, every other timeframe and PAIN matrix unchanged), by the policy golden, which gained the
  `VDR-TFR-NMV` entry under both classes, and by the six report goldens, which moved only in the
  rules provenance block and in the overdue explanations that cite the dataset commit.
- The CLI help text for report and ingest artifacts now reads "CKLB, CKL, XCCDF, ARF, SARIF, or
  HDF file", and the package description reads "Compiles STIG, SCAP, SARIF, and InSpec HDF output
  into schema-valid FedRAMP 20x vulnerability reports, with every response clock read from
  FedRAMP's published rules dataset". The PyPI summary is baked in at build time, so it carries
  the previous line until the next release.
- The observation helpers the STIG adapters shared (`_text`, `_unique`, `_parse_timestamp`,
  `_make_observation`, and `_missing_time_diagnostic`) moved out of `adapters/stig.py` into
  `adapters/common.py` as `text_of`, `unique`, `parse_timestamp`, `make_observation`, and
  `missing_time_diagnostic`, and `make_observation` takes a `resource_type` that defaults to
  `host`. The move is the only edit on the STIG code paths in this work; every existing golden
  is byte-identical, which is the proof it changed nothing.
- The evidence hygiene helpers, constants, and diagnostic coalescer the SARIF adapter used moved
  from `adapters/sarif.py` into `adapters/common.py` under public names (ADR 0013), and the eight
  evidence methods moved into a new `EvidenceParse` base class that the SARIF and HDF parsers both
  subclass. The per-observation ceiling and per-artifact byte budget checks became
  `common.observation_bytes`, with the same messages. `sarif.py` still binds every old private
  name it and its tests read, five test spies were re-pointed at `common`, and with the move alone
  every golden stayed byte-identical and 1,333 tests passed on Python 3.11, 3.13, and 3.14.
- `IngestLimits` gained `max_results_per_run` and `max_observations_per_artifact`, both 50,000 by
  default, and `max_observation_bytes_per_artifact`, 256 MiB of canonical JSON summed over an
  artifact's observations, since a fold copies the capped lists it keeps into every observation that
  carries them; exceeding any of them refuses the artifact as `artifact_parse_failed`. Every
  existing limit keeps its value.
- The HDF adapter reuses those limits rather than adding one: `max_results_per_run` bounds the
  controls in one profile and the results of one control, `max_observations_per_artifact` bounds
  the distinct observations, and the ceiling and byte budget apply as they do for SARIF. The only
  new bound is a module constant of 64 profiles per document.
- `stigroll` skips a SARIF log with a warning on stderr (`warning: <name> is a SARIF log; stigroll
  rolls up STIG checklists only, skipping`) instead of rolling it up; a run whose only input is a
  SARIF log ends with `error: no findings parsed from any input` and exit status 1.
- `stigroll` skips an HDF document the same way (`warning: <name> is an HDF document; stigroll
  rolls up STIG checklists only, skipping`). A bare `.json` HDF document that used to be told it
  has no `stigs` key now draws this line instead, and an HDF artifact that fails to parse, such as
  a checklist saved under a `.hdf.json` name, prints `warning: could not parse <name>: <reason>`
  as a checklist does rather than being named an HDF document.
- `stigroll` prints `warning: could not parse <name>: <reason>` for a SARIF artifact that fails to
  parse, as it does for a checklist, instead of naming it a SARIF log and hiding the refusal. A
  log that parses still draws the skip line.
- A report's `description` no longer repeats a record id the title already leads with: a title
  equal to the id, or one that starts with the id and `": "`, is written as it stands, and every
  other title keeps the `<id>: <title>` form. The rule sits in the shared record compiler, so the
  Vulnerability Detail Report, the Accepted Vulnerability Information report, and the Historical
  VER Activity report all take it. The match is exact and case-sensitive, and the observation and
  case titles are unchanged, since they are source facts. It moves any SARIF row whose rule text
  leads with its own rule id as well as the converted HDF CVE rows, whose titles lead with the
  CVE id.
- The Vulnerability Detail Report keeps a record with an open KEV clock even when it had no
  other activity in the period, provided it is not accepted, was detected on or before the period
  end, and one of its matched catalog entries was listed on or before that date. Under
  `VDR-TFR-KEV` a mitigated KEV is unresolved, and an unresolved weakness was already activity in
  every period; without this a provider could mitigate a KEV and watch it drop out of the next
  quiet period's report. Adding `--kev` can therefore raise the overdue count on a run that
  previously reported none, because a fully mitigated KEV past its catalog due date is now
  officially overdue. An accepted record is never officially overdue on any rule, including this
  one: it keeps `{"isOverdue": false}` and publishes the missed date in `x-complyroll`, which is
  the `FRD-ACV` and `FRD-ODV` partition made visible in the accepted-vulnerability report's
  Summary, where "Overdue 0" can sit beside "Past a CISA KEV due date 1". AVI and historical
  selection are unchanged, and a run without `--kev` selects exactly what it selected before.
- `CompiledDeadline.timeframe` may now be null, and the `x-complyroll` deadline row publishes
  `"timeframe": null` for a rule that carries none. `VDR-TFR-KEV` is the first selected rule with
  no structured timeframe, since its deadline is a date in someone else's document rather than a
  duration from an anchor. Every existing deadline row is unchanged.
- An evaluation is now ordered against its record's detection time. The compiler refuses a record
  whose `completedAt` is strictly earlier than a `detectedAt` that is the record's own, whether it
  comes from an artifact timestamp, an attestation, or a recorded detection process failure, with
  the ERROR `evaluation_before_detection`. The message names the tracking id, both instants, the
  source, and a remedy that holds on the stateless path and from history. An evaluation completed
  at the detection instant is in order. A partly timestamped group is published with the WARNING
  `evaluation_before_partial_detection`, since an untimed observation may have detected the
  weakness earlier, and the partial rule is unchanged. One run names every refusal it reaches.
  `cases evaluate` refuses a file with an entry completed before its case's own detection time, and
  `cases attest-detection` refuses an attestation that would become the detection time of a case
  whose current evaluation completed before it. Each names every blocking case and appends
  nothing. `store verify` gains the audit fault `evaluation_before_detection`, reported at the
  current evaluation's sequence with the compiler's message, because `ingest` can move a detection
  time later when a newer parser reads a timestamp an older one did not; it runs only on a log with
  no other fault but `event_metadata_invalid` or `failure_schema_unmarked`, and beside those only
  when it can fold. It folds every case first, so a log whose case streams do not fold now fails
  `store verify` with `history_invalid`, as `report vdt --db` already did. The writers and
  `store verify` skip a case no report prints: one with no open group (`stale_case`) or no
  resolvable detection time. Only `completedAt` is ordered: a reduction or a projected reduction
  dated before detection still publishes. This adds a divergence between the paths, refuse versus
  publish (ADR 0014, Decision 15): a stateless run at an as-of later than the evaluation's
  `completedAt` refuses a failure that a store which ingested it by then publishes, and a store that
  ingested it later refuses an evaluation that a stateless run at an earlier as-of accepts. The
  documented recipes meet neither, and no golden moved. A store an earlier build wrote with a case
  evaluated before its own detection time, or attested at an instant after its evaluation, now
  fails `store verify` and `report vdt --db`, and `cases evaluate` refuses to apply the same file
  again. Applying that case's entry with a `completedAt` at or after the detection time repairs
  it, and an attested case can instead be attested earlier with `cases attest-detection --case`.
  Amends ADR 0007, ADR 0008, and ADR 0014. Verified by 2,090 tests on Python 3.11, 3.13, and 3.14.
- `cases correlate` now folds every existing case stream of an open group, each one it may
  extend, before its first append. A stream that does not fold refuses the run with the error
  `report vdt --db` prints for that stream, and nothing is appended, inside a caller's open
  transaction too. Before this, correlate read those streams only for their links, so on a store
  whose case stream records another tracking id it linked new observations onto that stream and
  exited 0 while every report from the store refused it. Every case writer now folds each case
  stream it appends to. Correlate still never reads a case no open group names, so damage there
  does not stop it, while `report vdt --db`, `cases list` and `store verify` still refuse it. On a
  store whose case streams fold, correlate appends exactly what it did before. Amends ADR 0008
  (amendment 2026-10-14, second). Verified by `tests/test_history.py` with four damaged-stream
  shapes, each alone and inside a caller's transaction.
- `store verify` is documented as the command that reports the content-neutral faults: a
  metadata envelope outside the rules (`event_metadata_invalid`), an event on a non-case stream
  it does not belong on (`event_stream_mismatch`, with the contract or count faults only that
  event causes), and a failure schema marker left low (`failure_schema_unmarked`). No reader and
  no case writer refuses them, none changes the bytes of any report, and refusing them on read
  would leave an append-only store unreportable for good. One writer refuses one shape: a
  failure stream is written whole, so `ingest --record-failed-imports` exits 1 with
  `history_invalid` rather than resume one that holds an event no failure stream carries. The
  evaluation order check now also runs when a log's only other faults are
  `event_metadata_invalid` or `failure_schema_unmarked`, so one tampered metadata envelope no
  longer hides an inversion from `store verify`; when the check cannot fold such a log, the
  faults found are reported alone, as before. Amends ADR 0008 (amendment 2026-10-14, second).
  Verified by `tests/test_cli.py`, where eight shapes fail `store verify` at their sequence while
  `report vdt --db` and every case writer behave as on a clean twin, and by
  `tests/test_evaluation_order.py`.
- The README is now a short overview: a phase status table, one line per surface, a quick start that
  rebuilds the same report from history, and the rules. Its reference material moved: the full
  command rows, verbatim, to a new `docs/CLI.md`, which also gives the `cases` subcommands their own
  synopses; report period selection, output writes, the `stigroll` demo, and the Python API snippets
  to `examples/README.md`; the `x-complyroll` extension to `docs/DATA_MODEL.md`; the ADR summaries
  to a new `docs/decisions/README.md` index; the FedRAMP source links to
  `docs/FEDRAMP_2026_MAPPING.md`; and the argument-order paragraph to `docs/ARCHITECTURE.md`. The
  stale CLI block in `docs/BUILD_PLAN.md` now points to `docs/CLI.md`, and `docs/SECURITY.md`
  carries the redaction note. The Phase 2 narrative, the longer persisted-path walkthrough, the
  failed-import walkthrough, and the target pipeline diagram were dropped: `docs/BUILD_PLAN.md`, the
  ADRs, `examples/README.md`, and `docs/ARCHITECTURE.md` hold them, and the few facts only the
  README carried were added to `examples/README.md`. Three passages were corrected on the way: the
  period rule now states the KEV clause ADR 0007 added on 2026-09-25, the Markdown parity test is
  described in the direction it checks, and the `CompiledVulnerability` docstring cites README
  non-negotiable rule 6, the same-records rule, instead of rule 5. README links are absolute,
  because the README is also the PyPI project description, which changes only with the next release.

## 0.3.0a0 - 2026-08-23

### Added

- Persisted history (ADR 0008). Typed version-1 event contracts for `artifact.ingested`,
  `observation.recorded`, `case.created`, `case.observation_linked`, `detection.attested`,
  `case.evaluated`, `case.pain_reduced`, `case.disposition_recorded`, and `case.identified`,
  validated on every append by `complyroll.events.EventRepository`; event metadata records the
  actor, method, tool version, and a per-run identifier.
- `complyroll ingest`, `complyroll cases correlate`, `complyroll cases attest-detection`,
  `complyroll cases evaluate`, `complyroll cases list`, `complyroll cases history`,
  `complyroll report vdt --db`, and `complyroll store verify`. Every write is idempotent: a
  repeated command appends nothing and a changed evaluation appends a new `case.evaluated`
  event instead of overwriting the earlier one.
- An event-sourced rebuild of the Vulnerability Detail Report that rehydrates recorded
  observations, folds each case stream, and runs the same record compiler; its output is
  byte-identical to the stateless report for the same inputs and that equality is a test.
- `Observation.from_canonical_dict` (the inverse of the ADR 0002 canonical form) and
  `SQLiteEventStore.verify_history`, which walks the log checking digests, contiguity, the
  sequence counter, and schema definitions and returns a structured report.
- `SQLiteEventStore.open_for_verification`, a diagnostic open path that never creates or modifies
  the file, so `store verify` reports faults (a truncated tail, an altered or missing schema
  object) on stores the normal open refuses instead of raising. The normal open and every append
  now also refuse a hole anywhere in history (event count versus highest sequence, per stream
  and globally), not only a truncated tail, and `store verify` validates every payload against
  its published contract after the store-level walk.
- `cases evaluate` refuses an evaluations file that would give two cases the same effective
  tracking id, and warns (`disposition_retained`, `reduction_retained`,
  `identification_retained`) when an entry omits a disposition, PAIN reductions, or a tracking-id
  override the case already holds, because no retraction event exists. An evaluations file that
  states the same PAIN reduction twice is refused on both paths. `cases attest-detection`
  reports cases where any observation already carries a source timestamp as not applicable, and
  `--all-missing` skips cases that are already attested. Every command except `ingest` reports
  `store_missing` rather than creating an empty store, and a failed `ingest` creates no file.
- The `case.disposition_recorded` contract enforces the evaluations file's cross-field rules
  (closed needs a closed disposition; a rationale only with acceptance; acceptance needs a
  rationale) at append and in the fold; the `observation.recorded` contract accepts only the
  exact timestamp text the canonical writer produces, and the repository reads every observation
  payload back through the canonical reader before storing it. Completed PAIN reductions render in
  canonical order on both paths, and a disposition recorded without an evaluation makes the
  replay fail closed.
- `SQLiteEventStore.transaction()`: one write transaction that every append inside it joins. The
  case writers fold, check, and append inside one transaction, so concurrent `cases evaluate`
  runs cannot both record the same provider tracking id, an artifact is ingested atomically, and
  one `ingest` run is all-or-nothing across its artifacts on a new store and an existing one
  alike. The fold refuses an incomplete or overfull artifact stream and an event whose artifact
  identity differs from its stream or repeats an observation identifier within the stream, and
  `store verify` reports them (`artifact_incomplete`, `artifact_overfull`,
  `artifact_stream_mismatch`, `artifact_duplicate_observation`). A whitespace-only acceptance
  rationale is refused by the `case.disposition_recorded` contract itself, so the fold carries no
  cross-field rule the audit cannot see.
- The repository parses every timestamp field of every contract as a real instant (hour 24
  included, which Python would otherwise roll into the next day), refuses an event stored on
  the wrong kind of stream or a `case.created` on another case's stream, and enforces the
  metadata rules (`run-<uuid4>`, a published method, `tool` equal to `complyroll`, a non-blank
  version); `store verify` audits all of these at rest through
  `complyroll.history.audit_history`. The rules are public
  as `complyroll.events.metadata_breaches`, `timestamp_pointers_for`, and
  `event_belongs_on_stream`, and the parser-version split as `complyroll.history.artifact_history`.
- When one artifact has streams under several parser versions, replay uses the newest and
  reports older streams as `artifact_superseded`.
- Output files publish with rollback: a failure while replacing the destinations restores the
  previous files, a rollback that itself fails exits with `output_rollback_failed` naming every
  destination left in its new state and the kept copy of its previous content, and a symbolic
  link is refused as a destination (`output_is_symlink`). A new store is built at a temporary
  path beside the destination and published with a hard link only on success, which refuses to
  overwrite a store that appeared meanwhile (`store_conflict`); `ingest` never deletes the
  destination path, and refuses a dangling symbolic link as `--db` (`store_unavailable`).
- JSON deadline objects carry `satisfied`; the Markdown detail section lists every observation
  id of a partly timestamped group and marks the untimestamped ones; a parity test walks the
  records. Help text names ARF; `--all-missing` reports how many cases it selected; the
  `reduction_retained` warning points at a new evaluation entry.
- A `[tool.mypy]` configuration so the type gate is reproducible from the repository.
- A `release.yml` workflow that publishes to PyPI through trusted publishing (OIDC, no stored
  token) when a `v<version>` tag is pushed: the tag must equal the `pyproject` version, the suite
  runs on the exact tree being published, and the publish job is gated by a `pypi` environment.

### Changed

- Every command that folds observations (`cases correlate`, `cases attest-detection`,
  `cases evaluate`, `report vdt --db`) fails closed on a store carrying an artifact stream with
  fewer observations than its `artifact.ingested` event declares. Only an interrupted ingest
  from an earlier version leaves such a stream; re-running `ingest` for that artifact completes
  it, and `store verify` names it as `artifact_incomplete`.
- Repository and issue URLs point at the `ComplyRoll` GitHub organization
  (`github.com/ComplyRoll/ComplyRoll`); the previous path redirects.
- The Vulnerability Detail Report compiler is split into `compile_records`, shared by the
  stateless and persisted paths so neither can drift from the other; `compile_vdt_report` keeps
  its signature, behavior, and output. Detection-time attestations are per case on the persisted
  path: when every attested case shares one instant the report carries the same
  `detectionTimeAttestation` block as before; otherwise the block lists each instant with the
  tracking ids it covers and has no single `detectedAt`.

## 0.2.0a0 - 2026-08-21

Hardening release driven by an independent audit of the Phase 0 and Phase 1 primitives.

### Fixed

- XML DTD and ENTITY declarations are now rejected by the parser itself (expat declaration
  handlers) instead of a UTF-8 byte scan. The scan could be bypassed by UTF-16 encoded documents,
  which then expanded internal entities into evidence records, and it falsely rejected legitimate
  checklists that quoted `<!DOCTYPE` inside CDATA or comments.
- `read_bounded` requires a regular file and reads with a bounded loop, so FIFOs and devices fail
  fast instead of blocking or growing without limit.
- A failed `COMMIT` in the SQLite event store now rolls back and raises `EventStoreBusyError`
  instead of leaving the connection inside an open transaction with phantom, unrecorded events
  visible to later reads.
- Every event-store method now maps SQLite failures to ComplyRoll error types: lock contention
  raises the retryable `EventStoreBusyError`, a corrupt file raises `EventIntegrityError`, a
  non-database file raises `UnsupportedSchemaError`, and disk-full, read-only, or I/O failures
  raise `EventStoreError` with SQLite's message. No raw `sqlite3` exception crosses the public
  boundary.
- A rollback that fails after a failed commit or body error closes the connection and reports
  it, instead of leaving the store inside an open transaction.
- Opening a brand-new store from several processes at once no longer fails spuriously: the
  WAL switch is skipped on established files, retried within the busy timeout otherwise, and
  schema creation is re-checked under the write lock so a peer's initialization is accepted.
- Domain validators raise `TypeError` for wrong input types (non-string text, non-datetime
  timestamps, bytes digests, a missing `ResourceRef`, non-string display fields) instead of
  failing inside a helper; a system observation cannot smuggle a falsy non-string past the
  empty-artifact-field rule.
- Opening a store verifies the stored DDL of every expected table, index, and trigger against
  the source DDL, so a same-named trigger with a different body no longer passes as append-only.
- Deleting the most recent events is detected: the AUTOINCREMENT counter must match the last
  stored sequence on open and before every append, which also stops the next append from
  minting a permanent gap.
- A path that cannot be opened (directory, missing parent, read-only location) raises
  `EventStoreError` instead of a raw `sqlite3` exception from the constructor.
- Reopening a store whose append-only triggers, indexes, or tables were removed now fails with
  `UnsupportedSchemaError`; `read_all` and `read_stream` raise `EventIntegrityError` when a gap
  shows that history was deleted.
- Domain dataclasses validate enum and boolean fields (`PainRating`, `CaseStatus`,
  `ObservationDisposition`, `SourceSeverity`, IRV/LEV flags) and coerce sequence fields to tuples.
  Artifact digests are normalized to lowercase so letter case no longer changes identity.
- `VulnerabilityCase.with_evaluation` refuses to silently reactivate ACCEPTED or CLOSED cases and
  keeps prior evaluations in `evaluation_history`.

### Added

- `complyroll report vdt`: a stateless compiler that turns CKLB, CKL, XCCDF, and ARF artifacts
  plus an operator evaluations file into a schema-valid Vulnerability Detail Report
  (`VER-RPT-VDT`) with a Markdown twin rendered from the same records. Open findings group into
  vulnerabilities with stable `case-` tracking ids; every vulnerability carries class-aware
  evaluation, PAIN response, and acceptance-threshold deadlines with rule id and force; overdue
  flags name the rule, force, class, inputs, due instant, dataset commit, and the optional-adoption
  period; `x-complyroll` carries generator, parser, rules, and schema provenance, the attestation,
  grouped observation ids, affected resources, compile diagnostics, and the disclaimer. The report
  period selects contents (activity-in-period rule with `excluded_by_period` diagnostics and an
  excluded count); groups with only some timestamped observations are marked `artifact-partial`;
  effective tracking ids must be unique; a case may close as accepted and is then routed to the
  accepted-vulnerability path; output files are written all-or-nothing. The compiler fails closed
  on any ingest error, missing detection time, or unmatched evaluation and validates the document
  before writing it (ADR 0007 and its amendment).
- `complyroll validate REPORT --schema ...` for offline validation of any report against the
  pinned official schemas with JSON Pointers and provenance.
- Correlation v0 (`complyroll.correlation`) and the bounded evaluations-file loader
  (`complyroll.reports.evaluations`).
- A calendar timezone on `CertificationProfile`; month and year deadline arithmetic now runs in
  that zone (default UTC) instead of on the UTC instant.
- ADR 0007 recording the report mappings, `examples/evaluations.json`, and golden report outputs.
- `ObservationOrigin` and system-generated observations: detection and response process failures
  can now be represented without a source artifact, with their own deterministic identity recipe
  (ADR 0002 amendment).
- Per-adapter parser version constants so a fix to one adapter does not re-identify observations
  from the others.
- WAL journal mode with `synchronous=FULL`, a configurable busy timeout, and schema verification
  on open for the event store (ADR 0004 amendment).
- `NOTICE` and `src/complyroll/data/README.md` recording that the bundled FedRAMP dataset and
  schemas are U.S. Government works redistributed unmodified and are not covered by the project
  license.
- A root `SECURITY.md` with a private vulnerability reporting channel, issue and pull request
  templates that forbid attaching real assessment artifacts, and a Developer Certificate of Origin
  requirement in `CONTRIBUTING.md`.
- Python 3.14 in the CI matrix, commit-SHA-pinned GitHub Actions, a console-script smoke test,
  Dependabot configuration, `py.typed`, and PEP 639 license metadata.

### Changed

- License changed from MIT to the Apache License, Version 2.0, before any public release. The
  Apache license adds an explicit patent grant and withholds trademark rights to the ComplyRoll
  name (Section 6); `NOTICE` carries the copyright and the U.S. Government data statement.
- README restructured around what runs today, with a disclaimer section, an independent-assessor
  section, and FedRAMP trademark attribution.
- Documentation now says "official-format" or "schema-valid" reports rather than "official
  reports", records the VDR/VER effective dates, and notes that the PAIN response targets
  (`VDR-TFR-PVR`) and evaluation window (`VER-TFR-EVU`) are SHOULD while the 192-day acceptance
  boundary (`VER-TFR-MAV`) is MUST.
- `CONTRIBUTING.md` no longer claims the package has no runtime dependencies.

## 0.1.0a0 (unreleased history)

### Changed

- Renamed the project, Python package, CLI, and parser identifiers from TrustRoll to ComplyRoll.
- Adopted the positioning: "Evidence automation for continuous authorization."

### Added

- Started Phase 1 with a migration-managed, append-only SQLite event store.
- Added transactional batch appends, optimistic stream concurrency, canonical payload digests,
  bounded event JSON, ordered replay, and rebuildable projection checkpoints.
- Added ADR 0004 documenting the event-envelope and disposable-projection storage contract.
- Added an offline, digest-verified official FedRAMP rules snapshot and bounded loader.
- Added 20x Class B/Class C provider-policy selection and provenance-bearing deadline calculation.
- Added golden evaluation, recurrence, PAIN response, and acceptance-threshold policy matrices.
- Added ADR 0005 documenting verified policy selection and fail-closed timeframe behavior.
- Added a digest-verified offline registry for official FedRAMP Common Definitions and the three
  initial VER report schemas.
- Added Draft 2020-12 report validation with enforced formats, actionable JSON Pointers, bounded
  raw JSON parsing, schema provenance, and fail-closed reference resolution.
- Added ADR 0006 documenting immutable schema pinning and the `jsonschema` dependency boundary.
- Completed the Phase 0 CKLB, CKL, XCCDF/ARF, and CCI adapter layer.
- Added artifact provenance, structured diagnostics, canonical observation serialization, and
  artifact-bound deterministic observation IDs.
- Added bounded JSON/XML parsing, CSV formula neutralization, and Markdown field escaping.
- Added a pinned, digest-verified metadata manifest for the official FedRAMP 2026 rules source.
- Added the backward-compatible `stigroll` package entry point and source-checkout launcher.
- Added synthetic fixtures and golden compatibility, malformed-input, security, provenance, and
  idempotency tests.

## 0.1.0a0 - 2026-08-18

- Create the TrustRoll pre-alpha repository scaffold.
- Define the FedRAMP 20x VDR product direction and phased build plan.
- Add foundational observation, evaluation, evidence, and case domain types.
- Add a minimal dependency-free CLI and unit tests.
