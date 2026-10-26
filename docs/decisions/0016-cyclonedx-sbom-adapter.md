# ADR 0016: CycloneDX SBOM adapter

- Status: Accepted
- Date: 2026-10-19

## Context

Phase 2 of the build plan lists a CycloneDX or SPDX adapter. Syft, Grype, and Trivy all write
CycloneDX JSON, Grype and Trivy write vulnerability records into the same document, and
CycloneDX carries a VEX vocabulary for supplier statements. SPDX 2.3 has no vulnerability record,
and the SPDX 3.0 security profile is JSON-LD that few producers emit, so this record covers
CycloneDX only.

ADR 0011 left one question open for this adapter: package-level identity. A SARIF observation is
keyed on the located resource, so Trivy's two vulnerable packages in one `requirements.txt`
share one observation, and the "Rejected alternatives" of ADR 0011 refused `name@version` as a
resource. An SBOM names every package directly, so this adapter has to say what a package is to
ComplyRoll without breaking the rules the earlier adapters keep: observation identity is the ADR
0002 recipe over nine inputs with the artifact digest, a normalization rule is an identity input
that needs its own version (ADR 0011 Decision 2), the group key is `(source_type,
source_record_id, context_key)` (ADR 0007), and a scanner result is never complete proof of a
KSI.

A CycloneDX document also says less than it seems to. A BOM with no `vulnerabilities` member is
an inventory, not a detection. Trivy writes `"vulnerabilities": []` with vulnerability scanning
turned off, which is its default under `--format cyclonedx`, and the same empty list after a
match that found nothing, so an empty list does not show that a match ran. `metadata.tools`
names the tools that created, enriched, or validated the BOM, not a matcher. A standalone VEX
document points its `affects` at another document's components, which ComplyRoll cannot join.
Each of these shapes decides a disposition and a coverage reading below.

## Decision 1: one adapter, a suffix arm and a bare `.json` sniff

The adapter is `complyroll.cyclonedx`, parser version `1`, source type `cyclonedx`, media type
`application/vnd.cyclonedx+json`. A file whose name ends in `.cdx.json` is read as CycloneDX
and never sniffed. A bare `.json` file is read as CycloneDX after its bounded parse, after the
HDF sniff, when the root is an object with no `stigs` member and `bomFormat` is `CycloneDX`.
`specVersion` is not part of the sniff, so an unsupported version gets the adapter's precise
refusal. A bare `.json` file that fails the depth or node bound is never sniffed and is
attributed to CKLB. There is no `.bom.json` or `.vex.json` arm, and the media type is not read.

Spec versions 1.4 to 1.7 are read, with `metadata.tools` in both its legacy array shape and its
1.5 object shape; another version is refused. Validation is hand-written structural checks over
the fields the adapter reads. The four official schemas are not bundled: they are about 886 KB
of JSON with a license enum that would refuse newer licenses and a root that refuses fields the
adapter never reads.
Why: the conventional name is unambiguous, a `bom.json` written by a tool should not be a CKLB
refusal, and `jsonschema` stays the only runtime dependency.

## Decision 2: four document kinds, told apart by the `vulnerabilities` member

| Kind | Told apart by | Yields |
|---|---|---|
| K1 inventory | `vulnerabilities` absent | one NOT_REVIEWED scope observation, WARNING `vulnerabilities_absent` |
| K2 empty | `vulnerabilities` is `[]` | one NOT_REVIEWED scope observation, WARNING `match_unverified`, whatever tool is named |
| K3 matched | a non-empty list and at least one component besides the subject | a named tool is required; one OPEN observation per vulnerability and resource; a scope observation (Decision 9) |
| K4 standalone VEX | a non-empty list and no component besides the subject | refused as a format (Decision 11) |
| malformed | `vulnerabilities` present but not an array | refused as a format |

A structural error in a document that carries no vulnerability record (a K1, a K2, or a
non-array `vulnerabilities`) is refused as a format, `AdapterParseError`, fatal under every flag
and never recorded as a detection failure: such a document makes no detection claim, so it is
an unreadable inventory, the rule for a malformed CKL. An identity refusal on K1 or K2 (a tool
name with a control character, or a tool or scope id over 512 characters) is a format refusal
too, "CycloneDX inventory identity cannot be used as written", never ERROR
`identity_input_invalid`, so `--record-failed-imports` records no VDR-CSO-FAV for an inventory
(re-audit CL-5); on K3 the same refusals stay CONTENT. Only on K3 do structural errors in
`metadata`, the tools, or `components` stay ERROR `invalid_bom` (CONTENT), mintable as
VDR-CSO-FAV under `--record-failed-imports`. The K4 test leaves the subject out: a document whose
only component is `metadata.component` is a VEX document even when every `affects` ref names
that subject, which is the shape of every published VEX example the design read. K4 is decided
after indexing, so a BOM whose components all nest under the subject is K3.

The checks run in this order, so every document-level ERROR lands before any vulnerability is
folded: root shape, `bomFormat` and `specVersion`; the type of `vulnerabilities`; the types of
`metadata`, the tools and `components`; the component index; the K4 test; the tool; the subject,
its scope id and the clock; the vulnerability folds.
Why: an inventory file in an `ingest` glob should not stop the run, a broken inventory should
not be recorded as a failed detection, and a VEX file should never mint a detection.

## Decision 3: the package key, frozen at parser version 1

The package key is a version-free string computed from a component, with the raw strings kept
beside it as source facts. It has three forms with disjoint prefixes:

- `pkg:` when `component.purl` parses under ECMA-427 clause 5 syntax, read in the order of the
  purl "how to parse" procedure. Type rules (deb requiring a namespace, and so on) are not
  enforced, because producer test data breaks them.
- `component:<type>/<group>/<name>`, each percent-encoded outside the RFC 3986 unreserved set,
  when there is no purl or it does not parse, with WARNING `package_identity_weak`.
- `ref:<raw ref>`, percent-encoded the same way, when an `affects` ref resolves to no unique
  component (Decision 6).

The namespace and subpath are split on `/` before each segment is percent-decoded, and decoding
is strict: a bad escape, bytes that are not UTF-8, or a decoded `/` in a namespace or subpath
segment means the purl does not parse. The key function never raises, so a malformed purl costs
one weak key, never the document. Decoding before splitting would merge `a%2Fb` with `a/b`.

The version is removed and never decoded. Qualifiers are applied in a fixed order: an empty
qualifier string and empty pairs are ignored; keys are lowercased and must satisfy clause 5.6.6;
empty values are dropped; a duplicate key means the purl does not parse; a value equal to its type's
`default_value` (maven `type=jar`, gem `platform=ruby`) is dropped; the strip set removes `epoch`,
`distro`, `upstream`, `file_path`, `file_name`, `download_url`, `vcs_url`, `repository_url`,
`checksum`, and `package-id`; for `oci`, `tag` is stripped and `repository_url` is kept; for
`docker`, `repository_url` is kept and `tag` stays. Every other key stays, including `arch`, maven
`classifier`, and any unknown key, because keeping an unknown key can split one package in two while
dropping it could merge two. `upstream` joined the set during the build: syft and grype write
`upstream=<source>@<source version>` on deb and the source RPM file name, version included, on rpm,
so keeping it put a version into the key, and Trivy writes none, so it also split one package across
producers. `repository_url` left the docker set in the audit fix (2026-10-19): stripped, it merged
same-named docker images from two registries into one key, while keeping it costs only churn when
one export omits it, the trade-off `oci` already accepts. Docker does not take oci's `tag` strip.
The kept pairs are sorted as built `key=value` strings, as the purl "how to build" procedure says
("Sort this list of qualifier strings lexicographically"); this differs from sorting keys alone only
when one key is a prefix of another followed by a character below `=`. Every stripped or dropped
pair stays verbatim in metadata `purls`.

Case follows a frozen per-type table settled from the 24 published type definitions: a segment
is folded exactly when its definition marks it `case_sensitive: false`, and a `true` flag or no
flag keeps it verbatim whatever the note says. The type is lowercased; alpm, apk, bitbucket,
composer, deb, github, and hex fold namespace and name; oci folds the name; pypi folds the name
and replaces `_` with `-`; rpm folds the namespace only; every other type is verbatim. Two
definitions contradict their own flags, and verbatim is deliberate in both. The golang
definition marks both segments case-sensitive while its notes say "The namespace shall be
lowercased." and "The name shall be lowercased." The nuget definition marks the name
case-sensitive while its note says "Technically the name is case-preserving, but
case-insensitive". Folding either on its note would re-mint every key of the type, so a change
needs a parser-version bump.

Folding is ASCII only: `A` to `Z` become `a` to `z` and nothing else, never `str.lower()`. This
is a named deviation from purl clause 5.5, which defines lowercase as the Unicode full case
mapping. `str.lower()` reads the interpreter's Unicode database (14.0.0 on 3.11, 15.1.0 on
3.13, 16.0.0 on 3.14), so a character whose mapping changed between them would give two keys on
two supported interpreters. A pypi name holding U+00C4 keeps it, so a producer that writes one
non-ASCII name in two cases yields two keys. The interpreter-independence claim covers the
package key only. `identity_problem` and `sanitize` read `unicodedata.category`, which already
differs between interpreters (`chr(0x13439)` is `Cn` on 3.11 and `Cf` on 3.13 and 3.14), so a
refusal or a sanitized text can differ by interpreter for every adapter, SARIF and HDF included.
Why: a version in the key re-mints a resource on every upgrade, an unfrozen fold re-mints keys
when the table or the interpreter changes, and the key is an identity input.

## Decision 4: the subject, its scope id, and its lineage

The subject is `metadata.component` when it has a non-blank `name`. A subject whose `type` is
`container`, or whose purl has type `oci`, is an image: its scope resource has type `image` and
an id composed from `name` and `version`, the first rule that applies being the name alone when
its last path segment already carries a tag or digest; `<name>:<version>` when `version` is not
digest-shaped; `<name>@<version>` when it is (`sha256:` or `sha512:` with lowercase hex); and
the name alone otherwise. Grype and syft name a `registry:alpine:3.15` scan `alpine` with
version `3.15`, and Trivy names it `alpine:3.15`, so all three give `image:alpine:3.15`, the id an
inventory entry names. Before the join, `%` and `/` in `version` are encoded. Every other
subject has type `scan` and the id `<group>/<name>` with `%` and `/` encoded in each part, so
the raw `/` is the only separator. No usable subject gives `scan:<tool>` with WARNING
`subject_identity_fallback`. The composed id passes `identity_problem` at 512 characters or is
ERROR `identity_input_invalid` on K3 and a format refusal on K1 and K2 (Decision 2), the check the
inventory applies to `resourceId`, so every scope id the adapter emits is registrable.

The lineage, used only inside package resource ids, is the subject without its tag or digest: for an
image, a trailing digest is removed from the subject `name`, then a trailing `:<tag>` when the last
`:` follows the last `/`, so a registry port survives. It is derived from the name, never from the
composed id. When the strip leaves nothing (a name such as `:1.4`), the lineage is the name as
written, so subjects with such names do not share one empty lineage. A name that is wholly
`<alg>:<hex>`, where the algorithm is one of `md5`, `sha1`, `sha224`, `sha256`, `sha384`, `sha512`
and `blake3` and the hex is exactly that digest's length in lowercase hex (32, 40, 56, 64, 96, 128
and 64), is likewise its own lineage as written, never the bare algorithm, so two digest-named
subjects never share a lineage (re-audit CX-1); the scope id is unchanged, and its composition
rule still reads only `sha256:` and `sha512:` as a digest. The algorithms are named, not matched
by shape, because a hex tag such as `app:<git sha>` is a tag: it strips to `app`, so a rebuild
keeps its package rows (cross-vendor re-audit XV-1). The exact length does the same for a
repository named for an algorithm, so `sha256:<git sha>` strips to `sha256` (XV-9), and keeps a
tag-only name such as `redis:7` or `localhost:5000` stripping as a tag too. For
`scan` the lineage is the scope id. The tag and digest are kept as metadata (`subject_ref`,
`subject_version`).

Paths and registry references are not canonicalized: a directory subject is the path as typed,
and `alpine:3.15` and `docker.io/library/alpine:3.15` are two scope ids, which an inventory joins
with an alias.
Why: `web:1.4` and `web:1.5` should share a package row while a package is still vulnerable,
and one image scanned by three tools should reach one inventory entry.

## Decision 5: the package resource

A vulnerability is located on a resource of the new permanent type `package`, with id
`<scope type>:<lineage>|<package key>`, for example
`image:registry.example.test/web|pkg:npm/lodash`. A key never holds a raw `|`, so the id splits
back into its three parts. The composed id passes `identity_problem` at 512 characters or is
ERROR `identity_input_invalid`, refused and never repaired. An `affects` ref that names the
subject itself puts the observation on the scope resource. The version is not in the id, so a
routine upgrade keeps the row, and `package_versions` and `instances` carry each version on its
own observation. A different `arch` is a different binary and a new row.
Why: a version-free row never leaves a stale row per upgrade, and a package row keeps every
vulnerable package of one image apart, which a subject-only resource would collapse.

## Decision 6: references resolve locally and degrade

Refs resolve through an index of `metadata.component` and every component at every depth,
walked with an explicit bounded stack. Services are not indexed. A bom-ref carried by several
components resolves when every carrier yields one package key; when the keys differ it maps to
nothing, with WARNING `bom_ref_conflict`. An unresolved ref, a BOM-Link to another document
included, becomes `ref:<encoded ref>` under the subject lineage with WARNING
`affects_unresolved`. An ERROR here would make the reading partial and fatal, and the SBOM's real
findings would be lost.

## Decision 7: the context key is the tool

`context_key` and `source_tool` are the tool string, so a case is one CVE from one tool across
every subject and package, with every affected package kept as a resource. This is SARIF's
driver-in-context rule. A tool-less document falls back to the constant `cyclonedx` for K1 and
K2 only (Decision 10).

The consequence is that one evaluation covers every image the case spans. IRV, LEV, and PAIN
cannot differ per image under one case, so an evaluator who finds a CVE false positive in one
product and real in another must not mark the whole case false positive. Two tools reporting one
CVE are two cases, and so are two export formats of one tool's scan: Grype's SARIF and Grype's
CycloneDX for the same image carry different source types.
Why: keying on the subject lineage as well would re-mint cases, not just rows, for every
directory subject named by a different path, and cross-source correlation is a later decision.

## Decision 8: the detection instant is `metadata.timestamp`

A vulnerability observation is detected at `metadata.timestamp`, the BOM's creation time.
`--detected-at` applies only when it is absent or unparseable, the SARIF rule and the ADR 0007
amendment unchanged. On every producer the design captured, the timestamp is the time the run
finished writing, and a Grype or Trivy re-match of an older SBOM writes the re-match time and
keeps the input's nowhere, so on the matcher path it is the match time. Where creation and match
differ, as for a supplier document, creation comes first, so the clock starts earlier and the
deadline lands sooner, which is wrong only in the conservative direction.

## Decision 9: one scope observation per document

Every well-formed document yields exactly one scope observation of its subject: record id
`cyclonedx.bom`, the scope resource, the tool as context key and source tool, severity UNKNOWN,
fixed descriptions with no producer text. K1 is NOT_REVIEWED ("it is not a detection and verifies no
coverage clock"). K2 is NOT_REVIEWED with `match_unverified`. K3 is PASS when at least one `affects`
ref resolves through the index, directly or by a same-document BOM-Link, to a listed component other
than `metadata.component`, on a vulnerability whose `analysis` has the state `exploitable` or
`in_triage`, or none of a `state`, a `justification`, and a `detail`, in an `affects` entry that
does not mark the installed version `unaffected`. Such a record is positive evidence that a match
ran against this inventory. A ref to the subject never counts: it lands its observation on the scope
resource, and a document whose refs all name the subject has the K4 VEX shape. A supplier judgment
never counts either: `not_affected`, `false_positive`, `resolved`, and `resolved_with_pedigree`
describe a product, not a match, and an unknown, non-string, or `null` state fails closed the same
way. A `justification` with no `state`, whatever its value, is a judgment too, and so is a `detail`,
the supplier's own account (re-audit CL-2, cross-vendor re-audit XV-4), while a `response` alone is
not. An `affects` entry whose `versions` lists a component's own `version` with the status
`unaffected`, the comparison `affects_version_unaffected` makes, contradicts its own match and never
counts, while the detection still mints (re-audit CL-1). A K3
with no counting record, whether its refs all fall back, name only the subject, or sit on judged
records, or its vulnerabilities carry no `affects`, is NOT_REVIEWED with `match_unverified` ("no
unjudged vulnerability record resolves to a component this document lists besides its subject"), and
its detections still mint OPEN with their warnings. The PASS text says the tool matched the
components the document lists, which is not evidence that the subject is free of vulnerabilities or
that the list is complete. A vulnerability whose id is spelled `cyclonedx.bom` and resolves to the
scope resource takes the observation, and the scope candidate yields with INFO `scope_superseded`;
that record is OPEN, so it examines the subject and never verifies it (Decision 13).

The residual risk is named: a supplier that lists affected statements with no `analysis` against
components of its own document reads as a match and verifies the subject's clocks, because nothing
in such a record tells it from a matcher's output. Supplier judgments were excluded in the audit fix
(2026-10-19), after an embedded `not_affected` on a listed component was shown to verify coverage.

A K3 scope observation beside findings is a named departure from SARIF, where a run with results
yields no scope observation: a CycloneDX finding sits on a `package` resource that never matches
an inventory entry, so without the scope observation a vulnerable image would read `missing`
while a clean one read `undetermined`.

`withheld` is a second named deviation from SARIF. The scope candidate is kept outside the fold
map, and the reading is withheld only when an ERROR sits beside vulnerability folds. SARIF folds
its clean-run candidate into the map, so it counts. Counting the scope here would make any ERROR
in any SBOM an unmintable partial reading, and a defective SBOM could never become a VDR-CSO-FAV
case, which would break the rule that a detection process failure is eligible to become an
observation and case. A document with an ERROR beside real vulnerability folds is a partial
reading and fatal, as for SARIF.

The cost is stated plainly: a clean Grype or Trivy run never verifies a coverage clock under
this parser version, because a K2 is NOT_REVIEWED whatever tool is named. An operator-assertion
flag that marks a K2 as a clean match is a follow-up; its name and form are not designed here.

## Decision 10: a vulnerability document with no tool is `invalid_bom`

A K3 document that names no tool is ERROR `invalid_bom` (CONTENT), "no tool named; a
vulnerability statement without a producer is not a detection", the SARIF `invalid_run`
precedent. The check runs before any fold, so `--record-failed-imports` records it as a
VDR-CSO-FAV case. The `cyclonedx` fallback tool stays for K1 and K2, where no detection is
claimed. Tools are read from both `metadata.tools` shapes; when an object-form tool is an
`application`, only those count. Several names are deduplicated, `%` and `+` are encoded in each,
and they are sorted and joined with `+` under WARNING `tool_identity_ambiguous`.
Why: a constant tool would merge every tool-less producer's CVE into one case.

## Decision 11: supplier statements never move a disposition, and standalone VEX is refused

An embedded `analysis` is recorded under the `analysis_*` metadata keys and the disposition stays
OPEN. Each kind of claim draws its own coalesced WARNING so an evaluator can find what needs a
`cases evaluate` record: `analysis_not_affected`, `analysis_false_positive`, `analysis_resolved`,
`analysis_in_triage`, `response_will_not_fix`, `analysis_conflict`, `analysis_state_invalid`, and
`affects_version_unaffected` for an installed version the document itself marks `unaffected`. A
supplier's `not_affected` describes the supplier's product, not the provider's deployment, and the
precedents are ADR 0011 Decision 6 and ADR 0013 Decision 5. A judgment does keep its own record from
counting toward the PASS of the scope observation (Decision 9), which moves no finding's
disposition.

A standalone VEX document (K4) is refused as a format: "a standalone CycloneDX VEX document
cannot be resolved without the BOM it describes; ComplyRoll does not join artifacts; record its
statements as evaluations". The refusal is fatal under every flag, because a VEX file is not a
failed detection, so one VEX file in an `ingest` or `report` glob stops the run with exit 1 and
writes nothing. A later leg may read VEX as material for `cases evaluate`; it is never minted as
detections.

## Decision 12: the fold, the bounds, and the metadata

Candidates that share an identity fold into one observation, as in ADR 0011 Decision 9. Two
installs of one package in one subject are one observation with `occurrence_count` 2 and INFO
`package_instances_folded`; `instances` keeps each install's bom-ref, version, purl, and hashes
together, at most 64 (`MAX_INSTANCES_PER_PACKAGE`), with `instances_cut` set past that. The
instance cut never writes `truncated` by itself. Sixty-five installs that differ in version or
bom-ref also overflow the ordinary 64-item cap on `bom_refs` and `package_versions`, and that
list cut does name those two lists in `truncated`; `cve_may_be_missing` stays false, because it
fires only when the identifier list is cut. `purls` items are cut to 256 characters before
deduplication, so purls that differ only past the cut collapse, and `truncated` names `purls`.

Two count bounds are checked before any fold work: `len(vulnerabilities)` against
`max_results_per_run` and `MAX_AFFECTS_PER_VULNERABILITY` (1,024), both `InputLimitError`, so a huge
document fails early as a parse failure. `max_observations_per_artifact` counts the scope
observation for K1, K2, and K3: the fold step stops fold work at the cap, and once the folds are
built the reading is refused when they and the scope exceed it. A scope that yields to a producer
record named `cyclonedx.bom` is not counted. A candidate's fold order is built from one token per
carrier, the carrier's `repr` cut to 256 characters, then `#` and the SHA-256 of the whole `repr`,
so memory never grows with purl length times `affects` count and the order stays a pure function of
content; a 1 MiB purl named by 512 `affects` fell from 545.1 MiB to 33.7 MiB peak RSS. Each distinct
ref's carrier facts (its carriers, their sorted tokens as one JSON string, and their versions) are
built once and shared by every candidate that names it, so memory never grows with components
sharing one bom-ref times the `affects` entries naming it either; 20,000 such components named by
256 entries fell from about 1 GiB to about 70 MiB peak RSS, with fold output byte-identical
(re-audit CL-4). The same facts hold each distinct install's texts sanitized and capped once per
document, and a fold joins those results in the order of the raw texts, read from a rank computed
once, so it never rescans a purl: CPU no longer grows with purl length times the vulnerabilities
naming it. A 1 MB non-ASCII purl named by 200 vulnerabilities took 34.5 s and now 0.12 s, with
fold output byte-identical (cross-vendor re-audit XV-2). Every other
bound is the shared one, including the 512 KiB ceiling on one observation's canonical JSON. A fold
saturated with four-byte characters can exceed that ceiling where the same fold in ASCII fits, and
the artifact then fails closed, the behavior ADR 0011 already accepts for SARIF and HDF.

The scope observation carries `component_set_sha256`, a digest over the document's components
one per line. Before the join, a version encodes `%`, tab, LF, and CR, so a version holding a
line break cannot make two component sets print one line set. Keys, resources, and observation
ids are identical whatever the qualifier order of a purl; `purls` and `instances` keep the purl as
written, so canonical JSON differs between two spellings of one purl, as the invariant that
source identifiers are preserved requires.

Severity is the highest vendor word among `ratings` with no banding of scores; it is evidence
and never sets PAIN.

## Decision 13: packages are not inventory resources

The coverage reader skips an observation whose resource type is `package` before it counts
unregistered resources: a package is a component of its subject, and the subject's scope
observation carries the coverage. The inventory refuses `resourceType` `package`, on an entry or
an alias, with fixed text: "resourceType package is not an information resource; inventory the
image or host that carries it". Neither edit moves a pre-existing golden. The literal is defined
in the adapter, the coverage reader, and the inventory reader, pinned equal by a test, so
`reports/` imports no adapter.

Coverage reads a `cyclonedx` source only through its `cyclonedx.bom` record, and that record
verifies only when it is PASS. A vulnerability observation, on a package or on the scope resource,
never examines or verifies an entry and is never listed as later or untimed evidence; it still
counts toward an unregistered resource's observation count, which is why the spec-corners `scan`
subject reads unregistered with three observations. A producer record that took the scope's id is
OPEN and examines the entry without verifying it, the one place OPEN does not verify. The source
type and record id literals live in the coverage reader beside `package`, pinned equal to the
adapter's by a test.
Why: a finding is a package fact, not evidence that the image was examined. Before the
audit fix, a finding with no `affects`, a ref to the subject, or a producer record named
`cyclonedx.bom` read an image `current` beside a NOT_REVIEWED scope.

## Worked examples

`tests/fixtures/grype-image.cdx.json` and `tests/fixtures/trivy-image.cdx.json` describe one image,
`registry.example.test/api`, by digest and by tag. `complyroll report vdt` over both reports six
cases, one per CVE per tool, each detected at `2026-10-01T12:00:00Z` from `metadata.timestamp`.
Every reported resource has type `package` and an id under `image:registry.example.test/api|`, so
the digest-named and the tag-named subject share one lineage. Grype's busybox component has no
purl, so its id ends in `component:library//busybox-static` with WARNING
`package_identity_weak`. Trivy's CVE-2023-0286 is one case over two packages. `ingest` records 5
and 4 observations, each count including the scope observation, and the persisted reports equal
the stateless ones byte for byte in either ingest order (`tests/golden/vdt-cyclonedx.*`,
`historical-cyclonedx.*`).

`tests/golden/vdt-cyclonedx-coverage.*` measures four inventoried images: a timed K1 reads
`undetermined`, an untimed K1 `missing`, a Grype K2 `undetermined`, and a Trivy K3 with a resolved
ref `current`.

## Consequences

- A package row grows per new package lineage, never per version, and web:prod and web:staging
  deployed at once share one row; `subject_ref` keeps each tag on its own observation.
- The report names the package but not its version or the carrying image's digest; a reader goes
  to the store or the artifact. Making them visible (`observedVersions`, `observedSubjects`) is a
  follow-up, since versions in a shared report fall under VER-RPT-NID.
- One case per CVE per tool spans every image, with one IRV, LEV, and PAIN (Decision 7).
- A clean scan never verifies a coverage clock in this parser version (Decision 9).
- A supplier SBOM whose every record carries a judgment, or names only its subject, verifies no
  clock (Decision 9).
- One VEX file, one malformed inventory, or one malformed empty BOM stops an `ingest` or
  `report` glob.
- Ingesting two export formats of one tool's scan of one target counts every CVE twice.
- `arch` stays in the key, so two tools that pull different platform images of one tag give
  two package rows per package.
- A short and a fully qualified image reference are two scope ids and two lineages. A daemon or
  archive source that names its subject `user-input` would give every image its own scope id
  while their packages share the lineage `user-input`; no such source was captured.
- Changing the strip set, the case table, or the parse rules re-mints package resources, so each
  needs a parser-version bump.
- The supersession and resume rules of the event store apply unchanged: a later parser version
  of the same bytes supersedes the earlier reading with an `artifact_superseded` info, and a
  changed reading under the same version is refused as `history_invalid`.

Follow-ups, none built here: the operator-assertion flag for a clean match; versions and digests
in reports; VEX as evaluation material; SPDX 2.3 as inventory-only scope observations under the
same key rule; and a frozen Unicode category table shared by every adapter's identity check.

## Open risks

Recorded in the audit fix (2026-10-19), with no code change:

- The subject's own purl is not read, so an `oci` subject with one name and version pulled from two
  registries gives one scope id and one lineage: the reference as typed, Decision 4.
- The `ref:` fallback keys the raw document-local bom-ref, so a reused token such as `component-1`
  merges unrelated packages across documents of one lineage. Decision 6 stands, because every
  alternative re-mints the key per export.
- A standalone VEX document with a structural error in `metadata`, the tools, or `components` is
  ERROR `invalid_bom`, mintable as VDR-CSO-FAV, while a well-formed one is refused as a format,
  because those checks run before the K4 test (Decision 2).
- pypi names do not fold `.` as PEP 503 normalization does, so two spellings of one package give two
  keys: churn, never a merge.
- A name made only of a host and port, such as `localhost:5000`, loses its port in the lineage. It
  is not a realistic image reference.
- An unversioned scoped npm purl with a raw `@` falls to a `component:` key, which churns only when
  a producer omits the version.
- A supplier that lists affected statements with no `analysis` verifies the subject's clocks
  (Decision 9).

Recorded in the re-audit (2026-10-19), with no code change:

- A component that copies the subject (same container name and version, another bom-ref) evades the
  subject-ref rule, beside the supplier-listing residual risk above (CL-3).
- Subjectless documents of one tool merge under `scan:<tool>`; it is the SARIF `scan:<driver>`
  fallback behavior, warned (CX-2).
- Namespace-less apk purls from two distros merge; it needs non-conformant purls (CX-4).
- docker keeps a `tag` qualifier, so a docker key churns on a retag, beside the `repository_url`
  trade-off of Decision 3 (CX-6).

Recorded in the cross-vendor re-audit (2026-10-19), with no code change:

- An `affects` version `range` marked `unaffected` is kept verbatim in `affects_ranges` but never
  evaluated, so a range that covers the installed version does not stop PASS; only a listed
  `version` equal to an install's does (Decision 9). Treating every `unaffected` range as a
  judgment was rejected: grype writes an `unaffected` fix range on every match, so every grype scan
  would read NOT_REVIEWED. Evaluating ranges needs a per-type `vers` comparison (XV-3).
- A subject name that is wholly a digest of an algorithm other than the seven Decision 4 names,
  such as `sha3:<hex>`, strips as a tag to the bare algorithm, so such subjects share one lineage
  and their packages merge. Matching any algorithm by shape kept every hex tag such as
  `app:<git sha>` in the lineage and re-minted every package row per rebuild (XV-1, XV-8).
- A repository named for an algorithm whose tag is hex of exactly that digest's length, such as
  `sha256:<64 hex>`, keeps its tag in the lineage, so its rebuilds do not share package rows (XV-9).

## Rejected alternatives

- The version in the package id: every routine upgrade leaves a stale persisted row that never
  says it was replaced.
- The subject as the resource and the package in metadata only: every vulnerable package of one
  image collapses to one row, the loss ADR 0011 deferred.
- The verbatim subject name, or name plus digest, as the lineage: every release or rebuild
  re-mints every package row.
- Keeping every qualifier, or an allowlist of qualifiers: a point release or a path move re-mints,
  or an unlisted identity qualifier merges silently.
- `str.lower()` or a frozen full case-mapping table: the first differs by interpreter, and the
  second is a large literal that is itself an identity input.
- PASS for every K2 that names a tool, or for an allowlist of tools: Trivy's empty list does not
  say a match ran, and no tool name tells an inventory export from a clean match.
- A format refusal for every K1: one syft file in a glob would stop the run. A CONTENT failure
  for every K1 would record a detection failure that never happened.
- Ingesting standalone VEX: OPEN cases manufactured from "not affected" statements.
- `analysis.state` setting the disposition: NOT_REVIEWED would close a case by absence and PASS
  would verify coverage.
- `<tool>|<lineage>` as the context key: one case per CVE per application line, and directory
  subjects would re-mint cases.
- Banding CVSS scores into severity: wrong for EPSS, KEV, CVSS v2, and the 4.0 vectors some tools
  file as `other`.
- Source type `sbom`: a later SPDX adapter would merge cases with these before cross-source
  correlation.

## Amendment 2026-10-25: the GHSA pattern, and a frozen Unicode category table

The shared GHSA pattern now matches GitHub's format exactly (ADR 0011, amendment of this date), so a
vulnerability id or reference id that runs a fourth group on, or uses a character outside
`23456789cfghjmpqrvwx`, yields no GHSA identifier under the same parser version. The record id is
the vulnerability id as written and is unchanged. A store an earlier build wrote that re-ingests
such a file says `already_recorded` and keeps its old `source_identifiers`, so that store's `report
--db` can differ from a fresh stateless report for the same file. No fixture or golden carries such
a token; every golden is byte-identical.

The follow-up "a frozen Unicode category table shared by every adapter's identity check" is built.
`identity_problem` and `sanitize` read the Unicode 16.0.0 table in `adapters/categories.py`, not
`unicodedata.category`, so the paragraph above that says they differ between interpreters no longer
holds: `chr(0x13439)` is a format control on every supported interpreter. Their callers are this
adapter, the SARIF and HDF adapters, the KEV and inventory readers, and the detection-failure and
duplicate-artifact diagnostics; the CKLB, CKL and XCCDF readers call neither, so they make no
identity check on any interpreter. The seven code points U+13439 to U+1343F were unassigned in
3.11's 14.0.0 database, so earlier builds on 3.11 accepted them in an identity and kept them in
evidence text. A current build refuses them in an identity and strips them from evidence on 3.11
too. A stored identity that holds one still reads and verifies, since neither path calls
`identity_problem`; reading the same bytes again refuses it. The table names its version in
`UNICODE_VERSION`, is regenerated with `python -W ignore::RuntimeWarning -m
complyroll.adapters.categories` on an interpreter of that version (without `-W`, runpy warns that
the package already imported the module; the output is the same), and a test fails when the running
interpreter's database disagrees with it outside the known 14.0.0 delta.
