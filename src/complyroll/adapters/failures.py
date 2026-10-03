# ******************************************************************************
# *Title: Detection Failures*
# *Author: Kyle Versluis*
# *Description: Classify failed readings and build VDR-CSO-FAV system records.*
# ******************************************************************************
"""Detection process failures: classification, diagnostics, and system records (ADR 0014)."""

# *--- Imports ---*

from __future__ import annotations

from collections.abc import Iterable
from dataclasses import dataclass, replace
from datetime import datetime
from enum import Enum

from complyroll.models import (
    Observation,
    ObservationDisposition,
    ObservationOrigin,
    ResourceRef,
    SourceSeverity,
)

from .base import ArtifactProvenance, DiagnosticLevel, IngestDiagnostic, IngestResult
from .common import diagnostic_text, encode_list

# *--- Configuration ---*

# One identity for every class (decision 4). The class, the codes, and the failed reading's
# parser live in metadata, so a parser that reclassifies a failure never re-mints it.
DETECTION_FAILURE_SOURCE_TYPE = "complyroll.detection-process"
DETECTION_FAILURE_SOURCE_TOOL = "complyroll"
DETECTION_FAILURE_PARSER_NAME = "complyroll.detection-failures"
DETECTION_FAILURE_PARSER_VERSION = "1"
DETECTION_FAILURE_RECORD_ID = "detection-process-failure"
DETECTION_FAILURE_RESOURCE_TYPE = "artifact"
DETECTION_FAILURE_RULE = "VDR-CSO-FAV"
# SECURITY: The title is built from the digest alone; no untrusted text reaches it.
DETECTION_FAILURE_TITLE = (
    "source artifact sha256:{digest} did not yield complete detection results (VDR-CSO-FAV)"
)

# The cap leaves room for two entries after it, the truncation notice and the recorded
# notice, so one failure contributes at most 64 diagnostics.
FAILURE_DIAGNOSTIC_CAP = 62
DETECTION_FAILURE_RECORDED = "detection_failure_recorded"
FAILURE_DIAGNOSTICS_TRUNCATED = "failure_diagnostics_truncated"

# The WARNING a failed scanner invocation raises. Its presence alone decides the execution
# class, so that class has no ERROR code of its own.
EXECUTION_UNSUCCESSFUL = "execution_unsuccessful"

# The closed vocabulary of ERROR codes (decision 1). Every ERROR an adapter can emit is in
# exactly one of CLASS_CODES and UNMINTABLE_CODES; tests/test_failures.py walks the
# adapters to hold that.
PARSE_CODES = frozenset({"artifact_parse_failed"})
CONTENT_CODES = frozenset(
    {
        "invalid_stig",
        "invalid_rules",
        "invalid_rule",
        "invalid_run",
        "invalid_result",
        "rule_id_missing",
        "identity_input_invalid",
        "invalid_profile",
        "invalid_control",
        "no_observations",
    }
)
CLASS_CODES = PARSE_CODES | CONTENT_CODES
# A reading that carries one of these has no identity, is operator input, or carries
# findings; the cci_ codes belong to the CCI map loader and never reach an ingest result.
UNMINTABLE_CODES = frozenset(
    {
        "artifact_read_failed",
        "unsupported_artifact",
        "duplicate_observation_identity",
        "cci_read_failed",
        "cci_parse_failed",
        "cci_map_empty",
    }
)

_UNSUPPORTED_ARTIFACT = "unsupported_artifact"
_DUPLICATE_IDENTITY = "duplicate_observation_identity"
_NO_OBSERVATIONS = "no_observations"
_RUN_CLEAN = "run_clean"
_RESULTS_UNKNOWN = "results_unknown"

# *--- Types ---*


class FailureClass(str, Enum):
    """The three mintable failure classes, checked in this order, first match wins."""

    EXECUTION = "execution"
    PARSE = "parse"
    CONTENT = "content"


class UnmintableReason(str, Enum):
    """Why a failed reading stays fatal instead of minting a system record (decision 2).

    classify_ingest checks the first seven in the order listed. READ_ELSEWHERE is never
    returned by it: only a caller that sees every reading of a run, or the store, knows the
    same bytes also read successfully, and it assigns the reason with
    FailureClassification.read_elsewhere.
    """

    NO_DIGEST = "no_digest"
    UNSUPPORTED = "unsupported"
    FORMAT_REJECTED = "format_rejected"
    DUPLICATE_IDENTITY = "duplicate_identity"
    PARTIAL_READING = "partial_reading"
    UNKNOWN_CODE = "unknown_code"
    CLEAN_SCAN = "clean_scan"
    READ_ELSEWHERE = "read_elsewhere"


@dataclass(frozen=True, slots=True)
class FailureClassification:
    """How one failed reading is treated: minted under one class, or refused for one reason.

    Exactly one of failure_class and reason is set; mintable is True when failure_class
    is. codes is sorted and distinct and is the failure.codes metadata value: the reading's
    ERROR codes, plus execution_unsuccessful when the class is execution, so a side
    record's list is never empty. side_record is True only for an execution failure in a
    reading with no ERROR: the artifact's own observations import as they do today, and the
    system record is minted beside them. clock is the failed invocation's own declared clock
    (IngestResult.failed_execution_at) for the execution class, and None otherwise.
    """

    failure_class: FailureClass | None
    reason: UnmintableReason | None
    codes: tuple[str, ...]
    side_record: bool = False
    clock: datetime | None = None

    def __post_init__(self) -> None:
        if self.failure_class is not None and not isinstance(self.failure_class, FailureClass):
            raise TypeError("failure_class must be a FailureClass or None")
        if self.reason is not None and not isinstance(self.reason, UnmintableReason):
            raise TypeError("reason must be an UnmintableReason or None")
        if (self.failure_class is None) == (self.reason is None):
            raise ValueError("a classification names exactly one of a class and a reason")
        if not isinstance(self.codes, tuple) or not all(
            isinstance(code, str) for code in self.codes
        ):
            raise TypeError("codes must be a tuple of strings")
        if self.codes != tuple(sorted(set(self.codes))):
            raise ValueError("codes must be sorted and distinct")
        if self.failure_class is not FailureClass.EXECUTION and (
            self.side_record or self.clock is not None
        ):
            raise ValueError("only an execution failure is a side record or carries a clock")

    @property
    def mintable(self) -> bool:
        """Return whether this failure becomes a system record."""
        return self.failure_class is not None

    @classmethod
    def unmintable(cls, reason: UnmintableReason, codes: Iterable[str]) -> FailureClassification:
        """Return a refusal for one reason, carrying the given codes sorted and distinct."""
        return cls(failure_class=None, reason=reason, codes=tuple(sorted(set(codes))))

    def read_elsewhere(self) -> FailureClassification:
        """Return this failure refused because its bytes read successfully elsewhere."""
        return FailureClassification.unmintable(UnmintableReason.READ_ELSEWHERE, self.codes)


# *--- Helper Functions ---*


def _unmintable_reason(
    result: IngestResult, errors: frozenset[str], present: frozenset[str]
) -> UnmintableReason | None:
    """Return the first reason a reading with an ERROR cannot mint, in decision 2's order."""
    if result.artifact is None:
        return UnmintableReason.NO_DIGEST
    if _UNSUPPORTED_ARTIFACT in errors:
        return UnmintableReason.UNSUPPORTED
    if result.format_rejected:
        return UnmintableReason.FORMAT_REJECTED
    if _DUPLICATE_IDENTITY in errors:
        return UnmintableReason.DUPLICATE_IDENTITY
    # Minting beside real findings would drop them from the report, and SARIF and HDF
    # withhold every finding they read once the reading has an ERROR.
    if result.observations or result.withheld:
        return UnmintableReason.PARTIAL_READING
    # SECURITY: A code no class accounts for fails closed. An unmintable code that no
    # earlier reason caught counts here too, so it can never fall into a class.
    if not errors <= CLASS_CODES:
        return UnmintableReason.UNKNOWN_CODE
    # A clean scan is the coverage slice's to report, not a detection failure.
    clean_run = any(
        item.level is DiagnosticLevel.INFO and item.code == _RUN_CLEAN
        for item in result.diagnostics
    )
    if (
        errors == {_NO_OBSERVATIONS}
        and clean_run
        and not present & {EXECUTION_UNSUCCESSFUL, _RESULTS_UNKNOWN}
    ):
        return UnmintableReason.CLEAN_SCAN
    return None


def _require_mintable(
    result: IngestResult, classification: FailureClassification
) -> tuple[ArtifactProvenance, FailureClass]:
    """Return the artifact and class of a mintable classification of exactly this result."""
    failure_class = classification.failure_class
    if failure_class is None:
        raise ValueError(f"an unmintable failure ({classification.reason}) has no system record")
    if result.artifact is None or classify_ingest(result) != classification:
        raise ValueError("classification does not describe this result")
    return result.artifact, failure_class


def _raw_order(diagnostic: IngestDiagnostic) -> tuple[str, str, str, str]:
    """Return the order a failed reading's diagnostics are kept in, before the cap."""
    return (
        diagnostic.code,
        diagnostic.location or "",
        diagnostic.message,
        diagnostic.level.value,
    )


# *--- Core Logic ---*


def classify_ingest(result: IngestResult) -> FailureClassification | None:
    """Classify one reading from its codes, levels, and structured fields, never its text.

    Returns None for a reading with no ERROR and no failed invocation. A reading with no
    ERROR and a failed invocation is an execution side record. A reading with an ERROR is
    refused for the first unmintable reason that applies, and otherwise takes the first
    class that matches.
    """
    errors = frozenset(item.code for item in result.errors)
    present = frozenset(item.code for item in result.diagnostics)
    executed = EXECUTION_UNSUCCESSFUL in present
    execution_codes = tuple(sorted(errors | {EXECUTION_UNSUCCESSFUL}))
    if not errors:
        if not executed:
            return None
        return FailureClassification(
            failure_class=FailureClass.EXECUTION,
            reason=None,
            codes=execution_codes,
            side_record=True,
            clock=result.failed_execution_at,
        )

    reason = _unmintable_reason(result, errors, present)
    if reason is not None:
        return FailureClassification.unmintable(reason, errors)

    # Every ERROR code is a class code and there are no observations by here.
    if executed:
        return FailureClassification(
            failure_class=FailureClass.EXECUTION,
            reason=None,
            codes=execution_codes,
            clock=result.failed_execution_at,
        )
    codes = tuple(sorted(errors))
    if errors & PARSE_CODES:
        return FailureClassification(failure_class=FailureClass.PARSE, reason=None, codes=codes)
    if errors & CONTENT_CODES:
        return FailureClassification(failure_class=FailureClass.CONTENT, reason=None, codes=codes)
    # NOTE: Unreachable while CLASS_CODES is PARSE_CODES and CONTENT_CODES; a class code
    # added without a class still fails closed here.
    return FailureClassification.unmintable(UnmintableReason.UNKNOWN_CODE, errors)


def failure_diagnostics(
    result: IngestResult, classification: FailureClassification, *, name: str
) -> tuple[IngestDiagnostic, ...]:
    """Return the diagnostics a recorded failure contributes, at most cap plus two.

    The reading's diagnostics, with each ERROR demoted to a WARNING under the same code,
    are ordered by code, location, message, and level, cut at FAILURE_DIAGNOSTIC_CAP with
    one failure_diagnostics_truncated notice naming the dropped count, and followed by
    detection_failure_recorded. A side record contributes only detection_failure_recorded,
    because its artifact's own diagnostics flow as they do today.
    """
    if not isinstance(name, str):
        raise TypeError("name must be text")
    artifact, failure_class = _require_mintable(result, classification)
    # SECURITY: The name and every message and location are untrusted text, so each is
    # sanitized and cut before it is stored or printed.
    location = diagnostic_text(name)
    recorded = IngestDiagnostic(
        DiagnosticLevel.WARNING,
        DETECTION_FAILURE_RECORDED,
        f"recorded a detection process failure of class {failure_class.value} for source "
        f"artifact sha256:{artifact.digest_sha256} ({DETECTION_FAILURE_RULE})",
        location,
    )
    if classification.side_record:
        return (recorded,)

    source = sorted(result.diagnostics, key=_raw_order)
    kept = source[:FAILURE_DIAGNOSTIC_CAP]
    rendered = [
        IngestDiagnostic(
            DiagnosticLevel.WARNING if item.level is DiagnosticLevel.ERROR else item.level,
            item.code,
            diagnostic_text(item.message),
            diagnostic_text(item.location or name),
        )
        for item in kept
    ]
    dropped = len(source) - len(kept)
    if dropped:
        rendered.append(
            IngestDiagnostic(
                DiagnosticLevel.WARNING,
                FAILURE_DIAGNOSTICS_TRUNCATED,
                f"{dropped} further diagnostic(s) of the failed reading were dropped; the "
                f"first {FAILURE_DIAGNOSTIC_CAP} are kept",
                location,
            )
        )
    rendered.append(recorded)
    return tuple(rendered)


def system_observation_for(
    result: IngestResult,
    classification: FailureClassification,
    *,
    name: str,
    observed_at: datetime,
) -> Observation:
    """Build the one system record of a mintable failure, named by its derived id.

    observed_at is the caller's as-of fallback. An execution failure whose scanner declared
    a clock is observed at that clock instead, and failure.clock says which was used.
    Identity depends on the digest and the observed instant only: never on the name, the
    ingest time, or the failed reading's parser (decision 4).
    """
    if not isinstance(name, str):
        raise TypeError("name must be text")
    artifact, failure_class = _require_mintable(result, classification)
    digest = artifact.digest_sha256
    reference = f"sha256:{digest}"
    clock = classification.clock
    metadata = {
        # SECURITY: The name is the only untrusted text here, sanitized and cut at 512.
        "artifact.name": diagnostic_text(name),
        "artifact.sha256": digest,
        "artifact.sizeBytes": str(artifact.size_bytes),
        "artifact.mediaType": artifact.media_type,
        "artifact.parser": artifact.parser_name,
        "artifact.parserVersion": artifact.parser_version,
        "failure.class": failure_class.value,
        "failure.codes": encode_list(classification.codes),
        "failure.clock": "invocation" if clock is not None else "as-of",
        "failure.rule": DETECTION_FAILURE_RULE,
    }
    # make_observation is artifact-bound, so the record is built by keyword here and then
    # replaced with the id it derives for itself.
    observation = Observation(
        observation_id="pending",
        source_type=DETECTION_FAILURE_SOURCE_TYPE,
        source_tool=DETECTION_FAILURE_SOURCE_TOOL,
        parser_name=DETECTION_FAILURE_PARSER_NAME,
        parser_version=DETECTION_FAILURE_PARSER_VERSION,
        source_record_id=DETECTION_FAILURE_RECORD_ID,
        resource=ResourceRef(resource_id=reference, resource_type=DETECTION_FAILURE_RESOURCE_TYPE),
        observed_at=clock if clock is not None else observed_at,
        ingested_at=artifact.ingested_at,
        disposition=ObservationDisposition.OPEN,
        source_severity=SourceSeverity.UNKNOWN,
        title=DETECTION_FAILURE_TITLE.format(digest=digest),
        description="",
        source_artifact_digest="",
        source_artifact_name="",
        source_identifiers=(),
        source_metadata=tuple(sorted(metadata.items())),
        evidence_ids=(reference,),
        context_key=reference,
        origin=ObservationOrigin.SYSTEM,
    )
    return replace(observation, observation_id=observation.derived_observation_id)
