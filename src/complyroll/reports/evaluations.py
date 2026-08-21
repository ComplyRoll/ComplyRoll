"""Bounded loading of the operator-supplied evaluations file (ADR 0007 Decision 9).

The evaluations file carries the contextual judgement ComplyRoll cannot derive
from a scanner: internet reachability, likely exploitability, PAIN, agency
impact, rationale, and the evaluator who stands behind them. It is untrusted
input and is parsed with the same bounds and duplicate-key rejection as every
other JSON ComplyRoll reads.
"""

from __future__ import annotations

import json
from collections.abc import Iterator
from dataclasses import dataclass
from datetime import datetime
from pathlib import Path
from typing import Any

from complyroll.models import CaseStatus, PainRating

MAX_EVALUATIONS_BYTES = 8 * 1024 * 1024
MAX_EVALUATIONS_DEPTH = 64
MAX_EVALUATIONS_VALUES = 200_000

#: Dispositions that may close a case, per ADR 0007 Decision 4.
CLOSED_DISPOSITIONS = (
    CaseStatus.FULLY_MITIGATED,
    CaseStatus.PARTIALLY_MITIGATED,
    CaseStatus.FALSE_POSITIVE,
    CaseStatus.REMEDIATED,
)

_ROOT_KEYS = frozenset({"$schema", "evaluations"})
_MATCH_KEYS = frozenset({"sourceRecordId", "contextKey", "sourceType"})
_ENTRY_KEYS = frozenset(
    {
        "match",
        "trackingId",
        "completedAt",
        "isInternetReachable",
        "isLikelyExploitable",
        "pain",
        "potentialAgencyImpact",
        "rationale",
        "evaluator",
        "isFalsePositive",
        "disposition",
        "closedDisposition",
        "projectedNextReduction",
        "painReductionEvents",
        "supplementaryRiskInformation",
        "acceptanceRationale",
    }
)


class ReportInputError(ValueError):
    """An operator-supplied report input is malformed or exceeds a bound."""


@dataclass(frozen=True, slots=True)
class EvaluationMatch:
    """Selects the vulnerabilities an evaluation applies to."""

    source_record_id: str
    context_key: str | None = None
    source_type: str | None = None

    def describe(self) -> str:
        parts = [f"sourceRecordId={self.source_record_id!r}"]
        if self.source_type is not None:
            parts.append(f"sourceType={self.source_type!r}")
        if self.context_key is not None:
            parts.append(f"contextKey={self.context_key!r}")
        return ", ".join(parts)


@dataclass(frozen=True, slots=True)
class PainReductionEvent:
    reduced_at: datetime
    rating: PainRating


@dataclass(frozen=True, slots=True)
class ProjectedReduction:
    estimated_at: datetime
    target_rating: PainRating


@dataclass(frozen=True, slots=True)
class EvaluationInput:
    """One completed contextual evaluation supplied by the provider."""

    index: int
    match: EvaluationMatch
    completed_at: datetime
    is_internet_reachable: bool
    is_likely_exploitable: bool
    pain: PainRating
    potential_agency_impact: str
    rationale: str
    evaluator: str
    tracking_id: str | None = None
    is_false_positive: bool = False
    disposition: CaseStatus | None = None
    closed_disposition: CaseStatus | None = None
    projected_next_reduction: ProjectedReduction | None = None
    pain_reduction_events: tuple[PainReductionEvent, ...] = ()
    supplementary_risk_information: str | None = None
    acceptance_rationale: str | None = None

    @property
    def case_status(self) -> CaseStatus | None:
        """Return the recorded status, or None while the vulnerability is active.

        An evaluation that concludes false positive without an explicit
        disposition carries that conclusion, mirroring
        `VulnerabilityCase.with_evaluation`.
        """

        if self.disposition is not None:
            return self.disposition
        if self.is_false_positive:
            return CaseStatus.FALSE_POSITIVE
        return None

    @property
    def resolved_status(self) -> CaseStatus | None:
        """Return the status that decides `finalDisposition`, resolving `closed`."""

        status = self.case_status
        if status is CaseStatus.CLOSED:
            return self.closed_disposition
        return status

    @property
    def location(self) -> str:
        return f"evaluations[{self.index}]"


@dataclass(frozen=True, slots=True)
class EvaluationSet:
    """Every evaluation supplied for one compile run."""

    entries: tuple[EvaluationInput, ...] = ()

    def __len__(self) -> int:
        return len(self.entries)

    def __iter__(self) -> Iterator[EvaluationInput]:
        return iter(self.entries)


def load_evaluations(path: Path) -> EvaluationSet:
    """Read and validate one evaluations file from disk."""

    location = Path(path)
    try:
        size = location.stat().st_size
    except OSError as exc:
        raise ReportInputError(f"evaluations file cannot be read: {exc}") from exc
    if size > MAX_EVALUATIONS_BYTES:
        raise ReportInputError(
            f"evaluations file is {size} bytes; maximum is {MAX_EVALUATIONS_BYTES} bytes"
        )
    try:
        content = location.read_bytes()
    except OSError as exc:
        raise ReportInputError(f"evaluations file cannot be read: {exc}") from exc
    return parse_evaluations(content)


def parse_evaluations(content: bytes) -> EvaluationSet:
    """Validate bounded UTF-8 JSON into immutable evaluation records."""

    value = _parse_json_bounded(content)
    if not isinstance(value, dict):
        raise ReportInputError("evaluations file must contain a JSON object")
    _reject_unknown_keys(value, _ROOT_KEYS, "evaluations file")
    raw_entries = value.get("evaluations")
    if not isinstance(raw_entries, list):
        raise ReportInputError("evaluations must be an array")

    entries: list[EvaluationInput] = []
    for index, raw_entry in enumerate(raw_entries):
        entries.append(_parse_entry(raw_entry, index))
    return EvaluationSet(entries=tuple(entries))


def _parse_entry(raw_entry: Any, index: int) -> EvaluationInput:
    prefix = f"evaluations[{index}]"
    if not isinstance(raw_entry, dict):
        raise ReportInputError(f"{prefix} must be an object")
    _reject_unknown_keys(raw_entry, _ENTRY_KEYS, prefix)

    match = _parse_match(raw_entry.get("match"), prefix)
    disposition = _parse_status(raw_entry.get("disposition"), f"{prefix}.disposition")
    closed_disposition = _parse_status(
        raw_entry.get("closedDisposition"), f"{prefix}.closedDisposition"
    )
    is_false_positive = _parse_optional_bool(
        raw_entry.get("isFalsePositive"), f"{prefix}.isFalsePositive", default=False
    )
    acceptance_rationale = _parse_optional_text(
        raw_entry.get("acceptanceRationale"), f"{prefix}.acceptanceRationale"
    )
    _check_disposition_consistency(
        prefix=prefix,
        disposition=disposition,
        closed_disposition=closed_disposition,
        is_false_positive=is_false_positive,
        acceptance_rationale=acceptance_rationale,
    )

    return EvaluationInput(
        index=index,
        match=match,
        completed_at=_parse_timestamp(raw_entry.get("completedAt"), f"{prefix}.completedAt"),
        is_internet_reachable=_parse_bool(
            raw_entry.get("isInternetReachable"), f"{prefix}.isInternetReachable"
        ),
        is_likely_exploitable=_parse_bool(
            raw_entry.get("isLikelyExploitable"), f"{prefix}.isLikelyExploitable"
        ),
        pain=_parse_rating(raw_entry.get("pain"), f"{prefix}.pain"),
        potential_agency_impact=_parse_text(
            raw_entry.get("potentialAgencyImpact"), f"{prefix}.potentialAgencyImpact"
        ),
        rationale=_parse_text(raw_entry.get("rationale"), f"{prefix}.rationale"),
        evaluator=_parse_text(raw_entry.get("evaluator"), f"{prefix}.evaluator"),
        tracking_id=_parse_optional_text(raw_entry.get("trackingId"), f"{prefix}.trackingId"),
        is_false_positive=is_false_positive,
        disposition=disposition,
        closed_disposition=closed_disposition,
        projected_next_reduction=_parse_projection(
            raw_entry.get("projectedNextReduction"), f"{prefix}.projectedNextReduction"
        ),
        pain_reduction_events=_parse_reduction_events(
            raw_entry.get("painReductionEvents"), f"{prefix}.painReductionEvents"
        ),
        supplementary_risk_information=_parse_optional_text(
            raw_entry.get("supplementaryRiskInformation"),
            f"{prefix}.supplementaryRiskInformation",
        ),
        acceptance_rationale=acceptance_rationale,
    )


def _check_disposition_consistency(
    *,
    prefix: str,
    disposition: CaseStatus | None,
    closed_disposition: CaseStatus | None,
    is_false_positive: bool,
    acceptance_rationale: str | None,
) -> None:
    if disposition is CaseStatus.CLOSED:
        if closed_disposition is None:
            raise ReportInputError(
                f"{prefix}.closedDisposition is required when disposition is 'closed'"
            )
        if closed_disposition not in CLOSED_DISPOSITIONS:
            allowed = ", ".join(status.value for status in CLOSED_DISPOSITIONS)
            raise ReportInputError(f"{prefix}.closedDisposition must be one of: {allowed}")
    elif closed_disposition is not None:
        raise ReportInputError(
            f"{prefix}.closedDisposition is only valid when disposition is 'closed'"
        )

    if disposition is CaseStatus.ACCEPTED:
        if acceptance_rationale is None:
            raise ReportInputError(
                f"{prefix}.acceptanceRationale is required when disposition is 'accepted'"
            )
    elif acceptance_rationale is not None:
        raise ReportInputError(
            f"{prefix}.acceptanceRationale is only valid when disposition is 'accepted'"
        )

    if is_false_positive and disposition is not None:
        resolved = closed_disposition if disposition is CaseStatus.CLOSED else disposition
        if resolved is not CaseStatus.FALSE_POSITIVE:
            raise ReportInputError(
                f"{prefix}.isFalsePositive contradicts disposition {disposition.value!r}"
            )


def _parse_match(value: Any, prefix: str) -> EvaluationMatch:
    if value is None:
        raise ReportInputError(f"{prefix}.match is required")
    if not isinstance(value, dict):
        raise ReportInputError(f"{prefix}.match must be an object")
    _reject_unknown_keys(value, _MATCH_KEYS, f"{prefix}.match")
    return EvaluationMatch(
        source_record_id=_parse_text(
            value.get("sourceRecordId"), f"{prefix}.match.sourceRecordId"
        ),
        context_key=_parse_optional_text(value.get("contextKey"), f"{prefix}.match.contextKey"),
        source_type=_parse_optional_text(value.get("sourceType"), f"{prefix}.match.sourceType"),
    )


def _parse_projection(value: Any, prefix: str) -> ProjectedReduction | None:
    if value is None:
        return None
    if not isinstance(value, dict):
        raise ReportInputError(f"{prefix} must be an object")
    _reject_unknown_keys(value, frozenset({"estimatedAt", "targetRating"}), prefix)
    return ProjectedReduction(
        estimated_at=_parse_timestamp(value.get("estimatedAt"), f"{prefix}.estimatedAt"),
        target_rating=_parse_rating(value.get("targetRating"), f"{prefix}.targetRating"),
    )


def _parse_reduction_events(value: Any, prefix: str) -> tuple[PainReductionEvent, ...]:
    if value is None:
        return ()
    if not isinstance(value, list):
        raise ReportInputError(f"{prefix} must be an array")
    events: list[PainReductionEvent] = []
    for index, raw_event in enumerate(value):
        item_prefix = f"{prefix}[{index}]"
        if not isinstance(raw_event, dict):
            raise ReportInputError(f"{item_prefix} must be an object")
        _reject_unknown_keys(raw_event, frozenset({"reducedAt", "rating"}), item_prefix)
        events.append(
            PainReductionEvent(
                reduced_at=_parse_timestamp(raw_event.get("reducedAt"), f"{item_prefix}.reducedAt"),
                rating=_parse_rating(raw_event.get("rating"), f"{item_prefix}.rating"),
            )
        )
    return tuple(events)


def _parse_status(value: Any, field_name: str) -> CaseStatus | None:
    if value is None:
        return None
    if not isinstance(value, str):
        raise ReportInputError(f"{field_name} must be text")
    try:
        return CaseStatus(value)
    except ValueError as exc:
        allowed = ", ".join(status.value for status in CaseStatus)
        raise ReportInputError(f"{field_name} must be one of: {allowed}") from exc


def _parse_rating(value: Any, field_name: str) -> PainRating:
    if isinstance(value, bool) or not isinstance(value, int):
        raise ReportInputError(f"{field_name} must be an integer from 1 to 5")
    try:
        return PainRating(value)
    except ValueError as exc:
        raise ReportInputError(f"{field_name} must be an integer from 1 to 5") from exc


def _parse_bool(value: Any, field_name: str) -> bool:
    if not isinstance(value, bool):
        raise ReportInputError(f"{field_name} is required and must be true or false")
    return value


def _parse_optional_bool(value: Any, field_name: str, *, default: bool) -> bool:
    if value is None:
        return default
    if not isinstance(value, bool):
        raise ReportInputError(f"{field_name} must be true or false")
    return value


def _parse_text(value: Any, field_name: str) -> str:
    if not isinstance(value, str) or not value.strip():
        raise ReportInputError(f"{field_name} is required and must be non-blank text")
    return value


def _parse_optional_text(value: Any, field_name: str) -> str | None:
    if value is None:
        return None
    if not isinstance(value, str) or not value.strip():
        raise ReportInputError(f"{field_name} must be non-blank text when present")
    return value


def _parse_timestamp(value: Any, field_name: str) -> datetime:
    if not isinstance(value, str) or not value.strip():
        raise ReportInputError(f"{field_name} is required and must be an RFC 3339 timestamp")
    return parse_rfc3339(value, field_name)


def parse_rfc3339(value: str, field_name: str) -> datetime:
    """Parse an RFC 3339 timestamp, requiring an explicit UTC offset."""

    text = value.strip()
    if text.endswith(("Z", "z")):
        text = f"{text[:-1]}+00:00"
    try:
        timestamp = datetime.fromisoformat(text)
    except ValueError as exc:
        raise ReportInputError(
            f"{field_name} must be an RFC 3339 timestamp, got {value!r}"
        ) from exc
    if timestamp.tzinfo is None or timestamp.utcoffset() is None:
        raise ReportInputError(f"{field_name} must include a UTC offset, got {value!r}")
    return timestamp


def _reject_unknown_keys(value: dict[str, Any], allowed: frozenset[str], prefix: str) -> None:
    unknown = sorted(set(value) - allowed)
    if unknown:
        raise ReportInputError(f"{prefix} has unsupported field(s): {', '.join(unknown)}")


def _parse_json_bounded(content: bytes) -> Any:
    if not isinstance(content, bytes):
        raise TypeError("content must be bytes")
    if len(content) > MAX_EVALUATIONS_BYTES:
        raise ReportInputError(
            f"evaluations file is {len(content)} bytes; "
            f"maximum is {MAX_EVALUATIONS_BYTES} bytes"
        )

    def reject_nonstandard_constant(value: str) -> None:
        raise ReportInputError(f"non-standard JSON constant is prohibited: {value}")

    def reject_duplicate_keys(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
        value: dict[str, Any] = {}
        for key, item in pairs:
            if key in value:
                raise ReportInputError(f"duplicate JSON object key is prohibited: {key}")
            value[key] = item
        return value

    try:
        value = json.loads(
            content.decode("utf-8"),
            parse_constant=reject_nonstandard_constant,
            object_pairs_hook=reject_duplicate_keys,
        )
    except UnicodeDecodeError as exc:
        raise ReportInputError("evaluations file must be UTF-8 JSON") from exc
    except json.JSONDecodeError as exc:
        raise ReportInputError(f"evaluations file contains malformed JSON: {exc}") from exc
    except RecursionError as exc:
        raise ReportInputError("evaluations file exceeds the safe JSON recursion limit") from exc

    values_seen = 0
    stack: list[tuple[Any, int]] = [(value, 1)]
    while stack:
        current, depth = stack.pop()
        values_seen += 1
        if values_seen > MAX_EVALUATIONS_VALUES:
            raise ReportInputError(
                f"evaluations file contains more than {MAX_EVALUATIONS_VALUES} JSON values"
            )
        if depth > MAX_EVALUATIONS_DEPTH:
            raise ReportInputError(
                f"evaluations file exceeds {MAX_EVALUATIONS_DEPTH} levels of JSON nesting"
            )
        if isinstance(current, dict):
            stack.extend((item, depth + 1) for item in current.values())
        elif isinstance(current, list):
            stack.extend((item, depth + 1) for item in current)
    return value
