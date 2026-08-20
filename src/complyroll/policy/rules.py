"""Class-aware VDR and VER policy selection from pinned FedRAMP rules."""

from __future__ import annotations

import calendar
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from decimal import Decimal, InvalidOperation
from enum import Enum
from typing import Any

from complyroll.models import PainRating

from .source import RuleSourceSnapshot, load_bundled_rule_source_snapshot


class PolicyDataError(ValueError):
    """The verified policy snapshot has an unsupported or malformed rule shape."""


class PolicyRuleNotFoundError(PolicyDataError):
    """A required rule was not selected for the certification profile."""


class UnsupportedTimeframeError(PolicyDataError):
    """A source timeframe cannot be calculated without an explicit policy."""


class CertificationClass(str, Enum):
    B = "B"
    C = "C"


class CertificationType(str, Enum):
    TWENTY_X = "20x"


class CertificationPath(str, Enum):
    PROGRAM = "Program"


class RuleForce(str, Enum):
    MUST = "MUST"
    MUST_NOT = "MUST NOT"
    SHOULD = "SHOULD"
    SHOULD_NOT = "SHOULD NOT"
    MAY = "MAY"


class TimeframeUnit(str, Enum):
    BUSINESS_DAYS = "bizdays"
    DAYS = "days"
    HOURS = "hours"
    WEEKS = "weeks"
    MONTHS = "months"
    YEARS = "years"


class ResponseContext(str, Enum):
    INTERNET_REACHABLE_LIKELY_EXPLOITABLE = "irv_lev"
    NOT_INTERNET_REACHABLE_LIKELY_EXPLOITABLE = "nirv_lev"
    NOT_LIKELY_EXPLOITABLE = "nlev"


@dataclass(frozen=True, slots=True)
class CertificationProfile:
    certification_class: CertificationClass
    certification_type: CertificationType = CertificationType.TWENTY_X
    certification_path: CertificationPath = CertificationPath.PROGRAM
    affected_party: str = "Providers"

    def __post_init__(self) -> None:
        if not isinstance(self.certification_class, CertificationClass):
            raise TypeError("certification_class must be a CertificationClass")
        if not isinstance(self.certification_type, CertificationType):
            raise TypeError("certification_type must be a CertificationType")
        if not isinstance(self.certification_path, CertificationPath):
            raise TypeError("certification_path must be a CertificationPath")
        if not isinstance(self.affected_party, str) or not self.affected_party.strip():
            raise ValueError("affected_party must be non-blank text")


@dataclass(frozen=True, slots=True)
class PolicyProvenance:
    repository: str
    commit: str
    dataset_version: str
    dataset_last_updated: str
    dataset_sha256: str


@dataclass(frozen=True, slots=True)
class RuleTimeframe:
    amount: Decimal
    unit: TimeframeUnit

    def __post_init__(self) -> None:
        if not isinstance(self.amount, Decimal):
            raise TypeError("timeframe amount must be a Decimal")
        if not isinstance(self.unit, TimeframeUnit):
            raise TypeError("timeframe unit must be a TimeframeUnit")
        if self.amount <= 0:
            raise ValueError("timeframe amount must be positive")

    @property
    def display_amount(self) -> int | str:
        """Return an integer where exact, otherwise a non-exponent decimal string."""

        if self.amount == self.amount.to_integral_value():
            return int(self.amount)
        return format(self.amount, "f")

    def deadline_from(self, start: datetime) -> datetime:
        """Calculate a UTC deadline using the source unit's explicit semantics."""

        normalized = _require_aware_utc(start, "start")
        if self.unit is TimeframeUnit.BUSINESS_DAYS:
            raise UnsupportedTimeframeError(
                "business-day deadlines require an explicit holiday and timezone calendar"
            )
        if self.unit is TimeframeUnit.HOURS:
            return normalized + _decimal_timedelta(self.amount, seconds_per_unit=3_600)
        if self.unit is TimeframeUnit.DAYS:
            return normalized + _decimal_timedelta(self.amount, seconds_per_unit=86_400)
        if self.unit is TimeframeUnit.WEEKS:
            return normalized + _decimal_timedelta(self.amount, seconds_per_unit=604_800)
        if self.unit is TimeframeUnit.MONTHS:
            return _add_calendar_months(normalized, _require_integral(self.amount, "months"))
        if self.unit is TimeframeUnit.YEARS:
            years = _require_integral(self.amount, "years")
            return _add_calendar_months(normalized, years * 12)
        raise AssertionError(f"unhandled timeframe unit: {self.unit}")


@dataclass(frozen=True, slots=True)
class PainTimeframe:
    pain: PainRating
    context: ResponseContext
    timeframe: RuleTimeframe
    description: str


@dataclass(frozen=True, slots=True)
class SelectedRule:
    rule_id: str
    document_id: str
    subset_id: str
    source_scope: str
    name: str
    statement: str
    force: RuleForce
    timeframe: RuleTimeframe | None
    pain_timeframes: tuple[PainTimeframe, ...] = ()

    def response_timeframe(
        self,
        pain: PainRating,
        context: ResponseContext,
    ) -> PainTimeframe | None:
        """Return one class-selected PAIN target, or None for routine N1 work."""

        for target in self.pain_timeframes:
            if target.pain is pain and target.context is context:
                return target
        return None


@dataclass(frozen=True, slots=True)
class PolicyDeadline:
    rule_id: str
    rule_name: str
    force: RuleForce
    start_at: datetime
    due_at: datetime
    timeframe: RuleTimeframe
    profile: CertificationProfile
    provenance: PolicyProvenance
    description: str = ""


@dataclass(frozen=True, slots=True)
class SelectedPolicy:
    """Provider rules selected for one supported FedRAMP 20x profile."""

    profile: CertificationProfile
    provenance: PolicyProvenance
    rules: tuple[SelectedRule, ...]

    def rule(self, rule_id: str) -> SelectedRule:
        for rule in self.rules:
            if rule.rule_id == rule_id:
                return rule
        raise PolicyRuleNotFoundError(
            f"rule {rule_id!r} is not selected for Class {self.profile.certification_class.value}"
        )

    def deadline_for_rule(self, rule_id: str, start: datetime) -> PolicyDeadline:
        """Calculate a deadline for a selected rule with one direct timeframe."""

        rule = self.rule(rule_id)
        if rule.timeframe is None:
            raise PolicyDataError(f"rule {rule_id} does not define one direct timeframe")
        return self._deadline(rule, start, rule.timeframe)

    def evaluation_deadline(self, detected_at: datetime) -> PolicyDeadline:
        """Return the class-aware evaluation deadline from VER-TFR-EVU."""

        return self.deadline_for_rule("VER-TFR-EVU", detected_at)

    def acceptance_deadline(self, evaluated_at: datetime) -> PolicyDeadline:
        """Return the categorization threshold from VER-TFR-MAV.

        This deadline flags that a provider decision is required; it does not accept risk.
        """

        return self.deadline_for_rule("VER-TFR-MAV", evaluated_at)

    def response_deadline(
        self,
        evaluated_at: datetime,
        *,
        pain: PainRating,
        is_internet_reachable: bool,
        is_likely_exploitable: bool,
    ) -> PolicyDeadline | None:
        """Return the selected mitigation/remediation target from VDR-TFR-PVR."""

        if not isinstance(pain, PainRating):
            raise TypeError("pain must be a PainRating")
        _require_bool(is_internet_reachable, "is_internet_reachable")
        _require_bool(is_likely_exploitable, "is_likely_exploitable")
        rule = self.rule("VDR-TFR-PVR")
        context = _response_context(
            is_internet_reachable=is_internet_reachable,
            is_likely_exploitable=is_likely_exploitable,
        )
        target = rule.response_timeframe(pain, context)
        if target is None:
            if pain is PainRating.N1:
                return None
            raise PolicyDataError(
                f"rule {rule.rule_id} has no timeframe for PAIN {pain.name} and {context.value}"
            )
        return self._deadline(
            rule,
            evaluated_at,
            target.timeframe,
            description=target.description,
        )

    def _deadline(
        self,
        rule: SelectedRule,
        start: datetime,
        timeframe: RuleTimeframe,
        *,
        description: str = "",
    ) -> PolicyDeadline:
        normalized_start = _require_aware_utc(start, "start")
        return PolicyDeadline(
            rule_id=rule.rule_id,
            rule_name=rule.name,
            force=rule.force,
            start_at=normalized_start,
            due_at=timeframe.deadline_from(normalized_start),
            timeframe=timeframe,
            profile=self.profile,
            provenance=self.provenance,
            description=description,
        )


def load_bundled_policy(profile: CertificationProfile) -> SelectedPolicy:
    """Load the verified offline source and select policy for one profile."""

    return select_policy(load_bundled_rule_source_snapshot(), profile)


def select_policy(
    snapshot: RuleSourceSnapshot,
    profile: CertificationProfile,
) -> SelectedPolicy:
    """Select provider-facing VDR and VER rules using official applicability data."""

    if not isinstance(snapshot, RuleSourceSnapshot):
        raise TypeError("snapshot must be a RuleSourceSnapshot")
    if not isinstance(profile, CertificationProfile):
        raise TypeError("profile must be a CertificationProfile")
    frr = _require_mapping(snapshot.data.get("FRR"), "FRR")
    selected: list[SelectedRule] = []
    seen_rule_ids: set[str] = set()

    for document_id in ("VDR", "VER"):
        document = _require_mapping(frr.get(document_id), document_id)
        info = _require_mapping(document.get("info"), f"{document_id}.info")
        subsets = _require_mapping(info.get("subsets"), f"{document_id}.info.subsets")
        data = _require_mapping(document.get("data"), f"{document_id}.data")

        for source_scope in ("all", profile.certification_type.value):
            scoped_data = data.get(source_scope, {})
            if not isinstance(scoped_data, dict):
                raise PolicyDataError(f"{document_id}.data.{source_scope} must be an object")
            for subset_id, raw_rules in scoped_data.items():
                subset = _require_mapping(
                    subsets.get(subset_id),
                    f"{document_id}.info.subsets.{subset_id}",
                )
                applicability = _require_mapping(
                    subset.get("applicability"),
                    f"{document_id}.info.subsets.{subset_id}.applicability",
                )
                if not _applies_to_profile(applicability, profile):
                    continue
                rules = _require_mapping(
                    raw_rules,
                    f"{document_id}.data.{source_scope}.{subset_id}",
                )
                for rule_id, raw_rule in rules.items():
                    if rule_id in seen_rule_ids:
                        raise PolicyDataError(f"duplicate selected rule identifier: {rule_id}")
                    selected_rule = _select_rule(
                        rule_id=rule_id,
                        document_id=document_id,
                        subset_id=subset_id,
                        source_scope=source_scope,
                        raw_rule=_require_mapping(raw_rule, rule_id),
                        certification_class=profile.certification_class,
                    )
                    selected.append(selected_rule)
                    seen_rule_ids.add(rule_id)

    required_rule_ids = {"VDR-TFR-PVR", "VER-TFR-EVU", "VER-TFR-MAV"}
    missing = required_rule_ids - seen_rule_ids
    if missing:
        raise PolicyDataError(
            "selected policy is missing required operational rules: " + ", ".join(sorted(missing))
        )

    manifest = snapshot.manifest
    return SelectedPolicy(
        profile=profile,
        provenance=PolicyProvenance(
            repository=manifest.repository,
            commit=manifest.commit,
            dataset_version=manifest.dataset_version,
            dataset_last_updated=manifest.dataset_last_updated,
            dataset_sha256=snapshot.content_sha256,
        ),
        rules=tuple(sorted(selected, key=lambda rule: rule.rule_id)),
    )


def _select_rule(
    *,
    rule_id: str,
    document_id: str,
    subset_id: str,
    source_scope: str,
    raw_rule: dict[str, Any],
    certification_class: CertificationClass,
) -> SelectedRule:
    name = _require_text(raw_rule.get("name"), f"{rule_id}.name")
    varies = raw_rule.get("varies_by_class")
    if varies is None:
        level = raw_rule
    else:
        levels = _require_mapping(varies, f"{rule_id}.varies_by_class")
        level = _require_mapping(
            levels.get(certification_class.value.lower()),
            f"{rule_id}.varies_by_class.{certification_class.value.lower()}",
        )

    force_text = _require_text(level.get("force"), f"{rule_id}.force")
    try:
        force = RuleForce(force_text)
    except ValueError as exc:
        raise PolicyDataError(f"{rule_id}.force has unsupported value {force_text!r}") from exc
    statement = _require_text(level.get("statement"), f"{rule_id}.statement")
    timeframe = _parse_optional_timeframe(level, rule_id)
    pain_timeframes = _parse_pain_timeframes(level.get("pain_timeframes"), rule_id)
    return SelectedRule(
        rule_id=rule_id,
        document_id=document_id,
        subset_id=subset_id,
        source_scope=source_scope,
        name=name,
        statement=statement,
        force=force,
        timeframe=timeframe,
        pain_timeframes=pain_timeframes,
    )


def _parse_optional_timeframe(
    value: dict[str, Any],
    field_prefix: str,
) -> RuleTimeframe | None:
    unit = value.get("timeframe_type")
    amount = value.get("timeframe_num")
    if unit is None and amount is None:
        return None
    if unit is None or amount is None:
        raise PolicyDataError(
            f"{field_prefix} must provide timeframe_type and timeframe_num together"
        )
    return _parse_timeframe(unit, amount, field_prefix)


def _parse_pain_timeframes(
    value: Any,
    field_prefix: str,
) -> tuple[PainTimeframe, ...]:
    if value is None:
        return ()
    groups = _require_mapping(value, f"{field_prefix}.pain_timeframes")
    targets: list[PainTimeframe] = []
    for pain_value in range(1, 6):
        group = _require_mapping(
            groups.get(str(pain_value)),
            f"{field_prefix}.pain_timeframes.{pain_value}",
        )
        for context_text, raw_target in group.items():
            try:
                context = ResponseContext(context_text)
            except ValueError as exc:
                raise PolicyDataError(
                    f"{field_prefix} has unsupported response context {context_text!r}"
                ) from exc
            target = _require_mapping(
                raw_target,
                f"{field_prefix}.pain_timeframes.{pain_value}.{context_text}",
            )
            targets.append(
                PainTimeframe(
                    pain=PainRating(pain_value),
                    context=context,
                    timeframe=_parse_timeframe(
                        target.get("timeframe_type"),
                        target.get("timeframe_num"),
                        f"{field_prefix}.pain_timeframes.{pain_value}.{context_text}",
                    ),
                    description=_require_text(
                        target.get("description"),
                        f"{field_prefix}.pain_timeframes.{pain_value}.{context_text}.description",
                    ),
                )
            )
    return tuple(targets)


def _parse_timeframe(unit: Any, amount: Any, field_prefix: str) -> RuleTimeframe:
    try:
        selected_unit = TimeframeUnit(unit)
    except (TypeError, ValueError) as exc:
        raise PolicyDataError(f"{field_prefix}.timeframe_type is unsupported: {unit!r}") from exc
    if isinstance(amount, bool) or not isinstance(amount, (int, float)):
        raise PolicyDataError(f"{field_prefix}.timeframe_num must be a number")
    try:
        selected_amount = Decimal(str(amount))
    except InvalidOperation as exc:
        raise PolicyDataError(f"{field_prefix}.timeframe_num is invalid") from exc
    if not selected_amount.is_finite() or selected_amount <= 0:
        raise PolicyDataError(f"{field_prefix}.timeframe_num must be positive and finite")
    return RuleTimeframe(amount=selected_amount, unit=selected_unit)


def _applies_to_profile(
    applicability: dict[str, Any],
    profile: CertificationProfile,
) -> bool:
    types = _require_text_list(applicability.get("types"), "applicability.types")
    paths = _require_text_list(applicability.get("paths"), "applicability.paths")
    classes = _require_text_list(applicability.get("classes"), "applicability.classes")
    affects = _require_text_list(applicability.get("affects"), "applicability.affects")
    return (
        profile.certification_type.value in types
        and profile.certification_path.value in paths
        and profile.certification_class.value in classes
        and profile.affected_party in affects
    )


def _response_context(
    *,
    is_internet_reachable: bool,
    is_likely_exploitable: bool,
) -> ResponseContext:
    if not is_likely_exploitable:
        return ResponseContext.NOT_LIKELY_EXPLOITABLE
    if is_internet_reachable:
        return ResponseContext.INTERNET_REACHABLE_LIKELY_EXPLOITABLE
    return ResponseContext.NOT_INTERNET_REACHABLE_LIKELY_EXPLOITABLE


def _require_mapping(value: Any, field_name: str) -> dict[str, Any]:
    if not isinstance(value, dict):
        raise PolicyDataError(f"{field_name} must be an object")
    return value


def _require_text(value: Any, field_name: str) -> str:
    if not isinstance(value, str) or not value.strip():
        raise PolicyDataError(f"{field_name} must be non-blank text")
    return value


def _require_text_list(value: Any, field_name: str) -> tuple[str, ...]:
    if not isinstance(value, list) or any(not isinstance(item, str) for item in value):
        raise PolicyDataError(f"{field_name} must be an array of strings")
    return tuple(value)


def _require_bool(value: Any, field_name: str) -> None:
    if not isinstance(value, bool):
        raise TypeError(f"{field_name} must be a boolean")


def _require_aware_utc(value: datetime, field_name: str) -> datetime:
    if not isinstance(value, datetime) or value.tzinfo is None or value.utcoffset() is None:
        raise ValueError(f"{field_name} must include a timezone")
    return value.astimezone(UTC)


def _require_integral(value: Decimal, unit: str) -> int:
    if value != value.to_integral_value():
        raise UnsupportedTimeframeError(f"fractional calendar {unit} are not supported")
    return int(value)


def _decimal_timedelta(amount: Decimal, *, seconds_per_unit: int) -> timedelta:
    microseconds = amount * seconds_per_unit * 1_000_000
    if microseconds != microseconds.to_integral_value():
        raise UnsupportedTimeframeError("timeframe is more precise than one microsecond")
    return timedelta(microseconds=int(microseconds))


def _add_calendar_months(value: datetime, months: int) -> datetime:
    month_index = value.year * 12 + (value.month - 1) + months
    year, zero_based_month = divmod(month_index, 12)
    month = zero_based_month + 1
    day = min(value.day, calendar.monthrange(year, month)[1])
    return value.replace(year=year, month=month, day=day)
