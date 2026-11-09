# ******************************************************************************
# *Title: Change Obligation Tests*
# *Author: Kyle Versluis*
# *Description: Unit tests for per-change detection obligations.*
# ******************************************************************************
"""Tests for the change projection: matching, the status table, evidence, and its warnings."""

# *--- Imports ---*

from __future__ import annotations

import copy
import dataclasses
import json
import random
import unittest
from collections.abc import Iterable, Sequence
from datetime import UTC, date, datetime, timedelta
from functools import cache
from typing import Any
from unittest import mock

from complyroll.correlation import tracking_id_for
from complyroll.models import (
    Observation,
    ObservationDisposition,
    ObservationOrigin,
    ResourceRef,
)
from complyroll.policy import (
    CertificationClass,
    CertificationProfile,
    PolicyRuleNotFoundError,
    RuleForce,
    SelectedPolicy,
    load_bundled_policy,
)
from complyroll.reports import KevCatalog, KevEntry, parse_changes, parse_inventory
from complyroll.reports.changes import (
    CHANGE_BASIS,
    DAC_RULE,
    WAITING_STATUSES,
    ChangeObligation,
    ChangeProjection,
    ObligationStatus,
    derive_changes,
)
from complyroll.reports.changes_input import ChangeSet
from complyroll.reports.coverage import (
    CYCLONEDX_SCOPE_RECORD_ID,
    CYCLONEDX_SOURCE_TYPE,
    PSD_RULE,
    EvidenceKind,
    FiledEvidence,
    file_evidence,
)
from complyroll.reports.inventory import Inventory

# *--- Fixtures ---*

SINCE = datetime(2026, 7, 1, tzinfo=UTC)
T = datetime(2026, 9, 1, 12, tzinfo=UTC)
AS_OF = datetime(2026, 9, 10, tzinfo=UTC)
INGESTED_AT = datetime(2026, 9, 11, tzinfo=UTC)
HOUR = timedelta(hours=1)
SECOND = timedelta(seconds=1)
DIGEST = "a" * 64
OTHER_DIGEST = "b" * 64
PASS = ObservationDisposition.PASS
OPEN = ObservationDisposition.OPEN
CVE = "CVE-2026-0001"
LAB = ResourceRef("lab-01", "host")
GROUP_REF = ResourceRef("sample-group/web", "logical")
ALIAS = {"resourceType": "host", "resourceId": "lab-01.internal"}
ALIAS_REF = ResourceRef("lab-01.internal", "host")


def text(at: datetime) -> str:
    return at.isoformat()


def pair(resource_id: str = "lab-01", resource_type: str = "host") -> dict[str, str]:
    return {"resourceType": resource_type, "resourceId": resource_id}


GROUP_PAIR = pair("sample-group/web", "logical")


def host(resource_id: str = "lab-01", **fields: Any) -> dict[str, Any]:
    return {
        "resourceType": "host",
        "resourceId": resource_id,
        "machineBased": True,
        "driftLikely": False,
        "expectedSince": text(SINCE),
        **fields,
    }


def procedure(resource_id: str = "ir-plan", **fields: Any) -> dict[str, Any]:
    return {
        "resourceType": "logical",
        "resourceId": resource_id,
        "machineBased": False,
        "expectedSince": text(SINCE),
        **fields,
    }


def change(change_id: str = "CHG-1", *resources: dict[str, str], **fields: Any) -> dict[str, Any]:
    value: dict[str, Any] = {
        "changeId": change_id,
        "kind": "modified",
        "occurredAt": text(T),
        "source": {"tool": "git", "reference": "commit 0123abc"},
        "resources": list(resources) or [pair()],
        "significant": True,
        "rationale": "Kernel upgrade.",
    }
    value.update(fields)
    return value


def inventory_of(*entries: dict[str, Any]) -> Inventory:
    return parse_inventory(
        json.dumps(
            {
                "schema": "complyroll.inventory",
                "schemaVersion": 1,
                "name": "change-tests",
                "resources": list(entries),
            }
        ).encode("utf-8")
    )


def changes_of(*changes: dict[str, Any]) -> ChangeSet:
    return parse_changes(
        json.dumps(
            {
                "schema": "complyroll.changes",
                "schemaVersion": 1,
                "name": "change-file",
                "changes": list(changes),
            }
        ).encode("utf-8")
    )


def observation(
    resource_id: str = "lab-01",
    at: datetime | None = T,
    disposition: ObservationDisposition = PASS,
    *,
    resource_type: str = "host",
    record: str = "R-1",
    digest: str = DIGEST,
    identifiers: Sequence[str] = (),
    source_type: str = "sarif",
    context: str = "synthetic",
) -> Observation:
    stamp = "untimed" if at is None else at.isoformat()
    return Observation(
        observation_id=f"obs/{resource_type}/{resource_id}/{stamp}/{record}/{digest[:4]}",
        source_type=source_type,
        source_tool="synthetic-scanner",
        parser_name="complyroll.test",
        parser_version="1",
        source_record_id=record,
        resource=ResourceRef(resource_id=resource_id, resource_type=resource_type),
        observed_at=at,
        ingested_at=INGESTED_AT,
        disposition=disposition,
        source_artifact_digest=digest,
        source_artifact_name="synthetic.sarif",
        source_identifiers=tuple(identifiers),
        context_key=context,
    )


def system_observation(resource_id: str = "lab-01", at: datetime = T) -> Observation:
    return Observation(
        observation_id=f"sys/{resource_id}/{at.isoformat()}",
        source_type="complyroll.synthetic-other",
        source_tool="complyroll",
        parser_name="complyroll.synthetic-other",
        parser_version="1",
        source_record_id="synthetic-other",
        resource=ResourceRef(resource_id=resource_id, resource_type="host"),
        observed_at=at,
        ingested_at=INGESTED_AT,
        disposition=PASS,
        context_key="synthetic-other",
        origin=ObservationOrigin.SYSTEM,
    )


@cache
def policy(class_name: str = "B") -> SelectedPolicy:
    profile = CertificationProfile(CertificationClass(class_name), calendar_timezone="UTC")
    return load_bundled_policy(profile)


def catalog(date_added: date = date(2026, 8, 1), cve_id: str = CVE) -> KevCatalog:
    entry = KevEntry(cve_id=cve_id, date_added=date_added, due_date=date(2026, 8, 22))
    return KevCatalog(
        name="kev.json",
        sha256="c" * 64,
        size_bytes=1,
        catalog_version="2026.09.01",
        date_released=datetime(2026, 9, 1, tzinfo=UTC),
        declared_count=1,
        entries=(entry,),
    )


def run(
    entries: Sequence[dict[str, Any]],
    changes: Sequence[dict[str, Any]],
    observations: Iterable[Observation] = (),
    as_of: datetime = AS_OF,
    *,
    kev: KevCatalog | None = None,
    selected: SelectedPolicy | None = None,
) -> ChangeProjection:
    return derive_changes(
        observations,
        changes_of(*changes),
        inventory_of(*entries),
        selected or policy(),
        as_of,
        kev_catalog=kev,
    )


def only(projection: ChangeProjection) -> ChangeObligation:
    if len(projection.obligations) != 1:
        raise AssertionError(f"expected one row, got {len(projection.obligations)}")
    return projection.obligations[0]


def codes(projection: ChangeProjection) -> list[str]:
    return [item.code for item in projection.warnings]


# *--- Status Table ---*


class StatusTableTests(unittest.TestCase):
    def test_row_1_no_entry_and_no_group_is_unregistered(self) -> None:
        row = only(run([host()], [change("CHG-1", pair("elsewhere"))]))
        self.assertIs(row.status, ObligationStatus.UNREGISTERED)
        self.assertEqual(row.resource, ResourceRef("elsewhere", "host"))
        self.assertIsNone(row.entry)
        self.assertIsNone(row.matched_as)

    def test_row_2_decommissioned_before_the_change_is_retired_and_warns(self) -> None:
        projection = run([host(decommissionedAt=text(T - SECOND))], [change()])
        self.assertIs(only(projection).status, ObligationStatus.RETIRED)
        self.assertEqual(codes(projection), ["change_after_decommission"])
        self.assertEqual(projection.warnings[0].location, "change-file CHG-1 host:lab-01")

    def test_row_2_reads_before_a_non_significant_change_is_logged(self) -> None:
        projection = run([host(decommissionedAt=text(T - SECOND))], [change(significant=False)])
        self.assertIs(only(projection).status, ObligationStatus.RETIRED)
        self.assertEqual(codes(projection), ["change_after_decommission"])

    def test_row_3_decommissioned_with_no_window_is_retired_without_warning(self) -> None:
        for name, instant in (("at the change", T), ("after the change", T + HOUR)):
            with self.subTest(name=name):
                projection = run([host(decommissionedAt=text(instant))], [change()])
                self.assertIs(only(projection).status, ObligationStatus.RETIRED)
                self.assertEqual(projection.warnings, ())

    def test_row_3_decommissioned_inside_the_window_is_retired(self) -> None:
        projection = run(
            [host(decommissionedAt=text(T + HOUR))],
            [change(detectBy=text(T + HOUR + SECOND))],
        )
        self.assertIs(only(projection).status, ObligationStatus.RETIRED)
        self.assertIsNone(only(projection).window_closed_at)

    def test_a_window_at_or_before_decommission_closes_as_usual(self) -> None:
        for name, instant in (("on the due date", T + HOUR), ("after it", T + 2 * HOUR)):
            with self.subTest(name=name):
                row = only(
                    run(
                        [host(decommissionedAt=text(instant))],
                        [change(detectBy=text(T + HOUR))],
                    )
                )
                self.assertIs(row.status, ObligationStatus.LAPSED)
                self.assertEqual(row.window_closed_at, T + HOUR)

    def test_a_window_that_closes_at_the_change_and_the_decommission_lapses(self) -> None:
        row = only(run([host(decommissionedAt=text(T))], [change(detectBy=text(T))]))
        self.assertIs(row.status, ObligationStatus.LAPSED)

    def test_row_4_non_significant_modification_is_logged(self) -> None:
        row = only(run([host()], [change(significant=False)], [observation(at=T + HOUR)]))
        self.assertIs(row.status, ObligationStatus.LOGGED)
        self.assertIsNone(row.evidence)
        self.assertEqual(row.entry.ref, LAB)  # type: ignore[union-attr]

    def test_a_created_change_opens_whatever_significant_says(self) -> None:
        row = only(run([host()], [change(kind="created", significant=False)]))
        self.assertIs(row.status, ObligationStatus.PENDING)

    def test_row_5_verification_after_the_change_is_detected(self) -> None:
        verification = observation(at=T + 90 * SECOND)
        row = only(run([host()], [change()], [verification]))
        self.assertIs(row.status, ObligationStatus.DETECTED)
        self.assertEqual(row.evidence.reference, verification.observation_id)  # type: ignore
        self.assertEqual(row.lag_seconds, 90)
        self.assertIs(row.late, False)
        self.assertIsNone(row.window_closed_at)
        self.assertIsNone(row.resumed_at)
        self.assertIsNone(row.stand_in)

    def test_row_6_a_passed_window_with_nothing_verified_is_lapsed(self) -> None:
        row = only(run([host()], [change(detectBy=text(T + HOUR))]))
        self.assertIs(row.status, ObligationStatus.LAPSED)
        self.assertEqual(row.window_closed_at, T + HOUR)
        self.assertIsNone(row.evidence)

    def test_row_6_reads_before_examined_evidence_is_undetermined(self) -> None:
        row = only(
            run(
                [host()],
                [change(detectBy=text(T + HOUR))],
                [observation(at=T + SECOND, disposition=ObservationDisposition.ERROR)],
            )
        )
        self.assertIs(row.status, ObligationStatus.LAPSED)

    def test_row_7_examined_without_verification_is_undetermined(self) -> None:
        row = only(
            run(
                [host()],
                [change()],
                [observation(at=T, disposition=ObservationDisposition.ERROR)],
            )
        )
        self.assertIs(row.status, ObligationStatus.UNDETERMINED)
        self.assertIsNone(row.evidence)

    def test_row_8_nothing_examined_is_pending(self) -> None:
        self.assertIs(only(run([host()], [change()])).status, ObligationStatus.PENDING)

    def test_examined_before_the_change_is_still_pending(self) -> None:
        row = only(
            run(
                [host()],
                [change()],
                [observation(at=T - SECOND, disposition=ObservationDisposition.ERROR)],
            )
        )
        self.assertIs(row.status, ObligationStatus.PENDING)

    def test_each_status_is_lowercase_text(self) -> None:
        for status in ObligationStatus:
            with self.subTest(status=status):
                self.assertEqual(status.value, status.name.lower())
        self.assertEqual(
            WAITING_STATUSES,
            frozenset(
                {
                    ObligationStatus.LAPSED,
                    ObligationStatus.UNDETERMINED,
                    ObligationStatus.PENDING,
                }
            ),
        )


# *--- Evidence Edges ---*


class EvidenceTests(unittest.TestCase):
    def test_verification_at_exactly_occurred_at_satisfies(self) -> None:
        row = only(run([host()], [change()], [observation(at=T)]))
        self.assertIs(row.status, ObligationStatus.DETECTED)
        self.assertEqual(row.lag_seconds, 0)

    def test_verification_before_change_never_counts(self) -> None:
        row = only(run([host()], [change()], [observation(at=T - SECOND)]))
        self.assertIs(row.status, ObligationStatus.PENDING)

    def test_verification_at_exactly_detect_by_is_not_late(self) -> None:
        row = only(run([host()], [change(detectBy=text(T + HOUR))], [observation(at=T + HOUR)]))
        self.assertIs(row.status, ObligationStatus.DETECTED)
        self.assertIs(row.late, False)
        self.assertIsNone(row.window_closed_at)
        self.assertIsNone(row.resumed_at)

    def test_verification_after_detect_by_is_detected_and_late(self) -> None:
        at = T + HOUR + SECOND
        row = only(run([host()], [change(detectBy=text(T + HOUR))], [observation(at=at)]))
        self.assertIs(row.status, ObligationStatus.DETECTED)
        self.assertIs(row.late, True)
        self.assertEqual(row.window_closed_at, T + HOUR)
        self.assertEqual(row.resumed_at, at)
        self.assertEqual(row.lag_seconds, 3601)

    def test_the_first_satisfying_verification_is_the_one_named(self) -> None:
        early = observation(at=T + SECOND, record="R-early")
        late = observation(at=T + HOUR, record="R-late")
        row = only(run([host()], [change()], [late, early]))
        self.assertEqual(row.evidence.reference, early.observation_id)  # type: ignore

    def test_detect_by_equal_to_as_of_has_not_passed(self) -> None:
        row = only(run([host()], [change(detectBy=text(AS_OF))]))
        self.assertIs(row.status, ObligationStatus.PENDING)
        row = only(run([host()], [change(detectBy=text(AS_OF))], as_of=AS_OF + SECOND))
        self.assertIs(row.status, ObligationStatus.LAPSED)

    def test_no_detect_by_never_lapses(self) -> None:
        row = only(run([host()], [change()], as_of=T + timedelta(days=3650)))
        self.assertIs(row.status, ObligationStatus.PENDING)
        self.assertIsNone(row.window_closed_at)

    def test_evidence_after_as_of_is_not_used(self) -> None:
        row = only(run([host()], [change()], [observation(at=AS_OF + SECOND)]))
        self.assertIs(row.status, ObligationStatus.PENDING)
        row = only(run([host()], [change()], [observation(at=AS_OF)]))
        self.assertIs(row.status, ObligationStatus.DETECTED)

    def test_untimed_evidence_is_counted_and_never_satisfies(self) -> None:
        row = only(run([host()], [change()], [observation(at=None)]))
        self.assertIs(row.status, ObligationStatus.PENDING)
        self.assertEqual(row.untimed, 1)
        self.assertIsNone(row.evidence)

    def test_examined_only_disposition_is_undetermined(self) -> None:
        for disposition in (
            ObservationDisposition.NOT_REVIEWED,
            ObservationDisposition.ERROR,
            ObservationDisposition.UNKNOWN,
        ):
            with self.subTest(disposition=disposition):
                row = only(run([host()], [change()], [observation(disposition=disposition)]))
                self.assertIs(row.status, ObligationStatus.UNDETERMINED)

    def test_every_verifying_disposition_satisfies(self) -> None:
        for disposition in (OPEN, PASS, ObservationDisposition.NOT_APPLICABLE):
            with self.subTest(disposition=disposition):
                row = only(run([host()], [change()], [observation(disposition=disposition)]))
                self.assertIs(row.status, ObligationStatus.DETECTED)

    def test_cyclonedx_scope_satisfies_only_as_pass(self) -> None:
        def scope(disposition: ObservationDisposition) -> Observation:
            return observation(
                disposition=disposition,
                source_type=CYCLONEDX_SOURCE_TYPE,
                record=CYCLONEDX_SCOPE_RECORD_ID,
            )

        row = only(run([host()], [change()], [scope(PASS)]))
        self.assertIs(row.status, ObligationStatus.DETECTED)
        row = only(run([host()], [change()], [scope(OPEN)]))
        self.assertIs(row.status, ObligationStatus.UNDETERMINED)

    def test_a_cyclonedx_vulnerability_row_never_examines(self) -> None:
        row_observation = observation(source_type=CYCLONEDX_SOURCE_TYPE, record="CVE-2026-9")
        row = only(run([host()], [change()], [row_observation]))
        self.assertIs(row.status, ObligationStatus.PENDING)

    def test_system_observation_never_satisfies(self) -> None:
        row = only(run([host()], [change()], [system_observation()]))
        self.assertIs(row.status, ObligationStatus.PENDING)

    def test_attestation_satisfies_non_machine_entry(self) -> None:
        verified = procedure(verifications=[{"at": text(T + HOUR), "reference": "tabletop"}])
        row = only(run([verified], [change("CHG-1", pair("ir-plan", "logical"))]))
        self.assertIs(row.status, ObligationStatus.DETECTED)
        self.assertIs(row.evidence.kind, EvidenceKind.ATTESTATION)  # type: ignore[union-attr]
        self.assertEqual(row.evidence.reference, "tabletop")  # type: ignore[union-attr]

    def test_an_attestation_before_the_change_never_counts(self) -> None:
        verified = procedure(verifications=[{"at": text(T - SECOND), "reference": "tabletop"}])
        row = only(run([verified], [change("CHG-1", pair("ir-plan", "logical"))]))
        self.assertIs(row.status, ObligationStatus.PENDING)

    def test_artifact_evidence_alone_leaves_a_non_machine_entry_undetermined(self) -> None:
        row = only(
            run(
                [procedure()],
                [change("CHG-1", pair("ir-plan", "logical"))],
                [observation("ir-plan", resource_type="logical")],
            )
        )
        self.assertIs(row.status, ObligationStatus.UNDETERMINED)

    def test_two_changes_one_verification_between_satisfies_only_the_first(self) -> None:
        second_at = T + 2 * HOUR
        projection = run(
            [host()],
            [change("CHG-1"), change("CHG-2", occurredAt=text(second_at))],
            [observation(at=T + HOUR)],
        )
        first, second = projection.obligations
        self.assertEqual(first.change.change_id, "CHG-1")
        self.assertIs(first.status, ObligationStatus.DETECTED)
        self.assertIs(second.status, ObligationStatus.PENDING)

    def test_verification_after_decommission_is_not_used(self) -> None:
        row = only(
            run(
                [host(decommissionedAt=text(T + HOUR))],
                [change(detectBy=text(T + HOUR))],
                [observation(at=T + 2 * HOUR)],
            )
        )
        self.assertIs(row.status, ObligationStatus.LAPSED)
        self.assertIsNone(row.evidence)


# *--- Matching ---*


class MatchingTests(unittest.TestCase):
    def test_a_row_names_its_entry_and_spelling(self) -> None:
        row = only(run([host()], [change()]))
        self.assertEqual(row.resource, LAB)
        self.assertEqual(row.entry.ref, LAB)  # type: ignore[union-attr]
        self.assertEqual(row.matched_as, LAB)
        self.assertIsNone(row.sample_group)

    def test_alias_spelling_matches_and_is_named(self) -> None:
        verification = observation("lab-01.internal", at=T + HOUR)
        row = only(
            run(
                [host(aliases=[ALIAS])],
                [change("CHG-1", pair("lab-01.internal"))],
                [verification],
            )
        )
        self.assertIs(row.status, ObligationStatus.DETECTED)
        self.assertEqual(row.resource, LAB)
        self.assertEqual(row.matched_as, ALIAS_REF)

    def test_identities_are_never_normalized(self) -> None:
        row = only(run([host()], [change("CHG-1", pair("LAB-01"))]))
        self.assertIs(row.status, ObligationStatus.UNREGISTERED)

    def test_entry_and_alias_in_one_change_is_one_row(self) -> None:
        row = only(run([host(aliases=[ALIAS])], [change("CHG-1", pair(), pair("lab-01.internal"))]))
        self.assertEqual(row.resource, LAB)
        self.assertEqual(row.matched_as, LAB)

    def test_the_first_spelling_in_sort_order_is_named(self) -> None:
        alias = {"resourceType": "host", "resourceId": "a-first"}
        row = only(run([host(aliases=[alias])], [change("CHG-1", pair("a-first"), pair())]))
        self.assertEqual(row.resource, LAB)
        self.assertEqual(row.matched_as, ResourceRef("a-first", "host"))

    def test_group_change_satisfied_by_any_member_names_stand_in(self) -> None:
        members = [host("web-1", sampleGroup="web"), host("web-2", sampleGroup="web")]
        verification = observation("web-2", at=T + HOUR)
        row = only(run(members, [change("CHG-1", GROUP_PAIR)], [verification]))
        self.assertIs(row.status, ObligationStatus.DETECTED)
        self.assertEqual(row.resource, GROUP_REF)
        self.assertEqual(row.sample_group, "web")
        self.assertIsNone(row.entry)
        self.assertIsNone(row.matched_as)
        self.assertEqual(row.stand_in, ResourceRef("web-2", "host"))
        self.assertEqual(row.evidence.reference, verification.observation_id)  # type: ignore

    def test_a_group_tie_names_the_least_member_whatever_the_evidence_spells(self) -> None:
        # web-2's evidence is spelled by an alias that sorts before web-1.
        alias = {"resourceType": "host", "resourceId": "a-alias"}
        members = [
            host("web-1", sampleGroup="web"),
            host("web-2", sampleGroup="web", aliases=[alias]),
        ]
        at = T + HOUR
        row = only(
            run(
                members,
                [change("CHG-1", GROUP_PAIR)],
                [observation("web-1", at=at), observation("a-alias", at=at)],
            )
        )
        self.assertEqual(row.stand_in, ResourceRef("web-1", "host"))

    def test_an_attested_member_stands_in(self) -> None:
        members = [
            procedure("a-plan", sampleGroup="web"),
            procedure(
                "b-plan",
                sampleGroup="web",
                verifications=[{"at": text(T + HOUR), "reference": "tabletop"}],
            ),
        ]
        row = only(run(members, [change("CHG-1", GROUP_PAIR)]))
        self.assertIs(row.status, ObligationStatus.DETECTED)
        self.assertEqual(row.stand_in, ResourceRef("b-plan", "logical"))

    def test_group_examined_but_unverified_is_undetermined(self) -> None:
        members = [host("web-1", sampleGroup="web")]
        evidence = [observation("web-1", at=T, disposition=ObservationDisposition.ERROR)]
        row = only(run(members, [change("CHG-1", GROUP_PAIR)], evidence))
        self.assertIs(row.status, ObligationStatus.UNDETERMINED)
        self.assertIsNone(row.stand_in)

    def test_untimed_group_evidence_is_counted_across_members(self) -> None:
        members = [host("web-1", sampleGroup="web"), host("web-2", sampleGroup="web")]
        evidence = [
            observation("web-1", at=None, record="R-1"),
            observation("web-2", at=None, record="R-2"),
        ]
        self.assertEqual(only(run(members, [change("CHG-1", GROUP_PAIR)], evidence)).untimed, 2)

    def test_group_name_no_entry_carries_is_unregistered(self) -> None:
        projection = run([host()], [change("CHG-1", GROUP_PAIR)])
        row = only(projection)
        self.assertIs(row.status, ObligationStatus.UNREGISTERED)
        self.assertEqual(row.resource, GROUP_REF)
        self.assertEqual(codes(projection), ["change_resource_unregistered"])

    def test_a_group_pair_needs_the_exact_type_and_prefix(self) -> None:
        members = [host("web-1", sampleGroup="web")]
        for spelled in (pair("sample-group/web", "host"), pair("web", "logical")):
            with self.subTest(spelled=spelled):
                row = only(run(members, [change("CHG-1", spelled)]))
                self.assertIs(row.status, ObligationStatus.UNREGISTERED)

    def test_entry_spelling_the_group_pair_wins(self) -> None:
        member = host("web-1", sampleGroup="web")
        spelled = procedure("sample-group/web")
        row = only(run([member, spelled], [change("CHG-1", GROUP_PAIR)]))
        self.assertEqual(row.entry.ref, GROUP_REF)  # type: ignore[union-attr]
        self.assertIsNone(row.stand_in)
        self.assertIsNone(row.sample_group)

    def test_an_alias_spelling_the_group_pair_wins(self) -> None:
        member = host("web-1", sampleGroup="web")
        other = host(aliases=[GROUP_PAIR])
        row = only(run([member, other], [change("CHG-1", GROUP_PAIR)]))
        self.assertEqual(row.entry.ref, LAB)  # type: ignore[union-attr]
        self.assertEqual(row.matched_as, GROUP_REF)

    def test_group_and_member_in_one_change_are_two_rows(self) -> None:
        members = [host("web-1", sampleGroup="web"), host("web-2", sampleGroup="web")]
        projection = run(members, [change("CHG-1", GROUP_PAIR, pair("web-1"))])
        self.assertEqual(
            [row.resource for row in projection.obligations],
            [ResourceRef("web-1", "host"), GROUP_REF],
        )
        self.assertEqual(projection.obligations[0].sample_group, "web")

    def test_member_change_is_not_widened_to_its_group(self) -> None:
        members = [host("web-1", sampleGroup="web"), host("web-2", sampleGroup="web")]
        row = only(
            run(members, [change("CHG-1", pair("web-1"))], [observation("web-2", at=T + HOUR)])
        )
        self.assertIs(row.status, ObligationStatus.PENDING)
        self.assertIsNone(row.stand_in)

    def test_rows_are_ordered_by_change_then_resource(self) -> None:
        projection = run(
            [host("b"), host("a")],
            [
                change("CHG-2", pair("b"), pair("a"), occurredAt=text(T)),
                change("CHG-1", pair("b"), occurredAt=text(T + HOUR)),
            ],
        )
        self.assertEqual(
            [(row.change.change_id, row.resource.resource_id) for row in projection.obligations],
            [("CHG-2", "a"), ("CHG-2", "b"), ("CHG-1", "b")],
        )


# *--- Lifecycle And Later ---*


class LifecycleTests(unittest.TestCase):
    def test_change_after_as_of_is_later_only(self) -> None:
        after = T + timedelta(days=30)
        projection = run(
            [host()],
            [
                change("CHG-L", pair(), pair("elsewhere"), occurredAt=text(after)),
                change("CHG-P"),
            ],
        )
        self.assertEqual([row.change.change_id for row in projection.obligations], ["CHG-P"])
        self.assertEqual([item.change_id for item in projection.later], ["CHG-L"])
        self.assertEqual(projection.warnings, ())
        self.assertEqual(projection.unregistered, ())
        block = projection.to_dict()
        self.assertEqual([item["changeId"] for item in block["changes"]], ["CHG-P"])
        self.assertEqual(
            block["later"],
            [
                {
                    "changeId": "CHG-L",
                    "occurredAt": "2026-10-01T12:00:00Z",
                    "resources": [pair("elsewhere"), pair()],
                }
            ],
        )
        self.assertEqual(sum(block["summary"].values()), 1)

    def test_a_change_at_exactly_as_of_has_a_row(self) -> None:
        projection = run([host()], [change(occurredAt=text(AS_OF))], [observation(at=AS_OF)])
        self.assertIs(only(projection).status, ObligationStatus.DETECTED)
        self.assertEqual(projection.later, ())

    def test_decommission_after_as_of_is_ignored(self) -> None:
        projection = run([host(decommissionedAt=text(AS_OF + SECOND))], [change()])
        self.assertIs(only(projection).status, ObligationStatus.PENDING)

    def test_a_past_decommission_after_as_of_with_change_after_it_warns_nothing(self) -> None:
        # At this as-of the decommission has not happened, so the later change stands.
        change_at = AS_OF - HOUR
        projection = run(
            [host(decommissionedAt=text(AS_OF + SECOND))],
            [change(occurredAt=text(change_at))],
        )
        self.assertIs(only(projection).status, ObligationStatus.PENDING)
        self.assertEqual(projection.warnings, ())

    def test_decommission_at_as_of_is_considered(self) -> None:
        row = only(run([host(decommissionedAt=text(AS_OF))], [change()]))
        self.assertIs(row.status, ObligationStatus.RETIRED)

    def test_retired_row_keeps_its_evidence(self) -> None:
        verification = observation(at=T + HOUR)
        row = only(run([host(decommissionedAt=text(T + 2 * HOUR))], [change()], [verification]))
        self.assertIs(row.status, ObligationStatus.RETIRED)
        self.assertEqual(row.evidence.reference, verification.observation_id)  # type: ignore
        self.assertEqual(row.lag_seconds, 3600)
        self.assertIs(row.late, False)

    def test_a_retired_group_row_names_its_stand_in(self) -> None:
        members = [
            host("web-1", sampleGroup="web", decommissionedAt=text(T + HOUR)),
            host("web-2", sampleGroup="web", decommissionedAt=text(T + 2 * HOUR)),
        ]
        row = only(
            run(members, [change("CHG-1", GROUP_PAIR)], [observation("web-2", at=T + SECOND)])
        )
        self.assertIs(row.status, ObligationStatus.RETIRED)
        self.assertEqual(row.stand_in, ResourceRef("web-2", "host"))

    def test_a_group_is_retired_only_once_every_member_is(self) -> None:
        members = [
            host("web-1", sampleGroup="web", decommissionedAt=text(T - HOUR)),
            host("web-2", sampleGroup="web"),
        ]
        projection = run(members, [change("CHG-1", GROUP_PAIR)])
        self.assertIs(only(projection).status, ObligationStatus.PENDING)
        self.assertEqual(projection.warnings, ())

    def test_a_group_decommissioned_before_the_change_is_retired_and_warns(self) -> None:
        members = [
            host("web-1", sampleGroup="web", decommissionedAt=text(T - 2 * HOUR)),
            host("web-2", sampleGroup="web", decommissionedAt=text(T - HOUR)),
        ]
        projection = run(members, [change("CHG-1", GROUP_PAIR)])
        self.assertIs(only(projection).status, ObligationStatus.RETIRED)
        self.assertEqual(codes(projection), ["change_after_decommission"])

    def test_expected_since_after_as_of_leaves_the_obligation_standing(self) -> None:
        projection = run([host(expectedSince=text(AS_OF + HOUR))], [change()])
        self.assertIs(only(projection).status, ObligationStatus.PENDING)
        self.assertEqual(codes(projection), ["change_precedes_expected_since"])


# *--- Warnings ---*


class WarningTests(unittest.TestCase):
    def test_expected_since_after_change_warns_once(self) -> None:
        projection = run([host(expectedSince=text(T + SECOND))], [change()])
        self.assertEqual(codes(projection), ["change_precedes_expected_since"])
        item = projection.warnings[0]
        self.assertEqual(item.level.value, "warning")
        self.assertEqual(item.location, "change-file CHG-1 host:lab-01")
        self.assertIn("CHG-1", item.message)
        self.assertIn("2026-09-01T12:00:01Z", item.message)

    def test_expected_since_at_the_change_does_not_warn(self) -> None:
        self.assertEqual(run([host(expectedSince=text(T))], [change()]).warnings, ())

    def test_a_group_compares_its_earliest_member(self) -> None:
        early = host("web-1", sampleGroup="web")
        late = host("web-2", sampleGroup="web", expectedSince=text(T + HOUR))
        self.assertEqual(run([early, late], [change("CHG-1", GROUP_PAIR)]).warnings, ())
        both_late = host("web-1", sampleGroup="web", expectedSince=text(T + SECOND))
        self.assertEqual(
            codes(run([both_late, late], [change("CHG-1", GROUP_PAIR)])),
            ["change_precedes_expected_since"],
        )

    def test_logged_row_raises_no_expected_since_warning(self) -> None:
        projection = run([host(expectedSince=text(T + SECOND))], [change(significant=False)])
        self.assertIs(only(projection).status, ObligationStatus.LOGGED)
        self.assertEqual(projection.warnings, ())

    def test_a_retired_row_raises_no_expected_since_warning(self) -> None:
        entry = host(expectedSince=text(T + SECOND), decommissionedAt=text(T + HOUR))
        projection = run([entry], [change()])
        self.assertIs(only(projection).status, ObligationStatus.RETIRED)
        self.assertEqual(projection.warnings, ())

    def test_each_open_status_warns_on_expected_since(self) -> None:
        entry = host(expectedSince=text(T + SECOND))
        for name, fields, evidence in (
            ("detected", {}, [observation(at=T + HOUR)]),
            ("lapsed", {"detectBy": text(T + HOUR)}, []),
            (
                "undetermined",
                {},
                [observation(at=T + HOUR, disposition=ObservationDisposition.ERROR)],
            ),
            ("pending", {}, []),
        ):
            with self.subTest(name=name):
                projection = run([entry], [change(**fields)], evidence)
                self.assertEqual(only(projection).status.value, name)
                self.assertEqual(codes(projection), ["change_precedes_expected_since"])

    def test_unregistered_warns_once_per_pair(self) -> None:
        missing = pair("elsewhere")
        projection = run(
            [host()],
            [
                change("CHG-2", missing, occurredAt=text(T + HOUR)),
                change("CHG-1", missing),
                change("CHG-3", pair("other"), occurredAt=text(T + 2 * HOUR)),
            ],
        )
        self.assertEqual(
            [item.location for item in projection.warnings],
            ["change-file CHG-1 host:elsewhere", "change-file CHG-3 host:other"],
        )
        self.assertEqual(
            codes(projection),
            ["change_resource_unregistered", "change_resource_unregistered"],
        )
        self.assertIn("add the resource to the inventory", projection.warnings[0].message)
        self.assertIn("expectedSince", projection.warnings[0].message)
        self.assertEqual(len(projection.obligations), 3)
        self.assertEqual(
            [(item.resource, item.change_ids) for item in projection.unregistered],
            [
                (ResourceRef("elsewhere", "host"), ("CHG-1", "CHG-2")),
                (ResourceRef("other", "host"), ("CHG-3",)),
            ],
        )

    def test_after_decommission_warns_once_per_obligation(self) -> None:
        projection = run(
            [host(decommissionedAt=text(T - HOUR))],
            [change("CHG-1"), change("CHG-2", occurredAt=text(T + HOUR))],
        )
        self.assertEqual(
            [item.location for item in projection.warnings],
            ["change-file CHG-1 host:lab-01", "change-file CHG-2 host:lab-01"],
        )


# *--- KEV At Activation ---*


class KevTests(unittest.TestCase):
    def created(self, **fields: Any) -> dict[str, Any]:
        return change(kind="created", **fields)

    def test_kev_true_when_same_digest_carries_kev_listed_on_or_before_change(self) -> None:
        verification = observation(at=T + HOUR, record="R-verify")
        finding = observation(
            at=T + HOUR, disposition=OPEN, record="R-kev", identifiers=(CVE,), context="ctx-9"
        )
        projection = run([host()], [self.created()], [verification, finding], kev=catalog())
        row = only(projection)
        self.assertIs(row.status, ObligationStatus.DETECTED)
        self.assertIs(row.kev_at_activation, True)
        self.assertEqual(row.kev_tracking_ids, (tracking_id_for("sarif", "R-kev", "ctx-9"),))
        self.assertEqual(codes(projection), ["kev_at_activation"])
        self.assertEqual(projection.warnings[0].location, "change-file CHG-1 host:lab-01")

    def test_a_kev_listed_on_the_change_date_is_flagged(self) -> None:
        finding = observation(at=T + HOUR, disposition=OPEN, identifiers=(CVE,))
        row = only(run([host()], [self.created()], [finding], kev=catalog(date_added=T.date())))
        self.assertIs(row.kev_at_activation, True)

    def test_kev_false_when_catalog_added_after_change(self) -> None:
        finding = observation(at=T + HOUR, disposition=OPEN, identifiers=(CVE,))
        later_listing = T.date() + timedelta(days=1)
        projection = run(
            [host()], [self.created()], [finding], kev=catalog(date_added=later_listing)
        )
        self.assertIs(only(projection).kev_at_activation, False)
        self.assertEqual(only(projection).kev_tracking_ids, ())
        self.assertEqual(projection.warnings, ())

    def test_kev_false_with_no_finding_in_the_catalog(self) -> None:
        row = only(run([host()], [self.created()], [observation(at=T + HOUR)], kev=catalog()))
        self.assertIs(row.kev_at_activation, False)

    def test_kev_null_without_catalog(self) -> None:
        finding = observation(at=T + HOUR, disposition=OPEN, identifiers=(CVE,))
        row = only(run([host()], [self.created()], [finding]))
        self.assertIsNone(row.kev_at_activation)
        self.assertEqual(row.kev_tracking_ids, ())

    def test_kev_null_on_modified_change(self) -> None:
        finding = observation(at=T + HOUR, disposition=OPEN, identifiers=(CVE,))
        projection = run([host()], [change()], [finding], kev=catalog())
        self.assertIsNone(only(projection).kev_at_activation)
        self.assertEqual(projection.warnings, ())

    def test_kev_null_on_a_group_and_a_non_machine_entry(self) -> None:
        member = host("web-1", sampleGroup="web")
        finding = observation("web-1", at=T + HOUR, disposition=OPEN, identifiers=(CVE,))
        row = only(run([member], [self.created(resources=[GROUP_PAIR])], [finding], kev=catalog()))
        self.assertIsNone(row.kev_at_activation)
        attested = procedure(verifications=[{"at": text(T + HOUR), "reference": "tabletop"}])
        row = only(
            run(
                [attested],
                [self.created(resources=[pair("ir-plan", "logical")])],
                kev=catalog(),
            )
        )
        self.assertIs(row.status, ObligationStatus.DETECTED)
        self.assertIsNone(row.kev_at_activation)

    def test_kev_null_unless_detected(self) -> None:
        projection = run([host()], [self.created()], kev=catalog())
        self.assertIs(only(projection).status, ObligationStatus.PENDING)
        self.assertIsNone(only(projection).kev_at_activation)

    def test_a_finding_in_another_artifact_is_not_flagged(self) -> None:
        verification = observation(at=T + HOUR)
        finding = observation(
            at=T + 2 * HOUR, disposition=OPEN, identifiers=(CVE,), digest=OTHER_DIGEST
        )
        for evidence in ([verification, finding], [finding, verification]):
            row = only(run([host()], [self.created()], evidence, kev=catalog()))
            self.assertIs(row.kev_at_activation, False)

    def test_kev_null_on_a_retired_row(self) -> None:
        finding = observation(at=T + HOUR, disposition=OPEN, identifiers=(CVE,))
        projection = run(
            [host(decommissionedAt=text(T + 2 * HOUR))],
            [self.created()],
            [finding],
            kev=catalog(),
        )
        self.assertIs(only(projection).status, ObligationStatus.RETIRED)
        self.assertIsNone(only(projection).kev_at_activation)
        self.assertEqual(projection.warnings, ())

    def test_a_finding_on_another_resource_is_not_flagged(self) -> None:
        verification = observation(at=T + HOUR)
        finding = observation("lab-02", at=T + HOUR, disposition=OPEN, identifiers=(CVE,))
        row = only(
            run(
                [host(), host("lab-02")],
                [self.created()],
                [verification, finding],
                kev=catalog(),
            )
        )
        self.assertIs(row.kev_at_activation, False)

    def test_a_finding_spelled_by_an_alias_is_the_same_resource(self) -> None:
        finding = observation("lab-01.internal", at=T + HOUR, disposition=OPEN, identifiers=(CVE,))
        row = only(run([host(aliases=[ALIAS])], [self.created()], [finding], kev=catalog()))
        self.assertIs(row.kev_at_activation, True)

    def test_a_finding_that_is_not_open_is_not_flagged(self) -> None:
        verification = observation(at=T + HOUR, record="R-verify")
        finding = observation(at=T + HOUR, disposition=PASS, record="R-kev", identifiers=(CVE,))
        row = only(run([host()], [self.created()], [verification, finding], kev=catalog()))
        self.assertIs(row.kev_at_activation, False)

    def test_a_finding_after_as_of_is_not_flagged(self) -> None:
        verification = observation(at=T + HOUR, record="R-verify")
        finding = observation(
            at=AS_OF + SECOND, disposition=OPEN, record="R-kev", identifiers=(CVE,)
        )
        row = only(run([host()], [self.created()], [verification, finding], kev=catalog()))
        self.assertIs(row.kev_at_activation, False)

    def test_tracking_ids_are_sorted_and_distinct(self) -> None:
        records = [
            observation(
                at=T + HOUR, disposition=OPEN, record=record, identifiers=(CVE,), context="ctx"
            )
            for record in ("R-b", "R-a", "R-b")
        ]
        row = only(run([host()], [self.created()], records, kev=catalog()))
        expected = sorted(tracking_id_for("sarif", record, "ctx") for record in ("R-a", "R-b"))
        self.assertEqual(list(row.kev_tracking_ids), expected)

    # A CycloneDX vulnerability row sits on a package resource, so without call 13 an image
    # whose own BOM lists a KEV read an affirmative false.
    def bom(self, digest: str = DIGEST) -> Observation:
        return observation(
            at=T + HOUR,
            source_type=CYCLONEDX_SOURCE_TYPE,
            record=CYCLONEDX_SCOPE_RECORD_ID,
            digest=digest,
        )

    def package_row(self, digest: str = DIGEST, **fields: Any) -> Observation:
        values: dict[str, Any] = {
            "at": T + HOUR,
            "disposition": OPEN,
            "resource_type": "package",
            "record": CVE,
            "digest": digest,
            "identifiers": (CVE,),
            "source_type": CYCLONEDX_SOURCE_TYPE,
            "context": "pkg-ctx",
        }
        return observation("image:web|deb/openssl@3", **{**values, **fields})

    def test_kev_true_on_cyclonedx_package_row_in_the_verifying_bom(self) -> None:
        projection = run(
            [host()], [self.created()], [self.bom(), self.package_row()], kev=catalog()
        )
        row = only(projection)
        self.assertIs(row.status, ObligationStatus.DETECTED)
        self.assertIs(row.kev_at_activation, True)
        self.assertEqual(
            row.kev_tracking_ids,
            (tracking_id_for(CYCLONEDX_SOURCE_TYPE, CVE, "pkg-ctx"),),
        )
        self.assertEqual(codes(projection), ["kev_at_activation"])

    def test_package_row_of_another_artifact_is_not_counted(self) -> None:
        row = only(
            run(
                [host()],
                [self.created()],
                [self.bom(), self.package_row(OTHER_DIGEST)],
                kev=catalog(),
            )
        )
        self.assertIs(row.status, ObligationStatus.DETECTED)
        self.assertIs(row.kev_at_activation, False)

    def test_package_row_needs_a_bom_scope_verification(self) -> None:
        # The same digest, but the verification is an ordinary finding, so no BOM verified it.
        verification = observation(at=T + HOUR, record="R-verify")
        row = only(
            run([host()], [self.created()], [verification, self.package_row()], kev=catalog())
        )
        self.assertIs(row.status, ObligationStatus.DETECTED)
        self.assertIs(row.kev_at_activation, False)

    def test_package_row_of_another_source_type_is_not_counted(self) -> None:
        row = only(
            run(
                [host()],
                [self.created()],
                [self.bom(), self.package_row(source_type="sarif")],
                kev=catalog(),
            )
        )
        self.assertIs(row.kev_at_activation, False)

    def test_package_row_that_is_not_open_is_not_counted(self) -> None:
        row = only(
            run(
                [host()],
                [self.created()],
                [self.bom(), self.package_row(disposition=PASS)],
                kev=catalog(),
            )
        )
        self.assertIs(row.kev_at_activation, False)

    def test_package_row_after_as_of_is_not_counted(self) -> None:
        row = only(
            run(
                [host()],
                [self.created()],
                [self.bom(), self.package_row(at=AS_OF + SECOND)],
                kev=catalog(),
            )
        )
        self.assertIs(row.kev_at_activation, False)

    def test_a_bom_row_on_another_resource_type_is_not_counted(self) -> None:
        row = only(
            run(
                [host()],
                [self.created()],
                [self.bom(), self.package_row(resource_type="image")],
                kev=catalog(),
            )
        )
        self.assertIs(row.kev_at_activation, False)

    def test_a_scope_record_id_from_another_source_type_is_no_bom(self) -> None:
        verification = observation(at=T + HOUR, record=CYCLONEDX_SCOPE_RECORD_ID)
        row = only(
            run([host()], [self.created()], [verification, self.package_row()], kev=catalog())
        )
        self.assertIs(row.status, ObligationStatus.DETECTED)
        self.assertIs(row.kev_at_activation, False)

    def test_bom_and_finding_verifications_keep_their_own_answers(self) -> None:
        # One digest and one change day, so only whether a BOM verified can tell them apart.
        finding = observation(at=T + HOUR, record="R-first")
        later_bom = dataclasses.replace(self.bom(), observed_at=T + 3 * HOUR)
        first = self.created(occurredAt=text(T))
        second = change("CHG-2", kind="created", occurredAt=text(T + 2 * HOUR))
        projection = run(
            [host()],
            [first, second],
            [finding, later_bom, self.package_row(at=T + 3 * HOUR)],
            kev=catalog(),
        )
        by_change = {row.change.change_id: row for row in projection.obligations}
        self.assertIs(by_change["CHG-1"].kev_at_activation, False)
        self.assertIs(by_change["CHG-2"].kev_at_activation, True)

    def test_package_row_listed_after_the_change_is_not_counted(self) -> None:
        later_listing = T.date() + timedelta(days=1)
        row = only(
            run(
                [host()],
                [self.created()],
                [self.bom(), self.package_row()],
                kev=catalog(date_added=later_listing),
            )
        )
        self.assertIs(row.kev_at_activation, False)
        self.assertEqual(row.kev_tracking_ids, ())

    def test_one_artifact_is_matched_once_per_change_date(self) -> None:
        findings = [
            observation(at=T + HOUR, disposition=OPEN, record=f"R-{index}", identifiers=(CVE,))
            for index in range(5)
        ]
        changes = [self.created(change_id=f"CHG-{index}") for index in range(300)]
        real = KevCatalog.matches
        with mock.patch.object(KevCatalog, "matches", autospec=True, side_effect=real) as spy:
            projection = run([host()], changes, findings, kev=catalog())
        self.assertEqual(spy.call_count, len(findings))
        self.assertTrue(all(row.kev_at_activation for row in projection.obligations))


# *--- Policy And Shape ---*


class ProjectionTests(unittest.TestCase):
    def test_force_is_read_from_policy(self) -> None:
        for class_name in ("B", "C"):
            with self.subTest(class_name=class_name):
                selected = policy(class_name)
                projection = run([host()], [change()], selected=selected)
                self.assertIs(projection.force, selected.rule(DAC_RULE).force)
        rewritten = tuple(
            dataclasses.replace(rule, force=RuleForce.MUST) if rule.rule_id == DAC_RULE else rule
            for rule in policy().rules
        )
        selected = dataclasses.replace(policy(), rules=rewritten)
        projection = run([host()], [change()], selected=selected)
        self.assertIs(projection.force, RuleForce.MUST)
        block = projection.to_dict()
        self.assertEqual(block["force"], "MUST")
        self.assertEqual(block["changes"][0]["force"], "MUST")
        self.assertEqual(block["obligations"][0]["force"], "MUST")

    def test_a_policy_without_the_rule_is_refused(self) -> None:
        stripped = dataclasses.replace(
            policy(), rules=tuple(rule for rule in policy().rules if rule.rule_id != DAC_RULE)
        )
        with self.assertRaisesRegex(PolicyRuleNotFoundError, DAC_RULE):
            run([host()], [change()], selected=stripped)

    def test_as_of_must_be_aware(self) -> None:
        with self.assertRaises(ValueError):
            run([host()], [change()], as_of=datetime(2026, 9, 10))

    def test_the_block_shape(self) -> None:
        verification = observation(at=T + HOUR)
        projection = run(
            [host(aliases=[ALIAS])],
            [
                change(
                    "CHG-1",
                    pair("lab-01.internal"),
                    detectBy=text(T + 2 * HOUR),
                    job="nightly-openscap",
                ),
                change("CHG-2", pair("elsewhere")),
            ],
            [verification],
        )
        block = projection.to_dict()
        json.dumps(block)
        self.assertEqual(
            set(block),
            {
                "rule",
                "force",
                "provenance",
                "asOf",
                "input",
                "inventorySha256",
                "summary",
                "changes",
                "obligations",
                "unregistered",
                "later",
                "basis",
            },
        )
        self.assertEqual(block["rule"], "VDR-CSO-DAC")
        self.assertEqual(block["force"], "SHOULD")
        self.assertEqual(block["asOf"], "2026-09-10T00:00:00Z")
        self.assertEqual(block["basis"], CHANGE_BASIS)
        self.assertEqual(block["inventorySha256"], projection.inventory.sha256)
        provenance = policy().provenance
        self.assertEqual(
            block["provenance"],
            {
                "repository": provenance.repository,
                "commit": provenance.commit,
                "datasetVersion": provenance.dataset_version,
                "datasetLastUpdated": provenance.dataset_last_updated,
                "sha256": provenance.dataset_sha256,
            },
        )
        self.assertEqual(
            block["input"],
            {
                "name": "change-file",
                "sizeBytes": projection.change_set.size_bytes,
                "sha256": projection.change_set.sha256,
                "changeCount": 2,
            },
        )
        self.assertEqual(
            block["summary"],
            {
                "unregistered": 1,
                "retired": 0,
                "logged": 0,
                "detected": 1,
                "lapsed": 0,
                "undetermined": 0,
                "pending": 0,
            },
        )
        self.assertEqual(
            block["changes"][0],
            {
                "changeId": "CHG-1",
                "kind": "modified",
                "occurredAt": "2026-09-01T12:00:00Z",
                "source": {"tool": "git", "reference": "commit 0123abc"},
                "significant": True,
                "rationale": "Kernel upgrade.",
                "detectBy": "2026-09-01T14:00:00Z",
                "job": "nightly-openscap",
                "force": "SHOULD",
            },
        )
        self.assertEqual(
            block["obligations"][0],
            {
                "changeId": "CHG-1",
                "resourceType": "host",
                "resourceId": "lab-01",
                "entry": pair(),
                "sampleGroup": None,
                "matchedAs": pair("lab-01.internal"),
                "status": "detected",
                "force": "SHOULD",
                "evidence": verification_row(verification),
                "standIn": None,
                "lagSeconds": 3600,
                "ageSeconds": None,
                "late": False,
                "windowClosedAt": None,
                "resumedAt": None,
                "untimed": 0,
                "kevAtActivation": None,
                "kevTrackingIds": [],
            },
        )
        self.assertEqual(
            block["unregistered"],
            [{"resourceType": "host", "resourceId": "elsewhere", "changeIds": ["CHG-2"]}],
        )
        self.assertEqual(block["later"], [])

    def test_a_late_row_shows_its_window_and_resumption(self) -> None:
        at = T + 2 * HOUR
        row = run([host()], [change(detectBy=text(T + HOUR))], [observation(at=at)]).to_dict()[
            "obligations"
        ][0]
        self.assertIs(row["late"], True)
        self.assertEqual(row["windowClosedAt"], "2026-09-01T13:00:00Z")
        self.assertEqual(row["resumedAt"], "2026-09-01T14:00:00Z")

    def test_waiting_lists_exactly_the_waiting_rows(self) -> None:
        projection = run(
            [host("a"), host("b"), host("c"), host("d"), host("e", decommissionedAt=text(T))],
            [
                change("CHG-1", pair("a")),
                change("CHG-2", pair("b"), detectBy=text(T + HOUR)),
                change("CHG-3", pair("c")),
                change("CHG-4", pair("d"), significant=False),
                change("CHG-5", pair("e")),
                change("CHG-6", pair("zz")),
            ],
            [
                observation("a", at=T + HOUR),
                observation("c", at=T + HOUR, disposition=ObservationDisposition.ERROR),
            ],
        )
        statuses = {row.change.change_id: row.status.value for row in projection.obligations}
        self.assertEqual(
            statuses,
            {
                "CHG-1": "detected",
                "CHG-2": "lapsed",
                "CHG-3": "undetermined",
                "CHG-4": "logged",
                "CHG-5": "retired",
                "CHG-6": "unregistered",
            },
        )
        self.assertEqual([row.change.change_id for row in projection.waiting], ["CHG-2", "CHG-3"])

    def test_a_pending_row_is_waiting(self) -> None:
        self.assertEqual(len(run([host()], [change()]).waiting), 1)

    def test_a_waiting_row_prints_its_age_and_no_other_row_does(self) -> None:
        for name, entries, fields, evidence, age in (
            ("pending", [host()], {}, [], 8 * 86400 + 12 * 3600),
            ("lapsed", [host()], {"detectBy": text(T + HOUR)}, [], 8 * 86400 + 12 * 3600),
            (
                "undetermined",
                [host()],
                {},
                [observation(at=T, disposition=ObservationDisposition.ERROR)],
                8 * 86400 + 12 * 3600,
            ),
            ("detected", [host()], {}, [observation(at=T)], None),
            ("logged", [host()], {"significant": False}, [], None),
            ("retired", [host(decommissionedAt=text(T))], {}, [], None),
        ):
            with self.subTest(name=name):
                row = run(entries, [change(**fields)], evidence).to_dict()["obligations"][0]
                self.assertEqual(row["status"], name)
                self.assertEqual(row["ageSeconds"], age)

    def test_the_basis_says_what_no_status_claims(self) -> None:
        self.assertIn("not a compliance finding", CHANGE_BASIS)
        self.assertIn("never lapses", CHANGE_BASIS)
        self.assertIn("overlap on purpose", CHANGE_BASIS)

    def test_input_order_never_moves_the_projection(self) -> None:
        entries = [
            host("a", sampleGroup="web"),
            host("b", sampleGroup="web", aliases=[{"resourceType": "host", "resourceId": "a-b"}]),
            host("c"),
            procedure(verifications=[{"at": text(T + HOUR), "reference": "tabletop"}]),
        ]
        changes = [
            change("CHG-1", GROUP_PAIR, pair("c"), pair("zz"), kind="created"),
            change("CHG-2", pair("a-b"), pair("b"), detectBy=text(T + HOUR)),
            change("CHG-3", pair("ir-plan", "logical"), occurredAt=text(T + HOUR)),
            change("CHG-4", pair("zz"), occurredAt=text(AS_OF + HOUR)),
        ]
        evidence = [
            observation("a", at=T + HOUR, disposition=OPEN, identifiers=(CVE,), record="R-9"),
            observation("c", at=T + HOUR, disposition=OPEN, identifiers=(CVE,), record="R-8"),
            observation("c", at=T + HOUR, record="R-7"),
            observation("b", at=None, record="R-6"),
        ]
        baseline = run(entries, changes, evidence, kev=catalog())
        expected = baseline.to_dict()
        shuffler = random.Random(20261108)
        for _ in range(12):
            shuffled_entries = copy.deepcopy(entries)
            shuffled_changes = copy.deepcopy(changes)
            shuffled_evidence = list(evidence)
            shuffler.shuffle(shuffled_entries)
            shuffler.shuffle(shuffled_changes)
            shuffler.shuffle(shuffled_evidence)
            for item in shuffled_changes:
                shuffler.shuffle(item["resources"])
            again = run(shuffled_entries, shuffled_changes, shuffled_evidence, kev=catalog())
            block = again.to_dict()
            self.assertEqual(
                {
                    key: value
                    for key, value in block.items()
                    if key not in {"input", "inventorySha256"}
                },
                {
                    key: value
                    for key, value in expected.items()
                    if key not in {"input", "inventorySha256"}
                },
            )
            self.assertEqual(again.warnings, baseline.warnings)

    def test_observations_may_be_a_single_pass_iterator(self) -> None:
        row = only(
            derive_changes(
                iter([observation(at=T + HOUR, disposition=OPEN, identifiers=(CVE,))]),
                changes_of(change(kind="created")),
                inventory_of(host()),
                policy(),
                AS_OF,
                kev_catalog=catalog(),
            )
        )
        self.assertIs(row.status, ObligationStatus.DETECTED)
        self.assertIs(row.kev_at_activation, True)


def verification_row(item: Observation) -> dict[str, Any]:
    return {
        "kind": "observation",
        "at": "2026-09-01T13:00:00Z",
        "resourceType": item.resource.resource_type,
        "resourceId": item.resource.resource_id,
        "observationId": item.observation_id,
        "disposition": item.disposition.value,
    }


# *--- Scale And Filing ---*


class ScaleTests(unittest.TestCase):
    def test_each_subject_evidence_is_read_once(self) -> None:
        members = [host(f"web-{index}", sampleGroup="web") for index in range(200)]
        evidence = [observation(f"web-{index}", at=T + index * SECOND) for index in range(200)]
        changes = [change(f"CHG-{index}", GROUP_PAIR) for index in range(20_000)]
        real = FiledEvidence.verifying
        with mock.patch.object(FiledEvidence, "verifying", autospec=True, side_effect=real) as spy:
            projection = run(members, changes, evidence)
        self.assertEqual(spy.call_count, 1)
        self.assertEqual(spy.call_args.kwargs["rule_id"], PSD_RULE)
        self.assertEqual(len(projection.obligations), 20_000)
        self.assertTrue(
            all(row.status is ObligationStatus.DETECTED for row in projection.obligations)
        )

    def test_two_spellings_share_one_read(self) -> None:
        real = FiledEvidence.verifying
        with mock.patch.object(FiledEvidence, "verifying", autospec=True, side_effect=real) as spy:
            run(
                [host(aliases=[ALIAS])],
                [change("CHG-1"), change("CHG-2", pair("lab-01.internal"))],
                [observation(at=T + HOUR)],
            )
        self.assertEqual(spy.call_count, 1)


class FiledEvidenceTests(unittest.TestCase):
    def inventory(self) -> Inventory:
        return inventory_of(
            host("web-1", sampleGroup="web"),
            host("web-2", sampleGroup="web", aliases=[ALIAS]),
            host("solo"),
        )

    def test_examined_and_untimed_read_by_subject(self) -> None:
        inventory = self.inventory()
        error = observation("web-1", at=T, disposition=ObservationDisposition.ERROR)
        pass_on_alias = observation("lab-01.internal", at=T + HOUR, record="R-2")
        untimed = observation("web-2", at=None, record="R-3")
        filed = file_evidence([error, pass_on_alias, untimed], inventory, AS_OF)

        group_refs = [
            item.reference for item in filed.examined(rule_id=PSD_RULE, subject=GROUP_REF)
        ]
        self.assertEqual(group_refs, [error.observation_id, pass_on_alias.observation_id])
        self.assertEqual(
            [item.reference for item in filed.untimed(rule_id=PSD_RULE, subject=GROUP_REF)],
            [untimed.observation_id],
        )
        web_two = ResourceRef("web-2", "host")
        self.assertEqual(
            [item.reference for item in filed.examined(rule_id=DAC_RULE, subject=web_two)],
            [pass_on_alias.observation_id],
        )
        self.assertEqual(filed.examined(rule_id=DAC_RULE, subject=ResourceRef("no", "host")), ())

    def test_verifying_reads_a_group_by_its_members_in_order(self) -> None:
        inventory = self.inventory()
        first = observation("web-2", at=T + HOUR, record="R-2")
        second = observation("web-1", at=T + 2 * HOUR, record="R-3")
        filed = file_evidence([second, first], inventory, AS_OF)
        self.assertEqual(
            [item.reference for item in filed.verifying(rule_id=PSD_RULE, subject=GROUP_REF)],
            [first.observation_id, second.observation_id],
        )
        unknown = ResourceRef("sample-group/none", "logical")
        self.assertEqual(filed.verifying(rule_id=PSD_RULE, subject=unknown), ())

    def test_the_new_mappings_default_to_empty(self) -> None:
        inventory = self.inventory()
        filed = FiledEvidence(
            inventory=inventory,
            verifying_by_entry={entry.ref: () for entry in inventory.entries},
        )
        self.assertEqual(filed.examined(rule_id=PSD_RULE, subject=GROUP_REF), ())
        self.assertEqual(filed.untimed(rule_id=DAC_RULE, subject=LAB), ())


if __name__ == "__main__":
    unittest.main()
