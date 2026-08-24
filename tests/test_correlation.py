from __future__ import annotations

import hashlib
import json
import unittest
from dataclasses import replace
from datetime import UTC, datetime
from itertools import permutations
from pathlib import Path

from complyroll.adapters import ingest_stig_artifact
from complyroll.correlation import (
    VulnerabilityGroup,
    correlate_observations,
    group_open_observations,
)
from complyroll.models import (
    Observation,
    ObservationDisposition,
    ResourceRef,
    SourceSeverity,
)

FIXTURES = Path(__file__).parent / "fixtures"
INGESTED_AT = datetime(2026, 8, 21, 12, 0, tzinfo=UTC)


def _observation(
    *,
    source_record_id: str,
    resource_id: str = "host-a",
    source_type: str = "cklb",
    source_tool: str = "stig-viewer-3",
    context_key: str = "Example STIG",
    disposition: ObservationDisposition = ObservationDisposition.OPEN,
    observed_at: datetime | None = None,
    title: str = "Example rule title",
    description: str = "",
    source_identifiers: tuple[str, ...] = (),
    digest: str = "a" * 64,
) -> Observation:
    return Observation(
        observation_id=f"obs-{source_record_id}-{resource_id}",
        source_type=source_type,
        source_tool=source_tool,
        parser_name="complyroll.test",
        parser_version="1",
        source_record_id=source_record_id,
        resource=ResourceRef(resource_id=resource_id, resource_type="host"),
        observed_at=observed_at,
        ingested_at=INGESTED_AT,
        disposition=disposition,
        source_severity=SourceSeverity.MEDIUM,
        title=title,
        description=description,
        source_artifact_digest=digest,
        source_artifact_name="example.cklb",
        source_identifiers=source_identifiers,
        context_key=context_key,
    )


class GroupingTests(unittest.TestCase):
    def test_one_rule_on_many_hosts_is_one_group_with_many_resources(self) -> None:
        """Grouping keeps every observation and reports each affected host once."""

        observations = (
            _observation(source_record_id="V-1", resource_id="host-b"),
            _observation(source_record_id="V-1", resource_id="host-a"),
            _observation(source_record_id="V-1", resource_id="host-b"),
        )

        groups = group_open_observations(observations)

        self.assertEqual(len(groups), 1)
        self.assertEqual(len(groups[0].observations), 3)
        self.assertEqual(
            {resource.resource_id for resource in groups[0].resources},
            {"host-a", "host-b"},
        )

    def test_group_members_are_ordered_by_resource_not_by_input_order(self) -> None:
        """One benchmark across many hosts arrives from many files, in any order.

        The order those files were read in is not a fact about the vulnerability, so
        it must not decide which host the report lists first, nor which observation
        identifier leads. This assertion used to read `("host-b", "host-a")`, which
        stated the order the observations happened to be constructed in rather than
        any property of the grouping.
        """

        first = _observation(source_record_id="V-1", resource_id="host-a")
        second = _observation(source_record_id="V-1", resource_id="host-b")
        third = _observation(source_record_id="V-1", resource_id="host-c")

        for order in permutations((first, second, third)):
            with self.subTest(order=[item.resource.resource_id for item in order]):
                groups = group_open_observations(order)

                self.assertEqual(len(groups), 1)
                self.assertEqual(
                    tuple(resource.resource_id for resource in groups[0].resources),
                    ("host-a", "host-b", "host-c"),
                )
                self.assertEqual(
                    groups[0].observation_ids,
                    ("obs-V-1-host-a", "obs-V-1-host-b", "obs-V-1-host-c"),
                )

    def test_two_readings_of_one_host_sort_by_artifact_name(self) -> None:
        """Two scans of one host are two members, ordered by the file they came from."""

        from_zulu = replace(
            _observation(source_record_id="V-1", resource_id="host-a"),
            observation_id="obs-zulu",
            source_artifact_name="zulu.cklb",
            source_artifact_digest="b" * 64,
        )
        from_alpha = replace(
            _observation(source_record_id="V-1", resource_id="host-a"),
            observation_id="obs-alpha",
            source_artifact_name="alpha.cklb",
        )

        groups = group_open_observations((from_zulu, from_alpha))

        self.assertEqual(groups[0].observation_ids, ("obs-alpha", "obs-zulu"))

    def test_a_group_reports_one_title_whatever_order_it_is_built_in(self) -> None:
        """`title` takes the first non-empty member, so order chose the reported text.

        This is the part of the defect that changed what the report said rather than
        only the order it said it in.
        """

        untitled = replace(
            _observation(source_record_id="V-1", resource_id="host-a", title="Ignored"),
            title="",
        )
        titled = _observation(
            source_record_id="V-1", resource_id="host-b", title="The rule title"
        )

        forward = group_open_observations((untitled, titled))
        backward = group_open_observations((titled, untitled))

        self.assertEqual(forward[0].title, backward[0].title)
        self.assertEqual(forward[0].title, "The rule title")

    def test_grouping_is_keyed_by_source_type_record_and_context(self) -> None:
        observations = (
            _observation(source_record_id="V-1", context_key="Profile A"),
            _observation(source_record_id="V-1", context_key="Profile B"),
            _observation(source_record_id="V-1", source_type="xccdf"),
            _observation(source_record_id="V-2"),
        )

        groups = group_open_observations(observations)

        self.assertEqual(len(groups), 4)

    def test_groups_are_sorted_deterministically(self) -> None:
        observations = (
            _observation(source_record_id="V-2", context_key="B"),
            _observation(source_record_id="V-1", context_key="B", source_type="xccdf"),
            _observation(source_record_id="V-1", context_key="A"),
            _observation(source_record_id="V-1", context_key="B"),
        )

        keys = [
            (group.source_type, group.source_record_id, group.context_key)
            for group in group_open_observations(observations)
        ]

        self.assertEqual(
            keys,
            [
                ("cklb", "V-1", "A"),
                ("cklb", "V-1", "B"),
                ("cklb", "V-2", "B"),
                ("xccdf", "V-1", "B"),
            ],
        )

    def test_tracking_id_is_a_stable_digest_of_the_group_key(self) -> None:
        group = group_open_observations((_observation(source_record_id="V-1"),))[0]
        payload = json.dumps(
            ["cklb", "V-1", "Example STIG"],
            separators=(",", ":"),
            ensure_ascii=True,
        )
        expected = "case-" + hashlib.sha256(payload.encode("utf-8")).hexdigest()[:16]

        self.assertEqual(group.tracking_id, expected)
        self.assertEqual(len(group.tracking_id), 21)

    def test_only_open_observations_become_vulnerabilities(self) -> None:
        observations = tuple(
            _observation(source_record_id=f"V-{index}", disposition=disposition)
            for index, disposition in enumerate(ObservationDisposition)
        )

        result = correlate_observations(observations)

        self.assertEqual(len(result.groups), 1)
        self.assertEqual(result.groups[0].source_record_id, "V-0")
        self.assertEqual(len(result.excluded), len(ObservationDisposition) - 1)

    def test_error_and_unknown_dispositions_are_surfaced_not_dropped(self) -> None:
        observations = (
            _observation(source_record_id="V-1", disposition=ObservationDisposition.ERROR),
            _observation(source_record_id="V-2", disposition=ObservationDisposition.UNKNOWN),
            _observation(source_record_id="V-3", disposition=ObservationDisposition.PASS),
        )

        result = correlate_observations(observations)

        unresolved = {item.source_record_id for item in result.unresolved}
        self.assertEqual(unresolved, {"V-1", "V-2"})
        self.assertEqual(len(result.excluded), 3)

    def test_earliest_observed_at_wins_and_absence_is_preserved(self) -> None:
        early = datetime(2026, 8, 1, tzinfo=UTC)
        late = datetime(2026, 8, 9, tzinfo=UTC)
        timed = group_open_observations(
            (
                _observation(source_record_id="V-1", resource_id="a", observed_at=late),
                _observation(source_record_id="V-1", resource_id="b", observed_at=early),
                _observation(source_record_id="V-1", resource_id="c", observed_at=None),
            )
        )[0]
        untimed = group_open_observations((_observation(source_record_id="V-2"),))[0]

        self.assertEqual(timed.earliest_observed_at, early)
        self.assertIsNone(untimed.earliest_observed_at)

    def test_a_mixed_group_names_its_untimestamped_observations(self) -> None:
        early = datetime(2026, 8, 1, tzinfo=UTC)
        group = group_open_observations(
            (
                _observation(source_record_id="V-1", resource_id="a", observed_at=early),
                _observation(source_record_id="V-1", resource_id="b", observed_at=None),
            )
        )[0]

        self.assertTrue(group.has_partial_timestamps)
        self.assertEqual(group.earliest_observed_at, early)
        self.assertEqual(group.untimestamped_observation_ids, ("obs-V-1-b",))

    def test_a_fully_timestamped_group_has_no_partial_flag(self) -> None:
        early = datetime(2026, 8, 1, tzinfo=UTC)
        group = group_open_observations(
            (_observation(source_record_id="V-1", resource_id="a", observed_at=early),)
        )[0]

        self.assertFalse(group.has_partial_timestamps)
        self.assertEqual(group.untimestamped_observation_ids, ())

    def test_a_fully_untimestamped_group_is_not_partial(self) -> None:
        group = group_open_observations(
            (
                _observation(source_record_id="V-1", resource_id="a"),
                _observation(source_record_id="V-1", resource_id="b"),
            )
        )[0]

        self.assertFalse(group.has_partial_timestamps)
        self.assertIsNone(group.earliest_observed_at)
        self.assertEqual(len(group.untimestamped_observation_ids), 2)

    def test_detection_sources_and_identifiers_are_a_sorted_union(self) -> None:
        group = group_open_observations(
            (
                _observation(
                    source_record_id="V-1",
                    resource_id="a",
                    source_tool="stig-viewer-3",
                    source_identifiers=("CCI-000366", "CCI-000048"),
                ),
                _observation(
                    source_record_id="V-1",
                    resource_id="b",
                    source_tool="acas",
                    source_identifiers=("CCI-000366",),
                ),
            )
        )[0]

        self.assertEqual(group.detection_sources, ("acas", "stig-viewer-3"))
        self.assertEqual(group.source_identifiers, ("CCI-000048", "CCI-000366"))

    def test_title_and_description_use_the_first_non_blank_value(self) -> None:
        group = group_open_observations(
            (
                _observation(source_record_id="V-1", resource_id="a", title="", description=""),
                _observation(
                    source_record_id="V-1",
                    resource_id="b",
                    title="Real title",
                    description="Real description",
                ),
            )
        )[0]

        self.assertEqual(group.title, "Real title")
        self.assertEqual(group.description, "Real description")

    def test_group_rejects_non_observation_input(self) -> None:
        with self.assertRaisesRegex(TypeError, "Observation"):
            group_open_observations(("not an observation",))  # type: ignore[arg-type]

    def test_group_is_frozen(self) -> None:
        group = group_open_observations((_observation(source_record_id="V-1"),))[0]

        self.assertIsInstance(group, VulnerabilityGroup)
        with self.assertRaises(AttributeError):
            group.tracking_id = "case-0000000000000000"  # type: ignore[misc]


class FixtureCorrelationTests(unittest.TestCase):
    def test_bundled_fixtures_group_into_six_open_vulnerabilities(self) -> None:
        observations: list[Observation] = []
        for name in ("ubuntu-host.cklb", "windows-host.ckl", "openscap-results.xml"):
            result = ingest_stig_artifact(FIXTURES / name, ingested_at=INGESTED_AT)
            self.assertEqual(result.errors, ())
            observations.extend(result.observations)

        groups = group_open_observations(observations)

        self.assertEqual(
            [group.source_record_id for group in groups],
            [
                "V-253260",
                "V-260469",
                "V-260470",
                "V-260474",
                "banner_etc_issue",
                "no_cci_mapping",
            ],
        )
        self.assertTrue(all(group.earliest_observed_at is None for group in groups))


if __name__ == "__main__":
    unittest.main()
