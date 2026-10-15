from __future__ import annotations

import calendar
import hashlib
import json
import tempfile
import unittest
from dataclasses import replace
from datetime import UTC, date, datetime, timedelta, tzinfo
from decimal import Decimal
from pathlib import Path
from zoneinfo import ZoneInfo

from complyroll.models import PainRating
from complyroll.policy import (
    COVERAGE_RULE_IDS,
    CertificationClass,
    CertificationProfile,
    PolicyRuleNotFoundError,
    PolicySourceIntegrityError,
    ResponseContext,
    RuleForce,
    RuleSourceManifest,
    RuleTimeframe,
    SelectedPolicy,
    TimeframeUnit,
    UnsupportedTimeframeError,
    load_bundled_policy,
    load_bundled_rule_source_manifest,
    load_bundled_rule_source_snapshot,
    load_rule_source_snapshot,
    select_policy,
)

TEST_ROOT = Path(__file__).parent
GOLDEN = TEST_ROOT / "golden" / "policy-class-b-c.json"
START = datetime(2026, 8, 20, 16, 0, tzinfo=UTC)


class RuleSourceSnapshotTests(unittest.TestCase):
    def test_bundled_snapshot_matches_pinned_manifest(self) -> None:
        snapshot = load_bundled_rule_source_snapshot()

        self.assertEqual(snapshot.content_sha256, snapshot.manifest.dataset_sha256)
        self.assertEqual(snapshot.data["info"]["version"], snapshot.manifest.dataset_version)
        self.assertIn("VDR", snapshot.data["FRR"])
        self.assertIn("VER", snapshot.data["FRR"])

    def test_verified_snapshot_data_is_defensively_copied(self) -> None:
        snapshot = load_bundled_rule_source_snapshot()
        changed = snapshot.data
        changed["info"]["version"] = "caller mutation"

        self.assertEqual(snapshot.data["info"]["version"], snapshot.manifest.dataset_version)

    def test_snapshot_digest_mismatch_blocks_policy_loading(self) -> None:
        manifest = load_bundled_rule_source_manifest()
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "rules.json"
            path.write_text("{}", encoding="utf-8")

            with self.assertRaisesRegex(PolicySourceIntegrityError, "does not match"):
                load_rule_source_snapshot(path, manifest)

    def test_manifest_rejects_parent_path_traversal(self) -> None:
        value = load_bundled_rule_source_manifest().to_dict()
        value["dataset_path"] = "../rules.json"

        with self.assertRaisesRegex(ValueError, "repository-relative"):
            RuleSourceManifest.from_dict(value)

    def test_snapshot_metadata_must_match_manifest(self) -> None:
        snapshot = load_bundled_rule_source_snapshot()
        content = json.dumps(snapshot.data, ensure_ascii=False, indent=2).encode("utf-8")
        manifest = replace(
            snapshot.manifest,
            dataset_sha256=hashlib.sha256(content).hexdigest(),
            dataset_version="different-version",
        )
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "rules.json"
            path.write_bytes(content)

            with self.assertRaisesRegex(PolicySourceIntegrityError, "version"):
                load_rule_source_snapshot(path, manifest)


class ClassAwarePolicyTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.policies = {
            class_name.value: load_bundled_policy(CertificationProfile(class_name))
            for class_name in CertificationClass
        }
        cls.golden = json.loads(GOLDEN.read_text(encoding="utf-8"))

    def test_class_b_and_c_selection_matches_official_golden_matrix(self) -> None:
        actual = {
            "source": {
                "commit": self.policies["B"].provenance.commit,
                "dataset_sha256": self.policies["B"].provenance.dataset_sha256,
                "dataset_version": self.policies["B"].provenance.dataset_version,
            },
            "profiles": {
                class_name: self._policy_summary(policy)
                for class_name, policy in self.policies.items()
            },
        }

        self.assertEqual(actual, self.golden)

    def test_selection_filters_non_provider_rules_and_applies_class_force(self) -> None:
        class_b = self.policies["B"]
        class_c = self.policies["C"]

        self.assertEqual(len(class_b.rules), 36)
        self.assertEqual(len(class_c.rules), 36)
        self.assertNotIn("VER-FRP-ARP", {rule.rule_id for rule in class_b.rules})
        self.assertNotIn("VER-AGM-RVR", {rule.rule_id for rule in class_b.rules})
        self.assertEqual(class_b.rule("VER-TFR-IRI").force, RuleForce.MAY)
        self.assertEqual(class_c.rule("VER-TFR-IRI").force, RuleForce.SHOULD)

    def test_evaluation_response_and_acceptance_deadlines_include_provenance(self) -> None:
        class_b = self.policies["B"]
        class_c = self.policies["C"]

        self.assertEqual(class_b.evaluation_deadline(START).due_at, START + timedelta(days=7))
        self.assertEqual(class_c.evaluation_deadline(START).due_at, START + timedelta(days=5))
        self.assertEqual(
            class_c.acceptance_deadline(START).due_at,
            START + timedelta(days=192),
        )

        class_b_response = class_b.response_deadline(
            START,
            pain=PainRating.N5,
            is_internet_reachable=True,
            is_likely_exploitable=True,
        )
        class_c_response = class_c.response_deadline(
            START,
            pain=PainRating.N5,
            is_internet_reachable=True,
            is_likely_exploitable=True,
        )
        assert class_b_response is not None
        assert class_c_response is not None
        self.assertEqual(class_b_response.due_at, START + timedelta(days=4))
        self.assertEqual(class_c_response.due_at, START + timedelta(days=2))
        self.assertEqual(class_c_response.rule_id, "VDR-TFR-PVR")
        self.assertEqual(class_c_response.provenance.commit, self.golden["source"]["commit"])
        self.assertEqual(
            class_c_response.provenance.dataset_sha256,
            self.golden["source"]["dataset_sha256"],
        )

    def test_not_likely_exploitable_uses_nlev_regardless_of_reachability(self) -> None:
        policy = self.policies["C"]
        reachable = policy.response_deadline(
            START,
            pain=PainRating.N5,
            is_internet_reachable=True,
            is_likely_exploitable=False,
        )
        not_reachable = policy.response_deadline(
            START,
            pain=PainRating.N5,
            is_internet_reachable=False,
            is_likely_exploitable=False,
        )

        assert reachable is not None
        assert not_reachable is not None
        self.assertEqual(reachable.due_at, START + timedelta(days=16))
        self.assertEqual(reachable, not_reachable)

    def test_n1_has_no_policy_response_deadline(self) -> None:
        policy = self.policies["C"]

        deadline = policy.response_deadline(
            START,
            pain=PainRating.N1,
            is_internet_reachable=True,
            is_likely_exploitable=True,
        )

        self.assertIsNone(deadline)

    def test_context_inputs_require_domain_types(self) -> None:
        policy = self.policies["C"]

        with self.assertRaisesRegex(TypeError, "pain must be a PainRating"):
            policy.response_deadline(
                START,
                pain=5,  # type: ignore[arg-type]
                is_internet_reachable=True,
                is_likely_exploitable=True,
            )
        with self.assertRaisesRegex(TypeError, "is_internet_reachable must be a boolean"):
            policy.response_deadline(
                START,
                pain=PainRating.N5,
                is_internet_reachable="false",  # type: ignore[arg-type]
                is_likely_exploitable=True,
            )

    def test_month_timeframe_uses_calendar_month_and_clamps_day(self) -> None:
        policy = self.policies["B"]
        january_end = datetime(2027, 1, 31, 12, 0, tzinfo=UTC)

        deadline = policy.deadline_for_rule("VER-TFR-MHR", january_end)

        self.assertEqual(deadline.due_at, datetime(2027, 2, 28, 12, 0, tzinfo=UTC))

    def test_calendar_months_use_the_configured_provider_timezone(self) -> None:
        phoenix_profile = CertificationProfile(
            CertificationClass.B,
            calendar_timezone="America/Phoenix",
        )
        policy = load_bundled_policy(phoenix_profile)
        phoenix = ZoneInfo("America/Phoenix")
        start = datetime(2027, 2, 28, 17, 0, tzinfo=phoenix)

        deadline = policy.deadline_for_rule("VER-TFR-MHR", start)
        local_due = deadline.due_at.astimezone(phoenix)

        self.assertEqual(local_due.date(), date(2027, 3, 28))
        self.assertEqual(local_due.hour, 17)
        self.assertEqual(deadline.due_at, datetime(2027, 3, 29, 0, 0, tzinfo=UTC))

    def test_utc_calendar_remains_the_default_and_is_unchanged(self) -> None:
        utc_policy = self.policies["B"]
        phoenix_policy = load_bundled_policy(
            CertificationProfile(CertificationClass.B, calendar_timezone="America/Phoenix")
        )
        start = datetime(2027, 2, 28, 17, 0, tzinfo=ZoneInfo("America/Phoenix"))

        self.assertEqual(utc_policy.profile.calendar_timezone, "UTC")
        self.assertEqual(
            utc_policy.deadline_for_rule("VER-TFR-MHR", start).due_at,
            datetime(2027, 4, 1, 0, 0, tzinfo=UTC),
        )
        self.assertNotEqual(
            utc_policy.deadline_for_rule("VER-TFR-MHR", start).due_at,
            phoenix_policy.deadline_for_rule("VER-TFR-MHR", start).due_at,
        )

    def test_exact_units_ignore_the_calendar_timezone(self) -> None:
        phoenix_policy = load_bundled_policy(
            CertificationProfile(CertificationClass.C, calendar_timezone="America/Phoenix")
        )

        self.assertEqual(
            phoenix_policy.evaluation_deadline(START).due_at,
            START + timedelta(days=5),
        )

    def test_calendar_timezone_must_be_an_iana_name(self) -> None:
        with self.assertRaisesRegex(ValueError, "calendar_timezone"):
            CertificationProfile(CertificationClass.C, calendar_timezone="Mars/Olympus_Mons")
        with self.assertRaisesRegex(ValueError, "calendar_timezone"):
            CertificationProfile(CertificationClass.C, calendar_timezone="   ")
        with self.assertRaisesRegex(ValueError, "calendar_timezone"):
            CertificationProfile(CertificationClass.C, calendar_timezone="/etc/passwd")

    def test_profile_stays_hashable_with_a_calendar_timezone(self) -> None:
        profile = CertificationProfile(CertificationClass.C, calendar_timezone="America/Phoenix")

        self.assertEqual(len({profile, replace(profile)}), 1)

    def test_rule_without_structured_timeframe_is_not_inferred_from_prose(self) -> None:
        policy = self.policies["C"]

        self.assertIsNone(policy.rule("VDR-TFR-KEV").timeframe)
        self.assertIn("CISA", policy.rule("VDR-TFR-KEV").statement)

    def test_nmv_carries_the_structured_timeframe_added_in_rules_2026_09_13(self) -> None:
        # NOTE: FedRAMP/rules 2026.09.13.01 (pull request 28) answered discussion 164 by
        # adding the pair VDR-TFR-NMV had only stated in prose. The clock is exposed here and
        # is not a per-vulnerability report deadline.
        for class_name in ("B", "C"):
            with self.subTest(certification_class=class_name):
                rule = self.policies[class_name].rule("VDR-TFR-NMV")
                deadline = self.policies[class_name].deadline_for_rule("VDR-TFR-NMV", START)

                self.assertEqual(rule.timeframe, RuleTimeframe(Decimal(3), TimeframeUnit.MONTHS))
                self.assertIs(rule.force, RuleForce.MUST)
                self.assertEqual(deadline.due_at, datetime(2026, 11, 20, 16, 0, tzinfo=UTC))

    def test_business_day_deadline_requires_an_explicit_calendar(self) -> None:
        timeframe = RuleTimeframe(Decimal(2), TimeframeUnit.BUSINESS_DAYS)

        with self.assertRaisesRegex(UnsupportedTimeframeError, "holiday and timezone"):
            timeframe.deadline_from(START)

    def test_timeframe_requires_domain_types(self) -> None:
        with self.assertRaisesRegex(TypeError, "amount must be a Decimal"):
            RuleTimeframe(2, TimeframeUnit.DAYS)  # type: ignore[arg-type]
        with self.assertRaisesRegex(TypeError, "unit must be a TimeframeUnit"):
            RuleTimeframe(Decimal(2), "days")  # type: ignore[arg-type]

    @staticmethod
    def _policy_summary(policy: SelectedPolicy) -> dict[str, object]:
        direct_rule_ids = (
            "VDR-TFR-NMV",
            "VDR-TFR-MVX",
            "VDR-TFR-PDD",
            "VDR-TFR-PCD",
            "VDR-TFR-PSD",
            "VER-TFR-MHR",
            "VER-TFR-MRH",
            "VER-TFR-EVU",
            "VER-TFR-MAV",
        )
        timeframes: dict[str, object] = {}
        for rule_id in direct_rule_ids:
            rule = policy.rule(rule_id)
            assert rule.timeframe is not None
            timeframes[rule_id] = {
                "force": rule.force.value,
                "amount": rule.timeframe.display_amount,
                "unit": rule.timeframe.unit.value,
            }

        response_rule = policy.rule("VDR-TFR-PVR")
        response: dict[str, object] = {}
        for pain in PainRating:
            targets: dict[str, object] = {}
            for context in ResponseContext:
                target = response_rule.response_timeframe(pain, context)
                if target is not None:
                    targets[context.value] = {
                        "amount": target.timeframe.display_amount,
                        "unit": target.timeframe.unit.value,
                    }
            response[pain.name] = targets

        return {
            "selected_rule_count": len(policy.rules),
            "timeframes": timeframes,
            "response": response,
        }


def expected_due(timeframe: RuleTimeframe, start: datetime, zone: tzinfo) -> datetime:
    """Compute a coverage due date independently: exact days, or months clamped in `zone`."""

    if timeframe.unit is TimeframeUnit.DAYS:
        return start + timedelta(days=int(timeframe.amount))
    if timeframe.unit is TimeframeUnit.MONTHS:
        local = start.astimezone(zone)
        year, month_index = divmod(local.year * 12 + local.month - 1 + int(timeframe.amount), 12)
        day = min(local.day, calendar.monthrange(year, month_index + 1)[1])
        return local.replace(year=year, month=month_index + 1, day=day).astimezone(UTC)
    raise AssertionError(f"no coverage rule uses {timeframe.unit.value}; extend the oracle")


def snapshot_without(rule_ids: set[str], directory: Path) -> Path:
    """Write the bundled dataset with the named VDR rules removed; return its path."""

    data = load_bundled_rule_source_snapshot().data
    for scoped in data["FRR"]["VDR"]["data"].values():
        for rules in scoped.values():
            for rule_id in rule_ids & set(rules):
                del rules[rule_id]
    path = directory / "rules.json"
    path.write_bytes(json.dumps(data, ensure_ascii=False, indent=2).encode("utf-8"))
    return path


class CoverageDeadlineTests(unittest.TestCase):
    """The five detection cadence clocks come from the pinned dataset, never from literals."""

    @classmethod
    def setUpClass(cls) -> None:
        cls.policies = {
            class_name.value: load_bundled_policy(CertificationProfile(class_name))
            for class_name in CertificationClass
        }
        cls.golden = json.loads(GOLDEN.read_text(encoding="utf-8"))

    def test_the_coverage_rules_are_the_five_detection_cadence_rules(self) -> None:
        self.assertEqual(
            COVERAGE_RULE_IDS,
            ("VDR-TFR-MVX", "VDR-TFR-NMV", "VDR-TFR-PCD", "VDR-TFR-PDD", "VDR-TFR-PSD"),
        )

    def test_mvx_is_the_20x_scoped_rule_and_mvf_is_never_selected(self) -> None:
        for class_name, policy in self.policies.items():
            with self.subTest(certification_class=class_name):
                scopes = {
                    rule_id: policy.rule(rule_id).source_scope for rule_id in COVERAGE_RULE_IDS
                }
                self.assertEqual(scopes.pop("VDR-TFR-MVX"), "20x")
                self.assertEqual(set(scopes.values()), {"all"})
                with self.assertRaises(PolicyRuleNotFoundError):
                    policy.rule("VDR-TFR-MVF")

    def test_classes_b_and_c_read_every_coverage_clock_from_the_dataset(self) -> None:
        for class_name, policy in self.policies.items():
            golden = self.golden["profiles"][class_name]["timeframes"]
            for rule_id in COVERAGE_RULE_IDS:
                with self.subTest(certification_class=class_name, rule_id=rule_id):
                    rule = policy.rule(rule_id)
                    deadline = policy.coverage_deadline(rule_id, START)

                    assert rule.timeframe is not None
                    self.assertEqual(deadline, policy.deadline_for_rule(rule_id, START))
                    self.assertEqual(deadline.rule_id, rule_id)
                    self.assertEqual(deadline.rule_name, rule.name)
                    self.assertIs(deadline.force, rule.force)
                    self.assertEqual(deadline.timeframe, rule.timeframe)
                    self.assertEqual(deadline.start_at, START)
                    self.assertEqual(deadline.provenance, policy.provenance)
                    self.assertEqual(
                        golden[rule_id],
                        {
                            "force": deadline.force.value,
                            "amount": deadline.timeframe.display_amount,
                            "unit": deadline.timeframe.unit.value,
                        },
                    )
                    self.assertEqual(deadline.due_at, expected_due(rule.timeframe, START, UTC))

    def test_day_clocks_are_exact_elapsed_time_whatever_the_calendar(self) -> None:
        for class_name in CertificationClass:
            phoenix = load_bundled_policy(
                CertificationProfile(class_name, calendar_timezone="America/Phoenix")
            )
            utc = self.policies[class_name.value]
            timeframes = {rule_id: phoenix.rule(rule_id).timeframe for rule_id in COVERAGE_RULE_IDS}
            day_rules = {
                rule_id: timeframe
                for rule_id, timeframe in timeframes.items()
                if timeframe is not None and timeframe.unit is TimeframeUnit.DAYS
            }
            self.assertIn("VDR-TFR-MVX", day_rules)
            for rule_id, timeframe in day_rules.items():
                with self.subTest(certification_class=class_name.value, rule_id=rule_id):
                    due = phoenix.coverage_deadline(rule_id, START).due_at
                    self.assertEqual(due, utc.coverage_deadline(rule_id, START).due_at)
                    self.assertEqual(due - START, timedelta(days=int(timeframe.amount)))

    def test_month_clocks_clamp_in_the_provider_calendar(self) -> None:
        phoenix = ZoneInfo("America/Phoenix")
        # The 31st of January, 10:00 in Phoenix, is the 31st in UTC too: the clamp shows alone.
        month_end = datetime(2027, 1, 31, 10, 0, tzinfo=phoenix)
        # 20:00 on January 30 in Phoenix is already January 31 in UTC: the zone shows.
        evening = datetime(2027, 1, 30, 20, 0, tzinfo=phoenix)
        zone_mattered = False
        for class_name in CertificationClass:
            policy = load_bundled_policy(
                CertificationProfile(class_name, calendar_timezone="America/Phoenix")
            )
            utc = self.policies[class_name.value]
            timeframes = {rule_id: policy.rule(rule_id).timeframe for rule_id in COVERAGE_RULE_IDS}
            month_rules = {
                rule_id: timeframe
                for rule_id, timeframe in timeframes.items()
                if timeframe is not None and timeframe.unit is TimeframeUnit.MONTHS
            }
            self.assertIn("VDR-TFR-NMV", month_rules)
            for rule_id, timeframe in month_rules.items():
                with self.subTest(certification_class=class_name.value, rule_id=rule_id):
                    clamped = policy.coverage_deadline(rule_id, month_end).due_at
                    local = clamped.astimezone(phoenix)
                    self.assertEqual(clamped, expected_due(timeframe, month_end, phoenix))
                    self.assertEqual(local.day, calendar.monthrange(local.year, local.month)[1])
                    self.assertEqual((local.hour, local.minute), (10, 0))

                    shifted = policy.coverage_deadline(rule_id, evening).due_at
                    self.assertEqual(shifted, expected_due(timeframe, evening, phoenix))
                    self.assertEqual(shifted.astimezone(phoenix).hour, 20)
                    self.assertEqual(
                        utc.coverage_deadline(rule_id, evening).due_at,
                        expected_due(timeframe, evening, UTC),
                    )
                    zone_mattered |= shifted != utc.coverage_deadline(rule_id, evening).due_at
        self.assertTrue(zone_mattered)

    def test_a_policy_without_a_coverage_rule_refuses_it_by_the_policy_error(self) -> None:
        for class_name, policy in self.policies.items():
            for missing in COVERAGE_RULE_IDS:
                with self.subTest(certification_class=class_name, missing=missing):
                    stripped = replace(
                        policy,
                        rules=tuple(item for item in policy.rules if item.rule_id != missing),
                    )
                    with self.assertRaisesRegex(PolicyRuleNotFoundError, missing):
                        stripped.coverage_deadline(missing, START)
                    for rule_id in set(COVERAGE_RULE_IDS) - {missing}:
                        self.assertEqual(
                            stripped.coverage_deadline(rule_id, START),
                            policy.coverage_deadline(rule_id, START),
                        )

    def test_selection_never_requires_the_coverage_rules(self) -> None:
        snapshot = load_bundled_rule_source_snapshot()
        with tempfile.TemporaryDirectory() as directory:
            path = snapshot_without(set(COVERAGE_RULE_IDS), Path(directory))
            manifest = replace(
                snapshot.manifest,
                dataset_sha256=hashlib.sha256(path.read_bytes()).hexdigest(),
            )
            stripped = load_rule_source_snapshot(path, manifest)
        for class_name in CertificationClass:
            with self.subTest(certification_class=class_name.value):
                policy = select_policy(stripped, CertificationProfile(class_name))
                evaluation = policy.evaluation_deadline(START)
                bundled = self.policies[class_name.value].evaluation_deadline(START)
                # The stripped dataset carries its own digest, so only the clock is compared.
                self.assertEqual(
                    (evaluation.rule_id, evaluation.due_at), (bundled.rule_id, bundled.due_at)
                )
                for rule_id in COVERAGE_RULE_IDS:
                    with self.assertRaisesRegex(PolicyRuleNotFoundError, rule_id):
                        policy.coverage_deadline(rule_id, START)

    def test_only_a_coverage_rule_takes_a_coverage_deadline(self) -> None:
        policy = self.policies["B"]
        for rule_id in ("VER-TFR-EVU", "VDR-TFR-PVR", "VDR-TFR-MVF", "vdr-tfr-mvx", ""):
            with self.subTest(rule_id=rule_id):
                with self.assertRaisesRegex(ValueError, "is not a coverage rule"):
                    policy.coverage_deadline(rule_id, START)

    def test_a_coverage_anchor_must_be_aware(self) -> None:
        with self.assertRaisesRegex(ValueError, "start must include a timezone"):
            self.policies["C"].coverage_deadline("VDR-TFR-MVX", datetime(2026, 8, 20, 16))


if __name__ == "__main__":
    unittest.main()
