from __future__ import annotations

import hashlib
import json
import tempfile
import unittest
from dataclasses import replace
from datetime import UTC, date, datetime, timedelta
from decimal import Decimal
from pathlib import Path
from zoneinfo import ZoneInfo

from complyroll.models import PainRating
from complyroll.policy import (
    CertificationClass,
    CertificationProfile,
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

        self.assertIsNone(policy.rule("VDR-TFR-NMV").timeframe)

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


if __name__ == "__main__":
    unittest.main()
