# ******************************************************************************
# *Title: CycloneDX Adapter Tests*
# *Author: Kyle Versluis*
# *Description: Unit tests for the CycloneDX SBOM adapter (ADR 0016).*
# ******************************************************************************
"""Unit tests for the CycloneDX adapter: the frozen package key and the subject lineage."""

# *--- Imports ---*

from __future__ import annotations

import dataclasses
import hashlib
import json
import random
import tempfile
import tracemalloc
import unittest
from collections.abc import Sequence
from datetime import UTC, datetime, timedelta, timezone
from itertools import permutations
from pathlib import Path
from typing import Any
from unittest import mock

from test_replay import StoreFixture, bumped

from complyroll.adapters import (
    FailureClass,
    IngestResult,
    UnmintableReason,
    classify_ingest,
    common,
    ingest_stig_artifact,
)
from complyroll.adapters.base import (
    AdapterOutput,
    AdapterParseError,
    ArtifactProvenance,
    ParsedDocument,
)
from complyroll.adapters.common import (
    MAX_DESCRIPTION_CHARS,
    MAX_IDENTITY_CHARS,
    MAX_LIST_ITEM_CHARS,
    MAX_LIST_ITEMS,
    MAX_METADATA_VALUE_CHARS,
    MAX_OBSERVATION_JSON_BYTES,
    MAX_TITLE_CHARS,
)
from complyroll.adapters.cyclonedx import (
    CYCLONEDX_MEDIA_TYPE,
    CYCLONEDX_METADATA_KEYS,
    CYCLONEDX_PARSER_VERSION,
    CYCLONEDX_SOURCE_TYPE,
    MATCHED_DESCRIPTION,
    MAX_AFFECTS_PER_VULNERABILITY,
    MAX_INSTANCES_PER_PACKAGE,
    PURL_CASE_FOLDS,
    PURL_DASHED_NAME_TYPES,
    PURL_STRIPPED_QUALIFIERS,
    UNMATCHED_DESCRIPTION,
    VEX_REFUSAL,
    CycloneDxAdapter,
    _carrier,
    ascii_fold,
    digest_shaped,
    package_key,
    package_resource_id,
    purl_key,
    ref_key,
    split_package_resource_id,
    subject_lineage,
)
from complyroll.adapters.safeio import DEFAULT_LIMITS, InputLimitError
from complyroll.events import EventRepository
from complyroll.history import (
    HistoryError,
    audit_history,
    correlate_cases,
    record_ingest,
    rehydrate_observations,
)
from complyroll.models import Observation, ObservationDisposition, SourceSeverity
from complyroll.policy import CertificationClass
from complyroll.reports import (
    CompiledHistoricalReport,
    CompiledVdtReport,
    ReportOptions,
    compile_avi_report,
    compile_avi_report_from_history,
    compile_historical_report,
    compile_historical_report_from_history,
    compile_vdt_report,
    compile_vdt_report_from_history,
)
from complyroll.reports.kev import cve_may_be_missing

# *--- Configuration ---*

# A copy of the fold table in the plan's section 5.1 (Plans/phase2-sbom-adapter.md), which is
# not in the repository. The module literal is pinned against this text, not against itself.
PLAN_FOLD_TABLE = """
| alpm, apk, bitbucket, composer, deb, github, hex | folded (`false`) | folded (`false`) |
| oci | prohibited | folded (`false`) |
| pypi | prohibited | folded (`false`), and `_` to `-` |
| rpm | folded (`false`) | verbatim (`true`) |
| golang, huggingface, maven, npm, swift | verbatim (`true`) | verbatim (`true`) |
| cargo, cocoapods, nuget | prohibited | verbatim (`true`) |
| conan, docker, generic | verbatim (no flag) | verbatim (no flag) |
| conda, gem, mlflow | prohibited | verbatim (no flag) |
"""

SHA256 = "sha256:" + "0123456789abcdef" * 4
IDENTITY = "CycloneDX inventory identity cannot be used as written: "
SHA512 = "sha512:" + "0123456789abcdef" * 8
UPPER_A_DIAERESIS = "\u00c4"
LOWER_A_DIAERESIS = "\u00e4"


# *--- Helpers ---*


def plan_fold_rows() -> dict[str, tuple[bool, bool, bool]]:
    """Read the plan's table copy as type to (namespace folded, name folded, name dashed)."""
    rows: dict[str, tuple[bool, bool, bool]] = {}
    for line in PLAN_FOLD_TABLE.strip().splitlines():
        types, namespace, name = (cell.strip() for cell in line.strip("|").split("|"))
        for purl_type in types.split(", "):
            rows[purl_type] = (
                namespace.startswith("folded"),
                name.startswith("folded"),
                "`_` to `-`" in name,
            )
    return rows


def key(purl: str) -> str:
    """Return the key of a component that carries only this purl."""
    return package_key({"type": "library", "name": "synthetic", "purl": purl})[0]


def weak(purl: str) -> bool:
    """Return whether a component carrying this purl falls back to the component: form."""
    return package_key({"type": "library", "name": "synthetic", "purl": purl})[1]


def hand_fold(text: str) -> str:
    """Lowercase A to Z by code point arithmetic, independent of any Unicode table."""
    return "".join(chr(ord(char) + 32) if "A" <= char <= "Z" else char for char in text)


# *--- Worked Examples ---*


class WorkedExampleTests(unittest.TestCase):
    """The worked examples of section 5.1, from the producer files."""

    def test_rpm_keeps_arch_and_strips_version_epoch_and_distro(self) -> None:
        purl = (
            "pkg:rpm/centos/openssl-libs@1.0.2k-16.el7?arch=x86_64&epoch=1&distro=centos-7.6.1810"
        )
        self.assertEqual(key(purl), "pkg:rpm/centos/openssl-libs?arch=x86_64")

    def test_deb_strips_version_and_distro(self) -> None:
        self.assertEqual(key("pkg:deb/debian/bash@5.0-4?distro=debian-10.2"), "pkg:deb/debian/bash")

    def test_gem_strips_version(self) -> None:
        self.assertEqual(key("pkg:gem/activesupport@6.0.2.1"), "pkg:gem/activesupport")

    def test_key_returns_raw_purl_and_strong_identity(self) -> None:
        purl = "pkg:deb/debian/bash@5.0-4?distro=debian-10.2"
        component = {"type": "library", "name": "bash", "purl": purl}
        self.assertEqual(package_key(component), ("pkg:deb/debian/bash", False, purl))

    def test_qualifier_order_does_not_change_the_key(self) -> None:
        first = key("pkg:rpm/centos/a@1?arch=x86_64&zz=1&classifier=c")
        second = key("pkg:rpm/centos/a@1?zz=1&classifier=c&arch=x86_64")
        self.assertEqual(first, "pkg:rpm/centos/a?arch=x86_64&classifier=c&zz=1")
        self.assertEqual(first, second)

    def test_qualifier_strings_sort_as_built(self) -> None:
        # purl-how-to-build sorts the built key=value strings, so "os.version=" sorts before
        # "os=" ('.' is below '='), where a sort by key alone would put "os" first.
        self.assertEqual(key("pkg:generic/a?os=x&os.version=y"), "pkg:generic/a?os.version=y&os=x")

    def test_syft_deb_upstream_version_does_not_split_an_upgrade(self) -> None:
        # syft writes upstream=<source>@<source version> on deb (debian/package.go).
        before = key("pkg:deb/debian/libgcc-s1@10.2.1-6?arch=amd64&upstream=gcc-10%4010.2.1-6")
        after = key("pkg:deb/debian/libgcc-s1@10.2.1-7?arch=amd64&upstream=gcc-10%4010.2.1-7")
        self.assertEqual(before, "pkg:deb/debian/libgcc-s1?arch=amd64")
        self.assertEqual(before, after)

    def test_syft_rpm_upstream_file_name_does_not_split_an_upgrade(self) -> None:
        # syft writes upstream=<source RPM file name> on rpm (redhat/package.go).
        before = key(
            "pkg:rpm/centos/openssl-libs@1.0.2k-16.el7?arch=x86_64"
            "&upstream=openssl-1.0.2k-16.el7.src.rpm"
        )
        after = key(
            "pkg:rpm/centos/openssl-libs@1.0.2k-19.el7?arch=x86_64"
            "&upstream=openssl-1.0.2k-19.el7.src.rpm"
        )
        self.assertEqual(before, "pkg:rpm/centos/openssl-libs?arch=x86_64")
        self.assertEqual(before, after)

    def test_apk_upstream_does_not_split_producers(self) -> None:
        # syft and grype write upstream on apk; trivy does not.
        self.assertEqual(
            key("pkg:apk/alpine/libcrypto1.1@1.1.1w-r1?arch=x86_64&upstream=openssl"),
            key("pkg:apk/alpine/libcrypto1.1@1.1.1w-r1?arch=x86_64"),
        )

    def test_strip_set_removes_each_key(self) -> None:
        stripped = (
            "epoch",
            "distro",
            "upstream",
            "file_path",
            "file_name",
            "download_url",
            "vcs_url",
            "repository_url",
            "checksum",
            "package-id",
        )
        for qualifier in stripped:
            with self.subTest(qualifier=qualifier):
                self.assertEqual(
                    key(f"pkg:generic/a@1?{qualifier}=v&arch=x"), "pkg:generic/a?arch=x"
                )

    def test_identity_qualifiers_and_unknown_keys_stay(self) -> None:
        self.assertEqual(
            key("pkg:maven/g/a@1?classifier=sources&zz=q&arch=x"),
            "pkg:maven/g/a?arch=x&classifier=sources&zz=q",
        )

    def test_tag_is_kept_outside_oci(self) -> None:
        self.assertEqual(key("pkg:docker/web@1?tag=1.4"), "pkg:docker/web?tag=1.4")

    def test_key_is_idempotent(self) -> None:
        purls = (
            "pkg:rpm/CentOS/openssl-libs@1?arch=x86_64&epoch=1",
            "pkg:pypi/Synthetic_Pkg@1.0",
            "pkg:generic/ns/a%2Fb?x=%7C%20y#./sub/../p",
            "pkg:npm/%40scope/a%7Cb@1",
            "pkg:oci/web?repository_url=registry.example.test/team/web&tag=1",
            "pkg:pypi/" + UPPER_A_DIAERESIS,
        )
        for purl in purls:
            with self.subTest(purl=purl):
                once = purl_key(purl)
                assert once is not None
                self.assertEqual(purl_key(once), once)


# *--- Fold Table ---*


class FoldTableTests(unittest.TestCase):
    """The frozen per-type case table of Decision E (A6, A23)."""

    def test_module_literal_equals_the_plan_table(self) -> None:
        rows = plan_fold_rows()
        self.assertEqual(len(rows), 24)
        self.assertEqual(
            dict(PURL_CASE_FOLDS), {name: (ns, nm) for name, (ns, nm, _) in rows.items()}
        )
        self.assertEqual(
            PURL_DASHED_NAME_TYPES, frozenset(name for name, row in rows.items() if row[2])
        )

    def test_every_listed_type_folds_or_keeps_each_segment(self) -> None:
        for purl_type, (namespace_folded, name_folded, dashed) in plan_fold_rows().items():
            with self.subTest(purl_type=purl_type):
                upper = key(f"pkg:{purl_type}/Ns_Seg/Na_Me@1")
                lower = key(f"pkg:{purl_type}/ns_seg/na_me@1")
                namespace = "ns_seg" if namespace_folded else "Ns_Seg"
                name = "na_me" if name_folded else "Na_Me"
                if dashed:
                    name = name.replace("_", "-")
                self.assertEqual(upper, f"pkg:{purl_type}/{namespace}/{name}")
                self.assertEqual(upper == lower, namespace_folded and name_folded)

    def test_unlisted_type_stays_verbatim(self) -> None:
        self.assertNotIn("synthetictype", PURL_CASE_FOLDS)
        self.assertEqual(key("pkg:SyntheticType/Ns/Na_Me@1"), "pkg:synthetictype/Ns/Na_Me")

    def test_pypi_case_and_underscore_are_one_key(self) -> None:
        self.assertEqual(key("pkg:pypi/Synthetic_Pkg@1"), "pkg:pypi/synthetic-pkg")
        self.assertEqual(key("pkg:pypi/Synthetic_Pkg@1"), key("pkg:pypi/synthetic-pkg@2"))

    def test_npm_names_in_two_cases_are_two_keys(self) -> None:
        self.assertEqual(key("pkg:npm/Synthetic@1"), "pkg:npm/Synthetic")
        self.assertNotEqual(key("pkg:npm/Synthetic@1"), key("pkg:npm/synthetic@1"))

    def test_composer_folds_namespace_and_name(self) -> None:
        self.assertEqual(key("pkg:composer/Vendor/Pkg@1"), "pkg:composer/vendor/pkg")
        self.assertEqual(key("pkg:composer/Vendor/Pkg@1"), key("pkg:composer/vendor/pkg@1"))

    def test_deb_namespace_folds(self) -> None:
        self.assertEqual(key("pkg:deb/Debian/bash@1"), "pkg:deb/debian/bash")
        self.assertEqual(key("pkg:deb/Debian/bash@1"), key("pkg:deb/debian/bash@1"))

    def test_rpm_namespace_folds_and_name_stays(self) -> None:
        self.assertEqual(key("pkg:rpm/CentOS/openssl@1"), "pkg:rpm/centos/openssl")
        self.assertEqual(key("pkg:rpm/CentOS/openssl@1"), key("pkg:rpm/centos/openssl@1"))
        self.assertEqual(key("pkg:rpm/centos/OpenSSL@1"), "pkg:rpm/centos/OpenSSL")
        self.assertNotEqual(key("pkg:rpm/centos/OpenSSL@1"), key("pkg:rpm/centos/openssl@1"))

    def test_maven_namespace_stays(self) -> None:
        self.assertEqual(key("pkg:maven/Org.Example/a@1"), "pkg:maven/Org.Example/a")
        self.assertNotEqual(key("pkg:maven/Org.Example/a@1"), key("pkg:maven/org.example/a@1"))

    def test_golang_stays_verbatim_against_its_note(self) -> None:
        # purl-types-golang.json marks both segments case_sensitive true while its notes say
        # "The namespace shall be lowercased." and "The name shall be lowercased." The flag
        # wins (A23): folding on the note would re-mint every golang key.
        upper = key("pkg:golang/GitHub.com/Example/Mod@v1")
        self.assertEqual(upper, "pkg:golang/GitHub.com/Example/Mod")
        self.assertNotEqual(upper, key("pkg:golang/github.com/example/mod@v1"))


# *--- ASCII Folding ---*


class AsciiFoldTests(unittest.TestCase):
    """Folding is A to Z only, never str.lower() (E2)."""

    def test_non_ascii_names_in_two_cases_are_two_keys(self) -> None:
        upper = key(f"pkg:pypi/{UPPER_A_DIAERESIS}x@1")
        lower = key(f"pkg:pypi/{LOWER_A_DIAERESIS}x@1")
        self.assertEqual(upper, "pkg:pypi/%C3%84x")
        self.assertEqual(lower, "pkg:pypi/%C3%A4x")
        self.assertNotEqual(upper, lower)

    def test_encoded_and_raw_non_ascii_are_one_key(self) -> None:
        self.assertEqual(key("pkg:pypi/%C3%84X@1"), key(f"pkg:pypi/{UPPER_A_DIAERESIS}X@1"))
        self.assertEqual(key("pkg:pypi/%c3%84X@1"), "pkg:pypi/%C3%84x")

    def test_fold_matches_hand_translation_on_every_code_point(self) -> None:
        text = "".join(chr(point) for point in range(0x110000) if not 0xD800 <= point <= 0xDFFF)
        self.assertEqual(ascii_fold(text), hand_fold(text))

    def test_fold_leaves_lookalikes_alone(self) -> None:
        # U+0130, U+212A and U+1E9E change under str.lower() on some interpreters.
        for char in ("\u0130", "\u212a", "\u1e9e", UPPER_A_DIAERESIS):
            with self.subTest(code_point=f"U+{ord(char):04X}"):
                self.assertEqual(ascii_fold(char), char)

    def test_qualifier_key_folds_ascii_only(self) -> None:
        # The Kelvin sign lowercases to "k" under str.lower(), which would make the key valid.
        self.assertTrue(weak("pkg:generic/a?\u212aey=v"))
        self.assertEqual(key("pkg:generic/a?KEY=v"), "pkg:generic/a?key=v")


# *--- Qualifier Rule ---*


class QualifierRuleTests(unittest.TestCase):
    """The ordered qualifier rule of Decision C (A7, A16), each with an exact key."""

    def test_trailing_question_mark_is_no_qualifiers(self) -> None:
        self.assertEqual(key("pkg:npm/a@1?"), "pkg:npm/a")
        self.assertEqual(key("pkg:npm/a@1?"), key("pkg:npm/a@1"))

    def test_empty_pairs_are_ignored(self) -> None:
        self.assertEqual(key("pkg:rpm/centos/a@1?arch=x86_64&&"), "pkg:rpm/centos/a?arch=x86_64")
        self.assertEqual(key("pkg:rpm/centos/a@1?&arch=x86_64"), "pkg:rpm/centos/a?arch=x86_64")

    def test_pair_without_equals_is_an_empty_value(self) -> None:
        self.assertEqual(key("pkg:npm/a@1?flag"), "pkg:npm/a")
        self.assertFalse(weak("pkg:npm/a@1?flag"))
        self.assertEqual(key("pkg:npm/a@1?flag&arch=x"), "pkg:npm/a?arch=x")

    def test_empty_value_is_dropped_and_a_space_is_kept(self) -> None:
        self.assertEqual(key("pkg:npm/a@1?arch=%20"), "pkg:npm/a?arch=%20")
        self.assertEqual(key("pkg:npm/a@1?arch="), "pkg:npm/a")

    def test_duplicate_keys_do_not_parse(self) -> None:
        self.assertTrue(weak("pkg:npm/a@1?arch=a&arch=b"))
        self.assertTrue(weak("pkg:npm/a@1?arch=a&ARCH=b"))
        self.assertTrue(weak("pkg:maven/g/a@1?type=jar&type=jar"))

    def test_duplicates_are_checked_after_the_empty_drop(self) -> None:
        self.assertEqual(key("pkg:npm/a@1?arch=&arch=b"), "pkg:npm/a?arch=b")
        self.assertFalse(weak("pkg:npm/a@1?arch=&arch=b"))

    def test_invalid_qualifier_keys_do_not_parse(self) -> None:
        for qualifiers in ("1a=b", "=v", "a b=c", "a%41=b", "_a=b", "1flag"):
            with self.subTest(qualifiers=qualifiers):
                self.assertTrue(weak(f"pkg:npm/a@1?{qualifiers}"))

    def test_maven_default_type_is_dropped(self) -> None:
        self.assertEqual(key("pkg:maven/g/a@1?type=jar"), "pkg:maven/g/a")
        self.assertEqual(key("pkg:maven/g/a@1?type=jar"), key("pkg:maven/g/a@1"))
        self.assertEqual(key("pkg:maven/g/a@1?type=pom"), "pkg:maven/g/a?type=pom")

    def test_default_is_compared_as_decoded_text(self) -> None:
        self.assertEqual(key("pkg:maven/g/a@1?type=%6Aar"), "pkg:maven/g/a")
        self.assertEqual(key("pkg:maven/g/a@1?type=JAR"), "pkg:maven/g/a?type=JAR")

    def test_gem_default_platform_is_dropped(self) -> None:
        self.assertEqual(key("pkg:gem/rails@7?platform=ruby"), "pkg:gem/rails")
        self.assertEqual(key("pkg:gem/rails@7?platform=java"), "pkg:gem/rails?platform=java")

    def test_defaults_are_per_type(self) -> None:
        self.assertEqual(key("pkg:npm/a@1?type=jar"), "pkg:npm/a?type=jar")
        self.assertEqual(key("pkg:maven/g/a@1?platform=ruby"), "pkg:maven/g/a?platform=ruby")

    def test_version_is_removed_and_never_decoded(self) -> None:
        # The version is split off from the right before any decoding, so an encoded @ in it
        # changes nothing and a bad escape in it is never read.
        self.assertEqual(key("pkg:npm/a@1%402"), "pkg:npm/a")
        self.assertEqual(key("pkg:npm/a@1%402"), key("pkg:npm/a@1.2"))
        self.assertEqual(key("pkg:npm/a@%ZZ"), "pkg:npm/a")
        # A raw second @ is the purl-how-to-parse right split: the name keeps the first.
        self.assertEqual(key("pkg:npm/a@1@2"), "pkg:npm/a%401")

    def test_empty_namespace_segment_is_dropped(self) -> None:
        self.assertEqual(key("pkg:deb//debian/bash@1"), "pkg:deb/debian/bash")
        self.assertEqual(key("pkg:deb/debian//bash@1"), "pkg:deb/debian/bash")

    def test_dot_subpath_segments_are_dropped(self) -> None:
        self.assertEqual(
            key("pkg:golang/example.test/mod@v1#./sub/../pkg/"),
            "pkg:golang/example.test/mod#sub/pkg",
        )
        self.assertEqual(key("pkg:golang/example.test/mod@v1#./.."), "pkg:golang/example.test/mod")
        self.assertEqual(key("pkg:golang/example.test/mod@v1#%2E"), "pkg:golang/example.test/mod")

    def test_dot_namespace_segment_is_kept(self) -> None:
        self.assertEqual(key("pkg:generic/./a@1"), "pkg:generic/./a")


class OciQualifierTests(unittest.TestCase):
    """The oci exception: tag is stripped and repository_url is kept (A16)."""

    def test_purls_differing_only_in_tag_are_one_key(self) -> None:
        base = "pkg:oci/web@" + SHA256.replace(":", "%3A")
        first = key(base + "?repository_url=registry.example.test/team/web&tag=1.4")
        second = key(base + "?repository_url=registry.example.test/team/web&tag=1.5")
        self.assertEqual(first, "pkg:oci/web?repository_url=registry.example.test%2Fteam%2Fweb")
        self.assertEqual(first, second)

    def test_purls_differing_in_repository_url_are_two_keys(self) -> None:
        first = key("pkg:oci/web@1?repository_url=registry.example.test/one/web")
        second = key("pkg:oci/web@1?repository_url=registry.example.test/two/web")
        self.assertEqual(first, "pkg:oci/web?repository_url=registry.example.test%2Fone%2Fweb")
        self.assertNotEqual(first, second)

    def test_oci_keeps_arch_and_strips_the_rest_of_the_set(self) -> None:
        self.assertEqual(
            key("pkg:oci/web@1?arch=amd64&tag=1&download_url=x&checksum=y"),
            "pkg:oci/web?arch=amd64",
        )


# *--- Percent Encoding ---*


class PercentEncodingTests(unittest.TestCase):
    """Strict decoding (Decision D) and clause 5.4 re-encoding."""

    def test_pipe_is_always_encoded(self) -> None:
        for purl in ("pkg:generic/a|b@1", "pkg:generic/a%7Cb@1", "pkg:generic/a%7cb@1"):
            with self.subTest(purl=purl):
                self.assertEqual(key(purl), "pkg:generic/a%7Cb")

    def test_plus_round_trips(self) -> None:
        self.assertEqual(key("pkg:generic/a%2Bb@1"), "pkg:generic/a%2Bb")
        self.assertEqual(key("pkg:generic/a+b@1"), "pkg:generic/a%2Bb")

    def test_encoded_slash_in_a_name_never_splits_it(self) -> None:
        self.assertEqual(key("pkg:generic/ns/a%2Fb@1"), "pkg:generic/ns/a%2Fb")
        self.assertEqual(key("pkg:generic/ns/a/b@1"), "pkg:generic/ns/a/b")
        self.assertNotEqual(key("pkg:generic/ns/a%2Fb@1"), key("pkg:generic/ns/a/b@1"))

    def test_encoded_slash_in_a_namespace_segment_does_not_parse(self) -> None:
        self.assertTrue(weak("pkg:generic/a%2Fb/name@1"))
        self.assertEqual(key("pkg:generic/a/b/name@1"), "pkg:generic/a/b/name")

    def test_encoded_slash_in_a_subpath_segment_does_not_parse(self) -> None:
        self.assertTrue(weak("pkg:generic/a@1#x%2Fy"))
        self.assertEqual(key("pkg:generic/a@1#x/y"), "pkg:generic/a#x/y")

    def test_colon_is_never_encoded_and_reserved_characters_are(self) -> None:
        self.assertEqual(key("pkg:generic/a%3Ab@1"), "pkg:generic/a:b")
        self.assertEqual(
            key("pkg:generic/a@1?x=%3F%23%26%3D%40%25%20~._-"),
            "pkg:generic/a?x=%3F%23%26%3D%40%25%20~._-",
        )

    def test_invalid_escapes_fall_back_without_raising(self) -> None:
        purls = (
            "pkg:generic/a%ZZ@1",
            "pkg:generic/a%@1",
            "pkg:generic/a%",
            "pkg:generic/a%F",
            "pkg:generic/a%FF@1",
            "pkg:generic/a%C3@1",
            "pkg:generic/ns%ZZ/a@1",
            "pkg:generic/a@1?x=%ZZ",
            "pkg:generic/a@1#%ZZ",
            "pkg:generic/a%\u0663\u0663@1",
            "pkg:generic/a\ud800@1",
            "pkg:generic/a%ED%A0%80@1",
        )
        for purl in purls:
            with self.subTest(purl=ascii(purl)):
                component = {"type": "library", "name": "synthetic", "purl": purl}
                result = package_key(component)
                self.assertEqual(result, ("component:library//synthetic", True, purl))

    def test_malformed_purls_fall_back(self) -> None:
        purls = (
            "",
            "a-purl-1",
            "invalid-purl-format",
            "npm/a@1",
            "pkgx:npm/a@1",
            "pkg:npm",
            "pkg:npm/",
            "pkg:npm/@1",
            "pkg:1npm/a@1",
            "pkg:n%70m/a@1",
            "pkg:n_pm/a@1",
            "pkg:/",
        )
        for purl in purls:
            with self.subTest(purl=purl):
                self.assertTrue(weak(purl))
                self.assertIsNone(purl_key(purl))

    def test_scheme_and_type_fold_and_leading_slashes_strip(self) -> None:
        self.assertEqual(key("PKG:NPM/a@1"), "pkg:npm/a")
        self.assertEqual(key("pkg://npm/a@1"), "pkg:npm/a")
        self.assertEqual(key("pkg:npm/a/@1"), "pkg:npm/a")

    def test_component_form_encodes_every_reserved_character(self) -> None:
        component = {"type": "library", "group": "org.example", "name": "a b:c|d/e"}
        self.assertEqual(
            package_key(component), ("component:library/org.example/a%20b%3Ac%7Cd%2Fe", True, None)
        )

    def test_component_form_treats_a_non_string_group_as_absent(self) -> None:
        for group in (None, 3, ["org"], {"name": "org"}):
            with self.subTest(group=group):
                component = {"type": "library", "group": group, "name": "a"}
                self.assertEqual(package_key(component)[0], "component:library//a")

    def test_component_form_keeps_an_invalid_or_non_string_purl_raw(self) -> None:
        component: dict[str, Any] = {"type": "library", "name": "a", "purl": "a-purl-1"}
        self.assertEqual(package_key(component), ("component:library//a", True, "a-purl-1"))
        component["purl"] = 7
        self.assertEqual(package_key(component), ("component:library//a", True, None))
        del component["purl"]
        self.assertEqual(package_key(component), ("component:library//a", True, None))

    def test_component_form_never_raises_on_unvalidated_fields(self) -> None:
        # Step 2 refuses these as invalid_component before a key is asked for (A10); the key
        # function still returns rather than raise.
        for component in ({}, {"name": 3, "type": None}, {"name": "a\ud800", "type": "x"}):
            with self.subTest(component=ascii(component)):
                self.assertTrue(package_key(component)[1])
        self.assertEqual(
            package_key({"type": "x", "name": "a\ud800"})[0], "component:x//a%ED%A0%80"
        )

    def test_ref_form_encodes_every_reserved_character(self) -> None:
        self.assertEqual(ref_key("a|b"), "ref:a%7Cb")
        self.assertEqual(ref_key("pkg:npm/a@1"), "ref:pkg%3Anpm%2Fa%401")

    def test_forms_never_share_a_key(self) -> None:
        purls = ("pkg:npm/a@1", "pkg:generic/component%3Aa", "pkg:generic/ref:a")
        components = [{"type": "library", "name": "a", "purl": purl} for purl in purls]
        components += [{"type": "pkg", "name": "npm/a"}, {"type": "library", "name": "pkg:a"}]
        refs = [ref_key(text) for text in (*purls, "pkg:npm/a", "component:library//a")]
        keys = [package_key(component) for component in components]
        strong = {result[0] for result in keys if not result[1]}
        fallback = {result[0] for result in keys if result[1]}
        self.assertEqual(len(strong), 3)
        self.assertTrue(all(value.startswith("pkg:") for value in strong))
        self.assertTrue(all(value.startswith("component:") for value in fallback))
        self.assertTrue(all(value.startswith("ref:") for value in refs))
        self.assertFalse(strong & fallback or strong & set(refs) or fallback & set(refs))


# *--- Subject Lineage ---*


class SubjectLineageTests(unittest.TestCase):
    """The image lineage strips a trailing digest, then a trailing tag (Decision B, S4)."""

    def test_bare_name_is_its_own_lineage(self) -> None:
        self.assertEqual(subject_lineage("image", "web"), "web")

    def test_tag_is_stripped(self) -> None:
        self.assertEqual(subject_lineage("image", "web:1.4"), "web")
        self.assertEqual(
            subject_lineage("image", "registry.example.test/web:1.4"), "registry.example.test/web"
        )

    def test_registry_port_survives(self) -> None:
        self.assertEqual(
            subject_lineage("image", "registry.example.test:5000/web"),
            "registry.example.test:5000/web",
        )
        self.assertEqual(
            subject_lineage("image", "registry.example.test:5000/web:1.4"),
            "registry.example.test:5000/web",
        )

    def test_digest_is_stripped(self) -> None:
        for digest in (SHA256, SHA512):
            with self.subTest(digest=digest[:6]):
                self.assertEqual(
                    subject_lineage("image", f"registry.example.test/web@{digest}"),
                    "registry.example.test/web",
                )

    def test_tag_and_digest_are_both_stripped(self) -> None:
        self.assertEqual(
            subject_lineage("image", f"registry.example.test:5000/web:1.4@{SHA256}"),
            "registry.example.test:5000/web",
        )

    def test_only_a_digest_shaped_suffix_is_stripped(self) -> None:
        self.assertEqual(subject_lineage("image", "web@latest"), "web@latest")
        # Not digest-shaped (uppercase hex, md5), so only the tag rule applies.
        self.assertEqual(subject_lineage("image", "web@sha256:ABC"), "web@sha256")
        self.assertEqual(subject_lineage("image", "web@md5:abc"), "web@md5")

    def test_digest_shape(self) -> None:
        self.assertTrue(digest_shaped(SHA256))
        self.assertTrue(digest_shaped(SHA512))
        for text in ("sha256:", "sha256:ABC", "sha1:abc", "sha256:abc ", "1.4", ""):
            with self.subTest(text=text):
                self.assertFalse(digest_shaped(text))

    def test_scan_lineage_is_the_scope_id_unchanged(self) -> None:
        self.assertEqual(subject_lineage("scan", "org/app:1.4"), "org/app:1.4")
        self.assertEqual(subject_lineage("scan", f"app@{SHA256}"), f"app@{SHA256}")


# *--- Package Resource ---*


class PackageResourceIdTests(unittest.TestCase):
    """The resource id <scope type>:<lineage>|<package key> and its 512 check (section 7)."""

    def test_composes_the_documented_shape(self) -> None:
        self.assertEqual(
            package_resource_id("image", "registry.example.test/web", "pkg:npm/lodash"),
            ("image:registry.example.test/web|pkg:npm/lodash", None),
        )

    def test_split_takes_the_first_colon_and_the_last_pipe(self) -> None:
        resource_id = "image:reg|x:5000/w|y|pkg:npm/a?x=1:2"
        self.assertEqual(
            split_package_resource_id(resource_id), ("image", "reg|x:5000/w|y", "pkg:npm/a?x=1:2")
        )
        self.assertIsNone(split_package_resource_id("image-web|pkg:npm/a"))
        self.assertIsNone(split_package_resource_id("image:web"))

    def test_the_composed_id_is_refused_past_512_characters(self) -> None:
        fixed = len("image:|pkg:npm/a")
        at_cap = package_resource_id("image", "w" * (MAX_IDENTITY_CHARS - fixed), "pkg:npm/a")
        self.assertEqual(len(at_cap[0]), MAX_IDENTITY_CHARS)
        self.assertIsNone(at_cap[1])
        over = package_resource_id("image", "w" * (MAX_IDENTITY_CHARS - fixed + 1), "pkg:npm/a")
        self.assertEqual(over[1], "is 513 characters; maximum is 512")

    def test_a_control_character_in_the_lineage_is_refused(self) -> None:
        problem = package_resource_id("scan", "a\x07b", "pkg:npm/a")[1]
        self.assertEqual(problem, "contains prohibited code point U+0007")

    def test_split_inverts_composition(self) -> None:
        alphabet = "ab:|/@%?#=&. -_~" + UPPER_A_DIAERESIS + "\u212a"
        for seed in range(400):
            chooser = random.Random(seed)

            def text(chooser: random.Random = chooser) -> str:
                return "".join(chooser.choice(alphabet) for _ in range(chooser.randint(0, 12)))

            form = chooser.randrange(3)
            if form == 0:
                package = purl_key(f"pkg:generic/{text()}/n{text()}?q={text()}#{text()}")
                if package is None:
                    package = ref_key(text())
            elif form == 1:
                package = package_key({"type": text(), "group": text(), "name": text()})[0]
            else:
                package = ref_key(text())
            scope_type = chooser.choice(("image", "scan"))
            lineage = subject_lineage(scope_type, text())
            with self.subTest(seed=seed):
                self.assertNotIn("|", package)
                resource_id, _ = package_resource_id(scope_type, lineage, package)
                self.assertEqual(
                    split_package_resource_id(resource_id), (scope_type, lineage, package)
                )


if __name__ == "__main__":
    unittest.main()


# *--- Adapter Helpers ---*

FIXTURES = Path(__file__).parent / "fixtures"
SYFT_FIXTURE = FIXTURES / "syft-image.cdx.json"
TRIVY_FIXTURE = FIXTURES / "trivy-clean.cdx.json"
NOW = datetime(2026, 10, 2, tzinfo=UTC)
HEX64 = "0123456789abcdef" * 4
HEX128 = HEX64 * 2
INVENTORY = "CycloneDX inventory document cannot be read: "
# A K3 shape: one component besides the subject and one vulnerability record.
MATCHED = {
    "components": [{"type": "library", "name": "a", "purl": "pkg:npm/a@1"}],
    "vulnerabilities": [{"id": "CVE-2026-0001", "published": "2026-01-01T00:00:00Z"}],
}


def bom(**members: Any) -> dict[str, Any]:
    """Build a CycloneDX 1.6 document with the given members."""
    return {"bomFormat": "CycloneDX", "specVersion": "1.6", **members}


def ingest(document: Any, name: str = "synthetic.cdx.json") -> IngestResult:
    with tempfile.TemporaryDirectory() as directory:
        path = Path(directory) / name
        path.write_bytes(json.dumps(document).encode("utf-8"))
        return ingest_stig_artifact(path, ingested_at=NOW)


def codes(result: IngestResult, level: str) -> list[str]:
    return [item.code for item in result.diagnostics if item.level.value == level]


def only(result: IngestResult) -> Any:
    assert len(result.observations) == 1, result.diagnostics
    return result.observations[0]


def scope_of(subject: dict[str, Any], **metadata: Any) -> tuple[str, str, str]:
    """Return the scope resource type, id and lineage a K1 document with this subject gets."""
    result = ingest(bom(metadata={"tools": [{"name": "syft"}], "component": subject, **metadata}))
    observation = only(result)
    lineage = dict(observation.source_metadata)["subject_lineage"]
    return observation.resource.resource_type, observation.resource.resource_id, lineage


# *--- Adapter Tests ---*


class DocumentKindTests(unittest.TestCase):
    """K1 and K2 are each one NOT_REVIEWED scope observation, told apart by warning (A1)."""

    def test_the_syft_inventory_is_not_reviewed_with_vulnerabilities_absent(self) -> None:
        result = ingest_stig_artifact(SYFT_FIXTURE, ingested_at=NOW)
        observation = only(result)
        self.assertEqual(observation.disposition.value, "not_reviewed")
        self.assertEqual(codes(result, "warning"), ["vulnerabilities_absent"])
        self.assertEqual(observation.source_record_id, "cyclonedx.bom")
        self.assertEqual((observation.source_type, observation.source_tool), ("cyclonedx", "syft"))
        self.assertEqual(observation.context_key, "syft")
        self.assertEqual(observation.source_severity.value, "unknown")
        self.assertEqual(observation.source_identifiers, ())
        self.assertEqual(
            observation.title, "syft listed 6 components of image:registry.example.test/web:1.4"
        )
        self.assertEqual(dict(observation.source_metadata)["bom_kind"], "inventory")
        self.assertFalse(result.withheld)

    def test_the_trivy_empty_document_is_not_reviewed_with_match_unverified(self) -> None:
        result = ingest_stig_artifact(TRIVY_FIXTURE, ingested_at=NOW)
        observation = only(result)
        self.assertEqual(observation.disposition.value, "not_reviewed")
        self.assertEqual(codes(result, "warning"), ["match_unverified"])
        self.assertEqual(dict(observation.source_metadata)["bom_kind"], "empty")
        self.assertEqual(
            observation.title,
            "trivy reported no vulnerability records for image:registry.example.test/web:1.4",
        )

    def test_both_fixtures_name_one_scope(self) -> None:
        syft = only(ingest_stig_artifact(SYFT_FIXTURE, ingested_at=NOW))
        trivy = only(ingest_stig_artifact(TRIVY_FIXTURE, ingested_at=NOW))
        self.assertEqual(
            (syft.resource.resource_type, syft.resource.resource_id),
            ("image", "registry.example.test/web:1.4"),
        )
        self.assertEqual(syft.resource, trivy.resource)

    def test_a_named_scanner_on_an_empty_document_never_passes(self) -> None:
        for tool in ("grype", "trivy", "alpha"):
            for components in ([], [{"type": "library", "name": "a"}]):
                with self.subTest(tool=tool, components=len(components)):
                    result = ingest(
                        bom(
                            metadata={"tools": [{"name": tool}]},
                            components=components,
                            vulnerabilities=[],
                        )
                    )
                    self.assertEqual(only(result).disposition.value, "not_reviewed")
                    self.assertIn("match_unverified", codes(result, "warning"))

    def test_the_clock_is_the_document_timestamp_only(self) -> None:
        syft = only(ingest_stig_artifact(SYFT_FIXTURE, ingested_at=NOW))
        self.assertEqual(
            syft.observed_at, datetime(2026, 10, 1, 5, tzinfo=timezone(timedelta(hours=-7)))
        )
        # A vulnerability's published date is never the document clock (Decision Q).
        result = ingest(bom(metadata={"tools": [{"name": "grype"}]}, **MATCHED))
        scope = [item for item in result.observations if item.source_record_id == "cyclonedx.bom"]
        self.assertEqual([item.observed_at for item in scope], [None])
        self.assertIn("source_timestamp_missing", codes(result, "warning"))

    def test_an_unparseable_timestamp_is_absent(self) -> None:
        result = ingest(bom(metadata={"timestamp": "yesterday"}))
        self.assertIsNone(only(result).observed_at)
        self.assertIn("source_timestamp_invalid", codes(result, "warning"))


class ComponentWalkTests(unittest.TestCase):
    """Every depth is counted and indexed, the subject is left out (D1)."""

    def test_the_syft_fixture_counts(self) -> None:
        metadata = dict(only(ingest_stig_artifact(SYFT_FIXTURE, ingested_at=NOW)).source_metadata)
        lines = sorted(
            {
                "pkg:apk/alpine/musl?arch=x86_64\t1.2.5-r0",
                "pkg:apk/alpine/busybox?arch=x86_64\t1.36.1-r29",
                "component:file//%2Flib%2Fapk%2Fdb%2Finstalled\t",
                "pkg:npm/left-pad\t1.3.0",
                "pkg:npm/inner\t2.0.0",
            }
        )
        digest = hashlib.sha256("".join(f"{line}\n" for line in lines).encode()).hexdigest()
        self.assertEqual(metadata["component_count"], "6")
        self.assertEqual(metadata["package_count"], "5")
        self.assertEqual(metadata["weak_identity_count"], "1")
        self.assertEqual(metadata["vulnerability_count"], "0")
        self.assertEqual(metadata["component_set_sha256"], digest)

    def test_the_component_set_digest_ignores_order_serial_and_subject(self) -> None:
        components = [
            {"type": "library", "name": "a", "version": "1", "purl": "pkg:npm/a@1"},
            {"type": "library", "name": "b", "version": "2", "purl": "pkg:npm/b@2"},
        ]
        first = bom(serialNumber="urn:uuid:1", components=components)
        second = bom(
            serialNumber="urn:uuid:2",
            metadata={"component": {"type": "application", "name": "x", "purl": "pkg:npm/x@9"}},
            components=list(reversed(components)),
        )
        digests = [
            dict(only(ingest(document)).source_metadata)["component_set_sha256"]
            for document in (first, second)
        ]
        self.assertEqual(digests[0], digests[1])


class SpecVersionTests(unittest.TestCase):
    def test_each_supported_version_is_read(self) -> None:
        for version in ("1.4", "1.5", "1.6", "1.7"):
            with self.subTest(version=version):
                self.assertTrue(ingest(bom(specVersion=version)).successful)

    def test_an_unsupported_version_is_refused_quoted_sanitized_and_cut(self) -> None:
        cases = {
            "1.3": "'1.3'",
            "1.6\x07": "'1.6\\x07'",
        }
        for value, rendered in cases.items():
            with self.subTest(value=value):
                result = ingest(bom(specVersion=value))
                self.assertEqual([item.code for item in result.errors], ["artifact_parse_failed"])
                self.assertEqual(
                    result.errors[0].message,
                    f"CycloneDX specVersion {rendered} is not supported; this build reads 1.4 "
                    "to 1.7",
                )
                self.assertTrue(result.format_rejected)
        long = ingest(bom(specVersion="9" * 600)).errors[0].message
        quoted_part = long.removeprefix("CycloneDX specVersion ").split(" is not supported")[0]
        self.assertEqual(len(quoted_part), 512)
        self.assertNotIn("\x07", ingest(bom(specVersion="\x07")).errors[0].message)
        self.assertTrue(ingest(bom(specVersion=1.6)).format_rejected)


class MalformedInventoryTests(unittest.TestCase):
    """A K1 or K2 document with a structural error is a format refusal, never mintable (A12)."""

    SHAPES = (
        ({"metadata": "x"}, "metadata is not an object"),
        ({"components": {}}, "components is not an array"),
        ({"components": [{"type": "library"}]}, "a component name is missing or not a string"),
        (
            {"components": [{"name": "a", "hashes": [1]}]},
            "a component hash is not an object",
        ),
    )

    def assert_rejected(self, result: IngestResult, message: str) -> None:
        self.assertEqual([item.code for item in result.errors], ["artifact_parse_failed"])
        self.assertEqual(result.errors[0].message, message)
        classification = classify_ingest(result)
        assert classification is not None
        self.assertIs(classification.reason, UnmintableReason.FORMAT_REJECTED)

    def test_each_shape_is_refused_with_and_without_an_empty_vulnerabilities(self) -> None:
        for members, check in self.SHAPES:
            for extra in ({}, {"vulnerabilities": []}):
                with self.subTest(check=check, k2=bool(extra)):
                    self.assert_rejected(ingest(bom(**members, **extra)), INVENTORY + check)

    def test_a_non_list_vulnerabilities_is_refused(self) -> None:
        for value in (None, {}, "none"):
            with self.subTest(value=value):
                self.assert_rejected(
                    ingest(bom(vulnerabilities=value)), "CycloneDX vulnerabilities is not an array"
                )


class StructuralErrorTests(unittest.TestCase):
    """On a K3 document a structural error is CONTENT ERROR invalid_bom (A10)."""

    def test_each_shape_is_invalid_bom_with_no_observation(self) -> None:
        shapes = {
            "string tool item": {"tools": ["trivy"]},
            "non-list tools.components": {"tools": {"components": {}}},
            "numeric tool name": {"tools": [{"name": 7}]},
            "list subject": {"tools": [{"name": "grype"}], "component": []},
        }
        for label, metadata in shapes.items():
            with self.subTest(shape=label):
                result = ingest(bom(metadata=metadata, **MATCHED))
                self.assertEqual(result.observations, ())
                self.assertEqual([item.code for item in result.errors], ["invalid_bom"])
                classification = classify_ingest(result)
                assert classification is not None
                self.assertIs(classification.failure_class, FailureClass.CONTENT)
                self.assertFalse(result.withheld)

    def test_a_tool_less_matched_document_is_invalid_bom(self) -> None:
        result = ingest(bom(**MATCHED))
        self.assertEqual(result.observations, ())
        self.assertEqual([item.code for item in result.errors], ["invalid_bom"])
        self.assertIn("no tool named", result.errors[0].message)
        self.assertNotIn("tool_identity_fallback", codes(result, "warning"))

    def test_a_bad_nested_component_is_invalid_component(self) -> None:
        components = [{"type": "library", "name": "a", "components": [{"type": "library"}]}]
        result = ingest(
            bom(
                metadata={"tools": [{"name": "grype"}]},
                components=components,
                **{"vulnerabilities": MATCHED["vulnerabilities"]},
            )
        )
        self.assertEqual([item.code for item in result.errors], ["invalid_component"])
        self.assertIn("components[0].components[0].name", result.errors[0].message)


class ToolTests(unittest.TestCase):
    def tool_of(self, tools: Any) -> tuple[str, list[str]]:
        result = ingest(bom(metadata={"tools": tools}))
        return only(result).source_tool, codes(result, "warning")

    def test_the_join_is_injective(self) -> None:
        self.assertEqual(self.tool_of([{"name": "beta"}, {"name": "alpha"}])[0], "alpha+beta")
        self.assertEqual(self.tool_of([{"name": "alpha+beta"}])[0], "alpha%2Bbeta")
        self.assertEqual(self.tool_of([{"name": "a%2Bb"}])[0], "a%252Bb")

    def test_several_tools_warn_and_duplicates_collapse(self) -> None:
        tool, warnings = self.tool_of([{"name": "b"}, {"name": "a"}, {"name": "a"}])
        self.assertEqual(tool, "a+b")
        self.assertIn("tool_identity_ambiguous", warnings)
        self.assertNotIn("tool_identity_ambiguous", self.tool_of([{"name": "a"}] * 2)[1])

    def test_only_application_tools_are_candidates_when_any_is_named(self) -> None:
        tools = {
            "components": [
                {"type": "library", "name": "cyclonedx-python-lib"},
                {"type": "application", "name": "cyclonedx-py"},
            ],
            "services": [{"name": "svc"}],
        }
        self.assertEqual(self.tool_of(tools)[0], "cyclonedx-py")
        self.assertEqual(self.tool_of({"services": [{"name": "svc"}]})[0], "svc")

    def test_no_tool_on_an_inventory_is_the_fallback(self) -> None:
        for tools in ([], {}, [{"version": "1"}], [{"name": "  "}]):
            with self.subTest(tools=tools):
                tool, warnings = self.tool_of(tools)
                self.assertEqual(tool, "cyclonedx")
                self.assertIn("tool_identity_fallback", warnings)

    # FX2 CL-5: on an inventory the refusal is a format refusal; K3 keeps CONTENT.
    def test_an_over_long_tool_on_an_inventory_is_a_format_refusal(self) -> None:
        result = ingest(bom(metadata={"tools": [{"name": "t" * 513}]}))
        self.assertEqual([item.code for item in result.errors], ["artifact_parse_failed"])
        self.assertEqual(
            result.errors[0].message, IDENTITY + "tool name is 513 characters; maximum is 512"
        )

    def test_tool_metadata_has_one_schema(self) -> None:
        trivy = dict(only(ingest_stig_artifact(TRIVY_FIXTURE, ingested_at=NOW)).source_metadata)
        self.assertEqual(
            json.loads(json.loads(trivy["tools"])[0]),
            {
                "name": "trivy",
                "version": "0.58.0",
                "group": "aquasecurity",
                "vendor": "Aqua Security Software Ltd.",
            },
        )
        tools = {"components": [{"type": "application", "name": "syft", "author": "anchore"}]}
        result = dict(only(ingest(bom(metadata={"tools": tools}))).source_metadata)
        self.assertEqual(
            json.loads(json.loads(result["tools"])[0]), {"name": "syft", "author": "anchore"}
        )
        legacy = dict(only(ingest_stig_artifact(SYFT_FIXTURE, ingested_at=NOW)).source_metadata)
        self.assertEqual(
            json.loads(json.loads(legacy["tools"])[0]),
            {"name": "syft", "vendor": "anchore", "version": "1.18.1"},
        )


class ScopeIdTests(unittest.TestCase):
    """The scope resource of section 6: A4, S2, S4 and Y1."""

    def test_group_and_name_are_encoded_before_the_join(self) -> None:
        self.assertEqual(
            scope_of({"type": "application", "group": "org", "name": "app"})[:2],
            ("scan", "org/app"),
        )
        self.assertEqual(
            scope_of({"type": "application", "name": "org/app"})[:2], ("scan", "org%2Fapp")
        )
        self.assertEqual(scope_of({"type": "library", "name": "a%b"})[:2], ("scan", "a%25b"))

    def test_a_container_group_goes_to_metadata_only(self) -> None:
        result = ingest(
            bom(metadata={"component": {"type": "container", "group": "g", "name": "web"}})
        )
        observation = only(result)
        self.assertEqual(observation.resource.resource_id, "web")
        self.assertEqual(dict(observation.source_metadata)["subject_group"], "g")

    def test_an_over_long_composed_id_on_an_inventory_is_a_format_refusal(self) -> None:
        subject = {"type": "container", "name": "w" * 500, "version": "v" * 20}
        result = ingest(bom(metadata={"component": subject}))
        self.assertEqual(result.observations, ())
        self.assertEqual([item.code for item in result.errors], ["artifact_parse_failed"])
        self.assertEqual(
            result.errors[0].message, IDENTITY + "scope id is 521 characters; maximum is 512"
        )

    def test_an_oci_purl_makes_an_image_whatever_the_type(self) -> None:
        oci = {"type": "application", "name": "org/app", "purl": "pkg:oci/app@sha256%3A" + HEX64}
        plain = {"type": "application", "group": "org", "name": "app"}
        self.assertEqual(scope_of(oci)[:2], ("image", "org/app"))
        self.assertEqual(scope_of(plain)[:2], ("scan", "org/app"))

    def test_the_lineage_comes_from_the_name(self) -> None:
        self.assertEqual(
            scope_of({"type": "container", "name": "web", "version": "1.4:x"}),
            ("image", "web:1.4:x", "web"),
        )

    def test_rule_1_a_tagged_or_digested_name_is_used_alone(self) -> None:
        for name in ("registry.example.test/web:1.4", f"registry.example.test/web@sha256:{HEX64}"):
            with self.subTest(name=name):
                result = ingest(
                    bom(
                        metadata={
                            "component": {"type": "container", "name": name, "version": "1.4"}
                        }
                    )
                )
                observation = only(result)
                self.assertEqual(observation.resource.resource_id, name)
                self.assertEqual(dict(observation.source_metadata)["subject_version"], "1.4")

    def test_rule_2_the_version_is_joined_as_a_tag(self) -> None:
        for name, expected in (
            ("registry.example.test/web", "registry.example.test/web:1.4"),
            ("registry.example.test:5000/web", "registry.example.test:5000/web:1.4"),
        ):
            with self.subTest(name=name):
                subject = {"type": "container", "name": name, "version": "1.4"}
                self.assertEqual(scope_of(subject)[1], expected)

    def test_rule_3_a_digest_version_is_joined_with_at(self) -> None:
        for digest in (f"sha256:{HEX64}", f"sha512:{HEX128}"):
            with self.subTest(digest=digest[:6]):
                subject = {"type": "container", "name": "user-input", "version": digest}
                self.assertEqual(scope_of(subject)[1:], (f"user-input@{digest}", "user-input"))

    def test_rule_4_no_usable_version_is_the_name_alone(self) -> None:
        for version in (None, "", "  ", 4):
            with self.subTest(version=version):
                subject: dict[str, Any] = {"type": "container", "name": "web"}
                if version is not None:
                    subject["version"] = version
                self.assertEqual(scope_of(subject)[1], "web")

    def test_a_version_slash_or_percent_is_encoded(self) -> None:
        subject = {"type": "container", "name": "web", "version": "a/b%c"}
        self.assertEqual(scope_of(subject)[1], "web:a%2Fb%25c")

    def test_grype_and_trivy_shapes_merge(self) -> None:
        pairs = (
            (
                {"name": "registry.example.test/web", "version": "1.4"},
                {"name": "registry.example.test/web:1.4"},
                "registry.example.test/web:1.4",
                "registry.example.test/web",
            ),
            (
                {"name": "registry.example.test/team/web", "version": "1.4"},
                {"name": "registry.example.test/team/web:1.4"},
                "registry.example.test/team/web:1.4",
                "registry.example.test/team/web",
            ),
            (
                {"name": "registry.example.test/team/web", "version": f"sha256:{HEX64}"},
                {"name": f"registry.example.test/team/web@sha256:{HEX64}"},
                f"registry.example.test/team/web@sha256:{HEX64}",
                "registry.example.test/team/web",
            ),
        )
        for grype, trivy, expected, lineage in pairs:
            with self.subTest(expected=expected):
                first = scope_of({"type": "container", **grype})
                second = scope_of({"type": "container", **trivy})
                self.assertEqual(first, ("image", expected, lineage))
                self.assertEqual(second, first)
                key = purl_key("pkg:apk/alpine/musl@1.2.5-r0")
                assert key is not None
                self.assertEqual(
                    package_resource_id(first[0], first[2], key),
                    package_resource_id(second[0], second[2], key),
                )

    def test_no_usable_subject_is_the_tool_fallback(self) -> None:
        for metadata in ({}, {"component": {"type": "container", "name": " "}}):
            with self.subTest(metadata=metadata):
                result = ingest(bom(metadata={"tools": [{"name": "syft"}], **metadata}))
                self.assertEqual(
                    (only(result).resource.resource_type, only(result).resource.resource_id),
                    ("scan", "syft"),
                )
                self.assertIn("subject_identity_fallback", codes(result, "warning"))


# *--- Fixture Invariants ---*

CYCLONEDX_ATTRIBUTION = ("complyroll.cyclonedx", CYCLONEDX_PARSER_VERSION, CYCLONEDX_MEDIA_TYPE)
# The observation ids each step 2 fixture yields, in output order (R1 5.3).
FIXTURE_IDS = {
    "syft-image.cdx.json": (
        "obs-cbbda5309765ec026db399858b2279a830ea4890336651360d2882a02b2afcdf",
    ),
    "trivy-clean.cdx.json": (
        "obs-1b9c4765ce29ba0e290a73498d80d22aff2748e120f0127cc80d456e65525f1e",
    ),
    "grype-image.cdx.json": (
        "obs-2e1d41be29610edb180e8d2bcb546dfda29eb1419f419f6a60ace5f3a0f304ea",
        "obs-03f26b45916cb1d0cd87f242ce7ad64fea8a25bc99f0db4216bfe3eb4833ac90",
        "obs-00ed41532d10f959bf6b6752ad645c5d2248a837b16d77c418857c4dccb5f13d",
        "obs-7c23e13f450624ed77ccb4fccf32caa82e8377b42b9be7b4871fcd01899c8414",
        "obs-923f768ac7f93f0d11aaf4b429fbcdd8a4d83da8e16b782c463ef1afc988abf4",
    ),
    "trivy-image.cdx.json": (
        "obs-5eabacb2bd8c18086d7d734ef42d562d1206af7a37c362d5fbad47d1e2055890",
        "obs-3ded09ae2784b5721b3a08442744726db79a0f70cd87e9c65e68f1554df8d75d",
        "obs-de2b67f016bab95eb0abfd15c9350634da019a52319800597379a777242511da",
        "obs-767337656cb549771ba6cc082a8c05c57d7d5f1349d07836d43b9b402e1451e3",
    ),
    # The spec-corners fixture raises WARNING and INFO only, so every invariant holds on it too.
    "cyclonedx-spec-corners.cdx.json": (
        "obs-59a86ce606bba62a1a2a833aad4c0591748241e37c3d32296b161d36733fc646",
        "obs-dfe2fd619698ad7620299672c296e8bdeb49bcb6b281d8953805c7f3738f6421",
        "obs-5417c4b18f7c13cf51503b2dceb84b6bd4b3550c0cc77eab397c6962ee45bf53",
        "obs-e1e73212cdd6c08ed3455ae31c7ac5a0a4b88b9864e523c082fe9972b36a0b77",
        "obs-1f6e0af9cf0d51941e8dc0e26a6c5b6b4d8446823f7fd52da8faac263b08cb0a",
        "obs-18f0a751951fe9a7431c27530813f34fd5a8cafefb7271261092461d2bc03391",
        "obs-0eb2c68122e45dd63294fc60546f2579f76b4db6e7c01c71edf6f41683d9457d",
        "obs-f5e81d5e48737f8571b87817896c084adc0281bb7de7dc35bcba39a09be0eb15",
        "obs-a1dee20a9a201653476c49a15912c79407ee3c4e91be15b892e09425642b68d2",
        "obs-76f062e88bd0a09dd9fae8a3a2433cf79a96d5c777f258a3836a411b2f7f58c4",
        "obs-c7f63f43a8686c379420063234f6955bafe3c7a2f6691868e4566ce3c7659158",
        "obs-6c244b51076205853c0abb70517a936f4d4f909914987739d1827fed8bc5909d",
        "obs-64bf76b23bcf9bad94575bf431b9e69cd6758340cfad271398f1cabfbdf3100b",
        "obs-251113e85d60528106c62254b9e3d073c18e4e2b28027941cc0d306385b8b22b",
        "obs-3a0cea0035f551483692cc0e085bef91b3af52066fed1190a101aa197e259d1c",
        "obs-969b21ab29ecb5fa9bea4ae509f7b87afc713201a925d291ab75875d58d1b439",
    ),
}


class CycloneDxFixtureInvariantTests(unittest.TestCase):
    """Properties every CycloneDX fixture holds regardless of its producer (R1 5.3)."""

    @classmethod
    def setUpClass(cls) -> None:
        cls.results = {
            name: ingest_stig_artifact(FIXTURES / name, ingested_at=NOW) for name in FIXTURE_IDS
        }

    def test_every_fixture_is_attributed_to_the_cyclonedx_adapter(self) -> None:
        for name, result in self.results.items():
            with self.subTest(fixture=name):
                artifact = result.artifact
                assert artifact is not None
                self.assertEqual(
                    (artifact.parser_name, artifact.parser_version, artifact.media_type),
                    CYCLONEDX_ATTRIBUTION,
                )
                self.assertTrue(result.successful)
                self.assertEqual(result.errors, ())

    def test_every_fixture_yields_its_pinned_observation_ids_in_order(self) -> None:
        for name, expected in FIXTURE_IDS.items():
            with self.subTest(fixture=name):
                observed = tuple(item.observation_id for item in self.results[name].observations)
                self.assertEqual(observed, expected)

    def test_no_fixture_produces_a_duplicate_observation_identity(self) -> None:
        for name, result in self.results.items():
            with self.subTest(fixture=name):
                self.assertNotIn(
                    "duplicate_observation_identity", [item.code for item in result.diagnostics]
                )
                ids = [item.observation_id for item in result.observations]
                self.assertEqual(len(ids), len(set(ids)))

    def test_every_observation_id_is_derived_from_its_fingerprint(self) -> None:
        for name, result in self.results.items():
            for observation in result.observations:
                with self.subTest(fixture=name, observation=observation.observation_id):
                    self.assertEqual(observation.observation_id, observation.derived_observation_id)
                    self.assertEqual(observation.source_type, CYCLONEDX_SOURCE_TYPE)
                    self.assertEqual(observation.parser_name, "complyroll.cyclonedx")
                    self.assertEqual(observation.parser_version, CYCLONEDX_PARSER_VERSION)

    def test_every_metadata_key_belongs_to_the_fixed_vocabulary(self) -> None:
        for name, result in self.results.items():
            for observation in result.observations:
                with self.subTest(fixture=name, observation=observation.observation_id):
                    keys = [key for key, _value in observation.source_metadata]
                    self.assertEqual(keys, sorted(keys))
                    self.assertTrue(
                        set(keys) <= CYCLONEDX_METADATA_KEYS, set(keys) - CYCLONEDX_METADATA_KEYS
                    )

    def test_every_observation_round_trips_through_canonical_json_under_the_cap(self) -> None:
        for name, result in self.results.items():
            for observation in result.observations:
                with self.subTest(fixture=name, observation=observation.observation_id):
                    encoded = observation.to_canonical_json()
                    self.assertLessEqual(len(encoded.encode("utf-8")), MAX_OBSERVATION_JSON_BYTES)
                    self.assertEqual(
                        Observation.from_canonical_dict(json.loads(encoded)), observation
                    )

    def test_every_diagnostic_is_located_at_the_artifact_name(self) -> None:
        for name, result in self.results.items():
            for diagnostic in result.diagnostics:
                with self.subTest(fixture=name, code=diagnostic.code):
                    self.assertEqual(diagnostic.location, name)


# *--- Determinism ---*


def permutation_document(
    components: list[dict[str, Any]], tools: Any, nested_under: int | None
) -> dict[str, Any]:
    """Build an inventory, optionally moving the last component under the one at an index."""
    items = [dict(item) for item in components]
    if nested_under is not None:
        moved = items.pop()
        items[nested_under]["components"] = [moved]
    subject = {"type": "container", "name": "registry.example.test/web", "version": "1.4"}
    return bom(
        metadata={"timestamp": "2026-10-01T12:00:00Z", "tools": tools, "component": subject},
        components=items,
    )


class PermutationTests(unittest.TestCase):
    """Component order, nesting, tool order and qualifier order never change output (sec. 20)."""

    COMPONENTS = (
        {"type": "library", "name": "musl", "version": "1", "purl": "pkg:apk/alpine/musl@1"},
        {"type": "library", "name": "a", "version": "2", "purl": "pkg:npm/a@2"},
        {"type": "file", "name": "/etc/os-release"},
        {"type": "library", "name": "a", "version": "2", "purl": "pkg:npm/a@2"},
        {"type": "library", "name": "z", "version": "3", "purl": "pkg:npm/z@3"},
    )
    LEGACY_TOOLS = ({"name": "beta", "version": "2"}, {"vendor": "v", "name": "alpha"})
    OBJECT_TOOLS = (
        {"type": "application", "name": "beta", "version": "2"},
        {"type": "application", "name": "alpha", "author": "a"},
        {"type": "library", "name": "lib"},
    )

    # One artifact for every arrangement: its digest is fixed, so only the parse can differ.
    ARTIFACT = ArtifactProvenance.from_bytes(
        path=Path("synthetic.cdx.json"),
        content=b"{}",
        media_type=CYCLONEDX_MEDIA_TYPE,
        parser_name="complyroll.cyclonedx",
        parser_version=CYCLONEDX_PARSER_VERSION,
        ingested_at=NOW,
    )

    def canonical(self, document: dict[str, Any]) -> tuple[str, list[str]]:
        output = CycloneDxAdapter().parse(
            ParsedDocument("json", document), self.ARTIFACT, ingested_at=NOW
        )
        self.assertEqual(len(output.observations), 1, output.diagnostics)
        return (
            output.observations[0].to_canonical_json(),
            [item.code for item in output.diagnostics],
        )

    def assert_order_free(self, tools_of: Any, tool_items: tuple[dict[str, Any], ...]) -> None:
        base = list(self.COMPONENTS)
        expected = self.canonical(permutation_document(base, tools_of(list(tool_items)), None))
        chooser = random.Random(20)
        for trial in range(12):
            components = chooser.sample(base, len(base))
            tools = chooser.sample(list(tool_items), len(tool_items))
            nested = chooser.choice([None, 0, 1])
            with self.subTest(trial=trial):
                document = permutation_document(components, tools_of(tools), nested)
                self.assertEqual(self.canonical(document), expected)

    def test_legacy_tool_documents_are_order_free(self) -> None:
        self.assert_order_free(lambda tools: tools, self.LEGACY_TOOLS)

    def test_object_tool_documents_are_order_free(self) -> None:
        self.assert_order_free(
            lambda tools: {"components": tools, "services": [{"name": "svc"}]}, self.OBJECT_TOOLS
        )

    def test_qualifier_order_does_not_change_the_scope_observation(self) -> None:
        first = {"type": "library", "name": "m", "purl": "pkg:apk/alpine/m@1?arch=x86_64&os=a"}
        second = {**first, "purl": "pkg:apk/alpine/m@1?os=a&arch=x86_64"}
        tools = [{"name": "syft"}]
        self.assertEqual(
            self.canonical(permutation_document([first], tools, None)),
            self.canonical(permutation_document([second], tools, None)),
        )


# *--- Step 3: Vulnerabilities ---*

SERIAL = "3e671687-395b-41f5-a30f-a58921a69b79"
OTHER_SERIAL = "9a1f8b2c-0000-4000-8000-000000000001"
SUBJECT = {
    "type": "container",
    "name": "registry.example.test/web",
    "version": "1.4",
    "bom-ref": "subject",
}
SCOPE = ("image", "registry.example.test/web:1.4")
PKG = "image:registry.example.test/web|"
LODASH = {
    "type": "library",
    "name": "lodash",
    "version": "4.17.20",
    "purl": "pkg:npm/lodash@4.17.20",
    "bom-ref": "lodash-ref",
    "hashes": [{"alg": "SHA-256", "content": "aa"}],
}
STEP3_ARTIFACT = ArtifactProvenance.from_bytes(
    path=Path("synthetic.cdx.json"),
    content=b"{}",
    media_type=CYCLONEDX_MEDIA_TYPE,
    parser_name="complyroll.cyclonedx",
    parser_version=CYCLONEDX_PARSER_VERSION,
    ingested_at=NOW,
)


def vuln(record_id: str = "CVE-2026-0001", refs: tuple[str, ...] = ("lodash-ref",), **members: Any):
    """Build one vulnerability record whose affects name the given refs."""
    return {"id": record_id, "affects": [{"ref": ref} for ref in refs], **members}


def k3(components: list[dict[str, Any]], vulnerabilities: list[Any]) -> dict[str, Any]:
    """Build a matched document of a container subject named by one tool."""
    metadata = {
        "timestamp": "2026-10-01T12:00:00Z",
        "tools": [{"name": "grype", "version": "0.99.0"}],
        "component": dict(SUBJECT),
    }
    return bom(
        serialNumber=f"urn:uuid:{SERIAL}",
        version=1,
        metadata=metadata,
        components=components,
        vulnerabilities=vulnerabilities,
    )


def run(document: dict[str, Any], limits: Any = DEFAULT_LIMITS) -> AdapterOutput:
    return CycloneDxAdapter(limits).parse(
        ParsedDocument("json", document), STEP3_ARTIFACT, ingested_at=NOW
    )


def level_codes(output: AdapterOutput, level: str) -> list[str]:
    return [item.code for item in output.diagnostics if item.level.value == level]


def finding(output: AdapterOutput, record_id: str = "CVE-2026-0001") -> Observation:
    found = [item for item in output.observations if item.source_record_id == record_id]
    assert len(found) == 1, (found, output.diagnostics)
    return found[0]


def scope(output: AdapterOutput) -> Observation:
    return finding(output, "cyclonedx.bom")


def md(observation: Observation) -> dict[str, str]:
    return dict(observation.source_metadata)


def resource(observation: Observation) -> tuple[str, str]:
    return observation.resource.resource_type, observation.resource.resource_id


class StepTwoRulingTests(unittest.TestCase):
    """The three main-loop rulings on step 2's open questions (R-S2-1 to R-S2-3)."""

    def test_an_empty_strip_keeps_the_name_as_written(self) -> None:
        for name in (":1.4", "@" + SHA256):
            with self.subTest(name=name):
                self.assertEqual(subject_lineage("image", name), name)
        self.assertEqual(
            subject_lineage("image", "registry.example.test/web:1.4"), "registry.example.test/web"
        )

    def test_a_version_cannot_forge_a_component_set(self) -> None:
        def digest(components: list[dict[str, Any]]) -> str:
            observation = only(
                ingest(bom(metadata={"tools": [{"name": "syft"}]}, components=components))
            )
            return dict(observation.source_metadata)["component_set_sha256"]

        forged = [{"name": "a", "purl": "pkg:npm/a@1", "version": "1\npkg:npm/b\t2"}]
        plain = [
            {"name": "a", "purl": "pkg:npm/a@1", "version": "1"},
            {"name": "b", "purl": "pkg:npm/b@2", "version": "2"},
        ]
        self.assertNotEqual(digest(forged), digest(plain))
        encoded = [{"name": "a", "purl": "pkg:npm/a@1", "version": "1%\r"}]
        self.assertEqual(digest(encoded), hashlib.sha256(b"pkg:npm/a\t1%25%0D\n").hexdigest())
        self.assertEqual(
            digest(forged), hashlib.sha256(b"pkg:npm/a\t1%0Apkg:npm/b%092\n").hexdigest()
        )


class StandaloneVexTests(unittest.TestCase):
    """K4 is decided after indexing, with the subject left out (A9, Decision N)."""

    def assert_vex(self, document: dict[str, Any]) -> None:
        with self.assertRaises(AdapterParseError) as caught:
            run(document)
        self.assertEqual(str(caught.exception), VEX_REFUSAL)

    def test_a_vex_whose_refs_name_the_subject_is_refused(self) -> None:
        self.assert_vex(k3([], [vuln(refs=("subject",))]))

    def test_the_cisa_case_shape_is_refused_as_vex_not_invalid_bom(self) -> None:
        document = bom(
            metadata={
                "component": {
                    "type": "application",
                    "name": "acme-product",
                    "bom-ref": "product-ABC",
                }
            },
            vulnerabilities=[
                {
                    "id": "CVE-2021-44228",
                    "analysis": {"state": "not_affected", "justification": "code_not_reachable"},
                    "affects": [{"ref": "product-ABC"}],
                }
            ],
        )
        self.assert_vex(document)

    def test_the_bomex_vex_shape_is_refused(self) -> None:
        link = f"urn:cdx:{OTHER_SERIAL}/1#pkg:maven/a/b@1"
        self.assert_vex(bom(vulnerabilities=[vuln("CVE-2020-25649", (link,))]))

    def test_components_nested_under_the_subject_make_k3_and_resolve(self) -> None:
        document = k3([], [vuln()])
        document["metadata"]["component"]["components"] = [dict(LODASH)]
        output = run(document)
        self.assertEqual(resource(finding(output)), ("package", PKG + "pkg:npm/lodash"))
        self.assertIs(scope(output).disposition, ObservationDisposition.PASS)


class ResolutionTests(unittest.TestCase):
    """Refs resolve through the index or degrade to ref:, never to an ERROR (Decision J)."""

    def test_a_direct_ref_lands_on_the_package_resource_and_the_scope_passes(self) -> None:
        output = run(k3([dict(LODASH)], [vuln()]))
        observation = finding(output)
        self.assertEqual(resource(observation), ("package", PKG + "pkg:npm/lodash"))
        self.assertIs(observation.disposition, ObservationDisposition.OPEN)
        self.assertEqual(md(observation)["package_identity"], "purl")
        self.assertEqual(md(observation)["subject_ref"], "image:registry.example.test/web:1.4")
        self.assertEqual(md(observation)["tool_version"], "0.99.0")
        self.assertIs(scope(output).disposition, ObservationDisposition.PASS)
        self.assertEqual(scope(output).description, MATCHED_DESCRIPTION)
        self.assertEqual(md(scope(output))["affected_count"], "1")
        self.assertNotIn("match_unverified", level_codes(output, "warning"))
        self.assertEqual(level_codes(output, "error"), [])

    def test_a_ref_to_the_subject_lands_on_the_scope_resource(self) -> None:
        output = run(k3([dict(LODASH)], [vuln(refs=("subject",))]))
        observation = finding(output)
        self.assertEqual(resource(observation), SCOPE)
        self.assertNotIn("package_identity", md(observation))
        self.assertNotIn("instances", md(observation))
        # FX F2: a subject ref is a product-level statement and never makes the scope PASS.
        self.assertIs(scope(output).disposition, ObservationDisposition.NOT_REVIEWED)
        self.assertIn("match_unverified", level_codes(output, "warning"))

    def test_a_same_serial_bom_link_fragment_is_never_decoded(self) -> None:
        components = [
            {"name": "other", "purl": "pkg:deb/debian/other@1", "bom-ref": "libstdc++6"},
            {
                "name": "libstdc++6",
                "purl": "pkg:deb/debian/libstdc%2B%2B6@1",
                "bom-ref": "libstdc%2B%2B6",
            },
        ]
        link = f"urn:cdx:{SERIAL}/1#libstdc%2B%2B6"
        output = run(k3(components, [vuln(refs=(link,))]))
        self.assertEqual(
            resource(finding(output)), ("package", PKG + "pkg:deb/debian/libstdc%2B%2B6")
        )
        self.assertNotIn("affects_unresolved", level_codes(output, "warning"))

    def test_a_bom_link_resolves_only_on_this_serial_and_version_text(self) -> None:
        for link in (
            f"urn:cdx:{OTHER_SERIAL}/1#lodash-ref",
            f"urn:cdx:{SERIAL}/01#lodash-ref",
            f"urn:cdx:{SERIAL}/2#lodash-ref",
            f"urn:cdx:{SERIAL}/1lodash-ref",
        ):
            with self.subTest(link=link):
                output = run(k3([dict(LODASH)], [vuln(refs=(link,))]))
                self.assertEqual(resource(finding(output)), ("package", PKG + ref_key(link)))
                self.assertIn("affects_unresolved", level_codes(output, "warning"))
                self.assertIs(scope(output).disposition, ObservationDisposition.NOT_REVIEWED)

    def test_a_bom_link_version_defaults_to_one(self) -> None:
        document = k3([dict(LODASH)], [vuln(refs=(f"urn:cdx:{SERIAL}/1#lodash-ref",))])
        del document["version"]
        self.assertEqual(resource(finding(run(document))), ("package", PKG + "pkg:npm/lodash"))

    def test_an_unresolved_ref_keeps_the_finding_and_the_scope_is_unverified(self) -> None:
        output = run(k3([dict(LODASH)], [vuln(refs=("missing ref",))]))
        observation = finding(output)
        self.assertEqual(resource(observation), ("package", PKG + "ref:missing%20ref"))
        self.assertEqual(md(observation)["package_identity"], "ref")
        self.assertIs(observation.disposition, ObservationDisposition.OPEN)
        self.assertEqual(level_codes(output, "error"), [])
        self.assertIs(scope(output).disposition, ObservationDisposition.NOT_REVIEWED)
        self.assertIn("match_unverified", level_codes(output, "warning"))
        self.assertEqual(md(scope(output))["bom_kind"], "matched")

    def test_one_resolved_ref_makes_the_scope_pass(self) -> None:
        vulnerabilities = [vuln(refs=("missing",)), vuln("CVE-2026-0002")]
        output = run(k3([dict(LODASH)], vulnerabilities))
        self.assertIs(scope(output).disposition, ObservationDisposition.PASS)

    def test_a_duplicate_bom_ref_with_two_keys_falls_back(self) -> None:
        components = [
            {**LODASH, "bom-ref": "dup"},
            {"name": "z", "purl": "pkg:npm/z@1", "bom-ref": "dup"},
        ]
        output = run(k3(components, [vuln(refs=("dup",))]))
        self.assertEqual(resource(finding(output)), ("package", PKG + "ref:dup"))
        self.assertIn("bom_ref_conflict", level_codes(output, "warning"))

    def test_a_duplicate_bom_ref_with_one_key_resolves_as_instances(self) -> None:
        components = [
            {**LODASH, "bom-ref": "dup"},
            {**LODASH, "bom-ref": "dup", "version": "4.17.21", "purl": "pkg:npm/lodash@4.17.21"},
        ]
        output = run(k3(components, [vuln(refs=("dup",))]))
        observation = finding(output)
        self.assertEqual(resource(observation), ("package", PKG + "pkg:npm/lodash"))
        self.assertNotIn("bom_ref_conflict", level_codes(output, "warning"))
        self.assertEqual(len(json.loads(md(observation)["instances"])), 2)
        self.assertEqual(md(observation)["occurrence_count"], "1")

    def test_no_affects_goes_on_the_scope_resource(self) -> None:
        output = run(k3([dict(LODASH)], [{"id": "CVE-2026-0001"}]))
        self.assertEqual(resource(finding(output)), SCOPE)
        self.assertIn("affects_missing", level_codes(output, "warning"))
        self.assertIs(scope(output).disposition, ObservationDisposition.NOT_REVIEWED)

    def test_a_component_without_a_purl_is_the_weak_identity(self) -> None:
        output = run(k3([{"type": "library", "name": "musl", "bom-ref": "m"}], [vuln(refs=("m",))]))
        observation = finding(output)
        self.assertEqual(resource(observation), ("package", PKG + "component:library//musl"))
        self.assertEqual(md(observation)["package_identity"], "component")
        self.assertIn("package_identity_weak", level_codes(output, "warning"))

    def test_an_over_long_resource_id_is_refused(self) -> None:
        output = run(k3([dict(LODASH)], [vuln(refs=("x" * 600,))]))
        self.assertEqual(output.observations, ())
        self.assertEqual(level_codes(output, "error"), ["identity_input_invalid"])

    def test_the_vulnerability_count_is_bounded(self) -> None:
        limits = dataclasses.replace(DEFAULT_LIMITS, max_results_per_run=1)
        with self.assertRaises(InputLimitError):
            run(k3([dict(LODASH)], [vuln(), vuln("CVE-2026-0002")]), limits)
        run(k3([dict(LODASH)], [vuln()]), limits)

    def test_the_affects_list_is_bounded(self) -> None:
        refs = ("lodash-ref",) * MAX_AFFECTS_PER_VULNERABILITY
        observation = finding(run(k3([dict(LODASH)], [vuln(refs=refs)])))
        self.assertEqual(md(observation)["occurrence_count"], str(MAX_AFFECTS_PER_VULNERABILITY))
        with self.assertRaises(InputLimitError):
            run(k3([dict(LODASH)], [vuln(refs=(*refs, "lodash-ref"))]))


class FieldMapTests(unittest.TestCase):
    """The field map of section 9, ratings (Decision V) and analysis codes (Decision O)."""

    def one(self, **members: Any) -> tuple[AdapterOutput, Observation]:
        output = run(k3([dict(LODASH)], [vuln(**members)]))
        return output, finding(output)

    def test_the_severity_is_the_highest_word_and_never_a_banded_score(self) -> None:
        ratings = [
            {"source": {"name": "nvd"}, "score": 9.8, "severity": "low", "method": "CVSSv31"},
            {"source": {"name": "ghsa"}, "severity": "medium"},
            {"source": {"name": "alpha"}, "severity": "medium"},
        ]
        _output, observation = self.one(ratings=ratings)
        self.assertIs(observation.source_severity, SourceSeverity.MEDIUM)
        self.assertEqual(md(observation)["severity_source"], "alpha")
        self.assertEqual(len(json.loads(md(observation)["ratings"])), 3)

    def test_a_score_alone_sets_no_severity(self) -> None:
        _output, observation = self.one(ratings=[{"score": 9.8, "method": "CVSSv31"}])
        self.assertIs(observation.source_severity, SourceSeverity.UNKNOWN)

    def test_info_and_none_are_informational(self) -> None:
        for word in ("info", "none"):
            with self.subTest(word=word):
                _output, observation = self.one(ratings=[{"severity": word}])
                self.assertIs(observation.source_severity, SourceSeverity.INFORMATIONAL)

    def test_scores_are_read_int_before_float_and_kept_verbatim(self) -> None:
        good = [{"score": 7}, {"score": 0.0, "severity": "none"}, {"score": -1}, {"score": 2.5}]
        bad = [{"score": float("inf")}, {"score": 10**400}, {"score": True}, {"score": "7"}]
        output, observation = self.one(ratings=good + bad + [{"method": "other"}])
        ratings = json.loads(md(observation)["ratings"])
        for text in ('"score":"7"', '"score":"0.0"', '"score":"-1"', '"score":"2.5"'):
            self.assertTrue(any(text in item for item in ratings), text)
        messages = [
            item.message for item in output.diagnostics if item.code == "rating_score_invalid"
        ]
        self.assertEqual(len(messages), 1)
        self.assertIn("(4 occurrences", messages[0])

    def test_identifiers_come_from_the_id_the_references_and_the_cwes(self) -> None:
        output = run(
            k3(
                [dict(LODASH)],
                [
                    vuln(
                        "GHSA-29mw-wpgm-hmr9",
                        references=[{"id": "CVE-2026-1234"}, {"id": 7}],
                        cwes=[79, 0, True, 100_000],
                    )
                ],
            )
        )
        observation = finding(output, "GHSA-29mw-wpgm-hmr9")
        self.assertEqual(
            observation.source_identifiers, ("CVE-2026-1234", "CWE-79", "GHSA-29mw-wpgm-hmr9")
        )
        messages = [item.message for item in output.diagnostics if item.code == "cwe_invalid"]
        self.assertIn("(3 occurrences", messages[0])

    def test_the_title_is_the_first_line_and_detail_the_fallback(self) -> None:
        _output, observation = self.one(description="\n first line\nsecond", detail="d")
        self.assertEqual(observation.title, "first line")
        self.assertEqual(observation.description, "first line\nsecond")
        _output, observation = self.one(detail="d1\nd2")
        self.assertEqual((observation.title, observation.description), ("d1", "d1\nd2"))

    def test_each_analysis_state_draws_its_own_code_and_stays_open(self) -> None:
        expected = {
            "not_affected": "analysis_not_affected",
            "false_positive": "analysis_false_positive",
            "resolved": "analysis_resolved",
            "resolved_with_pedigree": "analysis_resolved",
            "in_triage": "analysis_in_triage",
            "exploitable": None,
            "bogus": "analysis_state_invalid",
        }
        family = set(filter(None, expected.values())) | {"response_will_not_fix"}
        for state, code in expected.items():
            with self.subTest(state=state):
                output, observation = self.one(analysis={"state": state})
                self.assertIs(observation.disposition, ObservationDisposition.OPEN)
                drawn = set(level_codes(output, "warning")) & family
                self.assertEqual(drawn, {code} if code else set())
                self.assertEqual(json.loads(md(observation)["analysis_states"]), [state])

    def test_the_response_pair_draws_will_not_fix(self) -> None:
        analysis = {"state": "not_affected", "justification": "code_not_reachable"}
        output, observation = self.one(
            analysis={**analysis, "response": ["will_not_fix", "update"]}
        )
        self.assertIn("response_will_not_fix", level_codes(output, "warning"))
        self.assertEqual(
            json.loads(md(observation)["analysis_responses"]), ["update", "will_not_fix"]
        )
        self.assertEqual(
            json.loads(md(observation)["analysis_justifications"]), ["code_not_reachable"]
        )

    def test_two_states_in_one_fold_conflict(self) -> None:
        vulnerabilities = [
            vuln(analysis={"state": "not_affected"}),
            vuln(analysis={"state": "in_triage"}),
        ]
        output = run(k3([dict(LODASH)], vulnerabilities))
        observation = finding(output)
        self.assertEqual(md(observation)["occurrence_count"], "2")
        self.assertIn("analysis_conflict", level_codes(output, "warning"))
        self.assertIs(observation.disposition, ObservationDisposition.OPEN)

    def test_an_unaffected_installed_version_is_named_and_stays_open(self) -> None:
        versions = [
            {"version": "4.17.20", "status": "unaffected"},
            {"range": "vers:npm/<4.17.21", "status": "affected"},
        ]
        document = k3(
            [dict(LODASH)],
            [{"id": "CVE-2026-0001", "affects": [{"ref": "lodash-ref", "versions": versions}]}],
        )
        output = run(document)
        observation = finding(output)
        self.assertIn("affects_version_unaffected", level_codes(output, "warning"))
        self.assertIs(observation.disposition, ObservationDisposition.OPEN)
        self.assertEqual(json.loads(md(observation)["affects_ranges"]), ["vers:npm/<4.17.21"])

    def test_a_non_string_scalar_counts_as_absent(self) -> None:
        document = k3(
            [dict(LODASH)],
            [
                {
                    "id": "CVE-2026-0001",
                    "references": [{"id": 5}],
                    "analysis": {"state": 1, "justification": 2, "detail": 3},
                    "affects": [{"ref": "lodash-ref", "versions": [{"version": 1, "status": 2}]}],
                }
            ],
        )
        output = run(document)
        observation = finding(output)
        self.assertEqual(level_codes(output, "error"), [])
        self.assertNotIn("analysis_states", md(observation))


class VulnerabilityShapeTests(unittest.TestCase):
    """Every wrong-type read fails closed as a per-vulnerability ERROR (A10, D2)."""

    SHAPES = {
        "string item": "CVE-2026-0001",
        "affects object": {"id": "CVE-1", "affects": {}},
        "affects string item": {"id": "CVE-1", "affects": ["lodash-ref"]},
        "ref missing": {"id": "CVE-1", "affects": [{}]},
        "ref numeric": {"id": "CVE-1", "affects": [{"ref": 1}]},
        "versions object": {"id": "CVE-1", "affects": [{"ref": "lodash-ref", "versions": {}}]},
        "versions string item": {"id": "CVE-1", "affects": [{"ref": "x", "versions": ["1"]}]},
        "ratings object": {"id": "CVE-1", "ratings": {}},
        "ratings string item": {"id": "CVE-1", "ratings": ["high"]},
        "references string": {"id": "CVE-1", "references": "x"},
        "references string item": {"id": "CVE-1", "references": ["x"]},
        "analysis list": {"id": "CVE-1", "analysis": []},
        "response string": {"id": "CVE-1", "analysis": {"response": "update"}},
        "cwes string": {"id": "CVE-1", "cwes": "79"},
        "cwes integer": {"id": "CVE-1", "cwes": 79},
        "advisories string": {"id": "CVE-1", "advisories": "x"},
        "advisories string item": {"id": "CVE-1", "advisories": ["x"]},
        "affects null": {"id": "CVE-1", "affects": None},
    }

    def test_each_shape_is_invalid_vulnerability(self) -> None:
        for label, item in self.SHAPES.items():
            with self.subTest(shape=label):
                output = run(k3([dict(LODASH)], [item]))
                self.assertEqual(level_codes(output, "error"), ["invalid_vulnerability"])
                self.assertEqual(output.observations, ())
                self.assertFalse(output.withheld)

    def test_an_absent_blank_or_non_string_id_is_vulnerability_id_missing(self) -> None:
        for record_id in (None, "", "  ", 7):
            with self.subTest(record_id=record_id):
                item = {"affects": [{"ref": "lodash-ref"}]}
                if record_id is not None:
                    item["id"] = record_id
                output = run(k3([dict(LODASH)], [item]))
                self.assertEqual(level_codes(output, "error"), ["vulnerability_id_missing"])

    def test_an_over_long_id_is_identity_input_invalid(self) -> None:
        output = run(k3([dict(LODASH)], [vuln("CVE-" + "9" * 600)]))
        self.assertEqual(level_codes(output, "error"), ["identity_input_invalid"])

    def test_an_error_beside_a_good_fold_is_a_withheld_partial_reading(self) -> None:
        output = run(k3([dict(LODASH)], [vuln(), {"id": "CVE-2026-0002", "affects": {}}]))
        self.assertEqual(output.observations, ())
        self.assertTrue(output.withheld)


class FoldTests(unittest.TestCase):
    """One observation per resource keeps each instance's facts together (A3, D3)."""

    def test_two_installs_fold_with_their_own_facts(self) -> None:
        components = [
            {
                **LODASH,
                "bom-ref": "b",
                "version": "4.17.21",
                "purl": "pkg:npm/lodash@4.17.21",
                "hashes": [{"alg": "SHA-1", "content": "22"}],
            },
            {
                **LODASH,
                "bom-ref": "a",
                "version": "4.17.15",
                "purl": "pkg:npm/lodash@4.17.15",
                "hashes": [{"alg": "SHA-256", "content": "11"}],
            },
        ]
        output = run(k3(components, [vuln(refs=("b", "a"))]))
        metadata = md(finding(output))
        self.assertEqual(metadata["occurrence_count"], "2")
        self.assertEqual(
            json.loads(metadata["instances"]),
            [
                {
                    "bom_ref": "a",
                    "version": "4.17.15",
                    "purl": "pkg:npm/lodash@4.17.15",
                    "hashes": ["SHA-256:11"],
                },
                {
                    "bom_ref": "b",
                    "version": "4.17.21",
                    "purl": "pkg:npm/lodash@4.17.21",
                    "hashes": ["SHA-1:22"],
                },
            ],
        )
        self.assertEqual(json.loads(metadata["package_versions"]), ["4.17.15", "4.17.21"])
        self.assertIn("package_instances_folded", level_codes(output, "info"))

    def test_the_text_winner_is_chosen_by_content_not_position(self) -> None:
        first = vuln(description="b text")
        second = vuln(description="a text")
        for order in ([first, second], [second, first]):
            with self.subTest(order=[item["description"] for item in order]):
                observation = finding(run(k3([dict(LODASH)], order)))
                self.assertEqual(observation.description, "a text")
                self.assertEqual(md(observation)["occurrence_count"], "2")

    def test_sixty_five_instances_keep_sixty_four_without_truncated_identifiers(self) -> None:
        components = [
            {**LODASH, "bom-ref": f"r{index:02d}", "version": f"1.{index:02d}"}
            for index in range(MAX_INSTANCES_PER_PACKAGE + 1)
        ]
        refs = tuple(item["bom-ref"] for item in components)
        metadata = md(finding(run(k3(components, [vuln(refs=refs)]))))
        instances = json.loads(metadata["instances"])
        self.assertEqual(len(instances), MAX_INSTANCES_PER_PACKAGE)
        self.assertEqual(instances[0]["version"], "1.00")
        self.assertEqual(metadata["instances_cut"], "true")
        truncated = json.loads(metadata.get("truncated", "[]"))
        self.assertNotIn("instances", truncated)
        self.assertNotIn("source_identifiers", truncated)

    def test_an_instance_keeps_sixty_four_hashes(self) -> None:
        hashes = [{"alg": "SHA-256", "content": f"{index:03d}"} for index in range(65)]
        metadata = md(finding(run(k3([{**LODASH, "hashes": hashes}], [vuln()]))))
        self.assertEqual(len(json.loads(metadata["instances"])[0]["hashes"]), 64)
        self.assertEqual(metadata["instances_cut"], "true")

    def test_an_instance_with_no_version_sorts_first(self) -> None:
        components = [dict(LODASH), {**LODASH, "bom-ref": "z-ref"}]
        del components[1]["version"]
        metadata = md(finding(run(k3(components, [vuln(refs=("lodash-ref", "z-ref"))]))))
        instances = json.loads(metadata["instances"])
        self.assertEqual([item.get("version") for item in instances], [None, "4.17.20"])

    def test_the_scope_yields_to_a_vulnerability_spelled_like_it(self) -> None:
        output = run(k3([dict(LODASH)], [{"id": "cyclonedx.bom"}]))
        self.assertEqual(len(output.observations), 1)
        self.assertIs(output.observations[0].disposition, ObservationDisposition.OPEN)
        self.assertEqual(resource(output.observations[0]), SCOPE)
        self.assertIn("scope_superseded", level_codes(output, "info"))

    def test_output_is_sorted_and_free_of_duplicate_identities(self) -> None:
        vulnerabilities = [vuln("CVE-2026-0009"), vuln(refs=("subject",)), vuln(refs=("nope",))]
        output = run(k3([dict(LODASH)], vulnerabilities))
        keys = [
            (
                item.resource.resource_type,
                item.resource.resource_id,
                item.source_record_id,
                item.observation_id,
            )
            for item in output.observations
        ]
        self.assertEqual(keys, sorted(keys))
        self.assertEqual(len({key[3] for key in keys}), len(keys))


class VulnerabilityPermutationTests(unittest.TestCase):
    """Vulnerability, affects, ratings, references and instance order never change output."""

    def canonical(self, document: dict[str, Any]) -> tuple[list[str], list[str]]:
        output = run(document)
        return (
            [item.to_canonical_json() for item in output.observations],
            sorted(item.code for item in output.diagnostics),
        )

    def test_vulnerability_documents_are_order_free(self) -> None:
        components = [
            {**LODASH, "bom-ref": "a", "version": "1", "hashes": [{"alg": "MD5", "content": "1"}]},
            {**LODASH, "bom-ref": "b", "version": "2"},
            {"name": "z", "purl": "pkg:npm/z@1", "bom-ref": "z"},
        ]
        ratings = [{"severity": "low", "source": {"name": "s1"}}, {"severity": "high", "score": 8}]
        references = [{"id": "CVE-2026-0005"}, {"id": "GHSA-29mw-wpgm-hmr9"}]
        vulnerabilities = [
            vuln(refs=("a", "b", "z"), ratings=ratings, references=references, description="x"),
            vuln(refs=("b",), description="y", analysis={"state": "in_triage"}),
            vuln("CVE-2026-0002", refs=("subject", "missing")),
        ]
        expected = self.canonical(k3(components, vulnerabilities))
        chooser = random.Random(30)
        for trial in range(12):
            shuffled = []
            for item in chooser.sample(vulnerabilities, len(vulnerabilities)):
                copy = dict(item)
                for member in ("affects", "ratings", "references"):
                    if member in copy:
                        copy[member] = chooser.sample(copy[member], len(copy[member]))
                shuffled.append(copy)
            document = k3(chooser.sample(components, len(components)), shuffled)
            with self.subTest(trial=trial):
                self.assertEqual(self.canonical(document), expected)


# *--- Step 3: Fixtures ---*

GRYPE_IMAGE = FIXTURES / "grype-image.cdx.json"
TRIVY_IMAGE = FIXTURES / "trivy-image.cdx.json"
SPEC_CORNERS = FIXTURES / "cyclonedx-spec-corners.cdx.json"
CORNER_PKG = "scan:corner-app|"
# What each named corner of the spec-corners fixture yields: (record id, resource type, id).
CORNER_IDS = {
    "components nested three deep": ("CVE-2026-1001", "package", CORNER_PKG + "pkg:npm/deep-c"),
    "a ref to metadata.component": ("CVE-2026-1002", "scan", "corner-app"),
    "a same-serial BOM-Link with a %2B fragment": (
        "CVE-2026-1003",
        "package",
        CORNER_PKG + "pkg:deb/debian/libstdc%2B%2B6",
    ),
    "a foreign BOM-Link": (
        "CVE-2026-1004",
        "package",
        CORNER_PKG + "ref:urn%3Acdx%3A9a1f8b2c-0000-4000-8000-000000000001%2F1%23deep-1",
    ),
    "an unresolved ref": ("CVE-2026-1005", "package", CORNER_PKG + "ref:no-such-ref"),
    "a duplicate bom-ref whose carriers differ in key": (
        "CVE-2026-1006",
        "package",
        CORNER_PKG + "ref:dup-split",
    ),
    "a duplicate bom-ref whose carriers share a key": (
        "CVE-2026-1007",
        "package",
        CORNER_PKG + "pkg:npm/same",
    ),
    "a GHSA id whose references carry the CVE": (
        "GHSA-2c3f-4g5h-6j7m",
        "package",
        CORNER_PKG + "pkg:pypi/flask-cors",
    ),
    "not_affected with the response pair": (
        "CVE-2026-1009",
        "package",
        CORNER_PKG + "pkg:generic/my%20tool",
    ),
    "in_triage": ("CVE-2026-1010", "package", CORNER_PKG + "pkg:deb/debian/zlib1g"),
    "an out-of-enum state": ("CVE-2026-1011", "package", CORNER_PKG + "pkg:npm/emptyver"),
    "one vulnerability listed twice with two states": (
        "CVE-2026-1012",
        "package",
        CORNER_PKG + "component:library//badpurl",
    ),
    "the installed version marked unaffected": (
        "CVE-2026-1013",
        "package",
        CORNER_PKG + "pkg:npm/twin",
    ),
    "a vulnerability with no affects": ("CVE-2026-1014", "scan", "corner-app"),
    "two installs of one package": ("CVE-2026-1016", "package", CORNER_PKG + "pkg:npm/twin"),
    "an id of cyclonedx.bom": ("cyclonedx.bom", "scan", "corner-app"),
}
# Every diagnostic the spec-corners fixture raises, in output order; none is an ERROR.
CORNER_DIAGNOSTICS = (
    ("warning", "affects_unresolved"),
    ("warning", "bom_ref_conflict"),
    ("warning", "analysis_not_affected"),
    ("warning", "response_will_not_fix"),
    ("warning", "analysis_in_triage"),
    ("warning", "analysis_state_invalid"),
    ("warning", "package_identity_weak"),
    ("warning", "analysis_false_positive"),
    ("warning", "affects_version_unaffected"),
    ("warning", "affects_missing"),
    ("info", "scope_superseded"),
    ("warning", "analysis_conflict"),
    ("info", "package_instances_folded"),
)


def fixture_result(path: Path) -> IngestResult:
    return ingest_stig_artifact(path, ingested_at=NOW)


def by_record(result: IngestResult, record_id: str) -> list[Observation]:
    return [item for item in result.observations if item.source_record_id == record_id]


def rating_scores(observation: Observation) -> list[str | None]:
    return [json.loads(item).get("score") for item in json.loads(md(observation)["ratings"])]


class SpecCornerFixtureTests(unittest.TestCase):
    """Each corner of the 1.5 spec-corners fixture yields what section 8 and 9 say (step 3)."""

    @classmethod
    def setUpClass(cls) -> None:
        cls.result = fixture_result(SPEC_CORNERS)

    def corner(self, label: str) -> Observation:
        record_id, resource_type, resource_id = CORNER_IDS[label]
        found = [
            item
            for item in by_record(self.result, record_id)
            if resource(item) == (resource_type, resource_id)
        ]
        self.assertEqual(len(found), 1, label)
        return found[0]

    def message(self, code: str) -> str:
        messages = [item.message for item in self.result.diagnostics if item.code == code]
        self.assertEqual(len(messages), 1, code)
        return messages[0]

    def test_every_corner_is_pinned_and_every_observation_is_a_corner(self) -> None:
        pinned = {CORNER_IDS[label] for label in CORNER_IDS}
        observed = {(item.source_record_id, *resource(item)) for item in self.result.observations}
        self.assertEqual(observed, pinned)
        for item in self.result.observations:
            self.assertIs(item.disposition, ObservationDisposition.OPEN)

    def test_the_diagnostics_are_pinned_and_none_is_an_error(self) -> None:
        self.assertEqual(
            tuple((item.level.value, item.code) for item in self.result.diagnostics),
            CORNER_DIAGNOSTICS,
        )
        self.assertTrue(self.result.successful)

    def test_an_application_subject_with_no_oci_purl_is_a_scan(self) -> None:
        observation = self.corner("a ref to metadata.component")
        self.assertEqual(observation.source_tool, "corner-scanner")
        self.assertEqual(md(observation)["subject_ref"], "scan:corner-app")
        self.assertEqual(md(observation)["tool_version"], "1.0.0")

    def test_the_fractional_second_offset_timestamp_is_the_clock(self) -> None:
        clock = datetime(2026, 10, 1, 12, 0, 0, 250_000, tzinfo=UTC)
        for item in self.result.observations:
            assert item.observed_at is not None
            self.assertEqual(item.observed_at, clock)

    def test_scores_of_every_kind_are_kept_and_never_set_the_severity(self) -> None:
        expected = {
            "components nested three deep": ("7", SourceSeverity.HIGH),
            "a ref to metadata.component": ("5.5", SourceSeverity.MEDIUM),
            "a same-serial BOM-Link with a %2B fragment": ("0.0", SourceSeverity.INFORMATIONAL),
            "a foreign BOM-Link": ("-1.5", SourceSeverity.LOW),
            "an unresolved ref": (None, SourceSeverity.CRITICAL),
        }
        for label, (score, severity) in expected.items():
            with self.subTest(corner=label):
                observation = self.corner(label)
                self.assertEqual(rating_scores(observation), [score])
                self.assertIs(observation.source_severity, severity)
        self.assertNotIn("rating_score_invalid", [item.code for item in self.result.diagnostics])

    def test_refs_resolve_or_fall_back_as_section_8_says(self) -> None:
        self.assertEqual(
            md(self.corner("components nested three deep"))["package_identity"], "purl"
        )
        self.assertNotIn("package_identity", md(self.corner("a ref to metadata.component")))
        for label in (
            "a foreign BOM-Link",
            "an unresolved ref",
            "a duplicate bom-ref whose carriers differ in key",
        ):
            with self.subTest(corner=label):
                self.assertEqual(md(self.corner(label))["package_identity"], "ref")
        # The conflicting duplicate takes the fallback too (leg 1 decision 1).
        self.assertIn("(3 occurrences", self.message("affects_unresolved"))
        self.assertIn("(1 occurrence", self.message("bom_ref_conflict"))
        shared = md(self.corner("a duplicate bom-ref whose carriers share a key"))
        self.assertEqual(json.loads(shared["package_versions"]), ["1.0.0", "1.0.1"])
        self.assertEqual(json.loads(shared["bom_refs"]), ["dup-same"])

    def test_the_ghsa_record_carries_the_cve_from_its_references(self) -> None:
        observation = self.corner("a GHSA id whose references carry the CVE")
        self.assertEqual(observation.source_identifiers, ("CVE-2026-1008", "GHSA-2c3f-4g5h-6j7m"))
        self.assertFalse(cve_may_be_missing(observation))
        self.assertEqual(json.loads(md(observation)["purls"]), ["pkg:pypi/Flask_Cors@4.0.0"])

    def test_the_analysis_corners_draw_their_codes_and_stay_open(self) -> None:
        pair = md(self.corner("not_affected with the response pair"))
        self.assertEqual(json.loads(pair["analysis_states"]), ["not_affected"])
        self.assertEqual(json.loads(pair["analysis_justifications"]), ["code_not_reachable"])
        self.assertEqual(json.loads(pair["analysis_responses"]), ["update", "will_not_fix"])
        self.assertEqual(json.loads(md(self.corner("in_triage"))["analysis_states"]), ["in_triage"])
        self.assertEqual(
            json.loads(md(self.corner("an out-of-enum state"))["analysis_states"]),
            ["maybe_affected"],
        )
        twice = self.corner("one vulnerability listed twice with two states")
        self.assertEqual(md(twice)["occurrence_count"], "2")
        self.assertEqual(
            json.loads(md(twice)["analysis_states"]), ["exploitable", "false_positive"]
        )
        for code in (
            "analysis_not_affected",
            "response_will_not_fix",
            "analysis_in_triage",
            "analysis_state_invalid",
            "analysis_false_positive",
            "analysis_conflict",
            "affects_version_unaffected",
        ):
            with self.subTest(code=code):
                self.assertIn("(1 occurrence", self.message(code))

    def test_the_package_key_corners(self) -> None:
        empty = md(self.corner("an out-of-enum state"))
        self.assertNotIn("package_versions", empty)
        self.assertEqual(
            json.loads(empty["instances"]),
            [{"bom_ref": "empty-version", "purl": "pkg:npm/emptyver"}],
        )
        weak = md(self.corner("one vulnerability listed twice with two states"))
        self.assertEqual(weak["package_identity"], "component")
        self.assertEqual(json.loads(weak["purls"]), ["pkg:npm"])
        self.assertIn("(2 occurrences", self.message("package_identity_weak"))
        qualifier = md(self.corner("in_triage"))
        self.assertEqual(
            json.loads(qualifier["purls"]), ["pkg:deb/debian/zlib1g@1.2.13?arch=&distro=debian-12"]
        )

    def test_two_installs_keep_their_own_versions_and_hashes(self) -> None:
        metadata = md(self.corner("two installs of one package"))
        instances = json.loads(metadata["instances"])
        self.assertEqual(
            [(item["bom_ref"], item["version"], item["hashes"]) for item in instances],
            [
                ("twin-1", "1.0", ["SHA-256:" + "1" * 64]),
                ("twin-2", "2.0", ["SHA-256:" + "2" * 64]),
            ],
        )
        self.assertEqual(metadata["occurrence_count"], "2")
        unaffected = md(self.corner("the installed version marked unaffected"))
        self.assertEqual(json.loads(unaffected["affects_ranges"]), ["vers:npm/>=2.0"])
        self.assertEqual(len(json.loads(unaffected["instances"])), 1)

    def test_the_scope_yields_and_a_record_with_no_affects_lands_on_the_subject(self) -> None:
        (superseding,) = by_record(self.result, "cyclonedx.bom")
        self.assertEqual(superseding.title, "An id spelled like the scope record.")
        self.assertIn("(2 occurrences", self.message("affects_missing"))
        self.assertIn("(1 occurrence", self.message("scope_superseded"))
        self.assertNotIn(
            "bom_kind", md(self.corner("an id of cyclonedx.bom")), "the scope observation yields"
        )


class ProducerFixtureTests(unittest.TestCase):
    """The grype and trivy image fixtures read the producer shapes the plan names (step 3)."""

    @classmethod
    def setUpClass(cls) -> None:
        cls.grype = fixture_result(GRYPE_IMAGE)
        cls.trivy = fixture_result(TRIVY_IMAGE)

    def test_both_scopes_pass_on_a_resolved_match(self) -> None:
        for result, scope_id in (
            (self.grype, "registry.example.test/api@sha256:" + "b" * 64),
            (self.trivy, "registry.example.test/api:2.1"),
        ):
            with self.subTest(scope=scope_id):
                observation = by_record(result, "cyclonedx.bom")[0]
                self.assertEqual(resource(observation), ("image", scope_id))
                self.assertIs(observation.disposition, ObservationDisposition.PASS)
                self.assertEqual(md(observation)["bom_kind"], "matched")
                self.assertEqual(md(observation)["affected_count"], "3")

    def test_grype_folds_one_cve_from_two_namespaces_on_one_component(self) -> None:
        (observation,) = by_record(self.grype, "CVE-2024-0727")
        metadata = md(observation)
        self.assertEqual(metadata["occurrence_count"], "2")
        self.assertEqual(
            json.loads(metadata["vulnerability_sources"]), ["debian:distro:debian:12", "nvd:cpe"]
        )
        self.assertIs(observation.source_severity, SourceSeverity.MEDIUM)
        self.assertEqual(json.loads(metadata["affects_ranges"]), ["vers:deb/>=3.0.16-1"])

    def test_grype_epss_and_kev_ratings_are_kept_and_never_set_the_severity(self) -> None:
        (observation,) = by_record(self.grype, "CVE-2023-5678")
        ratings = [json.loads(item) for item in json.loads(md(observation)["ratings"])]
        sources = sorted(item.get("source", "") for item in ratings)
        self.assertEqual(sources, ["", "CISA KEV Catalog", "FIRST"])
        self.assertIs(observation.source_severity, SourceSeverity.CRITICAL)

    def test_grype_two_package_id_bom_refs_on_one_purl_fold(self) -> None:
        (observation,) = by_record(self.grype, "CVE-2023-5678")
        metadata = md(observation)
        self.assertEqual(metadata["occurrence_count"], "2")
        self.assertEqual(len(json.loads(metadata["bom_refs"])), 2)
        self.assertEqual(len(json.loads(metadata["instances"])), 2)
        self.assertEqual(
            observation.resource.resource_id,
            "image:registry.example.test/api|pkg:deb/debian/libssl3?arch=amd64",
        )
        self.assertIn("package_instances_folded", codes(self.grype, "info"))

    def test_grype_a_component_with_no_purl_is_weak(self) -> None:
        (observation,) = by_record(self.grype, "CVE-2022-48174")
        self.assertEqual(md(observation)["package_identity"], "component")
        self.assertEqual(
            json.loads(md(observation)["cpes"]),
            ["cpe:2.3:a:busybox:busybox:1.36.1:*:*:*:*:*:*:*"],
        )
        self.assertEqual(codes(self.grype, "warning"), ["package_identity_weak"])

    def test_trivy_unsorted_qualifiers_and_a_gem_bom_ref_make_stable_keys(self) -> None:
        resources = sorted(item.resource.resource_id for item in self.trivy.observations)
        lineage = "image:registry.example.test/api|"
        self.assertEqual(
            resources,
            [
                lineage + "pkg:gem/activesupport",
                lineage + "pkg:rpm/centos/openssl-libs?arch=x86_64",
                lineage + "pkg:rpm/centos/openssl?arch=x86_64",
                "registry.example.test/api:2.1",
            ],
        )

    def test_trivy_one_cve_over_two_packages_is_two_observations(self) -> None:
        found = by_record(self.trivy, "CVE-2023-0286")
        self.assertEqual(len(found), 2)
        for observation in found:
            with self.subTest(resource=observation.resource.resource_id):
                self.assertEqual(md(observation)["occurrence_count"], "1")
                self.assertEqual(observation.source_identifiers, ("CVE-2023-0286", "CWE-843"))

    def test_trivy_eight_severity_only_ratings_take_the_highest_word(self) -> None:
        observation = by_record(self.trivy, "CVE-2023-0286")[0]
        ratings = [json.loads(item) for item in json.loads(md(observation)["ratings"])]
        self.assertEqual(len(ratings), 8)
        self.assertTrue(all("score" not in item for item in ratings))
        self.assertIs(observation.source_severity, SourceSeverity.HIGH)
        self.assertEqual(md(observation)["severity_source"], "alma")
        (gem,) = by_record(self.trivy, "CVE-2023-38037")
        self.assertEqual(gem.source_identifiers, ("CVE-2023-38037", "CWE-379", "CWE-732"))
        self.assertEqual(self.trivy.diagnostics, ())


# *--- Step 3: Built-in Cases ---*


class BomexVexShapeTests(unittest.TestCase):
    """The two standalone VEX shapes of external/bomex-VEX-*, rebuilt in code, are K4 (A9)."""

    def assert_vex(self, document: dict[str, Any]) -> None:
        with self.assertRaises(AdapterParseError) as caught:
            run(document)
        self.assertEqual(str(caught.exception), VEX_REFUSAL)
        result = ingest(document)
        self.assertEqual([item.code for item in result.errors], ["artifact_parse_failed"])

    def test_the_bomex_vex_shape_with_every_member_is_refused(self) -> None:
        # bomex-VEX-vex.json: no metadata, no components, no serial, one full record whose ref
        # is a BOM-Link into another document.
        link = f"urn:cdx:{SERIAL}/1#pkg:maven/com.example/databind@2.10.0?type=jar"
        record = {
            "id": "CVE-2020-25649",
            "source": {"name": "NVD", "url": "https://nvd.example.test/CVE-2020-25649"},
            "references": [{"id": "SNYK-JAVA-EXAMPLE-1", "source": {"name": "SNYK"}}],
            "ratings": [
                {"source": {"name": "NVD"}, "score": 7.5, "severity": "high", "method": "CVSSv31"},
                {"source": {"name": "Acme"}, "score": 0.0, "severity": "none", "method": "CVSSv31"},
            ],
            "cwes": [611],
            "description": "An XML external entity flaw.",
            "detail": "XXE detail.",
            "recommendation": "Upgrade.",
            "advisories": [{"title": "Commit", "url": "https://example.test/commit"}],
            "created": "2020-12-03T00:00:00.000Z",
            "published": "2020-12-03T00:00:00.000Z",
            "updated": "2021-10-26T00:00:00.000Z",
            "credits": {"individuals": [{"name": "Researcher"}]},
            "analysis": {
                "state": "not_affected",
                "justification": "code_not_reachable",
                "response": ["will_not_fix", "update"],
                "detail": "Not reachable.",
            },
            "affects": [{"ref": link}],
        }
        document = {"bomFormat": "CycloneDX", "specVersion": "1.4", "version": 1}
        self.assert_vex({**document, "vulnerabilities": [record]})

    def test_the_cisa_not_affected_shape_is_refused(self) -> None:
        # bomex-VEX-CISA-Case-1-vex-not_affected.json: a subject, no tools, no components, and
        # the only ref names the subject.
        document = {
            "bomFormat": "CycloneDX",
            "specVersion": "1.4",
            "version": 1,
            "metadata": {
                "timestamp": "2022-03-03T00:00:00Z",
                "component": {
                    "name": "ABC",
                    "version": "4.2",
                    "type": "application",
                    "bom-ref": "product-ABC",
                },
            },
            "vulnerabilities": [
                {
                    "id": "CVE-2021-44228",
                    "source": {"name": "NVD", "url": "https://nvd.example.test/CVE-2021-44228"},
                    "analysis": {
                        "state": "not_affected",
                        "justification": "code_not_present",
                        "response": ["will_not_fix"],
                        "detail": "The vulnerable class was removed before shipping.",
                    },
                    "affects": [{"ref": "product-ABC"}],
                }
            ],
        }
        self.assert_vex(document)


class MalformedMatchedTests(unittest.TestCase):
    """Step 2's malformed K1/K2 shapes beside one good vulnerability are K3 CONTENT ERRORs (A12)."""

    def test_each_shape_is_a_mintable_content_error(self) -> None:
        for members, check in MalformedInventoryTests.SHAPES:
            with self.subTest(check=check):
                document = bom(
                    metadata={"tools": [{"name": "grype"}]},
                    components=[dict(LODASH)],
                    vulnerabilities=[vuln()],
                )
                document.update(members)
                result = ingest(document)
                self.assertEqual(result.observations, ())
                error_codes = [item.code for item in result.errors]
                self.assertTrue(error_codes)
                self.assertNotIn("artifact_parse_failed", error_codes)
                self.assertTrue(set(error_codes) <= {"invalid_bom", "invalid_component"})
                classification = classify_ingest(result)
                assert classification is not None
                self.assertIs(classification.failure_class, FailureClass.CONTENT)
                self.assertIsNone(classification.reason)


def saturated_document(char: str) -> dict[str, Any]:
    """Return a K3 document whose one fold saturates every cap, padded with char.

    65 carriers of one package and 65 records of one id fill every list past 64 items of past
    256 characters, every scalar past 512, the title, the description and the identifiers; the
    record id and the resource id sit exactly at 512. Identity inputs stay ASCII.
    """
    over = MAX_LIST_ITEMS + 1
    name = "n" * (MAX_IDENTITY_CHARS - len(PKG) - len("pkg:npm/"))

    def pad(index: int) -> str:
        return f"{index:02d}" + char * (MAX_LIST_ITEM_CHARS + 44)

    components = [
        {
            "type": "library",
            "name": name,
            "version": pad(index),
            "purl": f"pkg:npm/{name}@{index:02d}",
            "bom-ref": "r" + pad(index),
            "cpe": "cpe:2.3:a:" + pad(index),
            "hashes": [{"alg": "SHA-256", "content": pad(index)}],
        }
        for index in range(over)
    ]
    refs = [item["bom-ref"] for item in components]
    record_id = "SAT-" + "x" * (MAX_IDENTITY_CHARS - 4)
    shared = {
        "description": "t" * (MAX_TITLE_CHARS + 88) + "\n" + char * MAX_DESCRIPTION_CHARS,
        **{member: char * 600 for member in ("recommendation", "published", "created", "updated")},
    }
    ranges = [{"range": "vers:npm/" + pad(index), "status": "affected"} for index in range(over)]
    first = {
        "id": record_id,
        **shared,
        "references": [{"id": f"CVE-2026-{1000 + index}"} for index in range(over)],
        "advisories": [{"url": "https://example.test/" + pad(index)} for index in range(over)],
        "affects": [{"ref": refs[0], "versions": ranges}] + [{"ref": ref} for ref in refs[1:]],
    }
    rest = [
        {
            "id": record_id,
            **shared,
            "bom-ref": "v" + pad(index),
            "source": {"name": pad(index)},
            "ratings": [{"source": {"name": pad(index)}, "severity": "high"}],
            "analysis": {
                member: pad(index)
                for member in ("state", "justification", "detail", "firstIssued", "lastUpdated")
            }
            | {"response": [pad(index)]},
            "affects": [{"ref": refs[0]}],
        }
        for index in range(over)
    ]
    return k3(components, [first, *rest])


# Every list and text the saturated fold cuts; `instances` is never among them (A3).
SATURATED_TRUNCATED = [
    "advisories",
    "affects_ranges",
    "affects_statuses",
    "analysis_details",
    "analysis_first_issued",
    "analysis_justifications",
    "analysis_last_updated",
    "analysis_responses",
    "analysis_states",
    "bom_refs",
    "component_hashes",
    "cpes",
    "created",
    "description",
    "package_versions",
    "published",
    "purls",
    "ratings",
    "recommendation",
    "source_identifiers",
    "title",
    "updated",
    "vulnerability_bom_refs",
    "vulnerability_sources",
]


class SaturatedCapTests(unittest.TestCase):
    """Every cap holds at saturation; four-byte text past the ceiling fails closed (sec. 18)."""

    def test_an_ascii_fold_saturating_every_cap_is_one_bounded_observation(self) -> None:
        output = run(saturated_document("a"))
        observation = finding(output, "SAT-" + "x" * (MAX_IDENTITY_CHARS - 4))
        metadata = md(observation)
        self.assertEqual(json.loads(metadata["truncated"]), SATURATED_TRUNCATED)
        for member in SATURATED_TRUNCATED:
            if member in ("description", "title", "source_identifiers", "purls"):
                continue
            with self.subTest(member=member):
                value = metadata[member]
                if value.startswith("["):
                    items = json.loads(value)
                    self.assertEqual(len(items), MAX_LIST_ITEMS)
                    self.assertEqual({len(item) for item in items}, {MAX_LIST_ITEM_CHARS})
                else:
                    self.assertEqual(len(value), MAX_METADATA_VALUE_CHARS)
        # The 65 purls differ only past the 256-character cut, so they collapse to one item.
        self.assertEqual([len(item) for item in json.loads(metadata["purls"])], [256])
        instances = json.loads(metadata["instances"])
        self.assertEqual(len(instances), MAX_INSTANCES_PER_PACKAGE)
        self.assertEqual(metadata["instances_cut"], "true")
        for instance in instances:
            for member in ("bom_ref", "version", "purl"):
                self.assertLessEqual(len(instance[member]), MAX_LIST_ITEM_CHARS)
        self.assertEqual(len(observation.title), MAX_TITLE_CHARS)
        self.assertEqual(len(observation.description), MAX_DESCRIPTION_CHARS)
        self.assertEqual(len(observation.source_identifiers), MAX_LIST_ITEMS)
        self.assertEqual(len(observation.source_record_id), MAX_IDENTITY_CHARS)
        self.assertEqual(len(observation.resource.resource_id), MAX_IDENTITY_CHARS)
        size = len(observation.to_canonical_json().encode("utf-8"))
        self.assertLess(size, MAX_OBSERVATION_JSON_BYTES)
        self.assertTrue(cve_may_be_missing(observation))

    def test_four_byte_and_escaped_text_past_the_ceiling_fail_closed(self) -> None:
        # Measured 2026-10-19: 350,195 bytes in ASCII, 1,222,490 in four-byte text and
        # 1,210,944 for a quote; the instances alone hold 64 x 4 cut strings.
        pattern = r"^observation obs-[0-9a-f]{64} is [0-9]+ bytes of canonical JSON; maximum is "
        for char in ("\U0001f600", '"', "\\"):
            with self.subTest(char=repr(char)):
                with self.assertRaisesRegex(
                    InputLimitError, pattern + f"{MAX_OBSERVATION_JSON_BYTES}$"
                ):
                    run(saturated_document(char))
                result = ingest(saturated_document(char))
                self.assertEqual(result.observations, ())
                self.assertEqual([item.code for item in result.errors], ["artifact_parse_failed"])


class CveMayBeMissingTests(unittest.TestCase):
    """`truncated` feeds kev.py's cve_may_be_missing; an instance cut never does (A3)."""

    def identifiers(self, references: list[str], record_id: str = "CVE-2026-0001") -> Observation:
        record = vuln(record_id, references=[{"id": text} for text in references])
        return finding(run(k3([dict(LODASH)], [record])), record_id)

    def test_a_cut_list_of_cves_may_have_lost_one(self) -> None:
        observation = self.identifiers([f"CVE-2026-{1000 + index}" for index in range(70)])
        self.assertIn("source_identifiers", json.loads(md(observation)["truncated"]))
        self.assertTrue(cve_may_be_missing(observation))

    def test_a_cut_list_whose_largest_kept_item_passes_cve_lost_none(self) -> None:
        alphabet = "23456789cfghjmpqrvwx"
        ghsa = [
            f"GHSA-2c3f-4g5h-{alphabet[index // 20]}{alphabet[index % 20]}xx" for index in range(70)
        ]
        observation = self.identifiers(ghsa)
        kept = observation.source_identifiers
        self.assertEqual(len(kept), MAX_LIST_ITEMS)
        self.assertIn("CVE-2026-0001", kept)
        self.assertIn("source_identifiers", json.loads(md(observation)["truncated"]))
        self.assertFalse(cve_may_be_missing(observation))

    def test_an_instance_cut_never_says_a_cve_may_be_missing(self) -> None:
        components = [
            {**LODASH, "bom-ref": f"r{index:02d}", "version": f"1.{index:02d}"}
            for index in range(MAX_INSTANCES_PER_PACKAGE + 1)
        ]
        refs = tuple(item["bom-ref"] for item in components)
        observation = finding(run(k3(components, [vuln(refs=refs)])))
        self.assertEqual(md(observation)["instances_cut"], "true")
        self.assertFalse(cve_may_be_missing(observation))


class AnalysisCodeOnceTests(unittest.TestCase):
    """Each analysis code is one diagnostic however many records draw it (Decision O)."""

    def test_each_code_is_raised_once_with_its_count(self) -> None:
        states = ("not_affected", "false_positive", "resolved", "in_triage", "bogus")
        vulnerabilities = [
            vuln(f"CVE-2026-{index:04d}", analysis={"state": state, "response": ["will_not_fix"]})
            for index, state in enumerate(states * 2, start=1)
        ]
        output = run(k3([dict(LODASH)], vulnerabilities))
        family = (
            "analysis_not_affected",
            "analysis_false_positive",
            "analysis_resolved",
            "analysis_in_triage",
            "analysis_state_invalid",
        )
        warnings = level_codes(output, "warning")
        for code in family:
            with self.subTest(code=code):
                self.assertEqual(warnings.count(code), 1)
                (message,) = [item.message for item in output.diagnostics if item.code == code]
                self.assertIn("(2 occurrences", message)
        self.assertEqual(warnings.count("response_will_not_fix"), 1)
        for observation in output.observations:
            if observation.source_record_id != "cyclonedx.bom":
                self.assertIs(observation.disposition, ObservationDisposition.OPEN)


# *--- Step 3: Determinism ---*


class MatchedPermutationTests(unittest.TestCase):
    """Step 2's permutation test on a K3 document: nesting, tool and qualifier order (sec. 20)."""

    TOOLS = (
        {"type": "application", "name": "grype", "version": "0.99.0"},
        {"type": "library", "name": "lib", "version": "1"},
    )
    COMPONENTS = (
        {"type": "library", "name": "a", "version": "1", "purl": "pkg:npm/a@1", "bom-ref": "a"},
        {"type": "library", "name": "m", "purl": "pkg:apk/alpine/m@1?arch=x86_64&os=a"},
        {"type": "library", "name": "z", "version": "3", "purl": "pkg:npm/z@3", "bom-ref": "z"},
        {"type": "file", "name": "/etc/os-release", "bom-ref": "f"},
    )

    def document(self, chooser: random.Random | None, reordered: bool) -> dict[str, Any]:
        components = [dict(item) for item in self.COMPONENTS]
        components[1]["bom-ref"] = "m"
        if reordered:
            components[1]["purl"] = "pkg:apk/alpine/m@1?os=a&arch=x86_64"
        tools = list(self.TOOLS)
        nested = None
        if chooser is not None:
            components = chooser.sample(components, len(components))
            tools = chooser.sample(tools, len(tools))
            nested = chooser.choice([None, "component", "subject"])
        document = k3([], [vuln(refs=("a", "m", "z", "subject")), vuln("CVE-2026-0002", ("m",))])
        document["metadata"]["tools"] = {"components": tools}
        if nested == "subject":
            document["metadata"]["component"]["components"] = components
        elif nested == "component":
            components[0]["components"] = components[1:]
            document["components"] = components[:1]
        else:
            document["components"] = components
        return document

    def canonical(self, document: dict[str, Any]) -> tuple[list[str], list[str]]:
        output = run(document)
        return (
            [item.to_canonical_json() for item in output.observations],
            [item.code for item in output.diagnostics],
        )

    def identities(self, document: dict[str, Any]) -> list[tuple[str, str, str, str]]:
        return [
            (item.source_record_id, *resource(item), item.observation_id)
            for item in run(document).observations
        ]

    def test_k3_documents_are_order_and_nesting_free(self) -> None:
        expected = {flag: self.canonical(self.document(None, flag)) for flag in (False, True)}
        self.assertEqual(len(expected[False][0]), 6)
        chooser = random.Random(40)
        for trial in range(16):
            reordered = chooser.random() < 0.5
            with self.subTest(trial=trial, reordered=reordered):
                document = self.document(chooser, reordered)
                self.assertEqual(self.canonical(document), expected[reordered])

    def test_qualifier_order_never_moves_an_identity(self) -> None:
        # The purl is evidence kept verbatim (section 9), so `purls` and `instances` show the
        # order as written; the key, the resource and every observation id do not move.
        self.assertEqual(
            self.identities(self.document(None, False)), self.identities(self.document(None, True))
        )


class FoldPropertyTests(unittest.TestCase):
    """The fold is a function of the candidate multiset: any arrangement, one output (sec. 13)."""

    def test_random_folds_survive_every_permutation(self) -> None:
        for seed in range(20):
            chooser = random.Random(seed)
            components = [
                {
                    **LODASH,
                    "bom-ref": f"r{index}",
                    "version": chooser.choice(["1", "2", "3", ""]),
                    "hashes": [
                        {"alg": chooser.choice(["MD5", "SHA-1"]), "content": f"{index}{item}"}
                        for item in range(chooser.randint(0, 3))
                    ],
                }
                for index in range(chooser.randint(1, 6))
            ]
            refs = [item["bom-ref"] for item in components]
            records = [
                vuln(
                    refs=tuple(chooser.sample(refs, chooser.randint(1, len(refs)))),
                    description=chooser.choice(["a", "b", "c"]),
                    ratings=[{"severity": chooser.choice(["low", "high", "medium"])}],
                    analysis={"state": chooser.choice(["in_triage", "resolved", "exploitable"])},
                )
                for _ in range(chooser.randint(1, 5))
            ]
            expected = run(k3(components, records))
            for trial in range(4):
                shuffled = []
                for item in chooser.sample(records, len(records)):
                    shuffled.append(
                        {**item, "affects": chooser.sample(item["affects"], len(item["affects"]))}
                    )
                arranged = [
                    {**item, "hashes": chooser.sample(item["hashes"], len(item["hashes"]))}
                    for item in chooser.sample(components, len(components))
                ]
                with self.subTest(seed=seed, trial=trial):
                    output = run(k3(arranged, shuffled))
                    self.assertEqual(
                        [item.to_canonical_json() for item in output.observations],
                        [item.to_canonical_json() for item in expected.observations],
                    )
                    self.assertEqual(
                        sorted(item.code for item in output.diagnostics),
                        sorted(item.code for item in expected.diagnostics),
                    )


class RawNumberTests(unittest.TestCase):
    """Scores written as JSON text reach the int-before-float read through the real parser."""

    def test_raw_overflowing_scores_are_rating_score_invalid(self) -> None:
        document = k3([dict(LODASH)], [vuln(ratings=[{"severity": "low", "score": 0}] * 3)])
        text = json.dumps(document)
        text = text.replace('"score": 0}', '"score": 1e400}', 1)
        text = text.replace('"score": 0}', '"score": ' + "9" * 400 + "}", 1)
        text = text.replace('"score": 0}', '"score": true}', 1)
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "raw.cdx.json"
            path.write_text(text, encoding="utf-8")
            result = ingest_stig_artifact(path, ingested_at=NOW)
        self.assertEqual(result.errors, ())
        (message,) = [
            item.message for item in result.diagnostics if item.code == "rating_score_invalid"
        ]
        self.assertIn("(3 occurrences", message)
        observation = [
            item for item in result.observations if item.source_record_id != "cyclonedx.bom"
        ][0]
        self.assertIs(observation.source_severity, SourceSeverity.LOW)


class ComponentHashShapeTests(unittest.TestCase):
    """A component `hashes` that is a string is a structural ERROR on K3, never a TypeError (D2)."""

    def test_a_string_hashes_is_invalid_component(self) -> None:
        output = run(k3([{**LODASH, "hashes": "aa"}], [vuln()]))
        self.assertEqual(output.observations, ())
        self.assertEqual(level_codes(output, "error"), ["invalid_component"])


# *--- Step 5: Goldens ---*

GOLDEN = Path(__file__).parent / "golden"
#: The `vdt-cyclonedx` and `historical-cyclonedx` runs: the grype and trivy matches of one image.
GOLDEN_ARTIFACTS = (GRYPE_IMAGE, TRIVY_IMAGE)
GOLDEN_PACKAGE_URI = "https://example.test/cpo"
GOLDEN_FROM = datetime(2026, 10, 1, tzinfo=UTC)
GOLDEN_TO = datetime(2026, 10, 31, 23, 59, 59, tzinfo=UTC)
GOLDEN_AS_OF = datetime(2026, 10, 3, 12, tzinfo=UTC)
#: Both documents declare this clock in `metadata.timestamp`, so no attestation is needed.
GOLDEN_DETECTED_AT = "2026-10-01T12:00:00Z"
#: After the documents' clock and before the as-of, so a substituted instant would show.
GOLDEN_INGESTED_AT = datetime(2026, 10, 2, 12, tzinfo=UTC)
GOLDEN_TRACKING_IDS = (
    "case-b6bd658a4ffea56b",
    "case-8b9104e175637348",
    "case-0f4d0f825af49a8a",
    "case-316e8e2251393517",
    "case-b6cc25fd202e4964",
    "case-031f4bfb066badaa",
)
#: Each case's record id and the tool that detected it: one case per CVE per tool.
GOLDEN_CASES = {
    "case-b6bd658a4ffea56b": ("CVE-2022-48174", "grype"),
    "case-8b9104e175637348": ("CVE-2023-0286", "trivy"),
    "case-0f4d0f825af49a8a": ("CVE-2023-38037", "trivy"),
    "case-316e8e2251393517": ("CVE-2023-5678", "grype"),
    "case-b6cc25fd202e4964": ("CVE-2024-0727", "grype"),
    "case-031f4bfb066badaa": ("GHSA-rv95-896h-c2vc", "grype"),
}
#: trivy's CVE-2023-0286 on openssl-libs and openssl: the one case with two members.
TWO_MEMBER_CASE = "case-8b9104e175637348"
GOLDEN_OBSERVATION_COUNTS = {GRYPE_IMAGE.name: 5, TRIVY_IMAGE.name: 4}


def golden_options() -> ReportOptions:
    """Return the options the documented `vdt-cyclonedx` command line passes."""
    return ReportOptions(
        certification_class=CertificationClass.C,
        package_uri=GOLDEN_PACKAGE_URI,
        period_from=GOLDEN_FROM,
        period_to=GOLDEN_TO,
        as_of=GOLDEN_AS_OF,
        calendar_timezone="UTC",
    )


def compile_cyclonedx_golden(
    artifacts: Sequence[Path] = GOLDEN_ARTIFACTS, *, record_failed_imports: bool = False
) -> CompiledVdtReport:
    """Compile the `vdt-cyclonedx` golden the way the documented command line does."""
    return compile_vdt_report(
        list(artifacts), options=golden_options(), record_failed_imports=record_failed_imports
    )


def compile_cyclonedx_historical_golden(
    artifacts: Sequence[Path] = GOLDEN_ARTIFACTS, *, record_failed_imports: bool = False
) -> CompiledHistoricalReport:
    """Compile `historical-cyclonedx`; the snapshot reads no period, so the options match."""
    return compile_historical_report(
        list(artifacts), options=golden_options(), record_failed_imports=record_failed_imports
    )


def golden_bytes(name: str) -> tuple[bytes, bytes]:
    return (GOLDEN / f"{name}.json").read_bytes(), (GOLDEN / f"{name}.md").read_bytes()


def rendered(report: CompiledVdtReport | CompiledHistoricalReport) -> tuple[bytes, bytes]:
    return report.to_json().encode("utf-8"), report.to_markdown().encode("utf-8")


class CycloneDxGoldenTests(unittest.TestCase):
    """The CycloneDX goldens are the stateless compile of the grype and trivy fixtures.

    `tests/golden/vdt-cyclonedx.{json,md}` and `historical-cyclonedx.{json,md}` were generated
    through the command line with the options `golden_options` names (the historical command
    takes no period); the compiler reproduces them here, whatever order the files arrive in.
    """

    @classmethod
    def setUpClass(cls) -> None:
        cls.vdt = compile_cyclonedx_golden()
        cls.historical = compile_cyclonedx_historical_golden()

    def test_the_vdt_golden_is_reproduced_byte_for_byte(self) -> None:
        self.assertEqual(rendered(self.vdt), golden_bytes("vdt-cyclonedx"))

    def test_the_historical_golden_is_reproduced_byte_for_byte(self) -> None:
        self.assertEqual(rendered(self.historical), golden_bytes("historical-cyclonedx"))

    def test_every_order_of_the_two_fixtures_yields_the_golden_bytes(self) -> None:
        for order in permutations(GOLDEN_ARTIFACTS):
            with self.subTest(order=[path.name for path in order]):
                self.assertEqual(
                    rendered(compile_cyclonedx_golden(order)), golden_bytes("vdt-cyclonedx")
                )
                self.assertEqual(
                    rendered(compile_cyclonedx_historical_golden(order)),
                    golden_bytes("historical-cyclonedx"),
                )

    def test_the_flag_without_a_failure_changes_no_byte(self) -> None:
        self.assertEqual(
            rendered(compile_cyclonedx_golden(record_failed_imports=True)),
            golden_bytes("vdt-cyclonedx"),
        )
        self.assertEqual(
            rendered(compile_cyclonedx_historical_golden(record_failed_imports=True)),
            golden_bytes("historical-cyclonedx"),
        )

    def test_both_goldens_validate_against_the_official_schemas(self) -> None:
        for report in (self.vdt, self.historical):
            with self.subTest(report=type(report).__name__):
                self.assertTrue(report.validation.is_valid)
                self.assertEqual(report.validation.issues, ())

    def test_the_goldens_attribute_the_cyclonedx_parser_and_its_two_inputs(self) -> None:
        for report in (self.vdt, self.historical):
            extension = report.document["x-complyroll"]
            with self.subTest(report=type(report).__name__):
                self.assertEqual(
                    extension["parserVersions"], {"complyroll.cyclonedx": CYCLONEDX_PARSER_VERSION}
                )
                self.assertEqual(
                    {item["name"]: item["observationCount"] for item in extension["artifacts"]},
                    GOLDEN_OBSERVATION_COUNTS,
                )
                self.assertEqual(
                    {item["parser"] for item in extension["artifacts"]}, {"complyroll.cyclonedx"}
                )

    def test_every_case_is_one_cve_from_one_tool_detected_at_the_document_clock(self) -> None:
        found = {
            item["providerTrackingId"]: (
                item["vulnerabilityDescription"].split(":")[0],
                item["detection"]["detectionSource"],
                item["detection"]["detectedAt"],
                item["x-complyroll"]["detectedAtSource"],
            )
            for item in self.vdt.document["vulnerabilities"]
        }
        self.assertEqual(list(found), list(GOLDEN_TRACKING_IDS))
        self.assertEqual(
            found,
            {
                tracking_id: (record_id, tool, GOLDEN_DETECTED_AT, "artifact")
                for tracking_id, (record_id, tool) in GOLDEN_CASES.items()
            },
        )
        self.assertIsNone(self.vdt.document["x-complyroll"]["detectionTimeAttestation"])

    def test_the_historical_snapshot_lists_the_same_cases(self) -> None:
        active = self.historical.document["activeVulnerabilities"]
        self.assertEqual([item["providerTrackingId"] for item in active], list(GOLDEN_TRACKING_IDS))
        self.assertEqual(self.historical.document["acceptedVulnerabilities"], [])

    def test_only_package_resources_are_reported_and_no_scope_observation(self) -> None:
        scopes = {
            item.observation_id
            for path in GOLDEN_ARTIFACTS
            for item in fixture_result(path).observations
            if item.source_record_id == "cyclonedx.bom"
        }
        self.assertEqual(len(scopes), 2)
        for item in self.vdt.document["vulnerabilities"]:
            extension = item["x-complyroll"]
            with self.subTest(case=item["providerTrackingId"]):
                self.assertEqual(
                    {resource["resourceType"] for resource in extension["resources"]}, {"package"}
                )
                self.assertEqual(set(extension["observationIds"]) & scopes, set())

    def test_the_two_member_case_lists_its_members_in_resource_order(self) -> None:
        # Resource order is not observation id order here, so a member order keyed on the
        # fingerprint, or on the order the file listed them, would show in both lists.
        (case,) = [
            item
            for item in self.vdt.document["vulnerabilities"]
            if item["providerTrackingId"] == TWO_MEMBER_CASE
        ]
        extension = case["x-complyroll"]
        resources = [item["resourceId"] for item in extension["resources"]]
        lineage = "image:registry.example.test/api|"
        self.assertEqual(
            resources,
            [
                lineage + "pkg:rpm/centos/openssl-libs?arch=x86_64",
                lineage + "pkg:rpm/centos/openssl?arch=x86_64",
            ],
        )
        by_resource = {
            item.resource.resource_id: item.observation_id
            for item in by_record(fixture_result(TRIVY_IMAGE), "CVE-2023-0286")
        }
        self.assertEqual(
            extension["observationIds"], [by_resource[resource] for resource in resources]
        )
        self.assertNotEqual(extension["observationIds"], sorted(extension["observationIds"]))


# *--- Step 5: Path Equivalence ---*


class CycloneDxPathEquivalenceTests(StoreFixture):
    """The persisted path over the grype and trivy fixtures reports the golden bytes.

    The adapter emits `observation.recorded` v1 on the existing artifact stream (plan section
    17), so ingest, correlation and replay reach the stateless bytes with no attestation.
    """

    def record(self, repository: EventRepository, paths: Sequence[Path]) -> None:
        for path in paths:
            record_ingest(
                repository,
                ingest_stig_artifact(path, ingested_at=GOLDEN_INGESTED_AT),
                metadata=self.metadata,
                ingested_at=GOLDEN_INGESTED_AT,
            )
        correlate_cases(repository, metadata=self.metadata, now=GOLDEN_INGESTED_AT)

    def test_history_reports_match_the_stateless_reports_and_the_goldens(self) -> None:
        self.record(self.repository, GOLDEN_ARTIFACTS)
        vdt = compile_vdt_report_from_history(self.repository, options=golden_options())
        historical = compile_historical_report_from_history(
            self.repository, options=golden_options()
        )
        self.assertEqual(rendered(vdt), golden_bytes("vdt-cyclonedx"))
        self.assertEqual(rendered(historical), golden_bytes("historical-cyclonedx"))
        pairs = (
            (vdt, compile_cyclonedx_golden()),
            (
                compile_avi_report_from_history(self.repository, options=golden_options()),
                compile_avi_report(list(GOLDEN_ARTIFACTS), options=golden_options()),
            ),
            (historical, compile_cyclonedx_historical_golden()),
        )
        for persisted, stateless in pairs:
            with self.subTest(report=type(persisted).__name__):
                self.assertTrue(persisted.validation.is_valid)
                self.assertEqual(persisted.to_json(), stateless.to_json())
                self.assertEqual(persisted.to_markdown(), stateless.to_markdown())

    def test_every_ingest_order_reports_the_golden_bytes_from_history(self) -> None:
        for order in permutations(GOLDEN_ARTIFACTS):
            with self.subTest(order=[path.name for path in order]):
                repository = self.open_repository(self.fresh_workspace())
                self.record(repository, order)
                self.assertEqual(
                    rendered(compile_vdt_report_from_history(repository, options=golden_options())),
                    golden_bytes("vdt-cyclonedx"),
                )
                self.assertEqual(
                    rendered(
                        compile_historical_report_from_history(repository, options=golden_options())
                    ),
                    golden_bytes("historical-cyclonedx"),
                )

    def test_replay_reads_back_every_observation_byte_for_byte(self) -> None:
        self.record(self.repository, GOLDEN_ARTIFACTS)
        expected = sorted(
            item.to_canonical_json()
            for path in GOLDEN_ARTIFACTS
            for item in ingest_stig_artifact(path, ingested_at=GOLDEN_INGESTED_AT).observations
        )
        replayed = sorted(
            item.to_canonical_json() for item in rehydrate_observations(self.repository)
        )
        self.assertEqual(len(expected), sum(GOLDEN_OBSERVATION_COUNTS.values()))
        self.assertEqual(replayed, expected)
        self.assertEqual(audit_history(self.repository), ())
        self.assertEqual(
            {record.event_type for record in self.repository.read_all()} & {"observation.recorded"},
            {"observation.recorded"},
        )
        for record in self.repository.read_all():
            if record.event_type == "observation.recorded":
                with self.subTest(observation=record.payload["observation_id"]):
                    self.assertEqual(record.event_version, 1)

    def test_reingesting_the_same_bytes_records_nothing_new(self) -> None:
        self.record(self.repository, GOLDEN_ARTIFACTS)
        before = len(self.repository.read_all())
        self.record(self.repository, GOLDEN_ARTIFACTS)
        self.assertEqual(len(self.repository.read_all()), before)
        vdt = compile_vdt_report_from_history(self.repository, options=golden_options())
        self.assertEqual(rendered(vdt), golden_bytes("vdt-cyclonedx"))


class CycloneDxSupersessionTests(StoreFixture):
    """A parser-version smoke test: the newest reading of the same bytes is the one reported.

    PR #32 made `record_ingest` refuse to resume a stream whose head declared another
    observation count, so a reading that changed under the same version is refused, and only
    a new parser version opens the new stream that supersedes the old one.
    """

    def first_reading(self) -> IngestResult:
        result = ingest_stig_artifact(GRYPE_IMAGE, ingested_at=GOLDEN_INGESTED_AT)
        record_ingest(
            self.repository, result, metadata=self.metadata, ingested_at=GOLDEN_INGESTED_AT
        )
        return result

    def test_a_later_parser_version_supersedes_the_reading_and_is_named(self) -> None:
        first = self.first_reading()
        second = bumped(first, "2")
        record_ingest(
            self.repository, second, metadata=self.metadata, ingested_at=GOLDEN_INGESTED_AT
        )
        correlate_cases(self.repository, metadata=self.metadata, now=GOLDEN_INGESTED_AT)

        report = compile_vdt_report_from_history(self.repository, options=golden_options())
        extension = report.document["x-complyroll"]
        superseded = [item for item in report.diagnostics if item.code == "artifact_superseded"]
        reported = {
            observation_id
            for item in report.document["vulnerabilities"]
            for observation_id in item["x-complyroll"]["observationIds"]
        }

        self.assertEqual(extension["parserVersions"], {"complyroll.cyclonedx": "2"})
        self.assertEqual(
            [(item["name"], item["parserVersion"]) for item in extension["artifacts"]],
            [(GRYPE_IMAGE.name, "2")],
        )
        self.assertEqual(len(superseded), 1)
        self.assertIn("complyroll.cyclonedx 1", superseded[0].message)
        self.assertIn("complyroll.cyclonedx 2", superseded[0].message)
        self.assertEqual(len(report.document["vulnerabilities"]), 4)
        self.assertEqual(reported & {item.observation_id for item in first.observations}, set())
        self.assertLessEqual(reported, {item.observation_id for item in second.observations})
        self.assertEqual(audit_history(self.repository), ())

    def test_a_changed_reading_under_the_same_version_is_refused(self) -> None:
        first = self.first_reading()
        before = len(self.repository.read_all())
        shorter = dataclasses.replace(first, observations=first.observations[:-1])

        with self.assertRaisesRegex(HistoryError, "another observation count"):
            record_ingest(
                self.repository, shorter, metadata=self.metadata, ingested_at=GOLDEN_INGESTED_AT
            )
        self.assertEqual(len(self.repository.read_all()), before)


class CycloneDxCrossImageMemberOrderTests(StoreFixture):
    """One grype match of two images: a case's members follow the resource, not the file.

    The goldens' one two-member case comes from a single file, so it cannot tell a member
    order keyed on the artifact name from one keyed on the resource. Here a copy of the grype
    fixture names another image, `registry.example.test/zzz`, and is called
    `a-grype.cdx.json`, so its name sorts first while its packages sort last; every shared
    CVE is one case of two members (one case per CVE per tool).
    """

    OTHER_IMAGE = "registry.example.test/zzz"

    def setUp(self) -> None:
        super().setUp()
        document = json.loads(GRYPE_IMAGE.read_text(encoding="utf-8"))
        document["metadata"]["component"]["name"] = self.OTHER_IMAGE
        self.other = self.workspace / "a-grype.cdx.json"
        self.other.write_text(json.dumps(document), encoding="utf-8")
        self.paths = (GRYPE_IMAGE, self.other)

    def assert_members_follow_the_resource(self, report: CompiledVdtReport) -> None:
        cases = report.document["vulnerabilities"]
        self.assertEqual(len(cases), 4)
        flipped = 0
        for case in cases:
            extension = case["x-complyroll"]
            with self.subTest(case=case["providerTrackingId"]):
                resources = [item["resourceId"] for item in extension["resources"]]
                self.assertEqual(len(resources), 2)
                self.assertTrue(resources[0].startswith("image:registry.example.test/api|"))
                self.assertTrue(resources[1].startswith(f"image:{self.OTHER_IMAGE}|"))
                flipped += extension["observationIds"] != sorted(extension["observationIds"])
        # At least one case orders its fingerprints against the resource order.
        self.assertGreater(flipped, 0)

    def test_every_input_order_lists_the_members_in_resource_order(self) -> None:
        reports = [
            compile_vdt_report(list(order), options=golden_options())
            for order in permutations(self.paths)
        ]
        for report in reports:
            self.assert_members_follow_the_resource(report)
            self.assertEqual(report.to_json(), reports[0].to_json())
            self.assertEqual(report.to_markdown(), reports[0].to_markdown())

    def test_every_ingest_order_replays_the_stateless_bytes(self) -> None:
        stateless = compile_vdt_report(list(self.paths), options=golden_options())
        for order in permutations(self.paths):
            with self.subTest(order=[path.name for path in order]):
                repository = self.open_repository(self.fresh_workspace())
                for path in order:
                    record_ingest(
                        repository,
                        ingest_stig_artifact(path, ingested_at=GOLDEN_INGESTED_AT),
                        metadata=self.metadata,
                        ingested_at=GOLDEN_INGESTED_AT,
                    )
                correlate_cases(repository, metadata=self.metadata, now=GOLDEN_INGESTED_AT)
                persisted = compile_vdt_report_from_history(repository, options=golden_options())
                self.assert_members_follow_the_resource(persisted)
                self.assertEqual(persisted.to_json(), stateless.to_json())
                self.assertEqual(persisted.to_markdown(), stateless.to_markdown())


# *--- Audit Fixes (FX) ---*


def judged(state: object) -> dict[str, Any]:
    """Build a vulnerability on lodash whose analysis carries the given state."""
    return vuln(analysis={"state": state})


class SubjectRefScopeTests(unittest.TestCase):
    """FX F2: a ref resolving to metadata.component never counts toward K3 PASS."""

    def test_a_subject_only_document_is_not_reviewed(self) -> None:
        # The audit's reproduction: the only ref names the subject.
        output = run(k3([dict(LODASH)], [vuln(refs=("subject",))]))
        self.assertEqual(resource(finding(output)), SCOPE)
        self.assertIs(finding(output).disposition, ObservationDisposition.OPEN)
        self.assertIs(scope(output).disposition, ObservationDisposition.NOT_REVIEWED)
        self.assertIn("match_unverified", level_codes(output, "warning"))

    def test_a_same_document_bom_link_to_the_subject_is_not_reviewed(self) -> None:
        link = f"urn:cdx:{SERIAL}/1#subject"
        output = run(k3([dict(LODASH)], [vuln(refs=(link,))]))
        self.assertEqual(resource(finding(output)), SCOPE)
        self.assertNotIn("affects_unresolved", level_codes(output, "warning"))
        self.assertIs(scope(output).disposition, ObservationDisposition.NOT_REVIEWED)

    def test_a_listed_component_ref_beside_a_subject_ref_passes(self) -> None:
        output = run(k3([dict(LODASH)], [vuln(refs=("subject", "lodash-ref"))]))
        self.assertIs(scope(output).disposition, ObservationDisposition.PASS)
        self.assertNotIn("match_unverified", level_codes(output, "warning"))


class AnalysisStateScopeTests(unittest.TestCase):
    """FX F3 (Kyle 2026-10-19): a supplier judgment never shows that a match ran."""

    def test_judgment_states_never_verify_and_still_mint(self) -> None:
        for state in ("not_affected", "false_positive", "resolved", "resolved_with_pedigree"):
            with self.subTest(state=state):
                output = run(k3([dict(LODASH)], [judged(state)]))
                observation = finding(output)
                self.assertEqual(resource(observation), ("package", PKG + "pkg:npm/lodash"))
                self.assertIs(observation.disposition, ObservationDisposition.OPEN)
                self.assertIs(scope(output).disposition, ObservationDisposition.NOT_REVIEWED)
                self.assertIn("match_unverified", level_codes(output, "warning"))

    def test_an_out_of_enum_or_non_string_state_fails_closed(self) -> None:
        for state in ("maybe_affected", "EXPLOITABLE", 7, None, ["exploitable"]):
            with self.subTest(state=state):
                output = run(k3([dict(LODASH)], [judged(state)]))
                self.assertIs(finding(output).disposition, ObservationDisposition.OPEN)
                self.assertIs(scope(output).disposition, ObservationDisposition.NOT_REVIEWED)

    def test_no_state_exploitable_and_in_triage_verify(self) -> None:
        for record in (
            vuln(),
            vuln(analysis={}),
            judged("exploitable"),
            judged("in_triage"),
        ):
            with self.subTest(record=record):
                output = run(k3([dict(LODASH)], [record]))
                self.assertIs(scope(output).disposition, ObservationDisposition.PASS)

    def test_one_unjudged_resolved_record_is_enough(self) -> None:
        records = [judged("not_affected"), vuln("CVE-2026-0002")]
        output = run(k3([dict(LODASH)], records))
        self.assertIs(scope(output).disposition, ObservationDisposition.PASS)


class UnmatchedWordingTests(unittest.TestCase):
    """FX E2: the unmatched text names judged and subject-only records, never overstating."""

    MESSAGE = (
        "no unjudged vulnerability record resolves to a component this document lists besides "
        "its subject; the document does not show that a match ran"
    )
    DESCRIPTION = (
        "This document carries no unjudged vulnerability record tied to a component it lists "
        "besides its subject; it does not show that a match ran and verifies no coverage clock."
    )

    def test_every_unmatched_shape_carries_the_text(self) -> None:
        shapes = {
            "empty": k3([dict(LODASH)], []),
            "subject only": k3([dict(LODASH)], [vuln(refs=("subject",))]),
            "judged": k3([dict(LODASH)], [judged("not_affected")]),
        }
        for name, document in shapes.items():
            with self.subTest(name):
                output = run(document)
                (diagnostic,) = [
                    item for item in output.diagnostics if item.code == "match_unverified"
                ]
                self.assertTrue(diagnostic.message.startswith(self.MESSAGE), diagnostic.message)
                self.assertEqual(UNMATCHED_DESCRIPTION, self.DESCRIPTION)
                self.assertEqual(scope(output).description, self.DESCRIPTION)


class CarrierOrderBoundTests(unittest.TestCase):
    """FX F4: a candidate's order is built from bounded facts, never an uncapped purl."""

    PURL = "pkg:npm/lodash@4.17.20?download_url=" + "x" * (1 << 18)

    def test_a_carrier_token_is_bounded_whatever_the_purl(self) -> None:
        carrier = _carrier({"name": "lodash", "purl": self.PURL}, "pkg:npm/lodash", False, "r")
        longer = {"name": "lodash", "purl": self.PURL + "y"}
        self.assertLessEqual(len(carrier.token), MAX_LIST_ITEM_CHARS + 65)
        self.assertNotEqual(carrier.token, _carrier(longer, "pkg:npm/lodash", False, "r").token)

    def test_memory_does_not_scale_with_purl_size_times_affects(self) -> None:
        # The audit's shape at a quarter of its size: before the fix every one of the 256
        # candidates held the whole purl in its order, 64 MiB; now well under 8 purls' worth.
        component = {**LODASH, "purl": self.PURL}
        document = k3([component], [vuln(refs=("lodash-ref",) * 256)])
        tracemalloc.start()
        try:
            output = run(document)
            peak = tracemalloc.get_traced_memory()[1]
        finally:
            tracemalloc.stop()
        self.assertEqual(md(finding(output))["occurrence_count"], "256")
        self.assertLess(peak, 8 * len(self.PURL))

    def test_carriers_tied_on_the_token_prefix_order_by_content(self) -> None:
        # Two installs whose reprs agree past the prefix cap: the digest still decides, so the
        # same carrier leads the fold whatever the affects order.
        refs = ("a" * 300 + "1", "a" * 300 + "2")
        components = [{**LODASH, "bom-ref": ref} for ref in refs]
        winners = set()
        for order in (refs, refs[::-1]):
            output = run(k3(components, [vuln(refs=order)]))
            (message,) = [
                item.message
                for item in output.diagnostics
                if item.code == "package_instances_folded"
            ]
            winners.add(order[0 if "affects[0]" in message else 1])
        self.assertEqual(len(winners), 1)


class DigestNamedSubjectTests(unittest.TestCase):
    """FX F5(b): a subject name that is wholly a digest keeps itself as its lineage."""

    def test_a_digest_name_is_its_own_lineage(self) -> None:
        for name in (SHA256, SHA512):
            with self.subTest(name=name):
                self.assertEqual(subject_lineage("image", name), name)

    def test_two_digest_named_subjects_keep_apart(self) -> None:
        other = "sha256:" + "f" * 64
        self.assertNotEqual(subject_lineage("image", SHA256), subject_lineage("image", other))

    def test_a_digest_named_container_scopes_its_packages_by_the_digest(self) -> None:
        document = k3([dict(LODASH)], [vuln()])
        document["metadata"]["component"] = {**SUBJECT, "name": SHA256}
        observation = finding(run(document))
        self.assertEqual(resource(observation), ("package", f"image:{SHA256}|pkg:npm/lodash"))


class DockerRepositoryUrlTests(unittest.TestCase):
    """FX F6 (Kyle 2026-10-19): pkg:docker keeps repository_url, as oci does (A16)."""

    BASE = "pkg:docker/library/nginx@1.25"

    def test_two_registries_are_two_keys(self) -> None:
        first = key(self.BASE + "?repository_url=docker.io")
        second = key(self.BASE + "?repository_url=registry.example.test")
        self.assertEqual(first, "pkg:docker/library/nginx?repository_url=docker.io")
        self.assertNotEqual(first, second)

    def test_other_docker_qualifiers_behave_as_before(self) -> None:
        self.assertEqual(
            key(self.BASE + "?arch=amd64&download_url=https://x.test&tag=t&checksum=c"),
            "pkg:docker/library/nginx?arch=amd64&tag=t",
        )
        self.assertEqual(key(self.BASE), "pkg:docker/library/nginx")
        self.assertIn("repository_url", PURL_STRIPPED_QUALIFIERS)

    def test_other_types_still_strip_repository_url(self) -> None:
        self.assertEqual(key("pkg:npm/lodash@1?repository_url=r.test"), "pkg:npm/lodash")


class ScopeObservationCapTests(unittest.TestCase):
    """FX F12: max_observations_per_artifact counts the scope observation."""

    def limited(self, count: int) -> Any:
        return dataclasses.replace(DEFAULT_LIMITS, max_observations_per_artifact=count)

    def test_k3_counts_the_scope(self) -> None:
        with self.assertRaises(InputLimitError):
            run(k3([dict(LODASH)], [vuln()]), self.limited(1))
        self.assertEqual(len(run(k3([dict(LODASH)], [vuln()]), self.limited(2)).observations), 2)

    def test_k1_and_k2_count_the_scope(self) -> None:
        inventory = k3([dict(LODASH)], [])
        del inventory["vulnerabilities"]
        for document in (inventory, k3([dict(LODASH)], [])):
            with self.subTest(kind="vulnerabilities" in document):
                with self.assertRaises(InputLimitError):
                    run(document, self.limited(0))
                self.assertEqual(len(run(document, self.limited(1)).observations), 1)

    def test_a_superseded_scope_is_not_counted_twice(self) -> None:
        output = run(k3([dict(LODASH)], [{"id": "cyclonedx.bom"}]), self.limited(1))
        self.assertEqual(len(output.observations), 1)
        self.assertIn("scope_superseded", level_codes(output, "info"))


# *--- Second Audit Fixes (FX2) ---*


def unaffected(version: str = "4.17.20", status: str = "unaffected") -> dict[str, Any]:
    """Build a vulnerability on lodash whose affects entry states one version's status."""
    entry = {"ref": "lodash-ref", "versions": [{"version": version, "status": status}]}
    return {"id": "CVE-2026-0001", "affects": [entry]}


class UnaffectedVersionScopeTests(unittest.TestCase):
    """FX2 CL-1: an entry marking the installed version unaffected never counts toward PASS."""

    def test_an_unaffected_install_is_not_reviewed_and_still_mints(self) -> None:
        # The audit's reproduction: no analysis, the installed version marked unaffected.
        output = run(k3([dict(LODASH)], [unaffected()]))
        self.assertEqual(resource(finding(output)), ("package", PKG + "pkg:npm/lodash"))
        self.assertIs(finding(output).disposition, ObservationDisposition.OPEN)
        self.assertIs(scope(output).disposition, ObservationDisposition.NOT_REVIEWED)
        warnings = level_codes(output, "warning")
        self.assertIn("affects_version_unaffected", warnings)
        self.assertIn("match_unverified", warnings)

    def test_an_affected_install_or_another_version_unaffected_passes(self) -> None:
        for record in (unaffected(status="affected"), unaffected("4.17.21")):
            with self.subTest(record=record):
                output = run(k3([dict(LODASH)], [record]))
                self.assertIs(scope(output).disposition, ObservationDisposition.PASS)

    def test_one_install_of_a_shared_ref_marked_unaffected_withholds_it(self) -> None:
        other = {**LODASH, "version": "4.17.21", "purl": "pkg:npm/lodash@4.17.21"}
        output = run(k3([dict(LODASH), other], [unaffected()]))
        self.assertIs(scope(output).disposition, ObservationDisposition.NOT_REVIEWED)

    def test_another_unjudged_record_still_passes(self) -> None:
        output = run(k3([dict(LODASH)], [unaffected(), vuln("CVE-2026-0002")]))
        self.assertIs(scope(output).disposition, ObservationDisposition.PASS)


class JustificationScopeTests(unittest.TestCase):
    """FX2 CL-2: a justification with no unjudged state is a judgment; a response is not."""

    def test_a_justification_without_a_state_is_not_reviewed(self) -> None:
        for analysis in (
            {"justification": "code_not_present"},
            {"justification": "code_not_present", "response": ["will_not_fix"]},
            {"justification": None},
        ):
            with self.subTest(analysis=analysis):
                output = run(k3([dict(LODASH)], [vuln(analysis=analysis)]))
                self.assertIs(finding(output).disposition, ObservationDisposition.OPEN)
                self.assertIs(scope(output).disposition, ObservationDisposition.NOT_REVIEWED)
                self.assertIn("match_unverified", level_codes(output, "warning"))

    def test_a_response_alone_or_a_match_state_with_a_justification_passes(self) -> None:
        for analysis in (
            {"response": ["will_not_fix"]},
            {"state": "in_triage", "justification": "code_not_present"},
            {"state": "exploitable", "justification": "requires_environment"},
        ):
            with self.subTest(analysis=analysis):
                output = run(k3([dict(LODASH)], [vuln(analysis=analysis)]))
                self.assertIs(scope(output).disposition, ObservationDisposition.PASS)


class SharedRefMemoryTests(unittest.TestCase):
    """FX2 CL-4: memory never grows with components sharing a bom-ref times entries naming it."""

    def test_memory_does_not_scale_with_carriers_times_affects(self) -> None:
        # The audit's amp.py shape at a twentieth of its size: before the fix every one of the
        # 256 candidates held a JSON string of all 1000 carriers' tokens in its order.
        components = [
            {
                "type": "library",
                "name": "lodash",
                "version": f"4.17.{index}",
                "purl": f"pkg:npm/lodash@4.17.{index}",
                "bom-ref": "r",
            }
            for index in range(1000)
        ]
        tokens = sorted(
            _carrier(component, "pkg:npm/lodash", False, "r").token for component in components
        )
        once = len(json.dumps(tokens))
        document = k3(components, [vuln(refs=("r",) * 256)])
        tracemalloc.start()
        try:
            output = run(document)
            peak = tracemalloc.get_traced_memory()[1]
        finally:
            tracemalloc.stop()
        self.assertEqual(md(finding(output))["occurrence_count"], "256")
        self.assertIs(scope(output).disposition, ObservationDisposition.PASS)
        self.assertLess(peak, 32 * once)

    def test_the_fold_is_the_same_whatever_the_order_of_shared_refs(self) -> None:
        components = [
            {**LODASH, "version": f"4.17.{index}", "bom-ref": ref}
            for index, ref in enumerate(("a", "a", "b"))
        ]
        records = [vuln(refs=("a", "b", "a")), vuln(refs=("b", "a", "a"))]
        outputs = {repr(run(k3(components, [record])).observations) for record in records}
        self.assertEqual(len(outputs), 1)


class InventoryIdentityRefusalTests(unittest.TestCase):
    """FX2 CL-5: every K1 and K2 identity refusal is a format refusal (A12); K3 keeps CONTENT."""

    SHAPES: tuple[tuple[dict[str, Any], str], ...] = (
        ({"tools": [{"name": "sy\u0000ft"}]}, "tool name contains prohibited code point U+0000"),
        (
            {"tools": [{"name": "a" * 300}, {"name": "b" * 300}]},
            "tool is 601 characters; maximum is 512",
        ),
        (
            {"component": {"type": "container", "name": "x" * 600}},
            "scope id is 600 characters; maximum is 512",
        ),
    )

    def test_each_is_a_format_refusal_as_k1_and_k2(self) -> None:
        for metadata, check in self.SHAPES:
            for extra in ({}, {"vulnerabilities": []}):
                with self.subTest(check=check, k2=bool(extra)):
                    result = ingest(bom(metadata=metadata, **extra))
                    self.assertEqual(
                        [item.code for item in result.errors], ["artifact_parse_failed"]
                    )
                    self.assertEqual(result.errors[0].message, IDENTITY + check)
                    classification = classify_ingest(result)
                    assert classification is not None
                    self.assertIs(classification.reason, UnmintableReason.FORMAT_REJECTED)

    def test_k3_identity_refusals_stay_content(self) -> None:
        for metadata, check in self.SHAPES:
            with self.subTest(check=check):
                document = k3([dict(LODASH)], [vuln()])
                document["metadata"].update(metadata)
                output = run(document)
                self.assertEqual(level_codes(output, "error"), ["identity_input_invalid"])
                self.assertEqual(output.observations, ())


class AnyAlgorithmDigestNameTests(unittest.TestCase):
    """FX2 CX-1, FX3 XV-1: a name wholly <alg>:<hex> of a named algorithm keeps itself."""

    NAMES = (
        "md5:" + "0f" * 16,
        "sha1:" + "f0" * 20,
        "sha224:" + "0a" * 28,
        "sha256:" + "ef" * 32,
        "sha384:" + "ab" * 48,
        "sha512:" + "01" * 64,
        "blake3:" + "cd" * 32,
    )

    def test_any_algorithm_digest_name_is_its_own_lineage(self) -> None:
        for name in self.NAMES:
            with self.subTest(name=name):
                self.assertEqual(subject_lineage("image", name), name)

    def test_two_algorithms_keep_apart(self) -> None:
        lineages = {subject_lineage("image", name) for name in self.NAMES}
        self.assertEqual(len(lineages), len(self.NAMES))

    # The main loop's narrowing: a tag-only name keeps the Y1 lineage, never itself.
    def test_a_tag_only_name_strips_as_a_tag(self) -> None:
        for name, lineage in (
            ("redis:7", "redis"),
            ("app:20261001", "app"),
            ("localhost:5000", "localhost"),
            ("md5:" + "0" * 31, "md5"),
            ("9abc:" + "0" * 64, "9abc"),
            ("blake3:" + "0" * 31, "blake3"),
        ):
            with self.subTest(name=name):
                self.assertEqual(subject_lineage("image", name), lineage)

    def test_the_five_ruled_names(self) -> None:
        for name in ("sha384:" + "ab" * 48, "blake3:" + "cd" * 32):
            with self.subTest(name=name):
                self.assertEqual(subject_lineage("image", name), name)
        for name, lineage in (("redis:7", "redis"), ("app:20261001", "app")):
            with self.subTest(name=name):
                self.assertEqual(subject_lineage("image", name), lineage)
        self.assertEqual(subject_lineage("image", "localhost:5000"), "localhost")

    def test_a_tag_that_is_not_lowercase_hex_still_strips(self) -> None:
        self.assertEqual(subject_lineage("image", "sha384:ABC"), "sha384")
        self.assertEqual(subject_lineage("image", "web:1.4"), "web")
        self.assertEqual(subject_lineage("image", "reg.test/web:cafe"), "reg.test/web")

    def test_rule_3_stays_sha256_and_sha512(self) -> None:
        self.assertFalse(digest_shaped("sha384:abc"))
        subject = {"type": "container", "name": "web", "version": "sha384:abc"}
        self.assertEqual(scope_of(subject)[:2], ("image", "web:sha384:abc"))


class HexTagLineageTests(unittest.TestCase):
    """FX3 XV-1: a hex tag such as a git sha strips as a tag; only named algorithms keep."""

    GIT_SHA = "0123456789abcdef0123456789abcdef01234567"

    def test_a_git_sha_tag_strips_to_the_repository(self) -> None:
        # The audit's reproduction: app:<40 hex> kept itself, so every rebuild re-minted.
        self.assertEqual(subject_lineage("image", "app:" + self.GIT_SHA), "app")
        self.assertEqual(subject_lineage("image", "reg.test/app:" + "f" * 64), "reg.test/app")

    def test_two_builds_tagged_by_git_sha_share_package_resources(self) -> None:
        ids = set()
        for tag in (self.GIT_SHA, self.GIT_SHA[::-1]):
            document = k3([dict(LODASH)], [vuln()])
            document["metadata"]["component"] = {**SUBJECT, "name": "app:" + tag}
            output = run(document)
            self.assertEqual(scope(output).resource.resource_id, "app:" + tag)
            ids.add(resource(finding(output)))
        self.assertEqual(ids, {("package", "image:app|pkg:npm/lodash")})

    def test_each_named_algorithm_keeps_the_whole_name(self) -> None:
        for alg, digits in (
            ("md5", 32),
            ("sha1", 40),
            ("sha224", 56),
            ("sha256", 64),
            ("sha384", 96),
            ("sha512", 128),
            ("blake3", 64),
        ):
            name = f"{alg}:" + "a" * digits
            with self.subTest(alg=alg):
                self.assertEqual(subject_lineage("image", name), name)
                # One digit short or long is not that digest, so it strips as a tag (XV-9).
                for wrong in (digits - 1, digits + 1):
                    self.assertEqual(subject_lineage("image", f"{alg}:" + "a" * wrong), alg)

    def test_a_repository_named_for_an_algorithm_keeps_git_sha_builds_together(self) -> None:
        # The delta audit's reproduction: sha256:<40 hex> kept itself, so every rebuild re-minted.
        ids = set()
        for tag in (self.GIT_SHA, self.GIT_SHA[::-1]):
            document = k3([dict(LODASH)], [vuln()])
            document["metadata"]["component"] = {**SUBJECT, "name": "sha256:" + tag}
            ids.add(resource(finding(run(document))))
        self.assertEqual(ids, {("package", "image:sha256|pkg:npm/lodash")})

    def test_two_sha224_names_keep_apart(self) -> None:
        # The delta audit's reproduction: both stripped to sha224, one package row (XV-8).
        ids = set()
        for digit in "ab":
            document = k3([dict(LODASH)], [vuln()])
            document["metadata"]["component"] = {**SUBJECT, "name": "sha224:" + digit * 56}
            ids.add(resource(finding(run(document))))
        self.assertEqual(len(ids), 2)

    # Recorded in ADR 0016 open risks: an unlisted algorithm strips as a tag, a merge.
    def test_an_unlisted_algorithm_strips_as_a_tag(self) -> None:
        for name, lineage in (("sha3:" + "f" * 64, "sha3"), ("xxh3:" + "0" * 32, "xxh3")):
            with self.subTest(name=name):
                self.assertEqual(subject_lineage("image", name), lineage)

    def test_tag_and_port_names_are_unchanged(self) -> None:
        for name, lineage in (
            ("redis:7", "redis"),
            ("localhost:5000/app:1", "localhost:5000/app"),
            ("localhost:5000/app", "localhost:5000/app"),
        ):
            with self.subTest(name=name):
                self.assertEqual(subject_lineage("image", name), lineage)


class DetailScopeTests(unittest.TestCase):
    """FX3 XV-4: a detail with no unjudged state is a judgment, as a justification is."""

    def test_a_detail_without_a_state_is_not_reviewed(self) -> None:
        # The audit's reproduction: an analysis holding only a supplier's detail verified.
        for analysis in (
            {"detail": "manual supplier assessment"},
            {"detail": "no state", "response": ["update"]},
            {"detail": None},
            {"detail": ""},
        ):
            with self.subTest(analysis=analysis):
                output = run(k3([dict(LODASH)], [vuln(analysis=analysis)]))
                self.assertIs(finding(output).disposition, ObservationDisposition.OPEN)
                self.assertIs(scope(output).disposition, ObservationDisposition.NOT_REVIEWED)
                self.assertIn("match_unverified", level_codes(output, "warning"))
                self.assertEqual(scope(output).description, UNMATCHED_DESCRIPTION)

    def test_a_match_state_with_a_detail_passes(self) -> None:
        for analysis in (
            {"state": "in_triage", "detail": "under review"},
            {"state": "exploitable", "detail": "reachable from the entry point"},
        ):
            with self.subTest(analysis=analysis):
                output = run(k3([dict(LODASH)], [vuln(analysis=analysis)]))
                self.assertIs(scope(output).disposition, ObservationDisposition.PASS)
                self.assertEqual(scope(output).description, MATCHED_DESCRIPTION)

    def test_the_detail_is_still_recorded(self) -> None:
        output = run(k3([dict(LODASH)], [vuln(analysis={"detail": "manual"})]))
        self.assertEqual(json.loads(md(finding(output))["analysis_details"]), ["manual"])


class CarrierCleanOnceTests(unittest.TestCase):
    """FX3 XV-2: a carrier's texts are cleaned once per parse, never once per fold."""

    PURL = "pkg:npm/lodash@4.17.20?download_url=" + "x" * 1_000_000

    def big_cleans(self, count: int) -> int:
        """Parse count distinct vulnerabilities on one 1 MB purl; count sanitize calls on it."""
        component = {**LODASH, "purl": self.PURL}
        records = [vuln(f"CVE-2026-{index:04d}") for index in range(count)]
        with mock.patch.object(common, "sanitize", wraps=common.sanitize) as spy:
            output = run(k3([component], records))
        self.assertEqual(len(output.observations), count + 1)
        self.assertIn("evidence_truncated", level_codes(output, "warning"))
        return sum(1 for call in spy.call_args_list if len(call.args[0]) >= len(self.PURL))

    def test_the_purl_is_cleaned_once_whatever_the_vulnerability_count(self) -> None:
        # The audit's reproduction at N=400: before the fix the purl was sanitized twice per
        # fold, 800 times; it is now cleaned once for the carrier, whatever N is.
        self.assertEqual(self.big_cleans(400), 1)
        self.assertEqual(self.big_cleans(1), 1)

    def test_every_fold_still_reports_the_cut_purl(self) -> None:
        component = {**LODASH, "purl": self.PURL}
        output = run(k3([component], [vuln("CVE-2026-0001"), vuln("CVE-2026-0002")]))
        for record_id in ("CVE-2026-0001", "CVE-2026-0002"):
            with self.subTest(record_id=record_id):
                metadata = md(finding(output, record_id))
                (purl,) = json.loads(metadata["purls"])
                self.assertLessEqual(len(purl), MAX_LIST_ITEM_CHARS)
                self.assertIn("purls", json.loads(metadata["truncated"]))
                (instance,) = json.loads(metadata["instances"])
                self.assertEqual(instance["purl"], purl)
        (diagnostic,) = [item for item in output.diagnostics if item.code == "evidence_truncated"]
        self.assertIn("vulnerabilities[0].affects[0]", diagnostic.message)
        self.assertIn("vulnerabilities[1].affects[0]", diagnostic.message)

    def test_sanitized_and_cut_texts_report_in_raw_text_order(self) -> None:
        # Two installs of one package: one purl only cut, one only sanitized. Cleaning the
        # sorted raw texts reported the sanitized one first, because BEL sorts before "a",
        # while its cleaned text "...=z" sorts after; the joined report must keep raw order.
        long = "pkg:npm/lodash@4.17.20?download_url=" + "a" * 400
        control = "pkg:npm/lodash@4.17.20?download_url=\u0007z"
        for first, second in ((long, control), (control, long)):
            components = [
                {**LODASH, "purl": first, "bom-ref": "one"},
                {**LODASH, "version": "4.17.21", "purl": second, "bom-ref": "two"},
            ]
            output = run(k3(components, [vuln(refs=("one", "two"))]))
            order = [
                item.code
                for item in output.diagnostics
                if item.code in ("evidence_sanitized", "evidence_truncated")
            ]
            with self.subTest(first=first[:40]):
                self.assertEqual(order, ["evidence_sanitized", "evidence_truncated"])
