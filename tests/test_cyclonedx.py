# ******************************************************************************
# *Title: CycloneDX Adapter Tests*
# *Author: Kyle Versluis*
# *Description: Unit tests for the CycloneDX SBOM adapter (ADR 0016).*
# ******************************************************************************
"""Unit tests for the CycloneDX adapter: the frozen package key and the subject lineage."""

# *--- Imports ---*

from __future__ import annotations

import hashlib
import json
import random
import tempfile
import unittest
from datetime import UTC, datetime, timedelta, timezone
from pathlib import Path
from typing import Any

from complyroll.adapters import (
    FailureClass,
    IngestResult,
    UnmintableReason,
    classify_ingest,
    ingest_stig_artifact,
)
from complyroll.adapters.base import ArtifactProvenance, ParsedDocument
from complyroll.adapters.common import MAX_IDENTITY_CHARS, MAX_OBSERVATION_JSON_BYTES
from complyroll.adapters.cyclonedx import (
    CYCLONEDX_MEDIA_TYPE,
    CYCLONEDX_METADATA_KEYS,
    CYCLONEDX_PARSER_VERSION,
    CYCLONEDX_SOURCE_TYPE,
    PURL_CASE_FOLDS,
    PURL_DASHED_NAME_TYPES,
    CycloneDxAdapter,
    ascii_fold,
    digest_shaped,
    package_key,
    package_resource_id,
    purl_key,
    ref_key,
    split_package_resource_id,
    subject_lineage,
)
from complyroll.models import Observation

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

    def test_an_over_long_tool_is_identity_input_invalid(self) -> None:
        result = ingest(bom(metadata={"tools": [{"name": "t" * 513}]}))
        self.assertEqual([item.code for item in result.errors], ["identity_input_invalid"])

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

    def test_an_over_long_composed_id_is_identity_input_invalid(self) -> None:
        subject = {"type": "container", "name": "w" * 500, "version": "v" * 20}
        result = ingest(bom(metadata={"component": subject}))
        self.assertEqual(result.observations, ())
        self.assertEqual([item.code for item in result.errors], ["identity_input_invalid"])

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
