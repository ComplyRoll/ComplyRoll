# ******************************************************************************
# *Title: CycloneDX Adapter*
# *Author: Kyle Versluis*
# *Description: CycloneDX SBOM package key, subject lineage and resource id.*
# ******************************************************************************
"""CycloneDX SBOM source adapter (ADR 0016)."""

# *--- Imports ---*

from __future__ import annotations

import re
import string
from collections.abc import Mapping
from types import MappingProxyType
from typing import Any

from .common import MAX_IDENTITY_CHARS, identity_problem

# *--- Configuration ---*

# WARN: The package key is an identity input frozen at parser version 1 (ADR 0016). Changing
# any table or rule in this section re-mints every affected package resource.

# Each type maps to (fold the namespace, fold the name), read from the fetched purl type
# definitions: a segment folds exactly when its case_sensitive flag is false (Decision E, A6).
# A true flag, no flag, a prohibited namespace and an unlisted type are all verbatim. golang
# and nuget notes contradict their true flags; verbatim is deliberate (A23).
PURL_CASE_FOLDS: Mapping[str, tuple[bool, bool]] = MappingProxyType(
    {
        "alpm": (True, True),
        "apk": (True, True),
        "bitbucket": (True, True),
        "composer": (True, True),
        "deb": (True, True),
        "github": (True, True),
        "hex": (True, True),
        "oci": (False, True),
        "pypi": (False, True),
        "rpm": (True, False),
        "golang": (False, False),
        "huggingface": (False, False),
        "maven": (False, False),
        "npm": (False, False),
        "swift": (False, False),
        "cargo": (False, False),
        "cocoapods": (False, False),
        "nuget": (False, False),
        "conan": (False, False),
        "docker": (False, False),
        "generic": (False, False),
        "conda": (False, False),
        "gem": (False, False),
        "mlflow": (False, False),
    }
)
# pypi also replaces _ with - in the name. Its dot rule is about distribution file names.
PURL_DASHED_NAME_TYPES = frozenset({"pypi"})
# A qualifier equal to its type's default_value, compared as decoded text, is dropped.
PURL_DEFAULT_QUALIFIERS: Mapping[str, Mapping[str, str]] = MappingProxyType(
    {
        "gem": MappingProxyType({"platform": "ruby"}),
        "maven": MappingProxyType({"type": "jar"}),
    }
)
# Version-like, location and provenance qualifiers never split a package (Decision C).
# NOTE: upstream joined the set on 2026-10-19 (step 1 build note): syft writes it as
# <source>@<version> on deb and as the source RPM file name on rpm, so keeping it re-minted
# a package resource on every upgrade.
PURL_STRIPPED_QUALIFIERS = frozenset(
    {
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
    }
)
# A tag is a mutable name for one oci artifact; the repository tells same-named images apart.
OCI_STRIPPED_QUALIFIERS = (PURL_STRIPPED_QUALIFIERS - {"repository_url"}) | {"tag"}

PKG_KEY_PREFIX = "pkg:"
COMPONENT_KEY_PREFIX = "component:"
REF_KEY_PREFIX = "ref:"
IMAGE_SCOPE_TYPE = "image"

_ALPHANUMERIC = (string.ascii_letters + string.digits).encode("ascii")
# Clause 5.4: alphanumerics, .-_~ and the colon are never percent-encoded in a purl.
_PURL_SAFE = frozenset(_ALPHANUMERIC + b".-_~:")
# RFC 3986 unreserved characters, for the component: and ref: forms.
_UNRESERVED = frozenset(_ALPHANUMERIC + b"-._~")
_HEX_DIGITS = frozenset(string.hexdigits)
_ASCII_FOLD = str.maketrans(string.ascii_uppercase, string.ascii_lowercase)
_PURL_TYPE = re.compile(r"[A-Za-z][A-Za-z0-9.-]*")
_QUALIFIER_KEY = re.compile(r"[a-z][a-z0-9._-]*")
_DIGEST = re.compile(r"(?:sha256|sha512):[0-9a-f]+")


# *--- Package Key ---*


# SECURITY: str.lower() reads the interpreter's Unicode database, which differs between 3.11,
# 3.13 and 3.14, so a key built with it could differ per interpreter (E2).
def ascii_fold(text: str) -> str:
    """Lowercase A to Z only; every other character is kept."""
    return text.translate(_ASCII_FOLD)


# surrogatepass keeps a lone surrogate encodable so this never raises; valid UTF-8 never
# holds those octets, so the encoding stays injective.
def _percent_encode(text: str, safe: frozenset[int]) -> str:
    """Percent-encode every UTF-8 octet outside the safe set, with uppercase hex."""
    return "".join(
        chr(octet) if octet in safe else f"%{octet:02X}"
        for octet in text.encode("utf-8", "surrogatepass")
    )


def _decode(text: str) -> str | None:
    """Percent-decode and UTF-8-decode strictly, or None when the text does not decode."""
    head, *escaped = text.split("%")
    try:
        octets = bytearray(head.encode("utf-8"))
        for part in escaped:
            if len(part) < 2 or part[0] not in _HEX_DIGITS or part[1] not in _HEX_DIGITS:
                return None
            octets.append(int(part[:2], 16))
            octets += part[2:].encode("utf-8")
        return octets.decode("utf-8")
    except UnicodeError:
        return None


def _segments(text: str, drop_dots: bool) -> list[str] | None:
    """Split on / first, then decode each segment, dropping empty (and dot) segments."""
    kept: list[str] = []
    for raw in text.split("/"):
        segment = _decode(raw)
        if segment is None or "/" in segment:
            return None
        if segment and not (drop_dots and segment in (".", "..")):
            kept.append(segment)
    return kept


def _qualifiers(purl_type: str, text: str) -> str | None:
    """Apply the ordered qualifier rule of Decision C, or None when the qualifiers do not parse."""
    pairs: list[tuple[str, str]] = []
    for pair in text.split("&"):
        if not pair:
            continue
        raw_key, _, raw_value = pair.partition("=")
        key = ascii_fold(raw_key)
        value = _decode(raw_value)
        if _QUALIFIER_KEY.fullmatch(key) is None or value is None:
            return None
        if value:
            pairs.append((key, value))
    # Duplicates are checked only after the empty-value drop (A7).
    if len({key for key, _ in pairs}) != len(pairs):
        return None
    defaults = PURL_DEFAULT_QUALIFIERS.get(purl_type, {})
    stripped = OCI_STRIPPED_QUALIFIERS if purl_type == "oci" else PURL_STRIPPED_QUALIFIERS
    # purl-how-to-build sorts the built key=value strings, not the keys alone.
    return "&".join(
        sorted(
            f"{key}={_percent_encode(value, _PURL_SAFE)}"
            for key, value in pairs
            if key not in stripped and defaults.get(key) != value
        )
    )


# NOTE: The split order is purl-how-to-parse's. Type rules (deb requiring a namespace, and so
# on) are not enforced, because producer test data breaks them.
def purl_key(purl: str) -> str | None:
    """Return the version-free pkg: key of a purl, or None when it does not parse."""
    remainder, subpath_text, qualifier_text = purl, "", ""
    if "#" in remainder:
        remainder, _, subpath_text = remainder.rpartition("#")
    if "?" in remainder:
        remainder, _, qualifier_text = remainder.rpartition("?")
    scheme, colon, remainder = remainder.partition(":")
    if not colon or ascii_fold(scheme) != "pkg":
        return None
    purl_type, slash, remainder = remainder.lstrip("/").partition("/")
    if not slash or _PURL_TYPE.fullmatch(purl_type) is None:
        return None
    purl_type = ascii_fold(purl_type)
    # The version is removed and never decoded, so nothing in it can change the key.
    remainder = remainder.rpartition("@")[0] if "@" in remainder else remainder
    namespace_text, _, name_text = remainder.rstrip("/").rpartition("/")
    name = _decode(name_text)
    namespace = _segments(namespace_text, drop_dots=False)
    subpath = _segments(subpath_text, drop_dots=True)
    qualifiers = _qualifiers(purl_type, qualifier_text)
    if not name or namespace is None or subpath is None or qualifiers is None:
        return None
    fold_namespace, fold_name = PURL_CASE_FOLDS.get(purl_type, (False, False))
    if fold_namespace:
        namespace = [ascii_fold(segment) for segment in namespace]
    if fold_name:
        name = ascii_fold(name)
    if purl_type in PURL_DASHED_NAME_TYPES:
        name = name.replace("_", "-")
    # The name is one segment, so a decoded / in it is re-encoded and never splits it.
    key = PKG_KEY_PREFIX + purl_type + "/"
    key += "".join(_percent_encode(segment, _PURL_SAFE) + "/" for segment in namespace)
    key += _percent_encode(name, _PURL_SAFE)
    if qualifiers:
        key += "?" + qualifiers
    if subpath:
        key += "#" + "/".join(_percent_encode(segment, _PURL_SAFE) for segment in subpath)
    return key


def ref_key(ref: str) -> str:
    """Return the ref: key of an affects ref that resolves to no unique component."""
    return REF_KEY_PREFIX + _percent_encode(ref, _UNRESERVED)


# Step 2 refuses a component with a non-string name or type as invalid_component before it
# asks for a key (A10); here such a field only reads as empty, so the function never raises.
def package_key(component: Mapping[str, Any]) -> tuple[str, bool, str | None]:
    """Return a component's package key, whether it is the weak form, and its raw purl."""
    raw = component.get("purl")
    if not isinstance(raw, str):
        raw = None
    elif (key := purl_key(raw)) is not None:
        return key, False, raw
    fields = (component.get("type"), component.get("group"), component.get("name"))
    texts = (value if isinstance(value, str) else "" for value in fields)
    fallback = COMPONENT_KEY_PREFIX + "/".join(_percent_encode(text, _UNRESERVED) for text in texts)
    return fallback, True, raw


# *--- Subject Lineage ---*


def digest_shaped(text: str) -> bool:
    """Return whether text is <alg>:<hex> with alg sha256 or sha512 and lowercase hex."""
    return _DIGEST.fullmatch(text) is not None


# The lineage comes from the subject name in every rule, never from the composed scope id
# (S4). A tag is stripped only when the last : follows the last /, so a registry port stays.
def subject_lineage(scope_type: str, name: str) -> str:
    """Return the subject part of a package resource id; for scan, the scope id unchanged."""
    if scope_type != IMAGE_SCOPE_TYPE:
        return name
    head, at, digest = name.rpartition("@")
    if at and digest_shaped(digest):
        name = head
    colon = name.rfind(":")
    if colon > name.rfind("/"):
        name = name[:colon]
    return name


# *--- Package Resource ---*


# A package key never holds a raw |, so the last | splits it off however the lineage reads.
# The id is refused, never repaired, past the identity cap: step 2 records a returned problem
# as ERROR identity_input_invalid (CONTENT) at its own JSON path.
def package_resource_id(scope_type: str, lineage: str, key: str) -> tuple[str, str | None]:
    """Compose <scope type>:<lineage>|<key> and why it cannot be an identity, or None."""
    resource_id = f"{scope_type}:{lineage}|{key}"
    return resource_id, identity_problem(resource_id, MAX_IDENTITY_CHARS)


def split_package_resource_id(resource_id: str) -> tuple[str, str, str] | None:
    """Split a package resource id at its first : and last |, or None when it has neither."""
    scope_type, colon, rest = resource_id.partition(":")
    lineage, pipe, key = rest.rpartition("|")
    if not colon or not pipe:
        return None
    return scope_type, lineage, key
