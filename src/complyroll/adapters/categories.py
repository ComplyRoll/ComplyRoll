# ******************************************************************************
# *Title: Frozen Unicode Categories*
# *Author: Kyle Versluis*
# *Description: The code points identity and evidence checks refuse, frozen.*
# ******************************************************************************
"""The Unicode 16.0.0 categories identity checks prohibit, frozen so every interpreter agrees.

`unicodedata` is the interpreter's own database: 14.0.0 on Python 3.11, 15.0.0 on 3.12, 15.1.0
on 3.13 and 16.0.0 on 3.14. U+13439 to U+1343F are unassigned (Cn) before 15.0.0 and format
controls (Cf) from it, so the same identity was accepted on 3.11 and refused on 3.14. This
table is what `identity_problem` and `sanitize` read instead (CL-65).

Regenerate on an interpreter whose `unicodedata.unidata_version` is `UNICODE_VERSION`, or after
changing the version, with `python -m complyroll.adapters.categories`, and paste the printed
`RANGES` over the one below; `tests/test_adapters.py` holds the table to `unicodedata`.
"""

# *--- Imports ---*

from __future__ import annotations

import bisect
import sys
import unicodedata

# *--- Configuration ---*

UNICODE_VERSION = "16.0.0"
# Control, format, surrogate, and line and paragraph separator code points.
PROHIBITED_CATEGORIES = frozenset({"Cc", "Cf", "Cs", "Zl", "Zp"})

# Generated from Unicode 16.0.0: every maximal run of code points sharing one category in
# PROHIBITED_CATEGORIES, as (first, last, category), in code point order.
RANGES: tuple[tuple[int, int, str], ...] = (
    (0x0000, 0x001F, "Cc"),
    (0x007F, 0x009F, "Cc"),
    (0x00AD, 0x00AD, "Cf"),
    (0x0600, 0x0605, "Cf"),
    (0x061C, 0x061C, "Cf"),
    (0x06DD, 0x06DD, "Cf"),
    (0x070F, 0x070F, "Cf"),
    (0x0890, 0x0891, "Cf"),
    (0x08E2, 0x08E2, "Cf"),
    (0x180E, 0x180E, "Cf"),
    (0x200B, 0x200F, "Cf"),
    (0x2028, 0x2028, "Zl"),
    (0x2029, 0x2029, "Zp"),
    (0x202A, 0x202E, "Cf"),
    (0x2060, 0x2064, "Cf"),
    (0x2066, 0x206F, "Cf"),
    (0xD800, 0xDFFF, "Cs"),
    (0xFEFF, 0xFEFF, "Cf"),
    (0xFFF9, 0xFFFB, "Cf"),
    (0x110BD, 0x110BD, "Cf"),
    (0x110CD, 0x110CD, "Cf"),
    (0x13430, 0x1343F, "Cf"),
    (0x1BCA0, 0x1BCA3, "Cf"),
    (0x1D173, 0x1D17A, "Cf"),
    (0xE0001, 0xE0001, "Cf"),
    (0xE0020, 0xE007F, "Cf"),
)

_STARTS = tuple(first for first, _, _ in RANGES)

# *--- Core Logic ---*


def prohibited_category(char: str) -> str | None:
    """Return the frozen category of one prohibited character, or None for any other."""
    code = ord(char)
    index = bisect.bisect_right(_STARTS, code) - 1
    if index < 0:
        return None
    first, last, category = RANGES[index]
    return category if first <= code <= last else None


def database_ranges() -> tuple[tuple[int, int, str], ...]:
    """Return RANGES as the running interpreter's `unicodedata` gives them."""
    ranges: list[tuple[int, int, str]] = []
    for code in range(sys.maxunicode + 1):
        category = unicodedata.category(chr(code))
        if category not in PROHIBITED_CATEGORIES:
            continue
        if ranges and ranges[-1][2] == category and ranges[-1][1] == code - 1:
            ranges[-1] = (ranges[-1][0], code, category)
        else:
            ranges.append((code, code, category))
    return tuple(ranges)


def render_ranges(ranges: tuple[tuple[int, int, str], ...]) -> str:
    """Return the source text of a RANGES assignment, as it is written above."""
    lines = ["RANGES: tuple[tuple[int, int, str], ...] = ("]
    lines += [
        f'    (0x{first:04X}, 0x{last:04X}, "{category}"),' for first, last, category in ranges
    ]
    lines.append(")")
    return "\n".join(lines)


def main() -> int:
    """Print RANGES from this interpreter's database, refusing another Unicode version."""
    if unicodedata.unidata_version != UNICODE_VERSION:
        print(
            f"this interpreter's Unicode database is {unicodedata.unidata_version}; the table "
            f"is {UNICODE_VERSION}, so run this on one that matches or change UNICODE_VERSION",
            file=sys.stderr,
        )
        return 1
    print(render_ranges(database_ranges()))
    return 0


if __name__ == "__main__":  # pragma: no cover - the regeneration entry point
    raise SystemExit(main())
