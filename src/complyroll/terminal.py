# ******************************************************************************
# *Title: Terminal Text*
# *Author: Kyle Versluis*
# *Description: Print command output that no input can forge a line in.*
# ******************************************************************************
"""Terminal-safe text output, shared by the `complyroll` and `stigroll` commands.

Every line either command prints, its usage errors included, passes through
`terminal_text`, and each command lets a stream that cannot encode a character write it
as a backslash escape (CL-50, CL-51, CL-78).
"""

# *--- Imports ---*

from __future__ import annotations

import argparse
import re
import sys
from typing import NoReturn, TextIO

# *--- Configuration ---*

# SECURITY: File names, stored text and messages that quote either reach a terminal through
# here. A newline, carriage return, line or paragraph separator, or any other C0 or C1
# control, DEL included, would forge a line or drive the terminal, so each is spelled as an
# escape; a tab, which moves no line, is kept (CL-50).
_TERMINAL_CONTROLS = re.compile("[\x00-\x08\x0a-\x1f\x7f-\x9f  ]")
_SHORT_ESCAPES = {"\n": "\\n", "\r": "\\r"}


# *--- Output ---*


def terminal_text(text: str) -> str:
    """Return one line of text output with every control character spelled as an escape."""

    return _TERMINAL_CONTROLS.sub(_control_escape, text)


def _control_escape(match: re.Match[str]) -> str:
    char = match.group()
    if char in _SHORT_ESCAPES:
        return _SHORT_ESCAPES[char]
    code = ord(char)
    return f"\\x{code:02x}" if code < 0x100 else f"\\u{code:04x}"


def say(text: str, *, file: TextIO | None = None) -> None:
    """Print one line of text output, the one way every command prints one."""

    print(terminal_text(text), file=file)


def tolerate_unencodable_output() -> None:
    """Let a stream that cannot encode a character write it as a backslash escape.

    Under `PYTHONIOENCODING=ascii` a strict stream ended the run on the first character it
    could not encode, and `ingest` did so after its store write had committed, so a saved
    write exited 1. Only a strict stream changes, and only for characters it cannot encode,
    so UTF-8 output is byte for byte what it was (CL-51). JSON is escaped before it is written
    (`cli._stdout_json`), since a backslash escape is not valid JSON.
    """

    for stream in (sys.stdout, sys.stderr):
        reconfigure = getattr(stream, "reconfigure", None)
        if reconfigure is not None and getattr(stream, "errors", None) == "strict":
            reconfigure(errors="backslashreplace")


# *--- Usage Errors ---*


class TerminalArgumentParser(argparse.ArgumentParser):
    """An argument parser whose usage errors print through `terminal_text`.

    argparse echoes an unrecognized or ambiguous argument as typed, so a newline in one forged
    a line (CL-78). A subparser is built with its parent's class, so every subcommand's errors
    pass through here too. The exit code, 2, and an error without a control character are
    argparse's own.
    """

    def error(self, message: str) -> NoReturn:
        super().error(terminal_text(message))


__all__ = ["TerminalArgumentParser", "say", "terminal_text", "tolerate_unencodable_output"]
