"""Neutralisation of attacker-controlled text.

Log content is hostile input. Before any value reaches storage it is made
inert for terminals, log viewers and line-oriented tooling: control, format,
line/paragraph separator and lone surrogate characters are replaced by a
visible escape sequence, so they can be neither interpreted nor hidden
(log line injection, ANSI escapes, bidi "Trojan Source" tricks, zero-width
characters). Tab is kept because it is ubiquitous in legitimate logs.
"""

import unicodedata

_ESCAPED_CATEGORIES = frozenset({"Cc", "Cf", "Zl", "Zp", "Cs"})

TRUNCATION_MARKER = "...[truncated]"


def _escape(char: str) -> str:
    code = ord(char)
    if code <= 0xFF:
        return f"\\x{code:02x}"
    if code <= 0xFFFF:
        return f"\\u{code:04x}"
    return f"\\U{code:08x}"


def neutralise(value: str) -> str:
    """Return ``value`` with every dangerous character escaped."""
    if value.isprintable():
        return value
    return "".join(
        _escape(c) if c != "\t" and unicodedata.category(c) in _ESCAPED_CATEGORIES else c
        for c in value
    )


def clamp(value: str, limit: int) -> tuple[str, bool]:
    """Neutralise ``value`` and cut it to at most ``limit`` characters.

    Truncating instead of rejecting matters for a SIEM: padding a command line
    must not be a way to make an event disappear. Returns the new value and
    whether it was truncated.
    """
    clean = neutralise(value)
    if len(clean) <= limit:
        return clean, False
    return clean[: limit - len(TRUNCATION_MARKER)] + TRUNCATION_MARKER, True
