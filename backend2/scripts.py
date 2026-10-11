"""
backend2/scripts.py
===================
Script detection and Unicode-aware word-boundary helper.

Script detection
----------------
We look at code-point ranges to classify characters, not heuristics.
This is a UNICODE FACT about the characters present, NOT a language
identification claim.  Devanagari is used by Hindi, Marathi, Nepali and
others; Tamil script does not tell us whether the detector understood the
message; Latin text may be English, Hinglish, Tanglish, or something else.

Unicode ranges used
-------------------
Latin word chars  : A-Z, a-z, 0-9, _ (standard ASCII word chars)
Devanagari        : U+0900–U+097F  (includes vowel signs and virama)
Tamil             : U+0B80–U+0BFF  (includes vowel signs and suffix chars)

Boundary helper
---------------
Python's \\b treats Devanagari and Tamil combining characters as
non-word chars, which breaks inside multi-syllable words.  We build
custom lookarounds that treat ASCII word chars PLUS Devanagari PLUS Tamil
ranges as "word" characters.
"""

from __future__ import annotations

import re
import unicodedata

# ---------------------------------------------------------------------------
# Unicode ranges for script detection
# ---------------------------------------------------------------------------

_DEVANAGARI_RANGE = (0x0900, 0x097F)
_TAMIL_RANGE      = (0x0B80, 0x0BFF)

# Characters counted as "word chars" for boundary purposes.
# ASCII: A-Za-z0-9_   Devanagari: U+0900-U+097F   Tamil: U+0B80-U+0BFF
_WORD_CHAR_PATTERN = r"[A-Za-z0-9_\u0900-\u097F\u0B80-\u0BFF]"
_NON_WORD_CHAR_PATTERN = r"[^A-Za-z0-9_\u0900-\u097F\u0B80-\u0BFF]"

# Pre-compiled lookaheads/lookbehinds for use in regex building.
# LB  = "preceded by a word char"  (left boundary: must NOT be preceded)
# LA  = "followed by a word char"  (right boundary: must NOT be followed)
_WORD_BEHIND = rf"(?<={_WORD_CHAR_PATTERN})"
_WORD_AHEAD  = rf"(?={_WORD_CHAR_PATTERN})"
_NO_WORD_BEHIND = rf"(?<!{_WORD_CHAR_PATTERN})"
_NO_WORD_AHEAD  = rf"(?!{_WORD_CHAR_PATTERN})"


def wb_left() -> str:
    """Return a regex fragment that asserts a word-start (not preceded by a word char)."""
    return _NO_WORD_BEHIND


def wb_right() -> str:
    """Return a regex fragment that asserts a word-end (not followed by a word char)."""
    return _NO_WORD_AHEAD


def wb(pattern: str) -> str:
    """
    Wrap *pattern* with Unicode-safe left and right word boundaries.

    Use this instead of \\b for any pattern that may match Devanagari or
    Tamil characters.  For pure Latin patterns \\b is fine but wb() still
    works correctly.

    Example
    -------
    >>> import re
    >>> re.search(wb("OTP"), "Your OTP-ஐ enter karein")  # matches "OTP"
    """
    return wb_left() + pattern + wb_right()


def wb_l(pattern: str) -> str:
    """Wrap *pattern* with a Unicode-safe LEFT boundary only (no right boundary)."""
    return wb_left() + pattern


def wb_r(pattern: str) -> str:
    """Wrap *pattern* with a Unicode-safe RIGHT boundary only (no left boundary)."""
    return pattern + wb_right()


# ---------------------------------------------------------------------------
# Script detection
# ---------------------------------------------------------------------------

def _char_script(ch: str) -> str:
    """Return the script name for a single character, or '' for punctuation/space."""
    cp = ord(ch)
    if cp < 0x80:
        if ch.isalpha() or ch.isdigit() or ch == "_":
            return "Latin"
        return ""   # punctuation/space
    if _DEVANAGARI_RANGE[0] <= cp <= _DEVANAGARI_RANGE[1]:
        return "Devanagari"
    if _TAMIL_RANGE[0] <= cp <= _TAMIL_RANGE[1]:
        return "Tamil"
    # Anything else that is a letter/digit/mark
    cat = unicodedata.category(ch)
    if cat[0] in ("L", "N", "M"):   # Letter, Number, Mark
        return "Other"
    return ""


def detect_scripts(text: str) -> list[str]:
    """
    Return a sorted list of script names present in *text*.

    Only scripts with at least one letter/digit/mark are returned.
    This is a Unicode fact about which code points are present — it is
    NOT a language identification claim.

    Returns a subset of ["Devanagari", "Latin", "Other", "Tamil"].
    """
    found: set[str] = set()
    for ch in text:
        s = _char_script(ch)
        if s:
            found.add(s)
    return sorted(found)


def script_char_fractions(text: str) -> dict[str, float]:
    """
    Return a dict mapping script name → fraction of total script characters.

    Useful for deciding whether a script is "meaningful" vs incidental.
    Only characters counted by _char_script() are in the denominator.
    """
    counts: dict[str, int] = {}
    total = 0
    for ch in text:
        s = _char_script(ch)
        if s:
            counts[s] = counts.get(s, 0) + 1
            total += 1
    if total == 0:
        return {}
    return {s: c / total for s, c in counts.items()}


def has_devanagari(text: str) -> bool:
    """True if *text* contains at least one Devanagari character."""
    return any(_DEVANAGARI_RANGE[0] <= ord(c) <= _DEVANAGARI_RANGE[1] for c in text)


def has_tamil(text: str) -> bool:
    """True if *text* contains at least one Tamil character."""
    return any(_TAMIL_RANGE[0] <= ord(c) <= _TAMIL_RANGE[1] for c in text)
