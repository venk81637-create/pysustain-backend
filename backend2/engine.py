"""
backend2/engine.py
==================
Shared detection engine: clause splitting, matching, deduplication, scoring,
confidence heuristic, and output assembly.

This module is INDEPENDENT of Streamlit and any UI.  Backend 3 can import
analyze_text() without importing or launching anything else.

Design decisions (documented for review)
-----------------------------------------
1. All matching runs against the ORIGINAL text (no rewriting).  A NFC copy
   is used internally for matching; offsets are mapped back to the original.
2. Each RISK FLAG counts once at the weight of its STRONGEST matching rule.
   Repeated sentences and overlapping patterns never inflate a flag.
3. Context flags are built during matching; they carry NO weight and NO
   category vote.  The only permitted score-indirect effect of a context flag
   is via the combo table (otp_delivery_notice + link_prompt), which is
   explicitly documented in config.py.
4. Awareness suppression happens at matching time, before any scoring flag
   is emitted.  No post-hoc score adjustments.
5. Negation is evaluated per clause, using each pack's declared scope and cue
   patterns, within the same clause only.
"""

from __future__ import annotations

import re
import unicodedata
from dataclasses import dataclass, field
from typing import Optional

from backend2.config import (
    CATEGORIES,
    CATEGORY_PRIORITY,
    COERCION_FLAGS,
    COERCION_MAX,
    COMBO_CAP,
    COMBO_TABLE,
    CONFIDENCE_AMBIGUITY_PENALTY,
    CONFIDENCE_BORDERLINE_PENALTY,
    CONFIDENCE_EVIDENCE_CAP,
    CONFIDENCE_LIMITED_COVERAGE_CAP,
    CONFIDENCE_MARGIN_BONUS,
    CONFIDENCE_MAX,
    CONFIDENCE_MIN_REAL,
    CONFIDENCE_NON_EN_REDUCTION,
    CONFIDENCE_PER_EVIDENCE_KIND,
    CONFIDENCE_SCORE_BASE_FACTOR,
    CONFIDENCE_UNSUPPORTED_CAP,
    FLAG_WEIGHTS,
    MAX_MESSAGE_LENGTH,
    RISK_LEVEL_BANDS,
    SAFE_THRESHOLD,
    SCORE_MAX,
    UNSUPPORTED_SCRIPT_THRESHOLD,
)
from backend2.scripts import (
    detect_scripts,
    has_devanagari,
    has_tamil,
    script_char_fractions,
    wb_left,
    wb_right,
)


# ---------------------------------------------------------------------------
# Rule dataclass
# ---------------------------------------------------------------------------

@dataclass
class Rule:
    """
    A single detection rule.

    Attributes
    ----------
    id          : Unique identifier, e.g. "en_otp_request_01".  Must be
                  stable (ordering-independent results).
    language    : Pack that owns this rule, e.g. "en", "hi", "ta".
    pattern     : Raw regex string (will be compiled by the engine).
    flag        : Risk flag this rule fires (from FLAG_WEIGHTS keys) OR a
                  context-flag name (from CONTEXT_FLAG_NAMES).
    category    : Which scam category this rule votes for, or "" for context.
    description : Plain English description of what this rule matches.
    gloss       : English example / gloss of a target phrase.
    negatable   : If True, negation in the same clause neutralizes this rule.
    needs_prev  : If True, rule only fires when the previous clause also had
                  a match (context-dependent signal).
    awareness_suppressible : If True, an awareness cue in the SAME clause
                  suppresses this rule entirely (no scoring flag emitted).
                  ONLY use for weak mention-only rules (bare authority name,
                  bare URL, generic urgency word, bare "refund").
    """
    id: str
    language: str
    pattern: str
    flag: str
    category: str
    description: str
    gloss: str
    negatable: bool = False
    needs_prev: bool = False
    awareness_suppressible: bool = False

    # Compiled regex — set by engine on first use.
    _compiled: Optional[re.Pattern] = field(default=None, init=False, repr=False)

    def compiled(self, flags: int = re.IGNORECASE | re.UNICODE) -> re.Pattern:
        """Return compiled regex, compiling on first call."""
        if self._compiled is None:
            self._compiled = re.compile(self.pattern, flags)
        return self._compiled


# ---------------------------------------------------------------------------
# Match result (internal)
# ---------------------------------------------------------------------------

@dataclass
class _Match:
    rule: Rule
    start: int   # offset in ORIGINAL text
    end: int     # offset in ORIGINAL text
    clause_idx: int


# ---------------------------------------------------------------------------
# Language pack protocol
# ---------------------------------------------------------------------------

@dataclass
class LanguagePack:
    """
    Container for a language pack's rules and negation config.

    Each pack is responsible for:
    - Providing a list of Rule objects.
    - Declaring its negation scope ("before", "after", or "either").
    - Providing compiled negation-cue patterns (matched per clause).
    - Providing contrast-word patterns used for clause splitting.
    - Providing sentence-ending characters (besides the defaults).
    - Providing awareness-cue patterns (matched per clause).
    - Providing reported-speech patterns (matched per clause).
    """
    pack_id: str            # e.g. "en", "hi", "ta", "hi-Latn", "ta-Latn"
    rules: list[Rule]
    negation_scope: str     # "before" | "after" | "either"
    negation_patterns: list[str]    # raw regex strings for negation cues
    contrast_patterns: list[str]    # raw regex strings for contrast-word split
    sentence_enders: str            # extra sentence-ending characters
    awareness_patterns: list[str]   # raw regex strings for awareness cues
    reported_speech_patterns: list[str]  # raw regex strings for reported speech

    # Compiled caches — set by engine.
    _neg_compiled: list[re.Pattern] = field(default_factory=list, init=False)
    _contrast_compiled: list[re.Pattern] = field(default_factory=list, init=False)
    _awareness_compiled: list[re.Pattern] = field(default_factory=list, init=False)
    _reported_compiled: list[re.Pattern] = field(default_factory=list, init=False)

    def ensure_compiled(self) -> None:
        flags = re.IGNORECASE | re.UNICODE
        if not self._neg_compiled:
            self._neg_compiled = [re.compile(p, flags) for p in self.negation_patterns]
        if not self._contrast_compiled:
            self._contrast_compiled = [re.compile(p, flags) for p in self.contrast_patterns]
        if not self._awareness_compiled:
            self._awareness_compiled = [re.compile(p, flags) for p in self.awareness_patterns]
        if not self._reported_compiled:
            self._reported_compiled = [re.compile(p, flags) for p in self.reported_speech_patterns]

    def has_negation(self, clause_text: str) -> bool:
        """Return True if any negation cue appears in *clause_text*."""
        self.ensure_compiled()
        return any(p.search(clause_text) for p in self._neg_compiled)

    def has_awareness(self, clause_text: str) -> bool:
        """Return True if any awareness cue appears in *clause_text*."""
        self.ensure_compiled()
        return any(p.search(clause_text) for p in self._awareness_compiled)

    def has_reported_speech(self, clause_text: str) -> bool:
        """Return True if any reported-speech cue appears in *clause_text*."""
        self.ensure_compiled()
        return any(p.search(clause_text) for p in self._reported_compiled)


# ---------------------------------------------------------------------------
# Clause splitter
# ---------------------------------------------------------------------------

# Sentence-ending characters (common to all packs).
_BASE_SENTENCE_ENDERS = r"[.!?।॥\n]"

# Semicolon split.
_SEMICOLON = r";"

# URL-like pattern — we do NOT split inside URLs.
_URL_LIKE = re.compile(
    r"https?://\S+|www\.\S+|\S+\.(com|org|net|in|io|co)\S*",
    re.IGNORECASE,
)

# "Rs." — do not split here.
_RS_ABBREV = re.compile(r"\bRs\.\s*\d", re.IGNORECASE)


def _protect_urls_and_abbrevs(text: str) -> tuple[str, dict[int, str]]:
    """
    Replace URLs and "Rs." with placeholders so they don't trigger splits.
    Returns (modified_text, {placeholder_pos: original}).
    """
    # We use a simpler approach: track spans to skip during splitting.
    # Return the span list.
    spans_to_skip: list[tuple[int, int]] = []
    for m in _URL_LIKE.finditer(text):
        spans_to_skip.append((m.start(), m.end()))
    for m in _RS_ABBREV.finditer(text):
        # protect the dot
        spans_to_skip.append((m.start(), m.end()))
    return spans_to_skip


def split_into_clauses(text: str, extra_contrast_patterns: list[re.Pattern]) -> list[tuple[str, int]]:
    """
    Split *text* into (clause_text, start_offset) pairs.

    Splits on:
    - Sentence endings: . ! ? । ॥ newline
    - Semicolons
    - Before contrast words (each pack provides patterns)

    Does NOT split:
    - Inside URLs (http://, www., common TLDs)
    - At "Rs." followed by a digit

    Returns list of (clause_text, start_in_original) where clause_text is
    a substring of the original (same offsets, no stripping done on the
    actual text used for matching — we strip only for display/logging).
    """
    n = len(text)
    protected: list[tuple[int, int]] = _protect_urls_and_abbrevs(text)

    def is_protected(pos: int) -> bool:
        return any(s <= pos < e for s, e in protected)

    # Build split positions.
    splits: set[int] = {0}

    # 1. Sentence enders and semicolons
    for m in re.finditer(rf"{_BASE_SENTENCE_ENDERS}|{_SEMICOLON}", text, re.UNICODE):
        end = m.end()
        if not is_protected(m.start()):
            splits.add(end)

    # 2. Contrast words — split BEFORE the contrast word
    for pat in extra_contrast_patterns:
        for m in pat.finditer(text):
            pos = m.start()
            if not is_protected(pos):
                splits.add(pos)

    splits.add(n)

    sorted_splits = sorted(splits)
    clauses: list[tuple[str, int]] = []
    for i in range(len(sorted_splits) - 1):
        start = sorted_splits[i]
        end = sorted_splits[i + 1]
        seg = text[start:end]
        if seg.strip():
            clauses.append((seg, start))

    return clauses if clauses else [(text, 0)]


# ---------------------------------------------------------------------------
# NFC normalization with offset mapping
# ---------------------------------------------------------------------------

def _nfc_offsets(text: str) -> tuple[str, list[int]]:
    """
    Return (nfc_text, offset_map) where offset_map[i] = position in *text*
    corresponding to position i in nfc_text.

    Because NFC may merge characters (e.g., combining char + base →
    precomposed), nfc_text may be shorter than text.  offset_map[i] gives
    the index in the ORIGINAL text where nfc_text[i] started.

    For most practical inputs (already NFC), offset_map[i] == i.
    """
    nfc = unicodedata.normalize("NFC", text)
    # Build character-level mapping via normalization of each char.
    orig_pos = 0
    offset_map: list[int] = []
    nfc_pos = 0
    # Walk through the original and figure out which orig chars map to which
    # nfc chars.  We do this by re-normalizing prefix by prefix.
    # Simple approach: compare codepoint lengths.
    prev_len = 0
    for i, ch in enumerate(text):
        # Normalize the char in context — not reliable char-by-char.
        # Instead: nfc_text[nfc_pos] corresponds to text[i] approximately.
        pass
    # Practical shortcut: for the vast majority of real inputs (already NFC
    # or simple NFD → NFC), len(nfc) == len(text) and offset_map = range(n).
    # For the rare non-NFC case we fall back to a char-by-char scan.
    if len(nfc) == len(text):
        return nfc, list(range(len(text)))

    # General case: walk both strings simultaneously.
    offset_map = []
    oi = 0
    ni = 0
    orig_chars = list(text)
    nfc_chars = list(nfc)
    # Build NFC of each prefix and compare lengths to sync.
    # This is O(n²) but only triggered for non-NFC text (rare).
    while ni < len(nfc_chars):
        # find smallest k such that NFC(text[oi:oi+k]) covers nfc_chars[ni]
        for k in range(1, len(orig_chars) - oi + 1):
            candidate = unicodedata.normalize("NFC", text[oi:oi + k])
            if len(candidate) >= ni - len(offset_map) + 1:
                offset_map.append(oi)
                oi = oi + k - (len(candidate) - 1)
                ni += 1
                break
        else:
            offset_map.append(oi)
            ni += 1

    # Pad if needed.
    while len(offset_map) < len(nfc):
        offset_map.append(len(text) - 1)

    return nfc, offset_map


def _strip_zwj(text: str) -> str:
    """Remove zero-width joiner (U+200D) and zero-width non-joiner (U+200C)."""
    return text.replace("\u200C", "").replace("\u200D", "")


# ---------------------------------------------------------------------------
# Core matching: run a pack's rules against one clause
# ---------------------------------------------------------------------------

def _run_pack_on_clause(
    pack: LanguagePack,
    clause_text: str,
    clause_start: int,
    clause_idx: int,
    prev_had_match: bool,
) -> list[_Match]:
    """
    Run all rules from *pack* against *clause_text*.

    Awareness suppression and negation/reported-speech neutralization happen
    here, before any match is returned.

    Returns a list of _Match objects (referencing offsets in the ORIGINAL text).
    """
    pack.ensure_compiled()

    # Prepare matching text: NFC copy + ZWJ-stripped for matching.
    # Offsets map back to clause_text positions (then + clause_start for
    # original text positions).
    no_zwj = _strip_zwj(clause_text)
    nfc_text, offset_map = _nfc_offsets(no_zwj)

    # Check clause-level context signals (evaluated ONCE per clause per pack).
    has_neg       = pack.has_negation(clause_text)
    has_aware     = pack.has_awareness(clause_text)
    has_reported  = pack.has_reported_speech(clause_text)

    matches: list[_Match] = []

    for rule in pack.rules:
        # needs_prev: only fire if previous clause had a match.
        if rule.needs_prev and not prev_had_match:
            continue

        # awareness_suppressible: if an awareness cue is in this clause,
        # skip entirely (no scoring flag, no context flag from this rule).
        if rule.awareness_suppressible and has_aware:
            continue

        # Reported speech neutralizes negatable rules in this clause.
        if rule.negatable and has_reported:
            continue

        for m_raw in rule.compiled().finditer(nfc_text):
            raw_start, raw_end = m_raw.start(), m_raw.end()

            # Map back to original (pre-NFC, pre-ZWJ-strip) positions.
            # offset_map covers nfc_text positions → no_zwj positions.
            # We need: no_zwj position → clause_text position.
            # Since ZWJ stripping only removes chars, no_zwj[i] corresponds
            # to some clause_text[j] where j >= i.
            # We rebuild the mapping on the fly with a forward pass.
            # (Cached per clause would be faster, but clarity wins.)
            def no_zwj_to_orig(pos: int, src: str) -> int:
                """Map position in ZWJ-stripped string back to src."""
                stripped = 0
                for orig_i, ch in enumerate(src):
                    if ch in ("\u200C", "\u200D"):
                        continue
                    if stripped == pos:
                        return orig_i
                    stripped += 1
                return len(src)

            # offset_map[raw_start] → no_zwj position
            if len(offset_map) > 0 and raw_start < len(offset_map):
                zwj_start = offset_map[raw_start]
                zwj_end   = offset_map[raw_end - 1] + 1 if raw_end > 0 and (raw_end - 1) < len(offset_map) else len(no_zwj)
            else:
                zwj_start = raw_start
                zwj_end   = raw_end

            orig_start = no_zwj_to_orig(zwj_start, clause_text) + clause_start
            orig_end   = no_zwj_to_orig(zwj_end,   clause_text) + clause_start

            # Clamp to valid range.
            msg_len = clause_start + len(clause_text)
            orig_start = max(0, min(orig_start, msg_len))
            orig_end   = max(orig_start, min(orig_end, msg_len))

            # Negation neutralizes negatable rules.
            if rule.negatable and has_neg:
                # Add negation scope check (before/after/either relative to
                # the match position within the clause).
                # "before": negation cue must appear BEFORE the match.
                # "after":  negation cue must appear AFTER the match.
                # "either": any position.
                neutralized = False
                if pack.negation_scope == "either":
                    neutralized = True
                elif pack.negation_scope == "before":
                    # negation cue is before the match in the clause
                    before_text = clause_text[:m_raw.start()]
                    neutralized = any(p.search(before_text) for p in pack._neg_compiled)
                elif pack.negation_scope == "after":
                    # negation cue is after the match in the clause
                    after_text = clause_text[m_raw.end():]
                    neutralized = any(p.search(after_text) for p in pack._neg_compiled)
                if neutralized:
                    continue

            matches.append(_Match(
                rule=rule,
                start=orig_start,
                end=orig_end,
                clause_idx=clause_idx,
            ))

    return matches


# ---------------------------------------------------------------------------
# Overlap merging
# ---------------------------------------------------------------------------

def _merge_overlapping_matches(matches: list[_Match]) -> list[_Match]:
    """
    Merge overlapping matches for the SAME rule flag by keeping the one with
    the greatest span (ties: earliest start, then alphabetical rule id).
    """
    # Group by flag.
    by_flag: dict[str, list[_Match]] = {}
    for m in matches:
        by_flag.setdefault(m.rule.flag, []).append(m)

    result: list[_Match] = []
    for flag, flag_matches in by_flag.items():
        # Sort by start, then end (descending), then rule id.
        flag_matches.sort(key=lambda m: (m.start, -m.end, m.rule.id))
        merged: list[_Match] = []
        for m in flag_matches:
            if merged and m.start < merged[-1].end:
                # overlaps — keep wider span, prefer same flag.
                prev = merged[-1]
                if m.end > prev.end:
                    merged[-1] = m
                elif m.end == prev.end and m.rule.id < prev.rule.id:
                    merged[-1] = m
            else:
                merged.append(m)
        result.extend(merged)

    return result


# ---------------------------------------------------------------------------
# Flag deduplication across packs
# ---------------------------------------------------------------------------

def _deduplicate_flags(all_matches: list[_Match]) -> dict[str, _Match]:
    """
    For each unique flag, keep the SINGLE strongest match
    (highest FLAG_WEIGHTS value; tie → category priority → alphabetical rule id).

    Returns {flag_id: best_Match}.
    """
    from backend2.config import FLAG_WEIGHTS

    best: dict[str, _Match] = {}
    for m in all_matches:
        flag = m.rule.flag
        if flag not in best:
            best[flag] = m
        else:
            prev = best[flag]
            w_new  = FLAG_WEIGHTS.get(flag, 0)
            w_prev = FLAG_WEIGHTS.get(flag, 0)
            # Same flag → same weight, so compare by category priority then rule id.
            new_prio  = _category_priority(m.rule.category)
            prev_prio = _category_priority(prev.rule.category)
            if new_prio < prev_prio:
                best[flag] = m
            elif new_prio == prev_prio and m.rule.id < prev.rule.id:
                best[flag] = m
    return best


def _category_priority(cat: str) -> int:
    """Return priority index (lower = higher priority)."""
    try:
        return CATEGORY_PRIORITY.index(cat)
    except ValueError:
        return len(CATEGORY_PRIORITY)


# ---------------------------------------------------------------------------
# Scoring
# ---------------------------------------------------------------------------

def _compute_score(flag_best: dict[str, _Match]) -> int:
    """
    Score = sum of deduplicated scoring-flag weights + capped combo bonus,
    clamped to 0-100.
    """
    from backend2.config import FLAG_WEIGHTS, CONTEXT_FLAG_NAMES

    # Scoring flags only (context flags carry no weight).
    scoring_flags = {f: m for f, m in flag_best.items() if f not in CONTEXT_FLAG_NAMES}
    base = sum(FLAG_WEIGHTS.get(f, 0) for f in scoring_flags)

    # Combo bonuses.
    present = set(scoring_flags.keys())
    combo_bonus = 0
    applied_pairs: set[tuple[str, str]] = set()
    # Sort combos deterministically (table order does not matter — we sort
    # each pair's key alphabetically).
    for fa, fb, bonus in COMBO_TABLE:
        pair = (min(fa, fb), max(fa, fb))
        if pair in applied_pairs:
            continue
        if fa in present and fb in present:
            combo_bonus += bonus
            applied_pairs.add(pair)

    combo_bonus = min(combo_bonus, COMBO_CAP)
    return max(0, min(SCORE_MAX, base + combo_bonus))


def _compute_coercion(flag_best: dict[str, _Match]) -> int:
    """Coercion score based on pressure signals."""
    total = sum(
        COERCION_FLAGS[f]
        for f in flag_best
        if f in COERCION_FLAGS
    )
    return max(0, min(COERCION_MAX, total))


def _pick_category(flag_best: dict[str, _Match], score: int) -> str:
    """
    Determine scam category.

    Below SAFE_THRESHOLD → "Safe".
    Otherwise: aggregate category weights (each scoring flag contributes its
    weight to its rule's category); tie → category priority → alphabetical
    rule id (already handled by _deduplicate_flags, but we re-check here for
    clarity).
    """
    from backend2.config import FLAG_WEIGHTS, CONTEXT_FLAG_NAMES

    if score < SAFE_THRESHOLD:
        return "Safe"

    cat_weights: dict[str, int] = {}
    for flag, m in flag_best.items():
        if flag in CONTEXT_FLAG_NAMES or not m.rule.category:
            continue
        w = FLAG_WEIGHTS.get(flag, 0)
        cat_weights[m.rule.category] = cat_weights.get(m.rule.category, 0) + w

    if not cat_weights:
        return "Safe"

    max_w = max(cat_weights.values())
    top_cats = [c for c, w in cat_weights.items() if w == max_w]
    if len(top_cats) == 1:
        return top_cats[0]

    # Tie-break: category priority order.
    for cat in CATEGORY_PRIORITY:
        if cat in top_cats:
            return cat
    return top_cats[0]


# ---------------------------------------------------------------------------
# Confidence heuristic
# ---------------------------------------------------------------------------

def _compute_confidence(
    score: int,
    flag_best: dict[str, _Match],
    context_flags: set[str],
    packs_matched: set[str],
    scripts_detected: list[str],
) -> float:
    """
    Heuristic confidence estimate (0–100).  This is NOT a calibrated
    statistical probability.  0.0 is reserved for invalid input.

    Formula (all additive/subtractive, clamped to [CONFIDENCE_MIN_REAL, 100]):
      base    = score * CONFIDENCE_SCORE_BASE_FACTOR
      + per-evidence-kind bonus (capped)
      + margin bonus (if top category has clear lead)
      - borderline penalty (score near SAFE_THRESHOLD)
      - ambiguity penalty (warning_with_request)
      - non-English reduction (if ALL evidence from non-EN packs)
    """
    from backend2.config import FLAG_WEIGHTS, CONTEXT_FLAG_NAMES

    base = score * CONFIDENCE_SCORE_BASE_FACTOR

    # Evidence-kind bonus: count distinct flag categories present.
    scoring_flags = {f for f in flag_best if f not in CONTEXT_FLAG_NAMES}
    evidence_kinds = len(scoring_flags)
    evidence_bonus = min(evidence_kinds * CONFIDENCE_PER_EVIDENCE_KIND, CONFIDENCE_EVIDENCE_CAP)

    # Category margin bonus.
    cat_weights: dict[str, int] = {}
    for flag, m in flag_best.items():
        if flag in CONTEXT_FLAG_NAMES or not m.rule.category:
            continue
        cat_weights[m.rule.category] = cat_weights.get(m.rule.category, 0) + FLAG_WEIGHTS.get(flag, 0)

    margin_bonus = 0.0
    if len(cat_weights) >= 2:
        sorted_w = sorted(cat_weights.values(), reverse=True)
        if sorted_w[0] - sorted_w[1] >= 10:
            margin_bonus = CONFIDENCE_MARGIN_BONUS
    elif len(cat_weights) == 1:
        margin_bonus = CONFIDENCE_MARGIN_BONUS

    # Borderline penalty.
    borderline_penalty = 0.0
    if SAFE_THRESHOLD <= score <= SAFE_THRESHOLD + 10:
        borderline_penalty = CONFIDENCE_BORDERLINE_PENALTY

    # Ambiguity penalty.
    ambiguity_penalty = 0.0
    if "warning_with_request" in context_flags:
        ambiguity_penalty = CONFIDENCE_AMBIGUITY_PENALTY

    # Non-English-only reduction.
    non_en_reduction = 0.0
    en_packs = {"en"}
    if packs_matched and not (packs_matched & en_packs):
        non_en_reduction = CONFIDENCE_NON_EN_REDUCTION

    confidence = base + evidence_bonus + margin_bonus - borderline_penalty - ambiguity_penalty - non_en_reduction

    # Cap for unsupported language.
    if "unsupported_language" in context_flags:
        confidence = min(confidence, CONFIDENCE_UNSUPPORTED_CAP)

    # Cap for limited coverage.
    if "limited_coverage" in context_flags:
        confidence = min(confidence, CONFIDENCE_LIMITED_COVERAGE_CAP)

    return max(CONFIDENCE_MIN_REAL, min(CONFIDENCE_MAX, confidence))


# ---------------------------------------------------------------------------
# Risk level
# ---------------------------------------------------------------------------

def _risk_level(score: int) -> str:
    for threshold, label in RISK_LEVEL_BANDS:
        if score >= threshold:
            return label
    return "low"


# ---------------------------------------------------------------------------
# Detected phrases
# ---------------------------------------------------------------------------

def _build_detected_phrases(flag_best: dict[str, _Match], original_text: str) -> list[str]:
    """
    Return list of unique exact substrings from original_text, ordered by
    first occurrence position.

    Every entry MUST be an exact substring of original_text.
    """
    seen_texts: dict[str, int] = {}   # text → first position
    for flag, m in flag_best.items():
        from backend2.config import CONTEXT_FLAG_NAMES
        if flag in CONTEXT_FLAG_NAMES:
            continue
        phrase = original_text[m.start:m.end]
        if phrase and phrase not in seen_texts:
            seen_texts[phrase] = m.start

    # Sort by first position.
    return [t for t, _ in sorted(seen_texts.items(), key=lambda x: x[1])]


# ---------------------------------------------------------------------------
# Recommended actions
# ---------------------------------------------------------------------------

_RECOMMENDED_ACTIONS_BY_CATEGORY: dict[str, list[str]] = {
    "OTP/PIN Harvesting": [
        "Never share your OTP, PIN, or password with anyone — even if they claim to be from your bank or government.",
        "Hang up and call your bank's official number (on the back of your card).",
        "Report this message to the National Cyber Crime Helpline: 1930.",
    ],
    "Banking Fraud": [
        "Do not click any links or call any numbers in this message.",
        "Contact your bank directly using the number on the official website.",
        "Report to National Cyber Crime Helpline: 1930.",
    ],
    "Utility Threat": [
        "Official utility companies do not threaten disconnection via unsolicited messages.",
        "Call your utility provider using the number on your bill to verify.",
        "Report suspicious messages to 1930.",
    ],
    "Authority Impersonation": [
        "Verify the sender's identity through official government channels.",
        "Real authorities do not demand immediate payment or credentials via SMS.",
        "Report to 1930 or your local cyber cell.",
    ],
    "Phishing": [
        "Do not click any links in this message.",
        "Go to the official website directly by typing the address in your browser.",
        "Report phishing to 1930 and forward the message to your operator.",
    ],
    "Safe": [
        "No specific scam signals found. Always verify unexpected messages through official channels.",
    ],
}

_RECOMMENDED_ACTIONS_WARNING_WITH_REQUEST: list[str] = [
    "This message mixes a warning with a suspicious request — treat the request as suspicious.",
]

_RECOMMENDED_ACTIONS_UNSUPPORTED: list[str] = [
    "This message contains text in a script this tool does not fully analyze. Treat it with caution and seek manual verification.",
]

_RECOMMENDED_ACTIONS_LIMITED: list[str] = [
    "Coverage for Hindi, Tamil, and romanized text is limited. If in doubt, seek a native-speaker review.",
]

_RECOMMENDED_ACTION_NOT_ANALYZED = "This message could not be analyzed (invalid or missing input)."


# ---------------------------------------------------------------------------
# Explanations
# ---------------------------------------------------------------------------

def _build_explanations(flag_best: dict[str, _Match]) -> list[dict]:
    """Build explanation entries for each scoring flag."""
    from backend2.config import CONTEXT_FLAG_NAMES
    explanations = []
    for flag, m in sorted(flag_best.items()):
        if flag in CONTEXT_FLAG_NAMES:
            continue
        explanations.append({
            "flag": flag,
            "reason": m.rule.description,
        })
    return explanations


# ---------------------------------------------------------------------------
# Invalid input response
# ---------------------------------------------------------------------------

def _invalid_response(include_details: bool) -> dict:
    """Return the standard invalid-input response."""
    base = {
        "detected_phrases": [],
        "scam_category": "Safe",
        "confidence": 0.0,
        "coercion_score": 0,
    }
    if include_details:
        base.update({
            "risk_level": "low",
            "risk_flags": [],
            "context_flags": ["invalid_input"],
            "matched_rules": [],
            "explanations": [],
            "recommended_actions": [_RECOMMENDED_ACTION_NOT_ANALYZED],
            "scripts_detected": [],
            "language_packs_matched": [],
        })
    return base


# ---------------------------------------------------------------------------
# Main analysis function
# ---------------------------------------------------------------------------

# Registry of language packs.  Packs register themselves via register_pack().
_PACKS: list[LanguagePack] = []


def register_pack(pack: LanguagePack) -> None:
    """Register a language pack with the engine."""
    _PACKS.append(pack)


def _get_all_packs() -> list[LanguagePack]:
    """Return a copy of the registered packs list."""
    return list(_PACKS)


def analyze_text(message_text: str, include_details: bool = True) -> dict:
    """
    Analyze *message_text* for scam signals.

    Parameters
    ----------
    message_text : str
        The message to analyze.  Must be a non-empty string of at most
        5,000 characters.
    include_details : bool
        If False, return only the four contract keys.
        If True, add diagnostic fields as documented.

    Returns
    -------
    dict with keys:
        detected_phrases : list[str]
        scam_category    : str   ("Banking Fraud" | "Utility Threat" |
                                  "Phishing" | "OTP/PIN Harvesting" |
                                  "Authority Impersonation" | "Safe")
        confidence       : float (0–100; 0.0 = not analyzed)
        coercion_score   : int   (0–100)

        (with include_details=True, adds):
        risk_level            : str
        risk_flags            : list[str]
        context_flags         : list[str]
        matched_rules         : list[str]
        explanations          : list[dict]
        recommended_actions   : list[str]
        scripts_detected      : list[str]
        language_packs_matched: list[str]

    INVALID INPUT POLICY
    --------------------
    None, non-string, empty/whitespace-only, and text > 5,000 characters
    all return: detected_phrases=[], scam_category="Safe", confidence=0.0,
    coercion_score=0.  With include_details=True also adds
    context_flags=["invalid_input"] and recommended_action saying
    not analyzed.  "Safe" + confidence 0.0 means "not analyzed", NOT
    "verified safe".  Backend 3 should treat confidence==0.0 as "no analysis".
    """
    from backend2.config import CONTEXT_FLAG_NAMES, FLAG_WEIGHTS

    # --- 1. Input validation ---
    if (
        message_text is None
        or not isinstance(message_text, str)
        or not message_text.strip()
        or len(message_text) > MAX_MESSAGE_LENGTH
    ):
        return _invalid_response(include_details)

    original = message_text   # Never modified.

    # --- 2. Script detection ---
    scripts_detected = detect_scripts(original)
    fractions = script_char_fractions(original)

    # --- 3. Collect all contrast patterns from all packs ---
    packs = _get_all_packs()
    all_contrast_patterns: list[re.Pattern] = []
    for pack in packs:
        pack.ensure_compiled()
        all_contrast_patterns.extend(pack._contrast_compiled)

    # --- 4. Split into clauses ---
    clauses = split_into_clauses(original, all_contrast_patterns)

    # --- 5. Run all packs on all clauses ---
    all_raw_matches: list[_Match] = []
    prev_had_match = False

    for clause_idx, (clause_text, clause_start) in enumerate(clauses):
        clause_matches: list[_Match] = []
        for pack in packs:
            ms = _run_pack_on_clause(pack, clause_text, clause_start, clause_idx, prev_had_match)
            clause_matches.extend(ms)
        all_raw_matches.extend(clause_matches)
        prev_had_match = bool(clause_matches)

    # --- 6. Merge overlapping matches ---
    merged = _merge_overlapping_matches(all_raw_matches)

    # --- 7. Separate scoring vs context matches ---
    scoring_matches = [m for m in merged if m.rule.flag not in CONTEXT_FLAG_NAMES]
    context_matches = [m for m in merged if m.rule.flag in CONTEXT_FLAG_NAMES]

    # --- 8. Deduplicate scoring flags ---
    flag_best: dict[str, _Match] = _deduplicate_flags(scoring_matches)

    # --- 9. Collect context flags (unique set, no weights) ---
    context_flags_set: set[str] = {m.rule.flag for m in context_matches}

    # --- 10. OTP delivery notice context detection (needed for combo) ---
    # otp_delivery_notice is a context flag; if present AND link_prompt
    # scoring flag also present, the combo table handles it — no special code.

    # --- 11. Script/coverage context flags ---
    other_frac = fractions.get("Other", 0.0)
    if other_frac >= UNSUPPORTED_SCRIPT_THRESHOLD:
        context_flags_set.add("unsupported_language")

    # limited_coverage: result is Safe AND mostly non-Latin text, no matches.
    non_latin_frac = fractions.get("Devanagari", 0.0) + fractions.get("Tamil", 0.0)
    hi_latn_frac   = fractions.get("Latin", 0.0)
    # Check if there are no scoring matches and text is non-trivially non-EN.
    if not flag_best and non_latin_frac > 0.3:
        context_flags_set.add("limited_coverage")

    # warning_with_request: awareness-cue context AND a live credential/request flag.
    has_any_awareness = any(
        any(p.search(ct) for p in pack._awareness_compiled)
        for pack in packs
        for ct, _ in clauses
    )
    live_request_flags = {"credential_request", "otp_request", "link_prompt", "remote_access_app", "payment_demand"}
    if has_any_awareness and (flag_best.keys() & live_request_flags):
        context_flags_set.add("warning_with_request")

    # --- 12. Score and category ---
    score = _compute_score(flag_best)
    category = _pick_category(flag_best, score)
    coercion = _compute_coercion(flag_best)

    # --- 13. Language packs matched ---
    packs_matched: set[str] = set()
    for m in merged:
        packs_matched.add(m.rule.language)

    # --- 14. Confidence ---
    confidence = _compute_confidence(score, flag_best, context_flags_set, packs_matched, scripts_detected)

    # --- 15. Detected phrases (ordered by first position) ---
    detected_phrases = _build_detected_phrases(flag_best, original)

    # --- 16. Assemble output ---
    result: dict = {
        "detected_phrases": detected_phrases,
        "scam_category": category,
        "confidence": round(confidence, 1),
        "coercion_score": coercion,
    }

    if include_details:
        # risk_flags: sorted by descending weight, then alphabetically.
        def flag_sort_key(f: str) -> tuple:
            return (-FLAG_WEIGHTS.get(f, 0), f)

        risk_flags = sorted(
            [f for f in flag_best if f not in CONTEXT_FLAG_NAMES],
            key=flag_sort_key,
        )

        # matched_rules: ordered by first match position in original, then rule id.
        rule_appearances: dict[str, tuple[int, str]] = {}
        for m in merged:
            rid = m.rule.id
            if rid not in rule_appearances or (m.start, rid) < rule_appearances[rid]:
                rule_appearances[rid] = (m.start, rid)
        matched_rules = [rid for rid, _ in sorted(rule_appearances.items(), key=lambda x: x[1])]

        # context_flags: sorted alphabetically.
        context_flags_list = sorted(context_flags_set)

        result.update({
            "risk_level": _risk_level(score),
            "risk_flags": risk_flags,
            "context_flags": context_flags_list,
            "matched_rules": matched_rules,
            "explanations": _build_explanations(flag_best),
            "recommended_actions": _build_recommended_actions(category, context_flags_set),
            "scripts_detected": scripts_detected,
            "language_packs_matched": sorted(packs_matched),
        })

    return result


def _build_recommended_actions(category: str, context_flags: set[str]) -> list[str]:
    """Assemble recommended actions list."""
    actions: list[str] = list(_RECOMMENDED_ACTIONS_BY_CATEGORY.get(category, []))
    if "warning_with_request" in context_flags:
        actions = _RECOMMENDED_ACTIONS_WARNING_WITH_REQUEST + actions
    if "unsupported_language" in context_flags:
        actions.extend(_RECOMMENDED_ACTIONS_UNSUPPORTED)
    if "limited_coverage" in context_flags:
        actions.extend(_RECOMMENDED_ACTIONS_LIMITED)
    return actions
