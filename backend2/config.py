"""
backend2/config.py
==================
All weights, thresholds, combo table, category priorities, and confidence
constants for the scam detector.  Every magic number lives here — the engine
and language packs import from this module only.

Design notes
------------
- Weights are heuristic integers (0-100 space), not probabilities.
- COMBO_CAP prevents combo inflation.
- SAFE_THRESHOLD: score below this → category "Safe".
- CONFIDENCE_MIN_REAL: every genuine analysis returns at least this value;
  0.0 is reserved for "not analyzed" (invalid input).
- Category priority resolves ties after aggregation:
    OTP/PIN Harvesting > Banking Fraud > Utility Threat >
    Authority Impersonation > Phishing
"""

from __future__ import annotations

# ---------------------------------------------------------------------------
# Category strings — NEVER change these; Backend 3 depends on them.
# ---------------------------------------------------------------------------
CATEGORIES: list[str] = [
    "Banking Fraud",
    "Utility Threat",
    "Phishing",
    "OTP/PIN Harvesting",
    "Authority Impersonation",
    "Safe",
]

# Priority order for tie-breaking (index 0 = highest priority).
CATEGORY_PRIORITY: list[str] = [
    "OTP/PIN Harvesting",
    "Banking Fraud",
    "Utility Threat",
    "Authority Impersonation",
    "Phishing",
]

# ---------------------------------------------------------------------------
# Scoring thresholds
# ---------------------------------------------------------------------------

# Minimum score to move out of "Safe".
SAFE_THRESHOLD: int = 25

# Maximum raw score before clamping.
SCORE_MAX: int = 100

# ---------------------------------------------------------------------------
# Combo bonus table
# Each entry: (flag_a, flag_b, bonus)
# Both flags must be present (after deduplication) for the bonus to fire.
# Each PAIR fires at most once.  Total bonus is capped at COMBO_CAP.
# Table order does NOT affect results — pairs are applied deterministically
# via sorted key (flag_a < flag_b alphabetically).
# ---------------------------------------------------------------------------

COMBO_CAP: int = 30

# fmt: off
COMBO_TABLE: list[tuple[str, str, int]] = [
    # credential request + urgency → classic harvest attempt
    ("credential_request",   "urgency",            12),
    # credential request + threat → coercive harvest
    ("credential_request",   "threat",             15),
    # credential request + link prompt → phishing kit
    ("credential_request",   "link_prompt",        15),
    # otp_request + link prompt — note: otp_delivery_notice context flag may
    # be present (see rule below); this is the ONLY combo involving a
    # context flag, and it is documented explicitly as required by spec §8
    ("otp_request",          "link_prompt",        12),
    # urgency + threat → high pressure
    ("urgency",              "threat",             10),
    # urgency + link prompt → drive-by phishing
    ("urgency",              "link_prompt",        10),
    # prize/refund + link prompt → classic lure
    ("prize_refund_lure",    "link_prompt",        12),
    # payment demand + link prompt → payment redirect
    ("payment_demand",       "link_prompt",        10),
    # kyc_verification + credential_request → identity theft
    ("kyc_verification",     "credential_request", 12),
    # remote_access + link prompt → RAT install
    ("remote_access_app",    "link_prompt",        15),
    # authority impersonation + threat → intimidation scam
    ("authority_impersonation", "threat",          10),
]
# fmt: on

# ---------------------------------------------------------------------------
# Risk-flag weights (used by engine; language packs reference these names)
# ---------------------------------------------------------------------------

FLAG_WEIGHTS: dict[str, int] = {
    # --- High severity (25-40) ---
    "credential_request":     40,   # explicit OTP/PIN/CVV/password ask
    "otp_request":            35,   # OTP specifically (subset of credential)
    "threat":                 30,   # arrest/account-block/legal threat
    "remote_access_app":      30,   # install AnyDesk / TeamViewer etc.
    # --- Medium-high (18-24) ---
    "payment_demand":         24,   # fee/fine/payment required
    "link_prompt":            22,   # "click this link" text-side only
    "kyc_verification":       20,   # KYC/verification lure
    "prize_refund_lure":      20,   # you won / get refund
    # --- Medium (12-17) ---
    "urgency":                15,   # hurry / deadline / expiry
    "authority_impersonation":12,   # weak: mentions authority name
    # --- Low (6-11) ---
    "suspicious_payment":     10,   # suspicious fee mention
    "account_mention":         6,   # bare "your account" — very weak
}

# ---------------------------------------------------------------------------
# Risk-level bands (based on final score, not raw flag sum)
# ---------------------------------------------------------------------------

RISK_LEVEL_BANDS: list[tuple[int, str]] = [
    (75, "critical"),
    (50, "high"),
    (25, "medium"),
    (0,  "low"),
]

# ---------------------------------------------------------------------------
# Confidence heuristic constants
# ---------------------------------------------------------------------------

# Minimum confidence for any real (non-invalid) analysis.
CONFIDENCE_MIN_REAL: float = 20.0

# Max confidence attainable.
CONFIDENCE_MAX: float = 100.0

# Points added per unique evidence type (independent kinds of evidence).
CONFIDENCE_PER_EVIDENCE_KIND: float = 8.0

# Maximum contribution from evidence-kind counting.
CONFIDENCE_EVIDENCE_CAP: float = 30.0

# Bonus when category has clear margin (winning weight > 2nd place by ≥ 10).
CONFIDENCE_MARGIN_BONUS: float = 10.0

# Penalty for borderline score (SAFE_THRESHOLD ≤ score ≤ SAFE_THRESHOLD+10).
CONFIDENCE_BORDERLINE_PENALTY: float = 10.0

# Penalty when warning_with_request context flag is present (ambiguous intent).
CONFIDENCE_AMBIGUITY_PENALTY: float = 8.0

# Reduction when ALL evidence comes from non-English packs only.
# Reflects smaller rule coverage of hi, ta, hi-Latn, ta-Latn packs.
CONFIDENCE_NON_EN_REDUCTION: float = 15.0

# Cap for unsupported_language messages.
CONFIDENCE_UNSUPPORTED_CAP: float = 30.0

# Cap for limited_coverage messages (safe result, mostly non-EN, no matches).
CONFIDENCE_LIMITED_COVERAGE_CAP: float = 50.0

# Base confidence from the score itself (linear, 0-40 range for 0-100 score).
CONFIDENCE_SCORE_BASE_FACTOR: float = 0.40

# ---------------------------------------------------------------------------
# Coercion score heuristic
# Coercion = pressure signals: threats + urgency + authority + payment
# This is computed separately from scam_category.
# ---------------------------------------------------------------------------

COERCION_FLAGS: dict[str, int] = {
    "threat":                 40,
    "urgency":                25,
    "payment_demand":         20,
    "authority_impersonation": 10,
    "suspicious_payment":      5,
}
COERCION_MAX: int = 100

# ---------------------------------------------------------------------------
# Input validation limits
# ---------------------------------------------------------------------------

MAX_MESSAGE_LENGTH: int = 5_000   # characters

# ---------------------------------------------------------------------------
# Context flags (these carry NO weight; documented list for validation)
# ---------------------------------------------------------------------------

CONTEXT_FLAG_NAMES: set[str] = {
    "invalid_input",
    "warning_with_request",
    "unsupported_language",
    "limited_coverage",
    "awareness_context",
    "credential_warning",
    "reported_incident",
    "security_warning",
    "benign_link_context",
    "utility_maintenance_notice",
    "otp_delivery_notice",
}

# ---------------------------------------------------------------------------
# Scripts
# ---------------------------------------------------------------------------

SUPPORTED_SCRIPTS: list[str] = ["Latin", "Devanagari", "Tamil", "Other"]

# Threshold: if fraction of word-chars in an unsupported script exceeds this,
# add "unsupported_language" context flag.
UNSUPPORTED_SCRIPT_THRESHOLD: float = 0.15
