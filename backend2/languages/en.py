"""
backend2/languages/en.py
========================
English language pack.

REVIEW_STATUS = "unreviewed"

All patterns use \\b (standard word boundary) since English is Latin-script only.
Rules are keyed to the language-independent risk flags defined in config.py.

Each rule has:
  - Plain English description
  - English gloss (example of what it matches)
  - Options: negatable, awareness_suppressible, needs_prev

Negation scope: "before" — English puts negation before the verb.
Example: "do NOT share" — negation comes before the request word.
"""

from __future__ import annotations

import re

from backend2.engine import LanguagePack, Rule, register_pack
from backend2.scripts import wb

REVIEW_STATUS = "unreviewed"


def _r(flag: str) -> str:
    """Helper: return raw regex for word-boundary wrapped flag."""
    return flag  # rules define their own patterns


# ─── Rules ────────────────────────────────────────────────────────────────────

RULES: list[Rule] = [

    # ── OTP / PIN / CVV / Credential requests ─────────────────────────────

    Rule(
        id="en_credential_01",
        language="en",
        pattern=r"\b(?:share|send|provide|submit|give|enter|type|input|reveal|disclose|tell)"
                r"[^.!?;।\n]{0,60}"
                r"\b(?:otp|pin|cvv|password|passcode|credential|secret\s+code|one[\s-]time[\s-](?:password|code))\b",
        flag="credential_request",
        category="OTP/PIN Harvesting",
        description="Request to share OTP/PIN/CVV/password",
        gloss="'share your OTP', 'provide your PIN', 'enter your password'",
        negatable=True,
    ),

    Rule(
        id="en_credential_02",
        language="en",
        pattern=r"\b(?:otp|pin|cvv|password|passcode|secret\s+code|one[\s-]time[\s-](?:password|code))"
                r"[^.!?;।\n]{0,40}"
                r"\b(?:share|send|provide|submit|give|enter|type|input|reveal|disclose)\b",
        flag="credential_request",
        category="OTP/PIN Harvesting",
        description="Credential mentioned before the action verb (request inversion)",
        gloss="'your OTP, share it now', 'PIN to submit'",
        negatable=True,
    ),

    Rule(
        id="en_otp_request_01",
        language="en",
        pattern=r"\b(?:share|send|provide|give|enter|type|input|reveal)\b[^.!?;।\n]{0,40}\botp\b",
        flag="otp_request",
        category="OTP/PIN Harvesting",
        description="Explicit request to share an OTP",
        gloss="'share your OTP', 'enter the OTP'",
        negatable=True,
    ),

    Rule(
        id="en_otp_request_02",
        language="en",
        pattern=r"\botp\b[^.!?;।\n]{0,40}\b(?:share|send|provide|give|enter|type|input)\b",
        flag="otp_request",
        category="OTP/PIN Harvesting",
        description="OTP followed by a sharing action",
        gloss="'your OTP, please enter it here'",
        negatable=True,
    ),

    # ── OTP delivery notice (context flag — NOT a scoring flag) ────────────

    Rule(
        id="en_otp_delivery_01",
        language="en",
        pattern=r"\b(?:your|the)\s+otp\s+(?:is|:)\s*[\d\u0966-\u096F\u0BE6-\u0BEF]{4,8}\b",
        flag="otp_delivery_notice",
        category="",
        description="OTP delivery: 'Your OTP is 482910' — not a scam by itself",
        gloss="'Your OTP is 482910. Use it to log in.'",
        negatable=False,
    ),

    # ── Urgency ────────────────────────────────────────────────────────────

    Rule(
        id="en_urgency_01",
        language="en",
        pattern=r"\b(?:immediately|instant(?:ly)?|right\s+now|urgent(?:ly)?|asap|"
                r"right\s+away|at\s+once|without\s+delay|expire[sd]?\s+(?:soon|today|now|in\s+\d)|"
                r"last\s+chance|act\s+now|within\s+\d+\s+(?:hour|minute|second|day)|"
                r"deadline|time\s+limit(?:ed)?)\b",
        flag="urgency",
        category="Banking Fraud",
        description="False urgency language",
        gloss="'immediately', 'act now', 'expires today'",
        negatable=False,
        awareness_suppressible=True,
    ),

    # ── Threats (account block / legal / arrest) ───────────────────────────

    Rule(
        id="en_threat_account_01",
        language="en",
        pattern=r"\b(?:account|service|access|card)\s+(?:will\s+be|has\s+been|shall\s+be|is\s+being)?"
                r"\s*(?:blocked?|suspended?|deactivated?|closed?|terminated?|disabled?|frozen?|restrict(?:ed)?)\b",
        flag="threat",
        category="Banking Fraud",
        description="Account-block threat",
        gloss="'your account will be blocked', 'access suspended'",
        negatable=False,
    ),

    Rule(
        id="en_threat_disconnect_01",
        language="en",
        pattern=r"\b(?:electricity|power|gas|water|internet|connection|service|supply)\s+"
                r"(?:will\s+be|has\s+been|shall\s+be)?\s*(?:disconnected?|cut\s+off|terminated?)\b",
        flag="threat",
        category="Utility Threat",
        description="Utility disconnection threat",
        gloss="'your electricity will be disconnected'",
        negatable=False,
    ),

    Rule(
        id="en_threat_legal_01",
        language="en",
        pattern=r"\b(?:legal\s+action|arrested?|arrest\s+warrant|fir|police\s+complaint|"
                r"court\s+order|lawsuit|imprisoned?|jail|cybercrime|cyber\s+cell|"
                r"summon(?:s|ed)?|prosecute[sd]?)\b",
        flag="threat",
        category="Authority Impersonation",
        description="Legal/arrest threat",
        gloss="'you will be arrested', 'legal action will be taken'",
        negatable=False,
    ),

    # ── KYC / Verification lures ──────────────────────────────────────────

    Rule(
        id="en_kyc_01",
        language="en",
        pattern=r"\b(?:kyc|know\s+your\s+customer|e[\s-]?kyc|re[\s-]?kyc|"
                r"verification|verify\s+your\s+(?:account|identity|details?|number)|"
                r"update\s+your\s+(?:kyc|details?|information|records?))\b",
        flag="kyc_verification",
        category="Banking Fraud",
        description="KYC or verification lure",
        gloss="'complete your KYC', 'verify your account'",
        negatable=False,
        awareness_suppressible=True,
    ),

    # ── Prize / Refund lures ───────────────────────────────────────────────

    Rule(
        id="en_prize_01",
        language="en",
        pattern=r"\b(?:won|winner|winning|lottery|prize|reward|congratulations?\s+you|"
                r"lucky\s+(?:draw|winner)|claim\s+your\s+(?:prize|reward|gift|cash)|"
                r"cash\s+(?:prize|reward|back)|refund\s+of\s+Rs|"
                r"eligible\s+for\s+(?:refund|cashback|reward))\b",
        flag="prize_refund_lure",
        category="Phishing",
        description="Prize, lottery, or refund lure",
        gloss="'you have won a prize', 'claim your refund'",
        negatable=False,
        awareness_suppressible=True,
    ),

    # ── Suspicious payment / fee demands ─────────────────────────────────

    Rule(
        id="en_payment_01",
        language="en",
        pattern=r"\b(?:processing\s+fee|registration\s+fee|tax\s+(?:clearance|deduction)|"
                r"delivery\s+charge|handling\s+fee|activation\s+fee|"
                r"pay\s+(?:now|immediately|first|Rs|₹)|"
                r"transfer\s+(?:Rs|₹|the\s+amount|funds?))\b",
        flag="payment_demand",
        category="Banking Fraud",
        description="Suspicious fee or immediate payment demand",
        gloss="'pay processing fee', 'transfer Rs 500 now'",
        negatable=False,
    ),

    Rule(
        id="en_suspicious_payment_01",
        language="en",
        pattern=r"\b(?:fine|penalty|dues|outstanding\s+amount|overdue)\b[^.!?;।\n]{0,40}\b(?:pay|clear|settle)\b",
        flag="suspicious_payment",
        category="Banking Fraud",
        description="Fine or due payment demand",
        gloss="'clear your outstanding dues', 'pay penalty now'",
        negatable=False,
    ),

    # ── Remote-access app installs ────────────────────────────────────────

    Rule(
        id="en_remote_access_01",
        language="en",
        pattern=r"\b(?:install|download|open)\b[^.!?;।\n]{0,50}"
                r"\b(?:anydesk|teamviewer|quicksupport|remote\s+(?:access|desktop|control|assist)|"
                r"screen\s+share[rd]?|screen[\s-]sharing)\b",
        flag="remote_access_app",
        category="Banking Fraud",
        description="Request to install a remote-access application",
        gloss="'install AnyDesk', 'download TeamViewer'",
        negatable=False,
    ),

    # ── Link prompts (text-side only; real link analysis = Backend 1) ─────

    Rule(
        id="en_link_prompt_01",
        language="en",
        pattern=r"\b(?:click|tap|open|visit|go\s+to|follow)\b[^.!?;।\n]{0,60}"
                r"(?:https?://|www\.|\.(?:com|org|in|net|io|co)\b|link|url)\b",
        flag="link_prompt",
        category="Phishing",
        description="Instruction to click/follow a link",
        gloss="'click this link', 'visit www.fake-bank.com'",
        negatable=False,
        awareness_suppressible=True,
    ),

    Rule(
        id="en_link_prompt_02",
        language="en",
        pattern=r"(?:https?://|www\.)[^\s\"'<>]{5,}",
        flag="link_prompt",
        category="Phishing",
        description="Bare URL in message (text-side flag only)",
        gloss="'http://bit.ly/xyz', 'www.secure-bank-update.com'",
        negatable=False,
        awareness_suppressible=True,
    ),

    # ── Authority impersonation (weak — suppressible) ─────────────────────

    Rule(
        id="en_authority_01",
        language="en",
        pattern=r"\b(?:rbi|reserve\s+bank\s+of\s+india|sebi|irdai|npci|trai|"
                r"income\s+tax\s+(?:department|dept)|it\s+department|"
                r"cbi|cid|enforcement\s+directorate|ed\b|"
                r"cyber\s+(?:crime|cell|police)|national\s+cyber|"
                r"ministry\s+of|government\s+of\s+india)\b",
        flag="authority_impersonation",
        category="Authority Impersonation",
        description="Mention of an authority name (weak signal — suppressible)",
        gloss="'RBI', 'Income Tax Department'",
        negatable=False,
        awareness_suppressible=True,
    ),

    # ── Account mention (very weak) ───────────────────────────────────────

    Rule(
        id="en_account_mention_01",
        language="en",
        pattern=r"\b(?:your\s+(?:bank\s+)?account)\b",
        flag="account_mention",
        category="Banking Fraud",
        description="Bare mention of 'your account' (very weak signal)",
        gloss="'your bank account'",
        negatable=False,
        awareness_suppressible=True,
    ),
]


# ─── Negation cue patterns ────────────────────────────────────────────────────
# English puts negation BEFORE the verb (negation_scope = "before").
# "do not hesitate to share" → negation before action → rule suppressed (correct).
# But we handle "do not hesitate to share" specially: see the composite pattern
# that excludes "hesitate" in the negation check.

NEGATION_PATTERNS: list[str] = [
    r"\b(?:do\s+not|don'?t|never|not|no|cannot|can'?t|shouldn'?t|should\s+not)\s+"
    r"(?!hesitate\b)",   # "do not hesitate to share" → NOT a negation of the request
    r"\bplease\s+(?:do\s+not|don'?t|never)\b",
    r"\bnever\s+(?:share|give|send|provide|reveal|disclose)\b",
    r"\brefrain\s+from\b",
    r"\bavoid\s+(?:sharing|giving|sending|providing)\b",
]

# ─── Contrast word patterns ───────────────────────────────────────────────────
# Split BEFORE these words.

CONTRAST_PATTERNS: list[str] = [
    r"\b(?:but|however|instead|although|whereas|yet|nevertheless|except)\b",
]

# ─── Awareness cue patterns ───────────────────────────────────────────────────

AWARENESS_PATTERNS: list[str] = [
    r"\b(?:beware|be\s+aware|stay\s+alert|caution|warning|fraud(?:ster)?s?\s+(?:often|may|might|will|can)|"
    r"scammer?s?\s+(?:often|may|might|will|can|never)|do\s+not\s+fall\s+for|"
    r"phishing|this\s+is\s+a\s+(?:scam|fraud)|protect\s+yourself|"
    r"never\s+share\s+your|(?:bank|rbi|sbi|hdfc|icici)\s+(?:never|will\s+never)\s+(?:ask|call))\b",
]

# ─── Reported speech patterns ─────────────────────────────────────────────────

REPORTED_SPEECH_PATTERNS: list[str] = [
    r"\b(?:scammer?s?|fraudster?s?|thief|thieves|attacker|hacker|criminal|they|he|she)\s+"
    r"(?:asked?|told?|said|demanded?|requested?|tried\s+to|want(?:ed)?|ask(?:ing)?)\b",
    r"\b(?:if\s+(?:someone|anyone|a\s+(?:caller?|person|stranger))\s+(?:asks?|call|tell))\b",
    r"\bsomeone\s+(?:might|may|will|can|could)\s+(?:ask|call|message|contact)\b",
    r"\b(?:a\s+(?:scam|fraud|phishing))\s+(?:message|call|email|sms)\b",
    r"\bthey\s+(?:often|may|might|will|can|never)\s+ask\s+(?:you\s+)?(?:for|to)\b",
]


# ─── Pack registration ────────────────────────────────────────────────────────

PACK = LanguagePack(
    pack_id="en",
    rules=RULES,
    negation_scope="before",
    negation_patterns=NEGATION_PATTERNS,
    contrast_patterns=CONTRAST_PATTERNS,
    sentence_enders="",
    awareness_patterns=AWARENESS_PATTERNS,
    reported_speech_patterns=REPORTED_SPEECH_PATTERNS,
)

register_pack(PACK)
