# encoding: utf-8
"""
=============================================================================
 PySustain-2026 · Backend 2 · Multilingual Scam Message Detector
 Single-file edition — everything in one file for easy submission
=============================================================================

 Hackathon : PySustain-2026 · "Tech for Social Good"
 SDGs      : No Poverty · Quality Education · Reduced Inequalities
 Component : Backend 2 — Multilingual scam-text & coercive-language detector

 Languages : English | Hindi (हिंदी) | Tamil (தமிழ்) | Hinglish | Tanglish
 Method    : Rule-based regex (no ML, no API, no external libs)
 Deps      : Python 3.10+ standard library only (+ streamlit for the demo)

=============================================================================
 HOW TO USE
=============================================================================

  # Import and call (Backend 3 integration):
  from backend2_scam_detector import analyze_text

  result = analyze_text("Your account will be blocked. Share your OTP now.")
  print(result["scam_category"])    # "OTP/PIN Harvesting"
  print(result["confidence"])       # e.g. 80.0
  print(result["coercion_score"])   # e.g. 65
  print(result["detected_phrases"]) # ["Share your OTP now"]

  # Run the demo:
  streamlit run backend2_scam_detector.py

=============================================================================
 CONTRACT (4 keys — Backend 3 depends on these, never change them)
=============================================================================
 analyze_text(message_text: str, include_details: bool = True) -> dict
 {
   "detected_phrases": [str],   # exact original substrings, unique, by position
   "scam_category":   str,      # "Banking Fraud"|"Utility Threat"|"Phishing"|
                                 # "OTP/PIN Harvesting"|"Authority Impersonation"|"Safe"
   "confidence":      float,    # 0-100 heuristic. 0.0 = NOT ANALYZED (invalid input)
   "coercion_score":  int,      # 0-100, pressure-signal intensity
 }
 confidence == 0.0 means NOT ANALYZED. Backend 3 must treat it as "no analysis",
 never as "verified safe".

=============================================================================
 REVIEW STATUS
=============================================================================
 English pack  : unreviewed
 Hindi pack    : unreviewed — NOT reviewed by a native Hindi speaker
 Tamil pack    : unreviewed — NOT reviewed by a native Tamil speaker
 Hinglish pack : unreviewed — limited coverage
 Tanglish pack : unreviewed — very limited coverage
=============================================================================
"""

from __future__ import annotations
import os, re, unicodedata
from dataclasses import dataclass, field
from typing import Optional

os.environ.setdefault("PYTHONUTF8", "1")

# ══════════════════════════════════════════════════════════════════════════════
# SECTION 1 — CONFIGURATION (all weights & thresholds in one place)
# ══════════════════════════════════════════════════════════════════════════════

CATEGORIES = [
    "Banking Fraud", "Utility Threat", "Phishing",
    "OTP/PIN Harvesting", "Authority Impersonation", "Safe",
]
CATEGORY_PRIORITY = [
    "OTP/PIN Harvesting", "Banking Fraud", "Utility Threat",
    "Authority Impersonation", "Phishing",
]

SAFE_THRESHOLD    = 25
SCORE_MAX         = 100
COMBO_CAP         = 30
MAX_MESSAGE_LENGTH = 5_000

COMBO_TABLE = [
    ("credential_request",    "urgency",            12),
    ("credential_request",    "threat",             15),
    ("credential_request",    "link_prompt",        15),
    ("otp_request",           "link_prompt",        12),
    ("urgency",               "threat",             10),
    ("urgency",               "link_prompt",        10),
    ("prize_refund_lure",     "link_prompt",        12),
    ("payment_demand",        "link_prompt",        10),
    ("kyc_verification",      "credential_request", 12),
    ("remote_access_app",     "link_prompt",        15),
    ("authority_impersonation","threat",            10),
]

FLAG_WEIGHTS = {
    "credential_request":      40,
    "otp_request":             35,
    "threat":                  30,
    "remote_access_app":       30,
    "payment_demand":          24,
    "link_prompt":             22,
    "kyc_verification":        20,
    "prize_refund_lure":       20,
    "urgency":                 15,
    "authority_impersonation": 12,
    "suspicious_payment":      10,
    "account_mention":          6,
}

RISK_LEVEL_BANDS = [(75,"critical"),(50,"high"),(25,"medium"),(0,"low")]

COERCION_FLAGS = {
    "threat": 40, "urgency": 25, "payment_demand": 20,
    "authority_impersonation": 10, "suspicious_payment": 5,
}

CONTEXT_FLAG_NAMES = {
    "invalid_input","warning_with_request","unsupported_language",
    "limited_coverage","awareness_context","credential_warning",
    "reported_incident","security_warning","benign_link_context",
    "utility_maintenance_notice","otp_delivery_notice",
}

CONFIDENCE_MIN_REAL          = 20.0
CONFIDENCE_UNSUPPORTED_CAP   = 30.0
CONFIDENCE_LIMITED_COVERAGE_CAP = 50.0
UNSUPPORTED_SCRIPT_THRESHOLD = 0.15

# ══════════════════════════════════════════════════════════════════════════════
# SECTION 2 — SCRIPT DETECTION & UNICODE BOUNDARY HELPERS
# ══════════════════════════════════════════════════════════════════════════════

_DEV = (0x0900, 0x097F)   # Devanagari
_TAM = (0x0B80, 0x0BFF)   # Tamil
_WC  = r"[A-Za-z0-9_\u0900-\u097F\u0B80-\u0BFF]"

def wb_l(p): return rf"(?<!{_WC})" + p
def wb_r(p): return p + rf"(?!{_WC})"
def wb(p):   return rf"(?<!{_WC})" + p + rf"(?!{_WC})"

def _char_script(ch):
    cp = ord(ch)
    if cp < 0x80:
        return "Latin" if (ch.isalpha() or ch.isdigit() or ch == "_") else ""
    if _DEV[0] <= cp <= _DEV[1]: return "Devanagari"
    if _TAM[0] <= cp <= _TAM[1]: return "Tamil"
    return "Other" if unicodedata.category(ch)[0] in ("L","N","M") else ""

def detect_scripts(text):
    return sorted({s for ch in text if (s := _char_script(ch))})

def script_char_fractions(text):
    counts = {}
    for ch in text:
        s = _char_script(ch)
        if s: counts[s] = counts.get(s,0) + 1
    total = sum(counts.values())
    return {s: c/total for s,c in counts.items()} if total else {}

# ══════════════════════════════════════════════════════════════════════════════
# SECTION 3 — RULE & LANGUAGE PACK DATA CLASSES
# ══════════════════════════════════════════════════════════════════════════════

@dataclass
class Rule:
    id: str; language: str; pattern: str; flag: str; category: str
    description: str; gloss: str
    negatable: bool = False; needs_prev: bool = False
    awareness_suppressible: bool = False
    _compiled: Optional[re.Pattern] = field(default=None,init=False,repr=False)
    def compiled(self, flags=re.IGNORECASE|re.UNICODE):
        if self._compiled is None:
            self._compiled = re.compile(self.pattern, flags)
        return self._compiled

@dataclass
class _Match:
    rule: Rule; start: int; end: int; clause_idx: int

@dataclass
class LanguagePack:
    pack_id: str; rules: list; negation_scope: str
    negation_patterns: list; contrast_patterns: list; sentence_enders: str
    awareness_patterns: list; reported_speech_patterns: list
    _neg: list = field(default_factory=list,init=False)
    _con: list = field(default_factory=list,init=False)
    _awa: list = field(default_factory=list,init=False)
    _rep: list = field(default_factory=list,init=False)
    def ensure_compiled(self):
        f = re.IGNORECASE|re.UNICODE
        if not self._neg: self._neg = [re.compile(p,f) for p in self.negation_patterns]
        if not self._con: self._con = [re.compile(p,f) for p in self.contrast_patterns]
        if not self._awa: self._awa = [re.compile(p,f) for p in self.awareness_patterns]
        if not self._rep: self._rep = [re.compile(p,f) for p in self.reported_speech_patterns]
    def has_negation(self,t):       self.ensure_compiled(); return any(p.search(t) for p in self._neg)
    def has_awareness(self,t):      self.ensure_compiled(); return any(p.search(t) for p in self._awa)
    def has_reported_speech(self,t):self.ensure_compiled(); return any(p.search(t) for p in self._rep)

_PACKS: list[LanguagePack] = []
def _register(pack): _PACKS.append(pack)

# ══════════════════════════════════════════════════════════════════════════════
# SECTION 4 — ENGLISH LANGUAGE PACK
# ══════════════════════════════════════════════════════════════════════════════

_EN_RULES = [
    Rule("en_credential_01","en",
         r"\b(?:share|send|provide|submit|give|enter|type|input|reveal|disclose|tell)"
         r"[^.!?;।\n]{0,60}"
         r"\b(?:otp|pin|cvv|password|passcode|credential|secret\s+code|one[\s-]time[\s-](?:password|code))\b",
         "credential_request","OTP/PIN Harvesting","Request to share OTP/PIN/CVV/password",
         "'share your OTP'",negatable=True),
    Rule("en_credential_02","en",
         r"\b(?:otp|pin|cvv|password|passcode|secret\s+code|one[\s-]time[\s-](?:password|code))"
         r"[^.!?;।\n]{0,40}"
         r"\b(?:share|send|provide|submit|give|enter|type|input|reveal|disclose)\b",
         "credential_request","OTP/PIN Harvesting","Credential before action verb",
         "'your OTP, share it now'",negatable=True),
    Rule("en_otp_request_01","en",
         r"\b(?:share|send|provide|give|enter|type|input|reveal)\b[^.!?;।\n]{0,40}\botp\b",
         "otp_request","OTP/PIN Harvesting","Explicit OTP share request","'share your OTP'",negatable=True),
    Rule("en_otp_request_02","en",
         r"\botp\b[^.!?;।\n]{0,40}\b(?:share|send|provide|give|enter|type|input)\b",
         "otp_request","OTP/PIN Harvesting","OTP then sharing action","'your OTP, enter here'",negatable=True),
    Rule("en_otp_delivery_01","en",
         r"\b(?:your|the)\s+otp\s+(?:is|:)\s*[\d\u0966-\u096F\u0BE6-\u0BEF]{4,8}\b",
         "otp_delivery_notice","","OTP delivery — not a scam","'Your OTP is 482910'",negatable=False),
    Rule("en_urgency_01","en",
         r"\b(?:immediately|instant(?:ly)?|right\s+now|urgent(?:ly)?|asap|right\s+away|at\s+once|"
         r"without\s+delay|expire[sd]?\s+(?:soon|today|now|in\s+\d)|last\s+chance|act\s+now|"
         r"within\s+\d+\s+(?:hour|minute|second|day)|deadline|time\s+limit(?:ed)?)\b",
         "urgency","Banking Fraud","False urgency","'immediately'",
         negatable=False,awareness_suppressible=True),
    Rule("en_threat_account_01","en",
         r"\b(?:account|service|access|card)\s+(?:will\s+be|has\s+been|shall\s+be|is\s+being)?"
         r"\s*(?:blocked?|suspended?|deactivated?|closed?|terminated?|disabled?|frozen?|restrict(?:ed)?)\b",
         "threat","Banking Fraud","Account-block threat","'your account will be blocked'",negatable=False),
    Rule("en_threat_disconnect_01","en",
         r"\b(?:electricity|power|gas|water|internet|connection|service|supply)\s+"
         r"(?:will\s+be|has\s+been|shall\s+be)?\s*(?:disconnected?|cut\s+off|terminated?)\b",
         "threat","Utility Threat","Utility disconnection threat","'electricity will be disconnected'",negatable=False),
    Rule("en_threat_legal_01","en",
         r"\b(?:legal\s+action|arrested?|arrest\s+warrant|fir|police\s+complaint|court\s+order|"
         r"lawsuit|imprisoned?|jail|cybercrime|cyber\s+cell|summon(?:s|ed)?|prosecute[sd]?)\b",
         "threat","Authority Impersonation","Legal/arrest threat","'you will be arrested'",negatable=False),
    Rule("en_kyc_01","en",
         r"\b(?:kyc|know\s+your\s+customer|e[\s-]?kyc|re[\s-]?kyc|verification|"
         r"verify\s+your\s+(?:account|identity|details?|number)|update\s+your\s+(?:kyc|details?|information|records?))\b",
         "kyc_verification","Banking Fraud","KYC / verification lure","'complete your KYC'",
         negatable=False,awareness_suppressible=True),
    Rule("en_prize_01","en",
         r"\b(?:won|winner|winning|lottery|prize|reward|congratulations?\s+you|lucky\s+(?:draw|winner)|"
         r"claim\s+your\s+(?:prize|reward|gift|cash)|cash\s+(?:prize|reward|back)|refund\s+of\s+Rs|"
         r"eligible\s+for\s+(?:refund|cashback|reward))\b",
         "prize_refund_lure","Phishing","Prize/lottery/refund lure","'you have won a prize'",
         negatable=False,awareness_suppressible=True),
    Rule("en_payment_01","en",
         r"\b(?:processing\s+fee|registration\s+fee|tax\s+(?:clearance|deduction)|delivery\s+charge|"
         r"handling\s+fee|activation\s+fee|pay\s+(?:now|immediately|first|Rs|₹)|"
         r"transfer\s+(?:Rs|₹|the\s+amount|funds?))\b",
         "payment_demand","Banking Fraud","Suspicious fee/payment demand","'pay processing fee'",negatable=False),
    Rule("en_remote_access_01","en",
         r"\b(?:install|download|open)\b[^.!?;।\n]{0,50}"
         r"\b(?:anydesk|teamviewer|quicksupport|remote\s+(?:access|desktop|control|assist)|"
         r"screen\s+share[rd]?|screen[\s-]sharing)\b",
         "remote_access_app","Banking Fraud","Remote-access app install request","'install AnyDesk'",negatable=False),
    Rule("en_link_prompt_01","en",
         r"\b(?:click|tap|open|visit|go\s+to|follow)\b[^.!?;।\n]{0,60}"
         r"(?:https?://|www\.|\.(?:com|org|in|net|io|co)\b|link|url)\b",
         "link_prompt","Phishing","Click/follow a link","'click this link'",
         negatable=False,awareness_suppressible=True),
    Rule("en_link_prompt_02","en",
         r"(?:https?://|www\.)[^\s\"'<>]{5,}",
         "link_prompt","Phishing","Bare URL in message","'http://bit.ly/xyz'",
         negatable=False,awareness_suppressible=True),
    Rule("en_authority_01","en",
         r"\b(?:rbi|reserve\s+bank\s+of\s+india|sebi|irdai|npci|trai|income\s+tax\s+(?:department|dept)|"
         r"it\s+department|cbi|cid|enforcement\s+directorate|ed\b|cyber\s+(?:crime|cell|police)|"
         r"national\s+cyber|ministry\s+of|government\s+of\s+india)\b",
         "authority_impersonation","Authority Impersonation","Authority name mention (weak)","'RBI'",
         negatable=False,awareness_suppressible=True),
    Rule("en_account_mention_01","en",
         r"\b(?:your\s+(?:bank\s+)?account)\b",
         "account_mention","Banking Fraud","Bare account mention (very weak)","'your bank account'",
         negatable=False,awareness_suppressible=True),
]
_register(LanguagePack("en",_EN_RULES,"before",
    negation_patterns=[
        r"\b(?:do\s+not|don'?t|never|not|no|cannot|can'?t|shouldn'?t|should\s+not)\s+(?!hesitate\b)",
        r"\bplease\s+(?:do\s+not|don'?t|never)\b",
        r"\bnever\s+(?:share|give|send|provide|reveal|disclose)\b",
        r"\brefrain\s+from\b",
        r"\bavoid\s+(?:sharing|giving|sending|providing)\b",
    ],
    contrast_patterns=[r"\b(?:but|however|instead|although|whereas|yet|nevertheless|except)\b"],
    sentence_enders="",
    awareness_patterns=[
        r"\b(?:beware|be\s+aware|stay\s+alert|caution|warning|fraud(?:ster)?s?\s+(?:often|may|might|will|can)|"
        r"scammer?s?\s+(?:often|may|might|will|can|never)|do\s+not\s+fall\s+for|phishing|"
        r"this\s+is\s+a\s+(?:scam|fraud)|protect\s+yourself|never\s+share\s+your|"
        r"(?:bank|rbi|sbi|hdfc|icici)\s+(?:never|will\s+never)\s+(?:ask|call))\b",
    ],
    reported_speech_patterns=[
        r"\b(?:scammer?s?|fraudster?s?|thief|thieves|attacker|hacker|criminal|they|he|she)\s+"
        r"(?:asked?|told?|said|demanded?|requested?|tried\s+to|want(?:ed)?|ask(?:ing)?)\b",
        r"\b(?:if\s+(?:someone|anyone|a\s+(?:caller?|person|stranger))\s+(?:asks?|call|tell))\b",
        r"\bsomeone\s+(?:might|may|will|can|could)\s+(?:ask|call|message|contact)\b",
        r"\b(?:a\s+(?:scam|fraud|phishing))\s+(?:message|call|email|sms)\b",
        r"\bthey\s+(?:often|may|might|will|can|never)\s+ask\s+(?:you\s+)?(?:for|to)\b",
    ],
))

# ══════════════════════════════════════════════════════════════════════════════
# SECTION 5 — HINDI (DEVANAGARI) PACK
# ⚠ UNREVIEWED — not checked by a native Hindi speaker
# ══════════════════════════════════════════════════════════════════════════════

_HI_SV = (r"(?:साझा\s*करें|साझा\s*करो|साझा\s*कीजिए|साझा\s*कर|बताएं|बताओ|बतायें|बताइए|बता\s*दें|"
           r"बता\s*दो|दें|दो|दीजिए|दे\s*दें|भेजें|भेजो|भेजिए|भेज\s*दें|"
           r"प्रदान\s*करें|दर्ज\s*करें|दर्ज\s*करो|दर्ज\s*कीजिए|टाइप\s*करें|सबमिट\s*करें)")
_HI_CR = (r"(?:OTP|ओटीपी|ओ\.टी\.पी\.|PIN|पिन|CVV|सीवीवी|पासवर्ड|पास\s*वर्ड|"
           r"गुप्त\s*कोड|गोपनीय\s*(?:नंबर|कोड|जानकारी)|पासकोड)")
_HI_BW = (r"(?:बंद\s*हो\s*(?:जाएगा|जाएगी|जायेगा|जायेगी|जाएंगे)|बंद\s*कर\s*(?:दिया\s*जाएगा|दिया\s*जायेगा)|"
           r"ब्लॉक\s*(?:हो|कर)\s*(?:जाएगा|दिया\s*जाएगा|दिया\s*जायेगा)|"
           r"निलंबित\s*(?:कर|हो)|निष्क्रिय\s*(?:कर|हो)|फ्रीज\s*(?:कर|हो)|बंद\s*होगा|बंद\s*होगी)")
_HI_RULES = [
    Rule("hi_credential_01","hi",wb_l(_HI_CR)+r"[^।॥\n;.!?]{0,60}"+_HI_SV,
         "credential_request","OTP/PIN Harvesting","Hindi: share OTP/PIN request","'अपना OTP साझा करें'",negatable=True),
    Rule("hi_credential_02","hi",_HI_SV+r"[^।॥\n;.!?]{0,60}"+wb_l(_HI_CR),
         "credential_request","OTP/PIN Harvesting","Hindi: verb-first credential","'साझा करें अपना OTP'",negatable=True),
    Rule("hi_otp_request_01","hi",r"(?:OTP|ओटीपी)"+r"[^।॥\n;.!?]{0,40}"+_HI_SV,
         "otp_request","OTP/PIN Harvesting","Hindi: OTP share request","'OTP साझा करें'",negatable=True),
    Rule("hi_otp_request_02","hi",_HI_SV+r"[^।॥\n;.!?]{0,40}"+r"(?:OTP|ओटीपी)",
         "otp_request","OTP/PIN Harvesting","Hindi: verb-first OTP","'साझा करें OTP'",negatable=True),
    Rule("hi_otp_delivery_01","hi",
         r"(?:आपका|आप\s+का|आपके\s+लिए)\s+(?:OTP|ओटीपी)\s+(?:है|:)\s*[\d\u0966-\u096F]{4,8}",
         "otp_delivery_notice","","Hindi OTP delivery","'आपका OTP है 482910'",negatable=False),
    Rule("hi_urgency_01","hi",
         r"(?:तुरंत|तुरन्त|अभी|फ़ौरन|फौरन|तत्काल|जल्दी\s*से|शीघ्र|जल्द\s*से\s*जल्द|अंतिम\s*(?:मौका|दिन|समय))",
         "urgency","Banking Fraud","Hindi urgency","'तुरंत'=immediately",negatable=False,awareness_suppressible=True),
    Rule("hi_threat_account_01","hi",
         r"(?:खाता|अकाउंट|सेवा|कार्ड|बिजली|गैस|पानी|कनेक्शन)\s*"+_HI_BW,
         "threat","Banking Fraud","Hindi: account block threat","'खाता बंद हो जाएगा'",negatable=False),
    Rule("hi_threat_account_02","hi",_HI_BW,
         "threat","Banking Fraud","Hindi: standalone block phrase","'बंद हो जाएगा'",negatable=False),
    Rule("hi_threat_legal_01","hi",
         r"(?:गिरफ्तार|गिरफ्तारी|FIR|एफआईआर|कानूनी\s*कार्रवाई|पुलिस|अदालत|न्यायालय|जेल|कैद|मुकदमा)",
         "threat","Authority Impersonation","Hindi: legal/arrest threat","'गिरफ्तार होगा'",negatable=False),
    Rule("hi_kyc_01","hi",
         r"(?:KYC|केवाईसी|सत्यापन\s*(?:करें|करो|कीजिए)|जानकारी\s*(?:अपडेट|सत्यापित)\s*(?:करें|करो)?)",
         "kyc_verification","Banking Fraud","Hindi: KYC lure","'KYC करें'",negatable=False,awareness_suppressible=True),
    Rule("hi_prize_01","hi",
         r"(?:जीत\s*(?:गए|गई|लिया)|पुरस्कार|इनाम|लॉटरी|राशि\s*(?:वापस|रिफंड)|रिफंड|कैशबैक|क्लेम\s*करें)",
         "prize_refund_lure","Phishing","Hindi: prize/refund lure","'जीत गए'",negatable=False,awareness_suppressible=True),
    Rule("hi_payment_01","hi",
         r"(?:भुगतान\s*(?:करें|करो|कीजिए)|शुल्क\s*(?:दें|जमा\s*करें)|राशि\s*(?:जमा\s*करें|ट्रांसफर\s*करें)|(?:जुर्माना|दंड|बकाया)\s*(?:दें|भरें|जमा\s*करें))",
         "payment_demand","Banking Fraud","Hindi: payment demand","'भुगतान करें'",negatable=False),
    Rule("hi_authority_01","hi",
         r"(?:RBI|आरबीआई|भारतीय\s*रिजर्व\s*बैंक|SBI|एसबीआई|आयकर\s*(?:विभाग|अधिकारी)|साइबर\s*(?:क्राइम|सेल|पुलिस)|भारत\s*सरकार)",
         "authority_impersonation","Authority Impersonation","Hindi: authority name (weak)","'RBI'",negatable=False,awareness_suppressible=True),
]
_register(LanguagePack("hi",_HI_RULES,"either",
    negation_patterns=[
        r"(?:^|[\s।\n])(?:न\s+करें|न\s+करो|न\s+कीजिए|मत\s+करो|मत\s+दें|मत\s+बताएं)(?:\s|$|[।!?])",
        r"(?:साझा|बताएं?|दें|भेजें?)\s+न\s+(?:करें|करो|कीजिए)",
        r"(?:कभी\s+(?:न|नहीं)|नहीं\s+(?:करना|देना|बताना|भेजना))",
        r"किसी\s+(?:के\s+साथ\s+)?(?:साझा\s+न|न\s+बताएं|न\s+दें)",
        r"(?<!\w)न\s+(?:करें|करो|दें|बताएं|भेजें)(?!\w)",
    ],
    contrast_patterns=[r"(?:लेकिन|परंतु|मगर|बल्कि|किंतु|तथापि|पर\b)"],
    sentence_enders="।॥",
    awareness_patterns=[
        r"(?:सावधान|सचेत|सतर्क|धोखाधड़ी\s*(?:से\s+बचें|है)|फर्जी|स्कैम|घोटाला|ठगी|जालसाज़ी|"
        r"(?:बैंक|RBI|SBI)\s+(?:कभी\s+नहीं|नहीं)\s+(?:मांगता|पूछता|मांगेगा)|साझा\s+न\s+करें|किसी\s+को\s+न\s+बताएं)",
    ],
    reported_speech_patterns=[
        r"(?:जालसाज़|ठग|स्कैमर|धोखेबाज|अपराधी|वो|उसने|उन्होंने)\s+(?:कहा|माँगा|मांगा|पूछा|बोला|कहते\s+हैं|करते\s+हैं)",
        r"(?:अगर\s+कोई|कोई\s+भी|कोई\s+अजनबी)\s+(?:मांगे|पूछे|कहे|फोन\s+करे)",
        r"(?:फर्जी|नकली)\s+(?:कॉल|संदेश|SMS)\s+(?:आ\s+(?:सकता|सकती)|में)",
    ],
))

# ══════════════════════════════════════════════════════════════════════════════
# SECTION 6 — TAMIL PACK
# ⚠ UNREVIEWED — not checked by a native Tamil speaker
# ══════════════════════════════════════════════════════════════════════════════

_TA_SFX = r"(?:[-ஐஓடுக்குகளையும்]*)"
_TA_SV  = (r"(?:பகிருங்கள்|பகிரவும்|பகிர்க|பகிரு(?:ங்கள்)?|கொடுங்கள்|கொடுக்கவும்|தாருங்கள்|தருக|"
            r"சொல்லுங்கள்|சொல்லவும்|கூறுங்கள்|உள்ளிடுங்கள்|உள்ளிடவும்|"
            r"டைப்\s*செய்யுங்கள்|அனுப்புங்கள்|அனுப்பவும்|சமர்ப்பிக்கவும்|சமர்ப்பிங்கள்)")
_TA_CR  = (r"(?:OTP"+_TA_SFX+r"|ஓடிபி"+_TA_SFX+r"|PIN"+_TA_SFX+r"|CVV"+_TA_SFX+
            r"|கடவுச்சொல்"+_TA_SFX+r"|இரகசிய\s*(?:எண்|குறியீடு)"+_TA_SFX+r"|பின்\s*எண்"+_TA_SFX+r")")
_TA_BW  = (r"(?:முடக்கப்படும்|முடக்கப்படுவீர்கள்|முடக்கப்படுவது|நிறுத்தப்படும்|"
            r"நிறுத்தப்படுவீர்கள்|தடை\s*செய்யப்படும்|தடுக்கப்படும்|"
            r"ரத்து\s*செய்யப்படும்|நிறுத்தி\s*வைக்கப்படும்|முடக்கி\s*வைக்கப்படும்)")
_TA_RULES = [
    Rule("ta_credential_01","ta",_TA_CR+r"[^.!?;\n]{0,60}"+_TA_SV,
         "credential_request","OTP/PIN Harvesting","Tamil: share OTP/PIN","'OTP-ஐ பகிருங்கள்'",negatable=True),
    Rule("ta_credential_02","ta",_TA_SV+r"[^.!?;\n]{0,60}"+_TA_CR,
         "credential_request","OTP/PIN Harvesting","Tamil: verb-first credential","'கொடுங்கள் OTP'",negatable=True),
    Rule("ta_otp_request_01","ta",r"(?:OTP"+_TA_SFX+r"|ஓடிபி"+_TA_SFX+r")"+r"[^.!?;\n]{0,50}"+_TA_SV,
         "otp_request","OTP/PIN Harvesting","Tamil: OTP share","'OTP-ஐ பகிருங்கள்'",negatable=True),
    Rule("ta_otp_delivery_01","ta",
         r"(?:உங்கள்|உங்களுடைய)\s+(?:OTP|ஓடிபி)\s*(?::|ஆனது|என்பது)?\s*[\d\u0BE6-\u0BEF]{4,8}",
         "otp_delivery_notice","","Tamil OTP delivery","'உங்கள் OTP 482910'",negatable=False),
    Rule("ta_urgency_01","ta",
         r"(?:உடனே|உடனடியாக|இப்போதே|தாமதமின்றி|விரைவாக|கடைசி\s*(?:வாய்ப்பு|நேரம்)|இறுதி\s*(?:வாய்ப்பு|தேதி))",
         "urgency","Banking Fraud","Tamil urgency","'உடனே'=immediately",negatable=False,awareness_suppressible=True),
    Rule("ta_threat_account_01","ta",
         r"(?:கணக்கு|வங்கி\s*கணக்கு|சேவை|அட்டை|மின்சாரம்|இணைப்பு)"+_TA_SFX+r"[^.!?;\n]{0,20}"+_TA_BW,
         "threat","Banking Fraud","Tamil: account block threat","'கணக்கு முடக்கப்படும்'",negatable=False),
    Rule("ta_threat_account_02","ta",_TA_BW,
         "threat","Banking Fraud","Tamil: standalone block","'முடக்கப்படும்'",negatable=False),
    Rule("ta_threat_legal_01","ta",
         r"(?:கைது|கைதுசெய்யப்படுவீர்கள்|FIR|சட்ட\s*நடவடிக்கை|கோர்ட்|நீதிமன்றம்|சிறை|போலீஸ்|குற்றவியல்\s*வழக்கு)",
         "threat","Authority Impersonation","Tamil: legal/arrest","'கைது'",negatable=False),
    Rule("ta_kyc_01","ta",
         r"(?:KYC"+_TA_SFX+r"|சரிபார்ப்பு|சரிபார்க்கவும்|கணக்கை\s*(?:சரிபார்க்க|புதுப்பிக்க|அப்டேட்)|விவரங்களை\s*(?:புதுப்பிக்க|சமர்ப்பிக்க))",
         "kyc_verification","Banking Fraud","Tamil: KYC lure","'KYC சரிபார்க்கவும்'",negatable=False,awareness_suppressible=True),
    Rule("ta_prize_01","ta",
         r"(?:வென்றீர்கள்|வெற்றி\s*பெற்றீர்கள்|பரிசு|லாட்டரி|பணம்\s*திரும்பப்\s*பெற|ரிஃபண்ட்|கேஷ்\s*பேக்|அதிர்ஷ்ட\s*வெற்றியாளர்)",
         "prize_refund_lure","Phishing","Tamil: prize/refund","'வென்றீர்கள்'",negatable=False,awareness_suppressible=True),
    Rule("ta_payment_01","ta",
         r"(?:கட்டணம்\s*(?:செலுத்துங்கள்|கட்டவும்)|தொகையை\s*(?:செலுத்துங்கள்|அனுப்புங்கள்)|அபராதம்\s*(?:செலுத்துங்கள்|கட்டவும்))",
         "payment_demand","Banking Fraud","Tamil: payment demand","'கட்டணம் செலுத்துங்கள்'",negatable=False),
    Rule("ta_authority_01","ta",
         r"(?:RBI|இந்திய\s*ரிசர்வ்\s*வங்கி|வங்கி\s*(?:அதிகாரி|மேலாளர்)|வருமான\s*வரி|சைபர்\s*(?:க்ரைம்|போலீஸ்)|இந்திய\s*அரசு)",
         "authority_impersonation","Authority Impersonation","Tamil: authority (weak)","'RBI'",negatable=False,awareness_suppressible=True),
]
_register(LanguagePack("ta",_TA_RULES,"after",
    negation_patterns=[
        r"வேண்டாம்",r"(?:பகிர|கொடுக்க|சொல்ல|அனுப்ப)\s+வேண்டாம்",
        r"(?:பகிராதீர்கள்|கொடுக்காதீர்கள்|சொல்லாதீர்கள்|அனுப்பாதீர்கள்)",
        r"யாருடனும்\s+(?:பகிர|கொடுக்க|சொல்ல)\s+வேண்டாம்",r"(?:இல்லை|வேண்டா(?:ம்)?)",
    ],
    contrast_patterns=[r"(?:ஆனால்|மாறாக|இருப்பினும்|எனினும்)"],
    sentence_enders="",
    awareness_patterns=[
        r"(?:எச்சரிக்கை|கவனமாக|விழிப்புடன்|ஏமாறாதீர்கள்|மோசடி|ஸ்கேம்|போலி\s*(?:அழைப்பு|செய்தி)|"
        r"வங்கி\s+(?:எப்போதும்\s+)?(?:கேட்காது|கேட்பதில்லை)|யாருடனும்\s+பகிர\s+வேண்டாம்)",
    ],
    reported_speech_patterns=[
        r"(?:மோசடிக்காரர்கள்|ஏமாற்றுபவர்கள்|கள்வர்கள்)\s+(?:கேட்பார்கள்|கேட்கிறார்கள்|கேட்கலாம்|கேட்டார்கள்)",
        r"(?:யாரேனும்|யாராவது|அந்நியர்)\s+(?:கேட்டால்|அழைத்தால்)",
        r"(?:மோசடி|போலி)\s+(?:அழைப்பு|செய்தி|SMS)\s+(?:வரலாம்|வரும்)",
    ],
))

# ══════════════════════════════════════════════════════════════════════════════
# SECTION 7 — HINGLISH (ROMANIZED HINDI) PACK
# ⚠ UNREVIEWED — limited coverage
# ══════════════════════════════════════════════════════════════════════════════

_HILN_SV = (r"(?:share\s*(?:karo|karein|kariye|kijiye|karna)|batao|bataiye|batayein|bata\s*do|"
             r"bhejo|bhejiye|bhejein|bhej\s*do|dena|dijiye|de\s*do|"
             r"send\s*(?:karo|karein|kariye)|enter\s*(?:karo|karein|kijiye)?|"
             r"type\s*(?:karo|karein)?|provide\s*(?:karo|karein)?)")
_HILN_CR = r"(?:otp|pin|cvv|password|passcode|secret\s*code|one[\s-]time[\s-](?:password|code))"
_HILN_RULES = [
    Rule("hi_latn_credential_01","hi-Latn",_HILN_CR+r"[^.!?;\n]{0,50}"+_HILN_SV,
         "credential_request","OTP/PIN Harvesting","Hinglish: share OTP","'apna OTP share karein'",negatable=True),
    Rule("hi_latn_credential_02","hi-Latn",_HILN_SV+r"[^.!?;\n]{0,50}"+_HILN_CR,
         "credential_request","OTP/PIN Harvesting","Hinglish: verb-first","'share karo apna OTP'",negatable=True),
    Rule("hi_latn_otp_01","hi-Latn",r"\botp\b[^.!?;\n]{0,40}"+_HILN_SV,
         "otp_request","OTP/PIN Harvesting","Hinglish: OTP share","'OTP share karein'",negatable=True),
    Rule("hi_latn_urgency_01","hi-Latn",
         r"\b(?:turant|turanth?|abhi|jaldi|jaldi\s*se|phoran|forun|tatkal|last\s*chance|aakhri\s*(?:mauka|din))\b",
         "urgency","Banking Fraud","Hinglish urgency","'turant'=immediately",negatable=False,awareness_suppressible=True),
    Rule("hi_latn_threat_01","hi-Latn",
         r"\b(?:account|khata)\s+(?:block|band|suspend|close|deactivate|freeze)\s*"
         r"(?:ho\s+(?:jayega|jayegi|jaega|jaegi|gaya|gayi)|kar\s+(?:diya\s+)?(?:jayega|jaega)|hoga|hogi)\b",
         "threat","Banking Fraud","Hinglish: account block","'account block ho jayega'",negatable=False),
    Rule("hi_latn_threat_legal_01","hi-Latn",
         r"\b(?:giraftaar|giraftari|FIR|police\s*complaint|kanuni\s*(?:karwai|action)|court|jail|arrest\s*(?:ho|kar))\b",
         "threat","Authority Impersonation","Hinglish: legal threat","'giraftaar hoga'",negatable=False),
    Rule("hi_latn_kyc_01","hi-Latn",r"\b(?:kyc|e-?kyc|re-?kyc|verification|verify\s*(?:karo|karein)?)\b",
         "kyc_verification","Banking Fraud","Hinglish: KYC","'KYC karein'",negatable=False,awareness_suppressible=True),
    Rule("hi_latn_prize_01","hi-Latn",
         r"\b(?:jeet\s*(?:gaye|gayi|liya)|inaam|prize|lottery|refund\s*(?:milega|aayega)|cashback|lucky\s*winner|claim\s*(?:karo|karein))\b",
         "prize_refund_lure","Phishing","Hinglish: prize/refund","'jeet gaye'",negatable=False,awareness_suppressible=True),
    Rule("hi_latn_payment_01","hi-Latn",
         r"\b(?:(?:Rs\.?\s*\d|rupay?e?|amount)\s*(?:bhejo|bhejiye|transfer|pay)|shulk\s*(?:do|dena|bharo)|jurmana\s*(?:bharo|do|pay)|(?:payment|fees?)\s*(?:karo|karein|kijiye)?)\b",
         "payment_demand","Banking Fraud","Hinglish: payment","'Rs 500 bhejo'",negatable=False),
]
_register(LanguagePack("hi-Latn",_HILN_RULES,"either",
    negation_patterns=[
        r"\b(?:mat|nahi|nahin|na|kabhi\s*(?:mat|nahi|na))\b",
        r"\b(?:share\s*mat|mat\s*share|na\s*karo|nahi\s*karna)\b",
        r"\bkisi\s*(?:ko|ke\s*sath)\s*(?:share|bata|do)\s*(?:mat|na|nahi)\b",
    ],
    contrast_patterns=[r"\b(?:lekin|magar|balki|parantu|kintu|par\b|phir\s*bhi)\b"],
    sentence_enders="",
    awareness_patterns=[
        r"\b(?:sawdhan|savdhan|sacheth?|alert\s*(?:raho|rahein)|dhokha(?:dhadi)?|scam|fraud|phishing|(?:bank|rbi)\s*(?:kabhi\s*)?(?:nahi|nahin)\s*(?:mangta|maangta|poochta))\b",
    ],
    reported_speech_patterns=[
        r"\b(?:scammer|fraud(?:ster)?|thag|dhokhebaaz)\s+(?:bolte|maangte|kahte|kehte|poochte)\s+(?:hain|hai|hein)\b",
        r"\b(?:agar\s*koi|koi\s*bhi|koi\s*anjaan)\s+(?:maange|poochhe|kahe)\b",
        r"\bfake\s+(?:call|message|sms)\b",
    ],
))

# ══════════════════════════════════════════════════════════════════════════════
# SECTION 8 — TANGLISH (ROMANIZED TAMIL) PACK
# ⚠ UNREVIEWED — very limited coverage
# ══════════════════════════════════════════════════════════════════════════════

_TALN_SV = (r"(?:anuppunga|anupunga|anuppu(?:nga)?|kuduppinga|kudunga|koduppinga|"
             r"sollunga|solunga|pagirunga|pagir(?:unga)?|share\s*pannunga|share\s*pannu|"
             r"type\s*pannunga|enter\s*pannunga|submit\s*pannunga)")
_TALN_CR = r"(?:otp|pin|cvv|password|passcode|secret\s*code)"
_TALN_RULES = [
    Rule("ta_latn_credential_01","ta-Latn",_TALN_CR+r"[^.!?;\n]{0,50}"+_TALN_SV,
         "credential_request","OTP/PIN Harvesting","Tanglish: share OTP","'OTP anuppunga'",negatable=True),
    Rule("ta_latn_credential_02","ta-Latn",_TALN_SV+r"[^.!?;\n]{0,50}"+_TALN_CR,
         "credential_request","OTP/PIN Harvesting","Tanglish: verb-first","'anuppunga ungal OTP'",negatable=True),
    Rule("ta_latn_otp_01","ta-Latn",r"\botp\b[^.!?;\n]{0,40}"+_TALN_SV,
         "otp_request","OTP/PIN Harvesting","Tanglish: OTP send","'OTP anuppunga'",negatable=True),
    Rule("ta_latn_urgency_01","ta-Latn",
         r"\b(?:udane|udaney|udanadiyaka|ippothe|ippodhe|ippe|undan|last\s*chance|kadasi\s*(?:vayppu|neram))\b",
         "urgency","Banking Fraud","Tanglish urgency","'udane'=immediately",negatable=False,awareness_suppressible=True),
    Rule("ta_latn_threat_01","ta-Latn",
         r"\b(?:account|kanakku)\s+(?:block|mudakka|mudakkam|suspend|close)\s*(?:aagum|aagidum|aayidum|aavadu|pannuvom|seiyappadum)\b",
         "threat","Banking Fraud","Tanglish: account block","'account block aagum'",negatable=False),
    Rule("ta_latn_threat_legal_01","ta-Latn",
         r"\b(?:kaidu|kaidhuseyappaduveergal|FIR|police\s*complaint|court|siragai|sattam\s*nada(?:vadi)?kai|arrest)\b",
         "threat","Authority Impersonation","Tanglish: legal threat","'kaidu'=arrest",negatable=False),
    Rule("ta_latn_payment_01","ta-Latn",
         r"\b(?:kattanam\s*(?:kattu|seluttu|pay)|thokai\s*(?:anuppu|anuppunga|transfer)|aradam\s*(?:kattu|seluttu)|(?:payment|fees?)\s*(?:pannunga|seiyunga))\b",
         "payment_demand","Banking Fraud","Tanglish: payment","'kattanam kattunga'",negatable=False),
]
_register(LanguagePack("ta-Latn",_TALN_RULES,"after",
    negation_patterns=[
        r"\b(?:pannaadheenga|pannatheenga|kudukkathe|solladheenga|anuppaadheenga|share\s*pannaadheenga|venda(?:am)?|yarukkum\s+(?:solladheega|kudukkathe|share\s+pannaadheenga))\b",
    ],
    contrast_patterns=[r"\b(?:aana[l]?|maaraaga|innum|eppovum|irundhalum)\b"],
    sentence_enders="",
    awareness_patterns=[
        r"\b(?:eccharikkai|kavanama|vilippu(?:narvu)?|mosadi|scam|fraud|fake\s*(?:call|message)|bank\s+(?:eppozhum\s+)?(?:ketkadhu|kettadhu|kettuvom))\b",
    ],
    reported_speech_patterns=[
        r"\b(?:mosadi|scammer|fraud(?:ster)?)\s+(?:kettpangal|ketpangal|sollepangal|solluvangal)\b",
        r"\b(?:yaaravadhu|edhaavadhu|anjaan)\s+(?:kettaal|solilaal)\b",
        r"\bfake\s+(?:call|message|sms)\b",
    ],
))

# ══════════════════════════════════════════════════════════════════════════════
# SECTION 9 — CORE ENGINE
# ══════════════════════════════════════════════════════════════════════════════

_URL_LIKE  = re.compile(r"https?://\S+|www\.\S+|\S+\.(com|org|net|in|io|co)\S*", re.IGNORECASE)
_RS_ABBREV = re.compile(r"\bRs\.\s*\d", re.IGNORECASE)

def _split_clauses(text, contrast_pats):
    n = len(text)
    protected = [(m.start(),m.end()) for m in _URL_LIKE.finditer(text)]
    protected += [(m.start(),m.end()) for m in _RS_ABBREV.finditer(text)]
    def protected_pos(pos): return any(s<=pos<e for s,e in protected)
    splits = {0}
    for m in re.finditer(r"[.!?।॥\n;]", text, re.UNICODE):
        if not protected_pos(m.start()): splits.add(m.end())
    for pat in contrast_pats:
        for m in pat.finditer(text):
            if not protected_pos(m.start()): splits.add(m.start())
    splits.add(n)
    result = []
    for a,b in zip(sorted(splits), sorted(splits)[1:]):
        seg = text[a:b]
        if seg.strip(): result.append((seg,a))
    return result or [(text,0)]

def _nfc_offsets(text):
    nfc = unicodedata.normalize("NFC", text)
    if len(nfc) == len(text): return nfc, list(range(len(text)))
    omap, oi = [], 0
    for ni in range(len(nfc)):
        for k in range(1, len(text)-oi+1):
            if len(unicodedata.normalize("NFC", text[oi:oi+k])) >= ni-len(omap)+1:
                omap.append(oi); oi = oi+k-(len(unicodedata.normalize("NFC",text[oi:oi+k]))-1); break
        else: omap.append(oi)
    while len(omap)<len(nfc): omap.append(len(text)-1)
    return nfc, omap

def _strip_zwj(t): return t.replace("\u200C","").replace("\u200D","")

def _no_zwj_orig(pos, src):
    s = 0
    for i,ch in enumerate(src):
        if ch in "\u200C\u200D": continue
        if s==pos: return i
        s+=1
    return len(src)

def _run_pack(pack, clause_text, clause_start, clause_idx, prev_hit):
    pack.ensure_compiled()
    no_zwj = _strip_zwj(clause_text)
    nfc, omap = _nfc_offsets(no_zwj)
    has_neg = pack.has_negation(clause_text)
    has_awa = pack.has_awareness(clause_text)
    has_rep = pack.has_reported_speech(clause_text)
    matches = []
    for rule in pack.rules:
        if rule.needs_prev and not prev_hit: continue
        if rule.awareness_suppressible and has_awa: continue
        if rule.negatable and has_rep: continue
        for m in rule.compiled().finditer(nfc):
            rs, re_ = m.start(), m.end()
            zs = omap[rs] if rs<len(omap) else rs
            ze = (omap[re_-1]+1 if re_>0 and re_-1<len(omap) else len(no_zwj))
            os_ = _no_zwj_orig(zs, clause_text) + clause_start
            oe  = _no_zwj_orig(ze, clause_text) + clause_start
            ml  = clause_start+len(clause_text)
            os_ = max(0,min(os_,ml)); oe = max(os_,min(oe,ml))
            if rule.negatable and has_neg:
                neu = False
                if pack.negation_scope=="either": neu=True
                elif pack.negation_scope=="before": neu=any(p.search(clause_text[:m.start()]) for p in pack._neg)
                elif pack.negation_scope=="after":  neu=any(p.search(clause_text[m.end():]) for p in pack._neg)
                if neu: continue
            matches.append(_Match(rule,os_,oe,clause_idx))
    return matches

def _merge_overlapping(matches):
    by_flag = {}
    for m in matches: by_flag.setdefault(m.rule.flag,[]).append(m)
    result = []
    for fl, fms in by_flag.items():
        fms.sort(key=lambda m:(m.start,-m.end,m.rule.id))
        merged = []
        for m in fms:
            if merged and m.start<merged[-1].end:
                if m.end>merged[-1].end: merged[-1]=m
                elif m.end==merged[-1].end and m.rule.id<merged[-1].rule.id: merged[-1]=m
            else: merged.append(m)
        result.extend(merged)
    return result

def _cat_prio(cat):
    try: return CATEGORY_PRIORITY.index(cat)
    except ValueError: return len(CATEGORY_PRIORITY)

def _dedup_flags(matches):
    best = {}
    for m in matches:
        f = m.rule.flag
        if f not in best: best[f]=m
        else:
            np_=_cat_prio(m.rule.category); pp=_cat_prio(best[f].rule.category)
            if np_<pp or (np_==pp and m.rule.id<best[f].rule.id): best[f]=m
    return best

def _score(flag_best):
    scoring = {f:m for f,m in flag_best.items() if f not in CONTEXT_FLAG_NAMES}
    base = sum(FLAG_WEIGHTS.get(f,0) for f in scoring)
    present = set(scoring); bonus = 0; pairs = set()
    for fa,fb,b in COMBO_TABLE:
        pair=(min(fa,fb),max(fa,fb))
        if pair not in pairs and fa in present and fb in present:
            bonus+=b; pairs.add(pair)
    return max(0,min(SCORE_MAX, base+min(bonus,COMBO_CAP)))

def _coercion(flag_best):
    return max(0,min(100,sum(COERCION_FLAGS[f] for f in flag_best if f in COERCION_FLAGS)))

def _category(flag_best, score):
    if score<SAFE_THRESHOLD: return "Safe"
    cw={}
    for f,m in flag_best.items():
        if f in CONTEXT_FLAG_NAMES or not m.rule.category: continue
        cw[m.rule.category]=cw.get(m.rule.category,0)+FLAG_WEIGHTS.get(f,0)
    if not cw: return "Safe"
    mx=max(cw.values()); tops=[c for c,w in cw.items() if w==mx]
    if len(tops)==1: return tops[0]
    for c in CATEGORY_PRIORITY:
        if c in tops: return c
    return tops[0]

def _confidence(score, flag_best, ctx_flags, packs_matched):
    scoring={f for f in flag_best if f not in CONTEXT_FLAG_NAMES}
    base=score*0.40
    ev_bonus=min(len(scoring)*8.0,30.0)
    cw={}
    for f,m in flag_best.items():
        if f in CONTEXT_FLAG_NAMES or not m.rule.category: continue
        cw[m.rule.category]=cw.get(m.rule.category,0)+FLAG_WEIGHTS.get(f,0)
    margin=10.0 if (len(cw)>=2 and sorted(cw.values(),reverse=True)[0]-sorted(cw.values(),reverse=True)[1]>=10) or len(cw)==1 else 0
    borderline=10.0 if SAFE_THRESHOLD<=score<=SAFE_THRESHOLD+10 else 0
    ambiguity=8.0 if "warning_with_request" in ctx_flags else 0
    non_en=15.0 if packs_matched and not(packs_matched&{"en"}) else 0
    conf=base+ev_bonus+margin-borderline-ambiguity-non_en
    if "unsupported_language" in ctx_flags: conf=min(conf,CONFIDENCE_UNSUPPORTED_CAP)
    if "limited_coverage"     in ctx_flags: conf=min(conf,CONFIDENCE_LIMITED_COVERAGE_CAP)
    return max(CONFIDENCE_MIN_REAL,min(100.0,conf))

def _risk_level(score):
    for thr,lbl in RISK_LEVEL_BANDS:
        if score>=thr: return lbl
    return "low"

def _phrases(flag_best, original):
    seen={}
    for f,m in flag_best.items():
        if f in CONTEXT_FLAG_NAMES: continue
        ph=original[m.start:m.end]
        if ph and ph not in seen: seen[ph]=m.start
    return [t for t,_ in sorted(seen.items(),key=lambda x:x[1])]

_ACTIONS={
    "OTP/PIN Harvesting":["Never share your OTP, PIN, or password with anyone.",
        "Hang up and call your bank's official number.",
        "Report to National Cyber Crime Helpline: 1930."],
    "Banking Fraud":["Do not click any links or call numbers in this message.",
        "Contact your bank directly via the official website.",
        "Report to National Cyber Crime Helpline: 1930."],
    "Utility Threat":["Utility companies don't threaten via unsolicited SMS.",
        "Call your provider using the number on your bill.","Report to 1930."],
    "Authority Impersonation":["Verify through official government channels.",
        "Real authorities don't demand credentials via SMS.","Report to 1930."],
    "Phishing":["Do not click any links in this message.",
        "Go directly to the official website.","Report to 1930."],
    "Safe":["No specific scam signals found. Always verify unexpected messages through official channels."],
}

def _invalid_response(include_details):
    r={"detected_phrases":[],"scam_category":"Safe","confidence":0.0,"coercion_score":0}
    if include_details:
        r.update({"risk_level":"low","risk_flags":[],"context_flags":["invalid_input"],
                  "matched_rules":[],"explanations":[],
                  "recommended_actions":["This message could not be analyzed (invalid or missing input)."],
                  "scripts_detected":[],"language_packs_matched":[]})
    return r

# ══════════════════════════════════════════════════════════════════════════════
# SECTION 10 — PUBLIC API
# ══════════════════════════════════════════════════════════════════════════════

def analyze_text(message_text: str, include_details: bool = True) -> dict:
    """
    Analyze a message for scam signals.

    Returns dict with 4 contract keys (always):
      detected_phrases, scam_category, confidence, coercion_score

    With include_details=True, adds diagnostic fields.

    INVALID INPUT (None, non-str, empty/whitespace, >5000 chars):
      → confidence=0.0, scam_category='Safe' (NOT ANALYZED — not verified safe)
    """
    if (message_text is None or not isinstance(message_text,str)
            or not message_text.strip() or len(message_text)>MAX_MESSAGE_LENGTH):
        return _invalid_response(include_details)

    original = message_text
    scripts  = detect_scripts(original)
    fracs    = script_char_fractions(original)

    for p in _PACKS: p.ensure_compiled()
    all_contrast = [pat for p in _PACKS for pat in p._con]
    clauses = _split_clauses(original, all_contrast)

    raw_matches=[]; prev_hit=False
    for ci,(ct,cs) in enumerate(clauses):
        cm=[]
        for pack in _PACKS: cm.extend(_run_pack(pack,ct,cs,ci,prev_hit))
        raw_matches.extend(cm); prev_hit=bool(cm)

    merged   = _merge_overlapping(raw_matches)
    scoring  = [m for m in merged if m.rule.flag not in CONTEXT_FLAG_NAMES]
    ctx_raw  = {m.rule.flag for m in merged if m.rule.flag in CONTEXT_FLAG_NAMES}

    flag_best = _dedup_flags(scoring)
    ctx_flags = set(ctx_raw)

    if fracs.get("Other",0)>=UNSUPPORTED_SCRIPT_THRESHOLD:
        ctx_flags.add("unsupported_language")
    if not flag_best and (fracs.get("Devanagari",0)+fracs.get("Tamil",0))>0.3:
        ctx_flags.add("limited_coverage")

    live_req={"credential_request","otp_request","link_prompt","remote_access_app","payment_demand"}
    if (flag_best.keys()&live_req) and any(
        any(p.search(ct) for p in pack._awa) for pack in _PACKS for ct,_ in clauses):
        ctx_flags.add("warning_with_request")

    score    = _score(flag_best)
    cat      = _category(flag_best,score)
    coerce   = _coercion(flag_best)
    packs_matched = {m.rule.language for m in merged}
    conf     = _confidence(score,flag_best,ctx_flags,packs_matched)
    phrases  = _phrases(flag_best,original)

    result={"detected_phrases":phrases,"scam_category":cat,
            "confidence":round(conf,1),"coercion_score":coerce}

    if include_details:
        def _flag_key(f): return (-FLAG_WEIGHTS.get(f,0),f)
        risk_flags=sorted([f for f in flag_best if f not in CONTEXT_FLAG_NAMES],key=_flag_key)
        rule_pos={}
        for m in merged:
            if m.rule.id not in rule_pos or m.start<rule_pos[m.rule.id]: rule_pos[m.rule.id]=m.start
        matched_rules=sorted(rule_pos,key=lambda r:(rule_pos[r],r))
        actions=list(_ACTIONS.get(cat,[]))
        if "warning_with_request" in ctx_flags:
            actions=["This message mixes a warning with a suspicious request — treat the request as suspicious."]+actions
        if "unsupported_language" in ctx_flags:
            actions.append("This message contains text in a script this tool doesn't fully analyze. Treat with caution.")
        if "limited_coverage" in ctx_flags:
            actions.append("Coverage for Hindi/Tamil/romanized text is limited. Seek a native-speaker review if unsure.")
        result.update({
            "risk_level":_risk_level(score),
            "risk_flags":risk_flags,
            "context_flags":sorted(ctx_flags),
            "matched_rules":matched_rules,
            "explanations":[{"flag":f,"reason":m.rule.description} for f,m in sorted(flag_best.items()) if f not in CONTEXT_FLAG_NAMES],
            "recommended_actions":actions,
            "scripts_detected":scripts,
            "language_packs_matched":sorted(packs_matched),
        })
    return result

# ══════════════════════════════════════════════════════════════════════════════
# SECTION 11 — STREAMLIT DEMO  (only runs when: streamlit run backend2_scam_detector.py)
# ══════════════════════════════════════════════════════════════════════════════

def _run_demo():
    import streamlit as st
    st.set_page_config(page_title="PySustain-2026 · Scam Detector",page_icon="🛡️",layout="centered")
    SAMPLES={
        "— select a sample —":"",
        "English scam (OTP + threat)":"Your account will be blocked immediately. Share your OTP now to avoid suspension.",
        "English warning (Safe)":"Beware of scammers! RBI never asks for your OTP or password. Stay alert.",
        "Hindi scam · हिंदी घोटाला":"आपका बैंक खाता बंद हो जाएगा। तुरंत अपना OTP साझा करें।",
        "Hindi warning (Safe)":"अपना OTP किसी के साथ साझा न करें।",
        "Tamil scam · தமிழ் மோசடி":"உங்கள் வங்கி கணக்கு முடக்கப்படும். உடனே உங்கள் OTP-ஐ பகிருங்கள்.",
        "Tamil warning (Safe)":"உங்கள் OTP-ஐ யாருடனும் பகிர வேண்டாம்.",
        "Hinglish scam":"Aapka account block ho jayega. Turant apna OTP share karein.",
        "Tanglish scam":"Ungal account block aayidum. Udane OTP anuppunga.",
        "OTP delivery (Safe)":"Your OTP is 482910. Use it to log in. Do not share it with anyone.",
        "Code-mixed (Hindi+English)":"Your account is at risk. अपना OTP अभी साझा करें।",
    }
    RC={"low":"#2E7D32","medium":"#F57F17","high":"#C62828","critical":"#6A1B9A"}
    RE_={"low":"🟢","medium":"🟡","high":"🔴","critical":"🟣"}
    CE={"Banking Fraud":"🏦","Utility Threat":"⚡","Phishing":"🎣",
        "OTP/PIN Harvesting":"🔑","Authority Impersonation":"👮","Safe":"✅"}
    def hl(msg,phrases):
        for p in sorted(phrases,key=len,reverse=True):
            if p: msg=re.sub(re.escape(p),lambda m:f'<mark style="background:#FFD700;border-radius:3px;padding:1px 3px">{m.group()}</mark>',msg)
        return msg
    st.title("🛡️ PySustain-2026 · Scam Message Detector")
    st.caption("Backend 2 · Multilingual scam-text and coercive-language detection")
    st.warning("**⚠️ Disclaimer:** Automated assessment only. Hindi/Tamil packs are UNREVIEWED.")
    st.divider()
    sel=st.selectbox("Load a sample:",list(SAMPLES.keys()))
    msg=st.text_area("Message to analyze:",value=SAMPLES[sel],height=130,
                     placeholder="English, हिंदी, தமிழ், Hinglish or Tanglish…")
    if st.button("🔍 Analyze",type="primary") and msg:
        r=analyze_text(msg,include_details=True)
        if r["confidence"]==0.0 and "invalid_input" in r.get("context_flags",[]):
            st.error("⚠️ Could not analyze."); st.stop()
        rl,cat=r["risk_level"],r["scam_category"]
        st.markdown(f'<div style="background:{RC[rl]};color:white;padding:14px 20px;border-radius:10px">'
                    f'<b style="font-size:1.4em">{RE_[rl]} {rl.upper()} RISK</b>&nbsp;&nbsp;'
                    f'{CE.get(cat,"")} {cat}</div>',unsafe_allow_html=True)
        c1,c2=st.columns(2)
        c1.metric("Confidence",f"{r['confidence']:.0f}/100")
        c2.metric("Coercion",f"{r['coercion_score']}/100")
        if r["scripts_detected"] or r["language_packs_matched"]:
            st.caption(f"Scripts: {', '.join(r['scripts_detected']) or 'none'} | Packs: {', '.join(r['language_packs_matched']) or 'none'}")
        for cf in r["context_flags"]:
            labels={"warning_with_request":"⚠️ Warning + live request — treat the request as suspicious",
                    "otp_delivery_notice":"📱 OTP delivery notice (not a scam request)",
                    "limited_coverage":"📉 Limited Hindi/Tamil coverage",
                    "unsupported_language":"🌐 Unsupported script"}
            st.info(labels.get(cf,f"ℹ️ {cf}"))
        if r["detected_phrases"]:
            st.markdown(f'<div style="font-size:1.05em;line-height:1.7;background:#F8F8F8;'
                        f'border:1px solid #DDD;border-radius:8px;padding:14px">{hl(msg,r["detected_phrases"])}</div>',
                        unsafe_allow_html=True)
        for exp in r.get("explanations",[]): st.write(f"🚩 **{exp['flag']}**: {exp['reason']}")
        for a in r.get("recommended_actions",[]): st.write(f"→ {a}")
        with st.expander("🔧 Full JSON"): st.json(r)
    elif st.button("🔍 Analyze",type="primary",key="b2") and not msg:
        st.warning("Please enter a message.")
    st.divider()
    st.caption("PySustain-2026 · No ML · No API · No data stored · SDGs: No Poverty · Quality Education · Reduced Inequalities")

try:
    import streamlit as st
    if hasattr(st,"_is_running_with_streamlit") or "streamlit" in os.environ.get("SERVER_SOFTWARE",""):
        _run_demo()
    else:
        raise ImportError
except Exception:
    pass
