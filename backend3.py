"""
Backend 3 – Multilingual Risk Score, Verdict & Report Engine
Module: backend3.py

Central decision engine for multilingual scam detection in English, Hindi,
Tamil, and code-mixed formats. Integrates:
- Backend 1: Link Unmasking & Domain Checker (link_analyzer)
- Backend 2: Scam Text & Coercive Language Detector (text_analyzer)

Features:
- Pure Python and standard library only.
- Strict 0-100 normalized weighted scoring system.
- Multilingual explanations and recommendations in English ('en'), Hindi ('hi'), and Tamil ('ta').
- Unicode & Code-mixed text support without crashing or character loss.
- Fallback & resilience for missing, malformed, or incomplete backend inputs.
"""

from __future__ import annotations

import logging
import re
from typing import Any, Dict, List, Optional, Set, Tuple, Union

logger = logging.getLogger("backend3")

# ==============================================================================
# 1. CONSTANTS & RISK VERDICT MAPPINGS
# ==============================================================================

# Verdict Levels based on final score
# 0-24: LOW RISK, 25-49: MEDIUM RISK, 50-74: HIGH RISK, 75-100: CRITICAL RISK
RISK_LEVEL_LOW = "LOW"
RISK_LEVEL_MEDIUM = "MEDIUM"
RISK_LEVEL_HIGH = "HIGH"
RISK_LEVEL_CRITICAL = "CRITICAL"

DEFAULT_WEIGHTS = {
    "text_score": 0.45,
    "coercion_score": 0.20,
    "link_score": 0.25,
    "domain_score": 0.10,
}

# ==============================================================================
# 2. MULTILINGUAL DICTIONARIES & PATTERNS
# ==============================================================================

# Regex for script identification
DEVANAGARI_REGEX = re.compile(r"[\u0900-\u097F]")
TAMIL_REGEX = re.compile(r"[\u0B80-\u0BFF]")
LATIN_REGEX = re.compile(r"[A-Za-z]")

# Romanized / Script keywords for language detection
HINDI_ROMAN_KEYWORDS = {
    "aapka", "aapki", "aapke", "khata", "band", "jayega", "jaega", "turant",
    "karein", "karo", "bhejo", "batao", "hoga", "hai", "pe", "se", "ko",
    "bijli", "kat", "de", "do", "kisi", "na", "raha", "rahe", "gaya"
}

TAMIL_ROMAN_KEYWORDS = {
    "unga", "ungal", "ungala", "vangi", "kanakku", "mudakkapadum", "aagum",
    "udane", "anuppunga", "pannunga", "seyyavum", "kidaikkum", "irukku",
    "illai", "koodathu", "thodarbu", "kollavum", "mudiyaadhu", "kettal"
}

# Multilingual Core Indicators & Translations
INDICATOR_NAMES = {
    "otp_harvesting": {
        "en": "OTP harvesting",
        "hi": "OTP चोरी का प्रयास",
        "ta": "OTP திருட்டு முயற்சி"
    },
    "credential_harvesting": {
        "en": "Credential harvesting",
        "hi": "गोपनीय जानकारी माँगना",
        "ta": "ரகசிய விவரங்களை கோருதல்"
    },
    "false_urgency": {
        "en": "False urgency",
        "hi": "झूठी जल्दबाजी व दबाव",
        "ta": "செயற்கையான அவசரம்"
    },
    "account_threat": {
        "en": "Account suspension threat",
        "hi": "खाता बंद करने की धमकी",
        "ta": "கணக்கு முடக்கப்படும் அச்சுறுத்தல்"
    },
    "utility_threat": {
        "en": "Utility disconnection threat",
        "hi": "बिजली या आवश्यक सेवा काटने की धमकी",
        "ta": "சேவை துண்டிப்பு அச்சுறுத்தல்"
    },
    "authority_impersonation": {
        "en": "Authority impersonation",
        "hi": "अधिकारी या संस्था का झूठा ढोंग",
        "ta": "அதிகாரிகள் போல ஆள்மாறாட்டம்"
    },
    "kyc_scam": {
        "en": "Fake KYC verification demand",
        "hi": "फर्जी KYC सत्यापन की माँग",
        "ta": "போலி KYC சரிபார்ப்பு கோரிக்கை"
    },
    "suspicious_url": {
        "en": "Suspicious URL",
        "hi": "संदिग्ध लिंक",
        "ta": "சந்தேகத்திற்குரிய இணைய இணைப்பு"
    },
    "typosquatting": {
        "en": "Deceptive lookalike domain",
        "hi": "धोखेबाज नकली डोमेन",
        "ta": "ஏமாற்றும் போலி இணைய முகவரி"
    },
    "suspicious_tld": {
        "en": "High-risk domain extension",
        "hi": "असुरक्षित डोमेन एक्सटेंशन",
        "ta": "அபாயகரமான டொமைன் நீட்டிப்பு"
    },
    "shortened_url": {
        "en": "Masked shortened link",
        "hi": "छुपाया गया छोटा लिंक",
        "ta": "மறைக்கப்பட்ட குறுகிய இணைப்பு"
    },
    "ip_hostname": {
        "en": "Raw IP address link",
        "hi": "असुरक्षित IP एड्रेस लिंक",
        "ta": "நேரடி IP முகவரி இணைப்பு"
    },
    "malicious_app": {
        "en": "Remote access app or APK prompt",
        "hi": "संदिग्ध ऐप या APK डाउनलोड का दबाव",
        "ta": "தீங்கிழைக்கும் செயலி பதிவிறக்க அழுத்தம்"
    },
    "urgent_payment": {
        "en": "Urgent payment demand",
        "hi": "तत्काल भुगतान का दबाव",
        "ta": "உடனடி பணப்பரிவர்த்தனை கோரிக்கை"
    },
    "lottery_job_fraud": {
        "en": "Fake lottery or job offer",
        "hi": "फर्जी लॉटरी या नौकरी का झांसा",
        "ta": "போலி லாட்டரி அல்லது வேலைவாய்ப்பு சலுகை"
    },
    "courier_fraud": {
        "en": "Courier or customs extortion",
        "hi": "कूरियर या कस्टम्स जब्ती का डर",
        "ta": "கூரியர் அல்லது சுங்கத்துறை மிரட்டல்"
    }
}

VERDICT_TEXTS = {
    RISK_LEVEL_LOW: {
        "en": "Low risk – No strong scam indicators detected",
        "hi": "कम जोखिम – कोई गंभीर संदिग्ध लक्षण नहीं मिले",
        "ta": "குறைந்த ஆபத்து – வலுவான மோசடி அறிகுறிகள் கண்டறியப்படவில்லை"
    },
    RISK_LEVEL_MEDIUM: {
        "en": "Caution – Suspicious elements detected",
        "hi": "सावधानी – कुछ संदिग्ध लक्षण पाए गए",
        "ta": "எச்சரிக்கை – சந்தேகத்திற்குரிய கூறுகள் கண்டறியப்பட்டன"
    },
    RISK_LEVEL_HIGH: {
        "en": "High risk – Potential scam detected",
        "hi": "उच्च जोखिम – संभावित ठगी का पता चला",
        "ta": "அதிக ஆபத்து – சாத்தியமான மோசடி கண்டறியப்பட்டது"
    },
    RISK_LEVEL_CRITICAL: {
        "en": "Critical risk – Severe scam threats detected",
        "hi": "अत्यधिक गंभीर जोखिम – गंभीर ठगी के संकेत मिले",
        "ta": "மிகவும் ஆபத்தானது – தீவிர மோசடி அச்சுறுத்தல்கள் கண்டறியப்பட்டன"
    }
}

RECOMMENDATION_TEMPLATES = {
    "otp_never_share": {
        "en": "Do not share your OTP, PIN, CVV, or passwords under any circumstances.",
        "hi": "किसी भी परिस्थिति में अपना OTP, PIN, CVV या पासवर्ड साझा न करें।",
        "ta": "எந்தச் சூழ்நிலையிலும் உங்கள் OTP, PIN, CVV அல்லது கடவுச்சொல்லைப் பகிர வேண்டாம்."
    },
    "verify_official": {
        "en": "Verify the sender through official bank or service provider channels.",
        "hi": "बैंक या सेवा प्रदाता के आधिकारिक संपर्क नंबर से ही पुष्टि करें।",
        "ta": "அதிகாரப்பூர்வ வங்கி அல்லது சேவை வழங்குநர் சேனல்கள் மூலம் அனுப்புநரைச் சரிபார்க்கவும்."
    },
    "avoid_links": {
        "en": "Avoid clicking on unverified links or entering credentials on external web pages.",
        "hi": "संदिग्ध या असत्यापित लिंक पर क्लिक न करें और कोई विवरण दर्ज न करें।",
        "ta": "சரிபார்க்கப்படாத இணைப்புகளைத் திறக்கவோ அல்லது விவரங்களைப் பதிவு செய்யவோ வேண்டாம்."
    },
    "no_urgent_transfer": {
        "en": "Do not transfer money in response to threats of immediate disconnection or penalty.",
        "hi": "सेवा काटने या जुर्माने की धमकी के दबाव में कभी भी पैसे ट्रांसफर न करें।",
        "ta": "துண்டிப்பு அல்லது அபராத அச்சுறுத்தல்களுக்குப் பயந்து அவசரமாகப் பணம் அனுப்ப வேண்டாம்."
    },
    "authority_warning": {
        "en": "Remember: Police, court, or government officers never demand money via messaging apps.",
        "hi": "याद रखें: पुलिस, अदालत या सरकारी अधिकारी मैसेजिंग ऐप पर कभी पैसे की माँग नहीं करते।",
        "ta": "நினைவில் கொள்க: காவல்துறை அல்லது அரசு அதிகாரிகள் மெசேஜிங் ஆப் வழியாகப் பணம் கேட்க மாட்டார்கள்."
    },
    "no_install_apps": {
        "en": "Never install unknown apps, APK files, or remote desktop software (e.g. AnyDesk).",
        "hi": "किसी के कहने पर कोई अज्ञात ऐप, APK या रिमोट कंट्रोल ऐप (AnyDesk आदि) इंस्टॉल न करें।",
        "ta": "தெரியாத செயலிகளையோ, APK கோப்புகளையோ அல்லது AnyDesk போன்ற செயலிகளையோ நிறுவ வேண்டாம்."
    },
    "helpline_report": {
        "en": "Report financial cyber fraud immediately to National Helpline 1930 or cybercrime.gov.in.",
        "hi": "वित्तीय साइबर धोखाधड़ी की सूचना तुरंत राष्ट्रीय हेल्पलाइन 1930 या cybercrime.gov.in पर दें।",
        "ta": "சைபர் நிதி மோசடி குறித்து உடனடியாக தேசிய உதவி எண் 1930 அல்லது cybercrime.gov.in இல் புகாரளிக்கவும்."
    },
    "standard_safety": {
        "en": "Maintain standard digital awareness. A low risk score does not guarantee the message is safe.",
        "hi": "सामान्य साइबर सुरक्षा का पालन करें। कम जोखिम का मतलब यह नहीं है कि संदेश पूरी तरह सुरक्षित है।",
        "ta": "வழக்கமான விழிப்புணர்வுடன் இருக்கவும். குறைந்த மதிப்பெண் செய்தி பாதுகாப்பானது என்பதற்கு முழு உத்தரவாதம் அல்ல."
    }
}

# Standalone Multilingual Patterns for Fallback / Standalone Text Analysis
MULTILINGUAL_PATTERNS = [
    # 1. OTP / Credential Harvesting
    {
        "key": "otp_harvesting",
        "category": "credential_theft",
        "weight_coercion": 30,
        "is_otp": True,
        "patterns": [
            # English
            r"\b(?:share|send|give|enter|submit|provide)\s+(?:your\s+)?(?:otp|one\s*time\s*password|pin|cvv|netbanking\s*password)\b",
            r"\b(?:share\s+your\s+otp)\b",
            # Hindi Devanagari
            r"अपना\s*(?:ओटीपी|OTP|पिन|PIN|पासवर्ड)\s*(?:भेजें|साझा\s*करें|दें|बताएं|दर्ज\s*करें)",
            r"(?:ओटीपी|OTP)\s*(?:साझा\s*करें|भेजें|बताओ|दे\s*दो|दर्ज\s*करें)",
            # Hindi Romanized
            r"\b(?:otp|pin)\s*(?:batao|share\s*karein|bhejo|de\s*do|enter\s*karein)\b",
            r"\b(?:apna\s*otp\s*bhejo|apna\s*otp\s*batao|share\s*karo\s*otp)\b",
            # Tamil Script
            r"(?:உங்கள்\s*)?(?:OTP|ஓடிபி|கடவுச்சொல்|பின்|PIN)[-–\s]*(?:ஐ)?\s*(?:அனுப்புங்கள்|பகிரவும்|பகிர்|தரவும்|உள்ளிடவும்)",
            r"உடனே\s*(?:OTP|ஓடிபி)\s*(?:அனுப்புங்கள்|பகிரவும்|போடுங்கள்)",
            # Tamil Romanized
            r"\b(?:unga|ungal|ungala)?\s*(?:otp|pin)\s*(?:anuppunga|share\s*pannunga|kudunga|anupavum|podunga)\b",
            r"\budane\s*(?:otp|pin)\s*(?:anuppunga|share\s*pannunga)\b"
        ]
    },
    # 2. Account Suspension & Blocking Threats
    {
        "key": "account_threat",
        "category": "account_threat",
        "weight_coercion": 35,
        "is_otp": False,
        "patterns": [
            # English
            r"\b(?:your\s+)?(?:bank\s+)?account\s+will\s+be\s+(?:blocked|suspended|frozen|deactivated|closed|terminated)\b",
            # Hindi Devanagari
            r"(?:बैंक\s*)?खाता\s*(?:बंद\s*हो\s*जाएगा|ब्लॉक\s*हो\s*जाएगा|फ्रीज\s*कर\s*दिया\s*जाएगा)",
            # Hindi Romanized
            r"\b(?:aapka\s+)?(?:bank\s+)?account\s+(?:band\s*ho\s*jayega|block\s*ho\s*jayega|freeze\s*ho\s*jayega)\b",
            r"\b(?:account\s+block\s+kar\s+diya\s+jayega)\b",
            # Tamil Script
            r"(?:உங்கள்\s*)?(?:வங்கி\s*)?கணக்கு\s*(?:முடக்கப்படும்|நிறுத்தப்படும்|செயலிழக்கப்படும்)",
            # Tamil Romanized
            r"\b(?:unga|ungal)?\s*(?:bank\s+)?account\s+(?:block\s*aagum|mudakkapadum|close\s*aagum|freeze\s*aagum)\b"
        ]
    },
    # 3. Electricity / Utility Threats
    {
        "key": "utility_threat",
        "category": "utility_threat",
        "weight_coercion": 40,
        "is_otp": False,
        "patterns": [
            # English
            r"\b(?:electricity|power\s*supply)\s*(?:will\s*be\s*disconnected|cut\s*off|power\s*cut\s*tonight)\b",
            # Hindi Devanagari
            r"बिजली\s*(?:काट\s*दी\s*जाएगी|कनेक्शन\s*काट\s*दिया\s*जाएगा|बंद\s*कर\s*दी\s*जाएगी)",
            # Hindi Romanized
            r"\b(?:bijli\s*connection\s*(?:kat\s*jayega|kat\s*jaega|band\s*ho\s*jayega|disconnect\s*hoga))\b",
            # Tamil Script
            r"மின்சார\s*இணைப்பு\s*(?:துண்டிக்கப்படும்|நிறுத்தப்படும்)",
            # Tamil Romanized
            r"\b(?:current|minsaram|electricity)\s*(?:cut\s*pannapadum|cut\s*aagum|disconnect\s*aagum)\b"
        ]
    },
    # 4. KYC Verification Scams
    {
        "key": "kyc_scam",
        "category": "kyc_verification_scam",
        "weight_coercion": 25,
        "is_otp": False,
        "patterns": [
            # English
            r"\b(?:kyc\s*(?:is\s*)?pending|pending\s*kyc|complete\s*kyc\s*immediately|update\s*your\s*kyc)\b",
            # Hindi Devanagari
            r"(?:केवाईसी|KYC)\s*(?:लंबित\s*है|अधूरा\s*है|अपडेट\s*करें|तुरंत\s*करें)",
            # Hindi Romanized
            r"\b(?:kyc\s*(?:pending\s*hai|update\s*karein|turant\s*karo))\b",
            # Tamil Script
            r"(?:KYC|கேஒய்சி)\s*(?:நிலுவையில்\s*உள்ளது|புதுப்பிக்கவும்|உடனே\s*முடிக்கவும்)",
            # Tamil Romanized
            r"\b(?:kyc\s*(?:pending|mudikka|update\s*pannunga))\b"
        ]
    },
    # 5. Authority & Legal Impersonation
    {
        "key": "authority_impersonation",
        "category": "authority_impersonation",
        "weight_coercion": 45,
        "is_otp": False,
        "patterns": [
            # English
            r"\b(?:arrest\s*warrant|cbi\s*(?:officer|inquiry)|police\s*case|digital\s*arrest)\b",
            # Hindi Devanagari
            r"(?:गिरफ्तारी\s*वारंट|पुलिस\s*केस|सीबीआई|डिजिटल\s*अरेस्ट)",
            # Hindi Romanized
            r"\b(?:police\s*case\s*(?:ho\s*jayega|darj)|arrest\s*warrant|digital\s*arrest)\b",
            # Tamil Script
            r"(?:கைது\s*வாரண்ட்|காவல்துறை\s*நடவடிக்கை|வழக்கு\s*பதிவு)",
            # Tamil Romanized
            r"\b(?:police\s*case\s*(?:aagum|varum)|arrest\s*warrant)\b"
        ]
    },
    # 6. Urgent Payment Demands
    {
        "key": "urgent_payment",
        "category": "urgent_payment_demand",
        "weight_coercion": 30,
        "is_otp": False,
        "patterns": [
            # English
            r"\b(?:pay\s*(?:immediately|now|urgently)|transfer\s*immediately|pay\s*within\s*\d+\s*(?:mins|hours))\b",
            # Hindi Devanagari
            r"(?:तुरंत\s*भुगतान\s*करें|अभी\s*पैसे\s*भेजें|पेमेंट\s*करें)",
            # Hindi Romanized
            r"\b(?:abhi\s*payment\s*karo|turant\s*payment|turant\s*bhejo)\b",
            # Tamil Script
            r"(?:உடனே\s*பணம்\s*செலுத்தவும்|இப்போதே\s*பணம்\s*அனுப்பவும்)",
            # Tamil Romanized
            r"\b(?:udane\s*pay\s*pannunga|ippove\s*kaasu\s*anuppunga)\b"
        ]
    },
    # 7. Malicious Link / App Pressure
    {
        "key": "malicious_app",
        "category": "malicious_link_or_app",
        "weight_coercion": 25,
        "is_otp": False,
        "patterns": [
            # English
            r"\b(?:click\s*(?:the\s*)?link\s*immediately|install\s*(?:apk|anydesk|quicksupport))\b",
            # Hindi Devanagari
            r"(?:तुरंत\s*लिंक\s*पर\s*क्लिक\s*करें|ऐप\s*डाउनलोड\s*करें)",
            # Hindi Romanized
            r"\b(?:turant\s*link\s*click\s*karo|link\s*pe\s*click\s*karein|apk\s*install\s*karo)\b",
            # Tamil Script
            r"(?:உடனே\s*இணைப்பை\s*கிளிக்\s*செய்யவும்|செயலியை\s*பதிவிறக்கம்\s*செய்யவும்)",
            # Tamil Romanized
            r"\b(?:link\s*click\s*pannunga|app\s*download\s*pannunga)\b"
        ]
    },
    # 8. Urgency / Coercive keywords
    {
        "key": "false_urgency",
        "category": "false_urgency",
        "weight_coercion": 20,
        "is_otp": False,
        "patterns": [
            r"\b(?:immediately|urgently|within\s*\d+\s*hours?|tonight\s*at|right\s*now)\b",
            r"(?:तुरंत|जल्दी|तत्काल|आज\s*रात|बिना\s*देरी)",
            r"\b(?:turant|jaldi|abhi\s*ke\s*abhi|aaj\s*raat)\b",
            r"(?:உடனே|உடனடியாக|இப்போதே|தாமதமின்றி|இன்றிரவு)",
            r"\b(?:udane|udanadiyaga|ippove)\b"
        ]
    }
]

# Legitimate educational warnings (e.g. "SBI never asks for OTP. Do not share.")
LEGITIMATE_EDUCATIONAL_PATTERNS = [
    r"\b(?:never|do\s+not|don'?t|kisi\s+ko\s+na)\s+(?:share|give|batao|disclose)\s+(?:your\s+)?(?:otp|pin|password|cvv)",
    r"\b(?:bank|sbi|rbi|hdfc|icici)\s+never\s+asks?\s+for\s+(?:otp|pin|cvv|password)",
    r"(?:कभी\s*(?:भी\s*)?(?:अपना\s*)?(?:ओटीपी|OTP|पिन|PIN)\s*साझा\s*न\s*करें|बैंक\s*कभी\s*(?:भी\s*)?ओटीपी\s*नहीं\s*माँगता)",
    r"(?:OTP-ஐ\s*யாரிடமும்\s*பகிர\s*வேண்டாம்|வங்கி\s*ஒருபோதும்\s*OTP\s*கேட்காது)",
    r"\b(?:if\s+not\s+(?:done|authorized)\s+by\s+you|to\s+block\s+sms)\b"
]


# ==============================================================================
# 3. HELPER FUNCTIONS: LANGUAGE DETECTION & URL EXTRACTION
# ==============================================================================

def detect_languages(text: str) -> List[str]:
    """
    Detects languages present in message text: English, Hindi, Tamil.
    Supports script detection and transliterated / Romanized Hindi and Tamil.
    """
    if not text or not isinstance(text, str):
        return ["English"]

    detected: Set[str] = set()

    # Script checks
    if DEVANAGARI_REGEX.search(text):
        detected.add("Hindi")

    if TAMIL_REGEX.search(text):
        detected.add("Tamil")

    # Word-level transliteration and English check
    words = re.findall(r"[A-Za-z]+", text.lower())
    if words:
        detected.add("English")

        word_set = set(words)
        # Check Hindi transliteration
        if word_set.intersection(HINDI_ROMAN_KEYWORDS):
            detected.add("Hindi")

        # Check Tamil transliteration
        if word_set.intersection(TAMIL_ROMAN_KEYWORDS):
            detected.add("Tamil")

    # Fallback default
    if not detected:
        detected.add("English")

    # Order nicely
    order = ["English", "Hindi", "Tamil"]
    return [lang for lang in order if lang in detected] or ["English"]


def extract_raw_urls(text: str) -> List[str]:
    """
    Extracts URLs from plain text using regex without third-party dependencies.
    """
    if not text or not isinstance(text, str):
        return []
    url_pattern = re.compile(
        r"(?:https?://|www\.)[^\s<>'\"`]+",
        re.IGNORECASE
    )
    raw_matches = url_pattern.findall(text)
    clean_urls = []
    for match in raw_matches:
        u = re.sub(r"[.,;:!?)\]}>]+$", "", match)
        if u not in clean_urls:
            clean_urls.append(u)
    return clean_urls


def is_legitimate_security_advisory(text: str) -> bool:
    """
    Determines if text is an official bank security advisory/alert
    informing users NEVER to share OTP/PIN.
    """
    if not text or not isinstance(text, str):
        return False
    for pat in LEGITIMATE_EDUCATIONAL_PATTERNS:
        if re.search(pat, text, re.IGNORECASE):
            return True
    return False


# ==============================================================================
# 4. ADAPTER & FALLBACK ANALYSIS LAYERS
# ==============================================================================

def execute_text_backend_fallback(text: str) -> Dict[str, Any]:
    """
    Native fallback analysis for message text when Backend 2 is not supplied
    or unavailable. Implements full multilingual pattern matching for
    English, Hindi (Devanagari & Romanized), and Tamil (Script & Romanized).
    """
    if not text or not text.strip():
        return {
            "available": True,
            "scam_category": [],
            "detected_phrases": [],
            "risk_flags": [],
            "coercion_score": 0,
            "confidence": 0.0,
            "has_otp_request": False
        }

    cleaned = text.strip()
    is_advisory = is_legitimate_security_advisory(cleaned)

    detected_phrases: List[str] = []
    scam_categories: Set[str] = set()
    risk_flags: Set[str] = set()
    coercion_points = 0
    has_otp_request = False

    for rule in MULTILINGUAL_PATTERNS:
        rule_matched = False
        for pat in rule["patterns"]:
            matches = list(re.finditer(pat, cleaned, re.IGNORECASE))
            for m in matches:
                if rule["is_otp"] and is_advisory:
                    continue  # Skip flagging OTP if it's an educational disclaimer
                phrase = cleaned[m.start():m.end()]
                if phrase not in detected_phrases:
                    detected_phrases.append(phrase)
                rule_matched = True

        if rule_matched:
            if rule["category"] != "false_urgency":
                scam_categories.add(rule["category"])
            risk_flags.add(rule["key"])
            coercion_points += rule["weight_coercion"]
            if rule["is_otp"]:
                has_otp_request = True

    # Coercion score clamped 0-100
    coercion_score = min(100, coercion_points)

    # Legitimate advisory suppression
    if is_advisory and len(scam_categories) <= 1:
        if "credential_theft" in scam_categories:
            scam_categories.remove("credential_theft")
        risk_flags.discard("otp_harvesting")
        has_otp_request = False
        coercion_score = 0
        detected_phrases = [
            p for p in detected_phrases
            if "otp" not in p.lower() and "pin" not in p.lower()
        ]

    confidence = 0.0
    if scam_categories or risk_flags:
        confidence = min(0.95, 0.60 + len(scam_categories) * 0.10)

    return {
        "available": True,
        "scam_category": sorted(list(scam_categories)),
        "detected_phrases": detected_phrases,
        "risk_flags": sorted(list(risk_flags)),
        "coercion_score": coercion_score,
        "confidence": confidence,
        "has_otp_request": has_otp_request
    }


def execute_link_backend_fallback(text: str) -> Dict[str, Any]:
    """
    Native fallback analysis for links when Backend 1 is not supplied or unavailable.
    Inspects extracted URLs for suspicious TLDs, IP hostnames, shorteners,
    and lookalike keywords offline.
    """
    urls = extract_raw_urls(text)
    if not urls:
        return {
            "available": True,
            "urls_detected": [],
            "risk_flags": [],
            "is_suspicious_link": False,
            "is_impersonation": False,
            "link_score": 0,
            "domain_score": 0
        }

    suspicious_tlds = {
        ".xyz", ".top", ".online", ".club", ".buzz", ".icu", ".work",
        ".click", ".link", ".monster", ".cf", ".ml", ".ga", ".tk"
    }
    shorteners = {
        "bit.ly", "tinyurl.com", "t.co", "is.gd", "cutt.ly", "shorturl.at"
    }
    trusted_brands = [
        "sbi", "hdfc", "icici", "axis", "pnb", "paytm", "phonepe",
        "uidai", "aadhaar", "incometax", "gov", "police", "customs"
    ]

    all_flags: List[str] = []
    link_points = 0
    domain_points = 0

    for u in urls:
        u_lower = u.lower()

        # Check raw IP
        if re.search(r"https?://\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}", u_lower):
            all_flags.append(f"ip_hostname_detected:{u}")
            link_points += 80
            domain_points += 60

        # Check suspicious TLD
        if any(u_lower.endswith(tld) or f"{tld}/" in u_lower for tld in suspicious_tlds):
            all_flags.append(f"suspicious_tld:{u}")
            link_points += 60
            domain_points += 40

        # Check shortener
        if any(shortener in u_lower for shortener in shorteners):
            all_flags.append(f"shortened_url:{u}")
            link_points += 40

        # Check brand impersonation / typosquat keyword in non-official domain
        for brand in trusted_brands:
            if brand in u_lower and not (u_lower.endswith(f".{brand}.com") or u_lower.endswith(f".{brand}.co.in") or u_lower.endswith(f".{brand}.gov.in")):
                all_flags.append(f"impersonation_keyword:{brand}:{u}")
                domain_points += 80
                link_points += 50
                break

    return {
        "available": True,
        "urls_detected": urls,
        "risk_flags": sorted(list(set(all_flags))),
        "is_suspicious_link": link_points > 0,
        "is_impersonation": domain_points > 0,
        "link_score": min(100, link_points),
        "domain_score": min(100, domain_points)
    }


# ==============================================================================
# 5. INTEGRATION LAYER: ADAPTING EXISTING BACKENDS SAFELY
# ==============================================================================

def run_backend2_integration(text: str, supplied_results: Optional[Any]) -> Tuple[Dict[str, Any], bool]:
    """
    Safely adapts or executes Backend 2 (text_analyzer).
    Fuses external text_analyzer with native multilingual fallback patterns
    to ensure full support for Devanagari, Tamil script, and Romanized code-mixing.
    Returns (normalized_dict, is_available).
    """
    if supplied_results is not None:
        if not isinstance(supplied_results, dict):
            # Malformed supplied result
            logger.warning("Supplied text_results is malformed (not a dict).")
            return {"available": False, "error": "Malformed text_results", "scam_category": [], "detected_phrases": []}, False
        # Supplied valid dict
        res = dict(supplied_results)
        res["available"] = res.get("available", True)
        return res, res.get("available", True)

    # 1. Compute native multilingual pattern detections
    fallback_res = execute_text_backend_fallback(text)

    # 2. Try importing and running external text_analyzer if available
    try:
        from text_analyzer import analyze_text
        raw = analyze_text(text)
        if isinstance(raw, dict):
            # Merge results: combine categories, flags, phrases, and take max coercion
            combined_cats = sorted(list(set(raw.get("scam_category", []) + fallback_res.get("scam_category", []))))
            combined_flags = sorted(list(set(raw.get("risk_flags", []) + fallback_res.get("risk_flags", []))))
            combined_phrases = []
            for p in raw.get("detected_phrases", []) + fallback_res.get("detected_phrases", []):
                if p not in combined_phrases:
                    combined_phrases.append(p)

            coercion = max(
                int(raw.get("coercion_score", 0)) if isinstance(raw.get("coercion_score"), (int, float)) else 0,
                fallback_res.get("coercion_score", 0)
            )
            confidence = max(
                float(raw.get("confidence", 0.0)) if isinstance(raw.get("confidence"), (int, float)) else 0.0,
                fallback_res.get("confidence", 0.0)
            )
            has_otp = (
                fallback_res.get("has_otp_request", False) or
                "credential_theft" in combined_cats or
                "credential_harvesting_request" in combined_flags or
                any("otp" in str(p).lower() for p in combined_phrases)
            )

            merged = {
                "available": True,
                "scam_category": combined_cats,
                "detected_phrases": combined_phrases,
                "risk_flags": combined_flags,
                "coercion_score": coercion,
                "confidence": confidence,
                "has_otp_request": has_otp
            }
            return merged, True
    except Exception as e:
        logger.info(f"Could not load or run external text_analyzer ({e}). Using native fallback.")

    return fallback_res, True


def run_backend1_integration(text: str, supplied_results: Optional[Any]) -> Tuple[Dict[str, Any], bool]:
    """
    Safely adapts or executes Backend 1 (link_analyzer).
    Returns (normalized_dict, is_available).
    """
    if supplied_results is not None:
        if not isinstance(supplied_results, (dict, list)):
            logger.warning("Supplied link_results is malformed.")
            return {"available": False, "error": "Malformed link_results", "risk_flags": []}, False

        if isinstance(supplied_results, list):
            # ScamShield link_analyzer returns a list of URL analyses
            flags = []
            for item in supplied_results:
                if isinstance(item, dict):
                    flags.extend(item.get("risk_flags", []))
            return {
                "available": True,
                "urls_data": supplied_results,
                "risk_flags": flags
            }, True

        res = dict(supplied_results)
        res["available"] = res.get("available", True)
        return res, res.get("available", True)

    # If no links in text, link check is available and clean
    urls = extract_raw_urls(text)
    if not urls:
        return {
            "available": True,
            "urls_data": [],
            "risk_flags": []
        }, True

    # Try importing existing link_analyzer
    try:
        from link_analyzer import analyze_urls_in_message
        raw = analyze_urls_in_message(text, enable_network=False, rdap_lookup=False)
        if isinstance(raw, list):
            flags = []
            for item in raw:
                if isinstance(item, dict):
                    flags.extend(item.get("risk_flags", []))
            return {
                "available": True,
                "urls_data": raw,
                "risk_flags": flags
            }, True
    except Exception as e:
        logger.info(f"Could not load or run external link_analyzer ({e}). Using native fallback.")

    # Use native fallback
    fallback_res = execute_link_backend_fallback(text)
    return fallback_res, True


# ==============================================================================
# 6. RISK SCORE CALCULATION ENGINE
# ==============================================================================

def normalize_component_scores(
    text_data: Dict[str, Any],
    link_data: Dict[str, Any],
    text_available: bool,
    link_available: bool,
    message_text: str = ""
) -> Tuple[float, float, float, float, Dict[str, bool]]:
    """
    Normalizes each component (text, coercion, link, domain) to 0-100.
    Returns (text_norm, coercion_norm, link_norm, domain_norm, availability_map).
    """
    availability = {
        "text": text_available,
        "coercion": text_available,
        "link": link_available,
        "domain": link_available
    }

    # 1. Text Score (0-100)
    text_norm = 0.0
    if text_available:
        categories = text_data.get("scam_category", [])
        if not isinstance(categories, list):
            categories = []
        flags = text_data.get("risk_flags", [])
        if not isinstance(flags, list):
            flags = []

        raw_points = 0.0
        # High danger categories
        if any("credential" in str(c) for c in categories) or any("otp" in str(f) for f in flags) or any("credential" in str(f) for f in flags):
            raw_points += 70
        if any("authority" in str(c) for c in categories) or any("authority" in str(f) for f in flags):
            raw_points += 60
        if any("threat" in str(c) for c in categories) or any("threat" in str(f) for f in flags):
            raw_points += 55
        if any("kyc" in str(c) for c in categories) or any("kyc" in str(f) for f in flags):
            raw_points += 45
        if any("payment" in str(c) for c in categories) or any("payment" in str(f) for f in flags):
            raw_points += 40
        if any("courier" in str(c) for c in categories) or any("courier" in str(f) for f in flags):
            raw_points += 35
        if any("lottery" in str(c) for c in categories) or any("lottery" in str(f) for f in flags):
            raw_points += 30
        if any("app" in str(c) for c in categories) or any("app" in str(f) for f in flags):
            raw_points += 35

        text_norm = min(100.0, raw_points)

    # 2. Coercion Score (0-100)
    coercion_norm = 0.0
    if text_available:
        coercion_val = text_data.get("coercion_score", 0)
        if isinstance(coercion_val, (int, float)):
            coercion_norm = max(0.0, min(100.0, float(coercion_val)))

    # 3. Link Score (0-100) and Domain Score (0-100)
    link_norm = 0.0
    domain_norm = 0.0
    if link_available:
        # Check direct link_score/domain_score if provided by fallback
        if "link_score" in link_data:
            link_norm = float(link_data.get("link_score", 0))
            domain_norm = float(link_data.get("domain_score", 0))
        else:
            # Parse from urls_data or risk_flags
            l_flags = link_data.get("risk_flags", [])
            urls_data = link_data.get("urls_data", [])

            l_pts = 0.0
            d_pts = 0.0

            if isinstance(urls_data, list):
                for u_item in urls_data:
                    if isinstance(u_item, dict):
                        if u_item.get("is_suspicious_tld"):
                            l_pts += 60
                            d_pts += 40
                        if u_item.get("is_typosquat"):
                            d_pts += 80
                            l_pts += 50
                        if u_item.get("is_new_domain") is True:
                            d_pts += 50
                        for f in u_item.get("risk_flags", []):
                            f_str = str(f).lower()
                            if "ip_based" in f_str:
                                l_pts += 80
                                d_pts += 60
                            elif "shortened" in f_str:
                                l_pts += 40
                            elif "deceptive" in f_str:
                                d_pts += 60

            if isinstance(l_flags, list):
                for f in l_flags:
                    f_str = str(f).lower()
                    if "tld" in f_str and l_pts < 60:
                        l_pts += 60
                        d_pts += 40
                    if "typo" in f_str or "impersonation" in f_str:
                        d_pts += 80
                        l_pts += 50
                    if "ip" in f_str and l_pts < 80:
                        l_pts += 80
                        d_pts += 60

            link_norm = min(100.0, l_pts)
            domain_norm = min(100.0, d_pts)

    return text_norm, coercion_norm, link_norm, domain_norm, availability


def calculate_calibrated_risk_score(
    text_score: float,
    coercion_score: float,
    link_score: float,
    domain_score: float,
    availability: Dict[str, bool],
    has_critical_trigger: bool = False
) -> int:
    """
    Calculates final risk score between 0 and 100 with dynamic weight renormalization
    for missing components and critical trigger floor enforcement.
    """
    weights = dict(DEFAULT_WEIGHTS)
    active_weights = {}

    if availability.get("text"):
        active_weights["text_score"] = weights["text_score"]
    if availability.get("coercion"):
        active_weights["coercion_score"] = weights["coercion_score"]
    if availability.get("link"):
        active_weights["link_score"] = weights["link_score"]
    if availability.get("domain"):
        active_weights["domain_score"] = weights["domain_score"]

    total_weight = sum(active_weights.values())
    if total_weight <= 0:
        return 0

    # Renormalize weights
    normalized_weights = {k: v / total_weight for k, v in active_weights.items()}

    final_score = 0.0
    if "text_score" in normalized_weights:
        final_score += text_score * normalized_weights["text_score"]
    if "coercion_score" in normalized_weights:
        final_score += coercion_score * normalized_weights["coercion_score"]
    if "link_score" in normalized_weights:
        final_score += link_score * normalized_weights["link_score"]
    if "domain_score" in normalized_weights:
        final_score += domain_score * normalized_weights["domain_score"]

    # Critical trigger safety floor (e.g. OTP harvesting request)
    if has_critical_trigger:
        final_score = max(final_score, 75.0)

    # Strictly clamp between 0 and 100
    clamped_score = int(round(max(0.0, min(100.0, final_score))))
    return clamped_score


def determine_verdict_and_level(score: int) -> Tuple[str, str]:
    """
    Maps 0-100 score to risk level and human-readable verdict name.
    - 0–24: LOW RISK
    - 25–49: MEDIUM RISK
    - 50–74: HIGH RISK
    - 75–100: CRITICAL RISK
    """
    if score >= 75:
        return RISK_LEVEL_CRITICAL, "CRITICAL RISK"
    elif score >= 50:
        return RISK_LEVEL_HIGH, "HIGH RISK"
    elif score >= 25:
        return RISK_LEVEL_MEDIUM, "MEDIUM RISK"
    else:
        return RISK_LEVEL_LOW, "LOW RISK"


# ==============================================================================
# 7. MULTILINGUAL EXPLANATION & RECOMMENDATION GENERATOR
# ==============================================================================

def generate_multilingual_explanation(
    detected_indicators: List[str],
    has_otp: bool,
    has_urgency: bool,
    has_threat: bool,
    has_link: bool,
    has_impersonation: bool,
    output_lang: str,
    original_phrases: List[str]
) -> str:
    """
    Generates a clear, contextual explanation in English ('en'), Hindi ('hi'), or Tamil ('ta').
    Uses predefined, verified translations.
    """
    lang = output_lang if output_lang in ("en", "hi", "ta") else "en"

    if not detected_indicators:
        if lang == "hi":
            return "इस संदेश में कोई गंभीर संदिग्ध गतिविधि या ठगी के संकेत नहीं मिले। फिर भी किसी अज्ञात स्रोत से सतर्क रहें।"
        elif lang == "ta":
            return "இந்தச் செய்தியில் குறிப்பிடத்தக்க மோசடி அல்லது அச்சுறுத்தல் எதுவும் கண்டறியப்படவில்லை. இருப்பினும் எச்சரிக்கையாக இருக்கவும்."
        else:
            return "No strong scam indicators were detected in this message. Maintain standard caution with unknown senders."

    # Highlighted phrase quote clause
    quoted_phrase = f" (e.g., \"{original_phrases[0]}\")" if original_phrases else ""

    if lang == "hi":
        parts = []
        if has_otp:
            parts.append("यह संदेश OTP या गोपनीय पिन माँगता है")
        if has_urgency:
            parts.append("तुरंत कार्रवाई करने का दबाव बनाता है")
        if has_threat:
            parts.append("खाता या आवश्यक सेवा बंद करने की धमकी देता है")
        if has_impersonation:
            parts.append("अधिकारी या सरकारी संस्था का झूठा ढोंग करता है")
        if has_link:
            parts.append("संदिग्ध या नकली लिंक पर जाने का दबाव बनाता है")

        if not parts:
            parts.append("इसमें संदिग्ध गतिविधियाँ पाई गई हैं")

        core_clause = " और ".join(parts)
        phrase_clause = f" (जैसे: \"{original_phrases[0]}\")" if original_phrases else ""
        return (
            f"{core_clause}{phrase_clause}। ठग इन तरीकों से आपके खाते तक पहुँचने "
            f"या धोखाधड़ी करने की कोशिश कर सकते हैं। अपना OTP साझा न करें और संदिग्ध लिंक पर क्लिक न करें।"
        )

    elif lang == "ta":
        parts = []
        if has_otp:
            parts.append("இந்தச் செய்தி OTP அல்லது ரகசிய விவரங்களைக் கேட்கிறது")
        if has_urgency:
            parts.append("உடனடியாகச் செயல்பட அழுத்தம் கொடுக்கிறது")
        if has_threat:
            parts.append("வங்கி கணக்கு அல்லது சேவையை முடக்குவதாக அச்சுறுத்துகிறது")
        if has_impersonation:
            parts.append("அதிகாரிகள் போல போலியாக நடிக்கிறது")
        if has_link:
            parts.append("சந்தேகத்திற்குரிய இணைய இணைப்பைக் கொண்டுள்ளது")

        if not parts:
            parts.append("இதில் சந்தேகத்திற்கிடமான கூறுகள் உள்ளன")

        core_clause = " மற்றும் ".join(parts)
        phrase_clause = f" (எடுத்துக்காட்டாக: \"{original_phrases[0]}\")" if original_phrases else ""
        return (
            f"{core_clause}{phrase_clause}। மோசடி செய்பவர்கள் இதைப் பயன்படுத்தி உங்கள் கணக்கை "
            f"அணுக முயற்சி செய்யலாம். உங்கள் OTP-ஐப் பகிர வேண்டாம்; சந்தேகமான இணைப்புகளைத் திறக்க வேண்டாம்."
        )

    else:
        # English
        parts = []
        if has_otp:
            parts.append("requests an OTP or sensitive credentials")
        if has_urgency:
            parts.append("creates artificial urgency")
        if has_threat:
            parts.append("threatens account blocking or service disconnection")
        if has_impersonation:
            parts.append("impersonates official authorities")
        if has_link:
            parts.append("includes suspicious or lookalike links")

        if not parts:
            parts.append("exhibits suspicious behavioral patterns")

        core_clause = " and ".join(parts)
        return (
            f"This message {core_clause}{quoted_phrase}. Scammers frequently use these tactics "
            f"to gain unauthorized access or induce panic. Do not share your OTP or click unverified links."
        )


def generate_recommendations(
    has_otp: bool,
    has_threat: bool,
    has_link: bool,
    has_impersonation: bool,
    score: int,
    output_lang: str
) -> List[str]:
    """
    Selects structured safety recommendations in the desired language.
    """
    lang = output_lang if output_lang in ("en", "hi", "ta") else "en"
    recs = []

    if has_otp or score >= 50:
        recs.append(RECOMMENDATION_TEMPLATES["otp_never_share"][lang])

    recs.append(RECOMMENDATION_TEMPLATES["verify_official"][lang])

    if has_link:
        recs.append(RECOMMENDATION_TEMPLATES["avoid_links"][lang])

    if has_threat:
        recs.append(RECOMMENDATION_TEMPLATES["no_urgent_transfer"][lang])

    if has_impersonation:
        recs.append(RECOMMENDATION_TEMPLATES["authority_warning"][lang])

    if score >= 50:
        recs.append(RECOMMENDATION_TEMPLATES["helpline_report"][lang])
    else:
        recs.append(RECOMMENDATION_TEMPLATES["standard_safety"][lang])

    # Deduplicate while preserving order
    unique_recs = []
    for r in recs:
        if r not in unique_recs:
            unique_recs.append(r)
    return unique_recs


# ==============================================================================
# 8. CENTRAL PUBLIC API: analyze_message()
# ==============================================================================

def analyze_message(
    message_text: Any,
    link_results: Optional[Any] = None,
    text_results: Optional[Any] = None,
    output_language: str = "en",
    enable_network: bool = True,
    rdap_lookup: bool = False
) -> Dict[str, Any]:
    """
    Main central decision engine for ScamShield (Backend 3).

    Integrates Backend 1 (link_analyzer) and Backend 2 (text_analyzer),
    calculates normalized risk score (0-100), maps verdict, explains why the
    message is suspicious, and outputs a complete JSON-serializable report.

    Parameters:
    - message_text: Raw message string entered by user.
    - link_results: Optional output from Backend 1 (dict or list).
    - text_results: Optional output from Backend 2 (dict).
    - output_language: 'en' (default), 'hi' (Hindi), or 'ta' (Tamil).
    - enable_network: Optional flag passed to Backend 1 when auto-invoking.
    - rdap_lookup: Optional flag passed to Backend 1 when auto-invoking.

    Returns:
    - JSON-serializable dictionary adhering strictly to the specifications.
    """
    # 1. Input sanitization & resilience
    if message_text is None:
        message_str = ""
    elif not isinstance(message_text, str):
        message_str = str(message_text)
    else:
        message_str = message_text

    # Language support validation
    target_lang = output_language if output_language in ("en", "hi", "ta") else "en"

    # Language detection in message body
    languages_detected = detect_languages(message_str)

    # 2. Handle empty or whitespace message safely
    if not message_str.strip():
        verdict_str = VERDICT_TEXTS[RISK_LEVEL_LOW][target_lang]
        explanation = (
            "No message text was provided for analysis." if target_lang == "en" else
            "विश्लेषण के लिए कोई संदेश सामग्री प्रदान नहीं की गई।" if target_lang == "hi" else
            "பகுப்பாய்வுக்கான செய்தி எதுவும் வழங்கப்படவில்லை."
        )
        return {
            "message": message_str,
            "language_detected": languages_detected,
            "risk_score": 0,
            "risk_level": RISK_LEVEL_LOW,
            "verdict": verdict_str,
            "explanation": explanation,
            "output_language": target_lang,
            "detected_indicators": [],
            "link_analysis": {
                "available": True,
                "risk_flags": []
            },
            "text_analysis": {
                "available": True,
                "scam_category": [],
                "detected_phrases": []
            },
            "recommendations": [
                RECOMMENDATION_TEMPLATES["standard_safety"][target_lang]
            ],
            "analysis_status": "complete"
        }

    # 3. Integrate Backend 2 (Text Analysis)
    text_data, text_available = run_backend2_integration(message_str, text_results)

    # 4. Integrate Backend 1 (Link Analysis)
    link_data, link_available = run_backend1_integration(message_str, link_results)

    # 5. Determine analysis status
    if text_available and link_available:
        analysis_status = "complete"
    elif text_available or link_available:
        analysis_status = "incomplete"
    else:
        analysis_status = "incomplete"

    # 6. Extract indicators & trigger signals
    detected_phrases = text_data.get("detected_phrases", []) if text_available else []
    scam_categories = text_data.get("scam_category", []) if text_available else []
    text_flags = text_data.get("risk_flags", []) if text_available else []
    link_flags = link_data.get("risk_flags", []) if link_available else []

    # Check for strong OTP trigger
    has_otp = (
        text_data.get("has_otp_request", False) or
        any("otp" in str(f).lower() for f in text_flags) or
        any("otp" in str(p).lower() for p in detected_phrases) or
        "credential_theft" in scam_categories
    )

    # Suppress OTP trigger if it's purely a legitimate bank security disclaimer
    if is_legitimate_security_advisory(message_str) and len(scam_categories) <= 1:
        has_otp = False

    has_threat = (
        any("threat" in str(c) for c in scam_categories) or
        any("threat" in str(f) for f in text_flags)
    )

    has_urgency = (
        text_data.get("coercion_score", 0) > 20 or
        any("urgency" in str(f) for f in text_flags) or
        any("payment" in str(c) for c in scam_categories)
    )

    has_impersonation = (
        any("impersonation" in str(c) for c in scam_categories) or
        any("impersonation" in str(f) for f in text_flags) or
        any("impersonation" in str(f) for f in link_flags)
    )

    has_link = bool(link_flags) or bool(extract_raw_urls(message_str))

    # Assemble human-readable detected indicators in target language
    detected_indicators_list: List[str] = []
    if has_otp:
        detected_indicators_list.append(INDICATOR_NAMES["otp_harvesting"][target_lang])
    if has_urgency:
        detected_indicators_list.append(INDICATOR_NAMES["false_urgency"][target_lang])
    if any("account" in str(c) or "account" in str(f) for c in scam_categories for f in text_flags):
        detected_indicators_list.append(INDICATOR_NAMES["account_threat"][target_lang])
    if any("utility" in str(c) or "utility" in str(f) for c in scam_categories for f in text_flags):
        detected_indicators_list.append(INDICATOR_NAMES["utility_threat"][target_lang])
    if has_impersonation:
        detected_indicators_list.append(INDICATOR_NAMES["authority_impersonation"][target_lang])
    if any("kyc" in str(c) or "kyc" in str(f) for c in scam_categories for f in text_flags):
        detected_indicators_list.append(INDICATOR_NAMES["kyc_scam"][target_lang])
    if any("typo" in str(f) for f in link_flags):
        detected_indicators_list.append(INDICATOR_NAMES["typosquatting"][target_lang])
    if any("tld" in str(f) for f in link_flags):
        detected_indicators_list.append(INDICATOR_NAMES["suspicious_tld"][target_lang])
    if any("shortened" in str(f) for f in link_flags):
        detected_indicators_list.append(INDICATOR_NAMES["shortened_url"][target_lang])
    if any("ip" in str(f) for f in link_flags):
        detected_indicators_list.append(INDICATOR_NAMES["ip_hostname"][target_lang])
    if has_link and not any("url" in ind.lower() or "link" in ind.lower() for ind in detected_indicators_list):
        detected_indicators_list.append(INDICATOR_NAMES["suspicious_url"][target_lang])

    # Deduplicate detected indicators
    unique_indicators: List[str] = []
    for item in detected_indicators_list:
        if item not in unique_indicators:
            unique_indicators.append(item)

    # 7. Normalize Component Scores & Calculate Overall Weighted Score
    text_norm, coercion_norm, link_norm, domain_norm, avail_map = normalize_component_scores(
        text_data=text_data,
        link_data=link_data,
        text_available=text_available,
        link_available=link_available,
        message_text=message_str
    )

    # Critical trigger condition: explicit OTP harvesting requests
    has_critical_trigger = has_otp and (text_norm >= 40 or coercion_norm >= 20)

    final_score = calculate_calibrated_risk_score(
        text_score=text_norm,
        coercion_score=coercion_norm,
        link_score=link_norm,
        domain_score=domain_norm,
        availability=avail_map,
        has_critical_trigger=has_critical_trigger
    )

    # 8. Verdict Mapping
    risk_level, verdict_label = determine_verdict_and_level(final_score)
    verdict_text = VERDICT_TEXTS[risk_level][target_lang]

    # 9. Explanation Engine
    explanation = generate_multilingual_explanation(
        detected_indicators=unique_indicators,
        has_otp=has_otp,
        has_urgency=has_urgency,
        has_threat=has_threat,
        has_link=bool(link_flags),
        has_impersonation=has_impersonation,
        output_lang=target_lang,
        original_phrases=detected_phrases
    )

    # 10. Recommendations
    recommendations = generate_recommendations(
        has_otp=has_otp,
        has_threat=has_threat,
        has_link=bool(link_flags) or bool(extract_raw_urls(message_str)),
        has_impersonation=has_impersonation,
        score=final_score,
        output_lang=target_lang
    )

    # 11. Format backend output sections faithfully
    formatted_link_analysis: Dict[str, Any] = {
        "available": bool(link_available),
        "risk_flags": link_flags if link_available else []
    }
    if "urls_data" in link_data:
        formatted_link_analysis["urls_inspected"] = link_data["urls_data"]

    formatted_text_analysis: Dict[str, Any] = {
        "available": bool(text_available),
        "scam_category": scam_categories if text_available else [],
        "detected_phrases": detected_phrases if text_available else []
    }
    if text_available and "coercion_score" in text_data:
        formatted_text_analysis["coercion_score"] = text_data["coercion_score"]

    # 12. Return structured JSON report
    return {
        "message": message_str,
        "language_detected": languages_detected,
        "risk_score": final_score,
        "risk_level": risk_level,
        "verdict": verdict_text,
        "explanation": explanation,
        "output_language": target_lang,
        "detected_indicators": unique_indicators,
        "link_analysis": formatted_link_analysis,
        "text_analysis": formatted_text_analysis,
        "recommendations": recommendations,
        "analysis_status": analysis_status
    }
