# -*- coding: utf-8 -*-
"""
FraudShield - Backend 1: Link Analysis & Intelligence Module
============================================================
A fast, robust, production-quality pure-Python module designed to analyze links inside
SMS and chat messages in English, Hindi (हिन्दी / Hinglish), and Tamil (தமிழ் / Tanglish).

Detects:
- Shortened URLs and resolves multi-hop HTTP redirects safely.
- Suspicious / cheap / abused TLDs (.xyz, .top, .club, .online, .tk, etc.).
- Multilingual brand impersonation targeting major Indian banks, UPI, and govt services
  (e.g., SBI / एसबीआई / எஸ்பிஐ, HDFC / एचडीएफसी / எச்டிஎஃப்சி, etc.).
- Typosquatting / lookalike domains with token-level and homoglyph analysis.
- Multilingual fraud / fear / urgency keyword stuffing (Devanagari, Tamil, Hinglish, Tanglish).
- Internationalized Domain Names (IDN / Punycode) and zero-day heuristics.

Main Public Interface:
    analyze_links(text: str) -> dict
"""

import sys
import re
import difflib
import socket
from urllib.parse import urlparse
from typing import List, Dict, Any, Optional, Set, Tuple

import requests

# Ensure terminal output handles UTF-8 (Devanagari & Tamil) gracefully on Windows
if sys.stdout and hasattr(sys.stdout, 'reconfigure'):
    try:
        sys.stdout.reconfigure(encoding='utf-8', errors='backslashreplace')
    except Exception:
        pass

# ---------------------------------------------------------------------------
# Configuration & Knowledge Bases
# ---------------------------------------------------------------------------

# Common URL Shortener Domains
KNOWN_SHORTENERS: Set[str] = {
    "bit.ly", "tinyurl.com", "t.co", "goo.gl", "cutt.ly", "rb.gy",
    "shorturl.at", "is.gd", "v.gd", "ow.ly", "rebrand.ly", "t.ly",
    "tiny.cc", "bc.vc", "clck.ru", "s.id", "rotf.lol", "buff.ly",
    "adf.ly", "bit.do", "bl.ink", "hyperurl.co", "q.gs", "short.io",
    "amzn.to", "fkrt.it", "wa.me", "t.me"
}

# High-risk / Cheap / Abused Top-Level Domains (TLDs) frequently used in phishing
SUSPICIOUS_TLDS: Set[str] = {
    "xyz", "top", "club", "online", "site", "icu", "buzz", "tk", "ml", "ga",
    "cf", "gq", "work", "click", "link", "live", "info", "rest", "cam", "fit",
    "vip", "surf", "space", "mom", "pw", "cn", "cc", "shop", "quest", "loan",
    "win", "bid", "stream", "party", "monster", "fun", "uno", "website",
    "tokyo", "kim", "country", "download", "racing", "gdn", "date", "faith", "apk"
}

# Free hosting / dynamic DNS platforms frequently abused to host phishing pages
FREE_HOSTING_DOMAINS: Set[str] = {
    "ngrok-free.app", "ngrok.io", "duckdns.org", "000webhostapp.com",
    "glitch.me", "pages.dev", "vercel.app", "firebaseapp.com", "web.app",
    "github.io", "gitlab.io", "weeblysite.com", "wixsite.com", "blogspot.com",
    "sites.google.com", "formsite.com", "render.com", "netlify.app"
}

# Multi-part TLD suffixes (India & International)
MULTI_PART_TLDS: List[str] = [
    "co.in", "gov.in", "org.in", "net.in", "res.in", "ac.in",
    "edu.in", "mil.in", "gen.in", "bank.in", "com.au", "co.uk",
    "org.uk", "gov.uk", "com.br", "co.jp"
]

# High-value targets for impersonation (Indian Banks, Wallets/UPI, Govt, Tech)
# Format: Brand Identifier -> List of verified legitimate domain suffixes
LEGITIMATE_BRAND_DOMAINS: Dict[str, List[str]] = {
    # Banks in India
    "sbi": [
        "sbi.co.in", "onlinesbi.sbi", "onlinesbi.com", "sbicard.com",
        "statebankofindia.com", "sbi.bank.in", "bank.sbi"
    ],
    "hdfc": [
        "hdfcbank.com", "hdfc.com", "hdfcbank.net", "hdfcsec.com",
        "hdfc.bank.in", "hdfcbank.co.in"
    ],
    "icici": [
        "icicibank.com", "icicidirect.com", "icicibank.co.in", "icici.bank.in"
    ],
    "axis": [
        "axisbank.com", "axisbank.co.in", "axis.bank.in"
    ],
    "pnb": [
        "pnbindia.in", "netpnb.com", "pnb.bank.in"
    ],
    "bob": [
        "bankofbaroda.in", "bankofbaroda.com", "bobibanking.com", "bob.bank.in"
    ],
    "kotak": [
        "kotak.com", "kotakcherry.com", "kotak.bank.in"
    ],
    "canara": [
        "canarabank.com", "canarabank.in", "canara.bank.in"
    ],
    "unionbank": [
        "unionbankofindia.co.in", "unionbankonline.co.in", "unionbank.bank.in"
    ],
    "indusind": [
        "indusind.com", "indusind.bank.in"
    ],
    "yesbank": [
        "yesbank.in", "yesbank.com", "yesbank.bank.in"
    ],
    "rbi": [
        "rbi.org.in"
    ],

    # UPI / Wallets / Fintech
    "paytm": [
        "paytm.com", "paytmbank.com", "paytmmoney.com"
    ],
    "phonepe": [
        "phonepe.com"
    ],
    "gpay": [
        "google.com", "pay.google.com"
    ],
    "googlepay": [
        "google.com", "pay.google.com"
    ],
    "bhim": [
        "bhimupi.org.in", "npci.org.in"
    ],
    "cred": [
        "cred.club"
    ],
    "mobikwik": [
        "mobikwik.com"
    ],
    "razorpay": [
        "razorpay.com"
    ],
    "zerodha": [
        "zerodha.com", "kite.zerodha.com"
    ],

    # Tech & Communication
    "google": [
        "google.com", "google.co.in", "goo.gl"
    ],
    "whatsapp": [
        "whatsapp.com", "wa.me"
    ],
    "facebook": [
        "facebook.com", "fb.com", "fb.me"
    ],
    "instagram": [
        "instagram.com"
    ],
    "amazon": [
        "amazon.in", "amazon.com", "amzn.to", "amzn.in"
    ],
    "flipkart": [
        "flipkart.com", "fkrt.it"
    ],
    "netflix": [
        "netflix.com"
    ],
    "microsoft": [
        "microsoft.com", "live.com", "office.com"
    ],
    "apple": [
        "apple.com", "icloud.com"
    ],
    "telegram": [
        "telegram.org", "t.me"
    ],

    # Government & Public Services (India)
    "uidai": [
        "uidai.gov.in", "myaadhaar.uidai.gov.in"
    ],
    "aadhaar": [
        "uidai.gov.in", "myaadhaar.uidai.gov.in"
    ],
    "incometax": [
        "incometax.gov.in", "incometaxindia.gov.in", "incometaxindiaefiling.gov.in"
    ],
    "epfo": [
        "epfindia.gov.in"
    ],
    "epfindia": [
        "epfindia.gov.in"
    ],
    "digilocker": [
        "digilocker.gov.in"
    ],
    "parivahan": [
        "parivahan.gov.in", "mparivahan.parivahan.gov.in"
    ],
    "mparivahan": [
        "parivahan.gov.in", "mparivahan.parivahan.gov.in"
    ],
    "passportindia": [
        "passportindia.gov.in"
    ],
    "cybercrime": [
        "cybercrime.gov.in"
    ],
    "irctc": [
        "irctc.co.in"
    ],
    "indiapost": [
        "indiapost.gov.in", "ippbonline.com"
    ]
}

# Multilingual Brand Aliases (Hindi Devanagari & Tamil Script to Canonical Brand ID)
MULTILINGUAL_BRAND_ALIASES: Dict[str, str] = {
    # Hindi (Devanagari)
    "एसबीआई": "sbi",
    "स्टेट बैंक": "sbi",
    "एचडीएफसी": "hdfc",
    "आईसीआईसीआई": "icici",
    "एक्सिस": "axis",
    "पीएनबी": "pnb",
    "पंजाब नेशनल": "pnb",
    "बैंक ऑफ बड़ौदा": "bob",
    "कोटक": "kotak",
    "केनरा": "canara",
    "यूनियन बैंक": "unionbank",
    "पेटीएम": "paytm",
    "फोनपे": "phonepe",
    "गूगलपे": "googlepay",
    "भीम": "bhim",
    "आधार": "uidai",
    "आयकर": "incometax",

    # Tamil Script
    "எஸ்பிஐ": "sbi",
    "ஸ்டேட் பாங்க்": "sbi",
    "எச்டிஎஃப்சி": "hdfc",
    "ஐசிஐசிஐ": "icici",
    "ஆக்சிஸ்": "axis",
    "பிஎன்பி": "pnb",
    "கோடக்": "kotak",
    "கனரா": "canara",
    "பேடிஎம்": "paytm",
    "போன்பே": "phonepe",
    "கூகுள்பே": "googlepay",
    "ஆதார்": "uidai",
    "வருமான வரி": "incometax"
}

# ---------------------------------------------------------------------------
# Multilingual Fraud Keywords (English, Hindi, Tamil, Hinglish/Tanglish)
# ---------------------------------------------------------------------------

FRAUD_KEYWORDS_EN: Set[str] = {
    "kyc", "pan", "otp", "verify", "verification", "update", "blocked",
    "unblock", "suspended", "reward", "refund", "cashback", "lottery",
    "bonus", "claim", "urgent", "login", "secure", "netbanking", "banking",
    "gift", "winner", "deactivate", "activate", "electric-bill", "bill-due",
    "electricity", "disconnection", "challan", "fine", "penalty"
}

# Backward compatibility alias
FRAUD_KEYWORDS: Set[str] = FRAUD_KEYWORDS_EN

FRAUD_KEYWORDS_HI: Set[str] = {
    "केवाईसी", "पैन", "ओटीपी", "सत्यापित", "सत्यापन", "अपडेट", "अमान्य",
    "निलंबित", "ब्लॉक", "बंद", "इनाम", "पुरस्कार", "लॉटरी", "रिफंड",
    "वापसी", "कैशबैक", "खाता", "बिजली", "विद्युत", "बिल", "काट",
    "तुरंत", "शीघ्र", "लॉगिन", "बैंक", "बैंकिंग", "विजेता", "उपहार",
    "जुर्माना", "चालान", "कटौती", "खत्म", "चेतावनी"
}

FRAUD_KEYWORDS_TA: Set[str] = {
    "கேஒய்சி", "பான்", "ஓடிபி", "முடக்கப்பட்டது", "முடக்கம்", "புதுப்பிக்கவும்",
    "புதுப்பிப்பு", "சரிபார்க்கவும்", "சரிபார்ப்பு", "பரிசு", "லாட்டரி",
    "கணக்கு", "மின் கட்டணம்", "மின் இணைப்பு", "துண்டிக்கப்படும்", "உடனடியாக",
    "உடனே", "வங்கி", "வென்றீர்கள்", "வெற்றி", "பணம்", "மீளளிப்பு", "உள்நுழைக",
    "லாகின்", "செயலிழக்கம்", "அபராதம்", "எச்சரிக்கை"
}

# Common transliterated / colloquial scam words in Hinglish & Tanglish
FRAUD_KEYWORDS_ROMANIZED: Set[str] = {
    "khata", "rok", "band", "turant", "inaam", "bijli", "kat", "jeeta",
    "chhoot", "dhyan", "paise", "jald", "karein", "kanakku", "mudakkapattadhu",
    "puduppikka", "sariparkka", "parisu", "udane", "vangi", "kattanam",
    "vetri", "panam", "thundikkapadum", "anuppavum"
}

# Homoglyph character substitutions commonly used in typosquatting
HOMOGLYPH_MAP: Dict[str, str] = {
    "0": "o",
    "1": "l",
    "|": "l",
    "i": "l",
    "5": "s",
    "8": "b",
    "vv": "w",
    "rn": "m"
}

# HTTP Request headers for unmasking
REQUEST_HEADERS: Dict[str, str] = {
    "User-Agent": (
        "Mozilla/5.0 (Windows NT 10.0; Win64; x64) "
        "AppleWebKit/537.36 (KHTML, like Gecko) "
        "Chrome/122.0.0.0 Safari/537.36 FraudShield/1.0"
    ),
    "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
    "Accept-Language": "en-US,en;q=0.5",
}

# Non-ASCII punctuation and brackets to clean from extracted URLs
UNICODE_TRAILING_PUNCT = ".,;:!?)>\"'।॥၊።\u201c\u201d\u2018\u2019\u200b\u200c\u200d\ufeff "


# ---------------------------------------------------------------------------
# Helper Functions
# ---------------------------------------------------------------------------

def detect_languages(text: str) -> List[str]:
    """
    Identifies languages present in text: 'en' (English), 'hi' (Hindi), 'ta' (Tamil).
    Zero external dependencies, fast Unicode-range check.
    """
    langs: List[str] = []
    if not text:
        return ["en"]

    # Devanagari script: U+0900 to U+097F
    if re.search(r'[\u0900-\u097F]', text):
        langs.append("hi")

    # Tamil script: U+0B80 to U+0BFF
    if re.search(r'[\u0B80-\u0BFF]', text):
        langs.append("ta")

    # Latin / English
    if re.search(r'[a-zA-Z]', text):
        langs.append("en")

    return langs or ["en"]


def extract_multilingual_fraud_keywords(text: str) -> Dict[str, List[str]]:
    """
    Extracts detected fraud/urgency keywords categorized by language.
    """
    matches: Dict[str, List[str]] = {
        "en": [],
        "hi": [],
        "ta": [],
        "romanized": []
    }
    if not text:
        return matches

    text_lower = text.lower()

    # English keywords
    for kw in FRAUD_KEYWORDS_EN:
        if kw in text_lower:
            matches["en"].append(kw)

    # Hindi Devanagari keywords
    for kw in FRAUD_KEYWORDS_HI:
        if kw in text:
            matches["hi"].append(kw)

    # Tamil script keywords
    for kw in FRAUD_KEYWORDS_TA:
        if kw in text:
            matches["ta"].append(kw)

    # Romanized / Hinglish / Tanglish keywords
    for kw in FRAUD_KEYWORDS_ROMANIZED:
        if kw in text_lower:
            matches["romanized"].append(kw)

    return matches


def extract_brands_from_message(text: str) -> Set[str]:
    """
    Identifies any brand mentioned in message text across English, Hindi, and Tamil.
    """
    found_brands: Set[str] = set()
    if not text:
        return found_brands

    text_lower = text.lower()

    # 1. Check English brands
    for brand in LEGITIMATE_BRAND_DOMAINS.keys():
        if len(brand) <= 3:
            if re.search(rf'\b{re.escape(brand)}\b', text_lower):
                found_brands.add(brand)
        else:
            if brand in text_lower:
                found_brands.add(brand)

    # 2. Check Hindi and Tamil aliases
    for alias, brand_id in MULTILINGUAL_BRAND_ALIASES.items():
        if alias in text:
            found_brands.add(brand_id)

    return found_brands


def decode_punycode_host(hostname: str) -> Tuple[str, bool]:
    """
    Decodes IDN Punycode hostname (e.g. xn--...) to Unicode.
    Returns: (decoded_host, is_punycode)
    """
    if not hostname:
        return "", False
    if "xn--" in hostname.lower():
        try:
            decoded = hostname.encode('ascii').decode('idna')
            return decoded, True
        except Exception:
            return hostname, True
    return hostname, False

def is_ip_address(hostname: str) -> bool:
    """Checks if hostname is an IPv4 or IPv6 address."""
    if not hostname:
        return False
    # Strip port if present
    host = hostname.split(':')[0]
    try:
        socket.inet_aton(host)
        return True
    except (socket.error, OSError):
        pass
    try:
        socket.inet_pton(socket.AF_INET6, host)
        return True
    except (socket.error, OSError, AttributeError):
        pass
    return False


def extract_domain_parts(url: str) -> Tuple[str, str, str]:
    """
    Extracts hostname/domain and parses (hostname, core_domain, tld).
    Handles second-level domains like .co.in, .gov.in, .org.in, .bank.in, and Punycode.
    """
    if not re.match(r'^[a-zA-Z]+://', url):
        url = "http://" + url

    try:
        parsed = urlparse(url)
        hostname = (parsed.hostname or "").lower().strip().rstrip('.')
    except Exception:
        hostname = ""

    if not hostname:
        return "", "", ""

    # Decode Punycode IDN if present
    hostname, _ = decode_punycode_host(hostname)

    # Check if host is raw IP
    if is_ip_address(hostname):
        return hostname, hostname, ""

    for multi in MULTI_PART_TLDS:
        if hostname.endswith("." + multi):
            tld = multi
            base = hostname[:-len(multi)-1]
            base_parts = base.split('.')
            domain_name = base_parts[-1]
            return hostname, domain_name, tld

    parts = hostname.split('.')
    if len(parts) >= 2:
        tld = parts[-1]
        domain_name = parts[-2]
    else:
        domain_name = parts[0] if parts else ""
        tld = ""

    return hostname, domain_name, tld


def extract_urls(text: str) -> List[str]:
    """
    Extracts all URLs from SMS/text messages across English, Hindi, and Tamil:
    - Standard http/https schemes
    - Schemes without protocol (e.g. bit.ly/xyz, sbi-kyc.top/login)
    - Raw IP address URLs (e.g. 192.168.1.1/login or http://103.22.x.x)
    - Safely strips English and Indic punctuation (danda ।, quotes, etc.)
    """
    if not text or not isinstance(text, str):
        return []

    found_urls: List[str] = []
    seen: Set[str] = set()

    # 1. Standard http/https/ftp URLs (including IP-based URLs)
    standard_url_pattern = r'https?://(?:[-a-zA-Z0-9@:%._\+~#=]{1,256}\.[a-zA-Z0-9()]{1,24}|(?:\d{1,3}\.){3}\d{1,3})(?::\d{1,5})?\b(?:[-a-zA-Z0-9()@:%_\+.~#?&//=]*)'
    
    # 2. Scheme-less domain URLs (e.g., bit.ly/xyz or secure-sbi.xyz/login)
    schemeless_domain_pattern = r'(?<![a-zA-Z0-9@.-])(?:[a-zA-Z0-9-]+\.)+(?:com|org|net|in|gov\.in|co\.in|bank\.in|xyz|top|club|online|site|icu|buzz|tk|ml|ga|cf|gq|work|click|link|live|info|ly|io|cc|is|gd|to|gl|app|dev|me)(?:/[^\s,;!?\'"।॥\u201c\u201d\u2018\u2019]*)?'

    # 3. Scheme-less IP address URLs (e.g., 192.168.1.100/login)
    schemeless_ip_pattern = r'\b(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)(?::\d{1,5})?(?:/[^\s,;!?\'"।॥\u201c\u201d\u2018\u2019]*)?'

    for match in re.finditer(standard_url_pattern, text, re.IGNORECASE):
        url = match.group(0).rstrip(UNICODE_TRAILING_PUNCT)
        if url and url not in seen:
            seen.add(url)
            found_urls.append(url)

    for match in re.finditer(schemeless_domain_pattern, text, re.IGNORECASE):
        raw_match = match.group(0).rstrip(UNICODE_TRAILING_PUNCT)
        if raw_match and not any(raw_match in u for u in seen):
            full_url = "http://" + raw_match
            if full_url not in seen:
                seen.add(full_url)
                found_urls.append(full_url)

    for match in re.finditer(schemeless_ip_pattern, text, re.IGNORECASE):
        raw_match = match.group(0).rstrip(UNICODE_TRAILING_PUNCT)
        if raw_match and not any(raw_match in u for u in seen):
            full_url = "http://" + raw_match
            if full_url not in seen:
                seen.add(full_url)
                found_urls.append(full_url)

    return found_urls


def is_known_shortener_url(url: str) -> bool:
    """Checks whether the given URL uses a known URL shortening service."""
    domain, _, _ = extract_domain_parts(url)
    clean_domain = domain.removeprefix("www.")
    return clean_domain in KNOWN_SHORTENERS


def unmask_url(url: str, timeout: float = 3.5) -> Tuple[str, bool, bool]:
    """
    Follows HTTP redirects to unmask shortened / obfuscated URLs.
    Returns:
        (final_url, is_shortened, expansion_success)
    """
    is_short = is_known_shortener_url(url)
    target_url = url
    if not target_url.startswith(("http://", "https://")):
        target_url = "http://" + target_url

    try:
        session = requests.Session()
        session.headers.update(REQUEST_HEADERS)
        
        # Try HEAD request first for fast redirect resolution
        response = session.head(target_url, allow_redirects=True, timeout=timeout)
        final_url = response.url

        # If HEAD request was blocked or not supported, fallback to GET stream
        if response.status_code in [405, 403, 501] or (final_url == target_url and is_short):
            response = session.get(target_url, allow_redirects=True, timeout=timeout, stream=True)
            final_url = response.url
            response.close()

        orig_host, _, _ = extract_domain_parts(target_url)
        final_host, _, _ = extract_domain_parts(final_url)

        # True if it was a known shortener or hopped cross-domain through redirect chain
        was_shortened = is_short or (orig_host != final_host and len(response.history) > 0 and len(orig_host) <= 10)
        return final_url, was_shortened, True

    except Exception:
        # Fallback to target URL if network request fails
        return target_url, is_short, False


def normalize_homoglyphs(text: str) -> str:
    """Replaces common leetspeak/homoglyphs with standard characters."""
    normalized = text.lower()
    for char, replacement in HOMOGLYPH_MAP.items():
        normalized = normalized.replace(char, replacement)
    return normalized


def is_brand_legitimate(hostname: str, brand: str) -> bool:
    """Verifies whether a hostname belongs to the brand's verified domain list."""
    clean_host = hostname.lower().removeprefix("www.")
    legit_domains = LEGITIMATE_BRAND_DOMAINS.get(brand, [])
    return any(clean_host == legit or clean_host.endswith("." + legit) for legit in legit_domains)


def is_any_brand_legitimate(hostname: str) -> bool:
    """Verifies if hostname is legitimately owned by ANY known official brand."""
    clean_host = hostname.lower().removeprefix("www.")
    for legit_domains in LEGITIMATE_BRAND_DOMAINS.values():
        if any(clean_host == legit or clean_host.endswith("." + legit) for legit in legit_domains):
            return True
    return False


def check_typosquatting_and_brand_abuse(
    hostname: str,
    full_url: str,
    message_brands: Optional[Set[str]] = None
) -> Tuple[bool, Optional[str], List[str]]:
    """
    Detects typosquatting, brand spoofing, and unauthorized impersonation.
    Evaluates both the URL structure and the message text context (Tamil, Hindi, English).
    Returns: (is_typosquat, targeted_brand, risk_flags)
    """
    hostname = hostname.lower()
    clean_host = hostname.removeprefix("www.")
    normalized_host = normalize_homoglyphs(clean_host)
    risk_flags: List[str] = []

    # If the domain is officially legitimate, bypass
    if is_any_brand_legitimate(hostname):
        return False, None, []

    _, core_domain, _ = extract_domain_parts(hostname)
    clean_core = re.sub(r'[^a-z0-9]', '', core_domain)
    normalized_clean_core = re.sub(r'[^a-z0-9]', '', normalize_homoglyphs(core_domain))

    # Tokenize hostname for compound lookalikes
    domain_tokens = [re.sub(r'[^a-z0-9]', '', t) for t in re.split(r'[-_.]', clean_host) if t]
    normalized_tokens = [re.sub(r'[^a-z0-9]', '', normalize_homoglyphs(t)) for t in re.split(r'[-_.]', clean_host) if t]

    # 1. Hostname-Level Brand Impersonation & Typosquatting
    for brand in LEGITIMATE_BRAND_DOMAINS.keys():
        brand_clean = re.sub(r'[^a-z0-9]', '', brand)

        brand_in_host = False
        if len(brand) <= 3:
            if re.search(rf'(^|[-_.0-9]){re.escape(brand)}([-_.0-9]|$)', clean_host) or \
               re.search(rf'(^|[-_.0-9]){re.escape(brand)}([-_.0-9]|$)', normalized_host):
                brand_in_host = True
        else:
            if brand in clean_host or brand in normalized_host or brand_clean in clean_core:
                brand_in_host = True

        if brand_in_host:
            risk_flags.append(f"brand_impersonation_{brand}")
            return True, brand, risk_flags

        # Levenshtein distance check on core and individual tokens
        candidates_to_check = [(clean_core, normalized_clean_core)]
        for t, nt in zip(domain_tokens, normalized_tokens):
            if t and t not in ["com", "org", "net", "in", "xyz", "top", "online", "site", "co"]:
                candidates_to_check.append((t, nt))

        for cand, norm_cand in candidates_to_check:
            if len(cand) >= 3 and len(brand_clean) >= 3 and abs(len(cand) - len(brand_clean)) <= 2:
                ratio = difflib.SequenceMatcher(None, cand, brand_clean).ratio()
                norm_ratio = difflib.SequenceMatcher(None, norm_cand, brand_clean).ratio()

                if ratio >= 0.78 or norm_ratio >= 0.78:
                    risk_flags.append(f"typosquatting_{brand}")
                    return True, brand, risk_flags

    # 2. Multilingual Context Impersonation:
    # If the message mentions a brand in English, Hindi (एसबीआई), or Tamil (எஸ்பிஐ),
    # but the destination domain is NOT legitimate for that brand.
    if message_brands:
        for brand in message_brands:
            if not is_brand_legitimate(hostname, brand):
                risk_flags.append(f"context_brand_impersonation_{brand}")
                return True, brand, risk_flags

    # 3. Abuse of free hosting with fraud keywords
    for free_host in FREE_HOSTING_DOMAINS:
        if clean_host == free_host or clean_host.endswith("." + free_host):
            url_lower = full_url.lower()
            found_keywords = [kw for kw in FRAUD_KEYWORDS_EN if kw in url_lower]
            if found_keywords:
                risk_flags.append(f"free_hosting_phishing_keywords_{','.join(found_keywords[:2])}")
                return True, "generic_service", risk_flags

    return False, None, risk_flags


def check_new_domain_and_heuristics(
    hostname: str,
    url: str,
    multilingual_keywords: Optional[Dict[str, List[str]]] = None
) -> Tuple[bool, List[str]]:
    """
    Evaluates heuristics for newly registered, zero-day, or suspicious domains:
    - Punycode IDN homograph attacks
    - IP address as hostname
    - Excessive hyphens or digits
    - Multilingual fraud / urgency keyword stuffing (English, Hindi, Tamil)
    - Abnormally long domain names
    - Free dynamic DNS abuse
    """
    if is_any_brand_legitimate(hostname):
        return False, []

    flags: List[str] = []
    is_suspicious_domain = False
    clean_host = hostname.lower().removeprefix("www.")

    # 1. Punycode IDN Homograph Detection
    if "xn--" in clean_host:
        flags.append("punycode_idn_domain")
        is_suspicious_domain = True

    # 2. HTTP Basic Auth (@ symbol) spoofing trick (e.g. sbi.co.in@evil.com)
    try:
        parsed_url = urlparse(url if "://" in url else "http://" + url)
        if parsed_url.username or ("@" in (url.split("/")[2] if len(url.split("/")) > 2 else "")):
            flags.append("userinfo_at_symbol_obfuscation")
            is_suspicious_domain = True
    except Exception:
        pass

    # 3. Direct IP address check
    if is_ip_address(hostname):
        flags.append("ip_address_as_hostname")
        is_suspicious_domain = True

    # 4. Free hosting domain used
    if any(clean_host == fh or clean_host.endswith("." + fh) for fh in FREE_HOSTING_DOMAINS):
        flags.append("free_hosting_provider")
        is_suspicious_domain = True

    # 5. Excessive hyphens in domain
    if hostname.count('-') >= 2:
        flags.append("multiple_hyphens_in_domain")
        is_suspicious_domain = True

    # 5. Digit-heavy domain name
    _, domain_name, _ = extract_domain_parts(hostname)
    if domain_name and not is_ip_address(hostname):
        digits_count = sum(c.isdigit() for c in domain_name)
        if digits_count >= 4 or (len(domain_name) > 0 and digits_count / len(domain_name) > 0.4):
            flags.append("high_digit_entropy")
            is_suspicious_domain = True

    # 6. URL & Hostname Fraud Keyword Matching
    full_str = (hostname + " " + url).lower()
    matched_en_url = [kw for kw in FRAUD_KEYWORDS_EN if kw in full_str]
    if matched_en_url:
        flags.append(f"contains_fraud_keywords_{'_'.join(matched_en_url[:2])}")
        if len(matched_en_url) >= 2 or any(k in ["kyc", "pan", "otp", "blocked", "suspended"] for k in matched_en_url):
            is_suspicious_domain = True

    # 7. Multilingual Message Context Correlation (Hindi & Tamil Urgency)
    if multilingual_keywords:
        hi_kws = multilingual_keywords.get("hi", [])
        ta_kws = multilingual_keywords.get("ta", [])
        rom_kws = multilingual_keywords.get("romanized", [])

        if hi_kws:
            flags.append("multilingual_urgency_hindi")
            is_suspicious_domain = True
        if ta_kws:
            flags.append("multilingual_urgency_tamil")
            is_suspicious_domain = True
        if rom_kws and len(rom_kws) >= 2:
            flags.append("multilingual_urgency_indic_romanized")
            is_suspicious_domain = True

    # 8. Abnormally long domain name
    if len(hostname) > 35:
        flags.append("excessive_domain_length")
        is_suspicious_domain = True

    return is_suspicious_domain, flags


def calculate_overall_risk(links_found: List[Dict[str, Any]]) -> str:
    """
    Calculates overall link risk level: 'high', 'medium', or 'low'.
    """
    if not links_found:
        return "low"

    max_severity = 0  # 0: low, 1: medium, 2: high

    for link in links_found:
        flags = link.get("risk_flags", [])
        is_typosquat = link.get("is_typosquat", False)
        is_suspicious_tld = link.get("is_suspicious_tld", False)
        is_new_domain = link.get("is_new_domain", False)
        is_shortened = link.get("is_shortened", False)

        # High severity triggers
        if (
            is_typosquat or
            "ip_address_as_hostname" in flags or
            (is_suspicious_tld and is_new_domain) or
            any("brand_impersonation" in f or "typosquatting" in f for f in flags) or
            len(flags) >= 2
        ):
            max_severity = max(max_severity, 2)
        # Medium severity triggers
        elif is_suspicious_tld or is_new_domain or is_shortened or len(flags) == 1:
            max_severity = max(max_severity, 1)

    if max_severity == 2:
        return "high"
    elif max_severity == 1:
        return "medium"
    return "low"


# ---------------------------------------------------------------------------
# Main Public Interface
# ---------------------------------------------------------------------------

def analyze_links(text: str) -> Dict[str, Any]:
    """
    Analyzes all links in a given text/SMS message with multilingual support
    for English, Hindi (हिन्दी / Hinglish), and Tamil (தமிழ் / Tanglish).

    Exact Output Schema:
    {
        "original_text": str,
        "links_found": [
            {
                "original_url": str,
                "final_url": str,
                "domain": str,
                "is_shortened": bool,
                "is_suspicious_tld": bool,
                "is_typosquat": bool,
                "is_new_domain": bool,
                "risk_flags": list[str]
            }
        ],
        "overall_link_risk": "high" | "medium" | "low"
    }
    """
    if not isinstance(text, str):
        text = str(text) if text is not None else ""

    # 1. Multilingual Context Pre-processing
    detected_langs = detect_languages(text)
    multilingual_kws = extract_multilingual_fraud_keywords(text)
    message_brands = extract_brands_from_message(text)

    raw_urls = extract_urls(text)
    links_found: List[Dict[str, Any]] = []

    for raw_url in raw_urls:
        # 2. Unmask / expand shortened URL
        final_url, is_shortened, expanded_ok = unmask_url(raw_url)

        # 3. Extract domain and TLD information
        domain, _, tld = extract_domain_parts(final_url)
        if not domain:
            domain, _, tld = extract_domain_parts(raw_url)

        # 4. Check Suspicious TLD
        is_suspicious_tld = tld.lower() in SUSPICIOUS_TLDS

        # 5. Check Typosquatting and Multilingual Brand Abuse
        is_typosquat, target_brand, typo_flags = check_typosquatting_and_brand_abuse(
            domain, final_url, message_brands=message_brands
        )

        # 6. Check New Domain / Heuristics / Multilingual Context
        is_new_domain, heuristic_flags = check_new_domain_and_heuristics(
            domain, final_url, multilingual_keywords=multilingual_kws
        )

        # Assemble risk flags
        risk_flags: List[str] = []
        if is_suspicious_tld:
            risk_flags.append("suspicious_tld")
        if is_shortened:
            risk_flags.append("shortened_url")
        if not expanded_ok and is_shortened:
            risk_flags.append("unmask_failed_offline")

        risk_flags.extend(typo_flags)
        risk_flags.extend(heuristic_flags)

        # Deduplicate while preserving insertion order
        deduped_flags = list(dict.fromkeys(risk_flags))

        link_entry = {
            "original_url": raw_url,
            "final_url": final_url,
            "domain": domain.removeprefix("www.") if domain else "",
            "is_shortened": is_shortened,
            "is_suspicious_tld": is_suspicious_tld,
            "is_typosquat": is_typosquat,
            "is_new_domain": is_new_domain,
            "risk_flags": deduped_flags
        }
        links_found.append(link_entry)

    overall_risk = calculate_overall_risk(links_found)

    return {
        "original_text": text,
        "links_found": links_found,
        "overall_link_risk": overall_risk
    }


# ---------------------------------------------------------------------------
# Test Section
# ---------------------------------------------------------------------------

if __name__ == "__main__":
    import json

    test_messages = [
        # Test Case 1: Safe English Message (Official HDFC Bank transaction)
        (
            "Safe Message (English)",
            "Dear Customer, your HDFC Bank A/c ending 4321 is credited with Rs 15,000 on 09-Oct. "
            "Check your statement on https://www.hdfcbank.com or via official mobile app."
        ),
        # Test Case 2: Hindi Phishing SMS (Devanagari - SBI suspension & electricity bill scam)
        (
            "Hindi Phishing SMS (Devanagari)",
            "प्रिय ग्राहक, आपका एसबीआई (SBI) खाता निलंबित कर दिया गया है। "
            "तुरंत अपना केवाईसी अपडेट करें: http://sbi-kyc-verification.top/login नहीं तो बिजली बिल बकाया की तरह सेवा बंद होगी।"
        ),
        # Test Case 3: Tamil Phishing SMS (Tamil Script - SBI blocked scam on suspicious TLD)
        (
            "Tamil Phishing SMS (Tamil Script)",
            "அன்புள்ள வாடிக்கையாளரே, உங்கள் எஸ்பிஐ வங்கி கணக்கு கேஒய்சி நிலுவையில் உள்ளதால் முடக்கப்பட்டுள்ளது. "
            "உடனடியாக புதுப்பிக்க கிளிக் செய்யவும்: http://sbi-unblock-portal.xyz/kyc"
        ),
        # Test Case 4: Hinglish Phishing SMS (Transliterated Romanized Hindi + Shortened Link)
        (
            "Hinglish Scam with Shortener",
            "Aapka PNB account block ho gaya hai. Turant pan card update karein aur 50000 inaam paayein: https://bit.ly/paytm-reward-claim"
        ),
        # Test Case 5: Tanglish Phishing SMS (Transliterated Romanized Tamil + Typosquat Domain)
        (
            "Tanglish Scam with Typosquat Domain",
            "Unga ICICI bank netbanking mudakkapattadhu. Udane login panni verify panna click pannunga: http://icicci-banking-update.xyz/login"
        ),
        # Test Case 6: Safe Tamil Message (Official HDFC Bank update)
        (
            "Safe Message (Tamil Script)",
            "அன்புள்ள வாடிக்கையாளரே, உங்கள் எச்டிஎஃப்சி வங்கி கணக்கில் ரூ 10,000 வரவு வைக்கப்பட்டுள்ளது. "
            "விவரங்களை https://www.hdfcbank.com இல் சரிபார்க்கவும்."
        ),
        # Test Case 7: Safe Hindi Message (Official SBI transaction)
        (
            "Safe Message (Hindi Devanagari)",
            "प्रिय ग्राहक, आपके एसबीआई खाते में रु 5,000 जमा हुए हैं। शेष राशि की जांच https://www.onlinesbi.sbi पर करें।"
        ),
        # Test Case 8: Multiple Links in a Single Multilingual Message
        (
            "Multiple Links (Multilingual Mixed Context)",
            "அதிகாரப்பூர்வ தகவல்: https://cybercrime.gov.in ஐப் பார்க்கவும். "
            "एसबीआई खाता तुरंत चालू करें: http://sbi-unblock-service.top/kyc"
        ),
        # Test Case 9: Scheme-less Raw IP Link (Refund Scam)
        (
            "Scheme-less Raw IP Link",
            "आयकर विभाग सूचना: आपका रिफंड स्वीकृत हो गया है। 192.168.1.100/refund-tax पर जाकर विवरण सत्यापित करें।"
        )
    ]

    print("=" * 80)
    print(" FraudShield - Backend 1: Multilingual Link Analysis Module Test Suite")
    print(" Languages Supported: English | Hindi (हिन्दी / Hinglish) | Tamil (தமிழ் / Tanglish)")
    print("=" * 80)

    for category, msg in test_messages:
        print(f"\n--- [{category}] ---")
        print(f"Input Text: \"{msg}\"")
        result = analyze_links(msg)
        print("Analysis Result:")
        print(json.dumps(result, indent=4, ensure_ascii=False))


