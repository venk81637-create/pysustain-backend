# FraudShield — Backend 1: Link Intelligence Module

> **Production-quality link unmasking, multilingual threat intelligence, and typosquatting detection for telecom scam prevention.**

---

3# ��� Overview
**FraudShield (Backend 1)** is an autonomous, fast, robust Python module that extracts, unshortens, and evaluates links found in SMS, WhatsApp, and chat messages. 

It is specifically engineered for the Indian telecom ecosystem, protecting users from designed lookalike links targeting major Indian banks, UPI apps, and government portals across **English**, *HIndi (हिन्दी |  Hinglish)*, and **Tamil (भमिऴ् |  Tanglish)*.

---

## ⨡ Core Features

1. **URL Extraction (Unicode-Aware)**:
   - Extracts http/https, scheme-less (goo.gl/xyz, sbi-kyc.top/login), and raw IP URLs (192.168.1.100/refund).
   - Cleans Unicode punctuation (including Hindi danda त| थ, Tamil punctuation, quotes, and zero-width spaces).

2. **Safe URL Unshortening**:
   - Unmasks redirects for bit.ly, tinyurl.com, t.co, goo.gl, cutt.ly, rb.gy, shorturl.at, etc.
   - Uses HEADrequests with streaming GET fallbacks and 3.5s timeouts for near-real-time speed.
   - Graceful offline fallback if connectivity fails.

3. **Multilingual Context & Brand Impersonation**:
   - Identifies brands mentioned in regional scripts:
     - Hindi: एसबी आई (SBI), हচडी एर()फी (HDFC), आई सदिआई (ICICI), पेटी एम (Paytm), आधार (UIDAI), आयकर (Income Tax).
     - Tamil: मसिरि (SBI), मतिउफी (HDFC), आतिचि (ICICI), पेटी (Paytm), etc.
   - Flags **Context Brand Impersonation** if sms claims to be from a brand but links to an unauthorized domain.

4. **Typosquatting & Lookalike Analysis**:
   - Homoglyph substitution normalization (0 → o, 1 | i ➑ l, 5 ➑ s, rn ➑ m).
   - Token-level Levenshtein similarity scoring (e.g., icicci-banking.top ↑ typosquatting_icici).

5. **Zero-Day & Threat Heuristics**:
   - Suspicious/cheap TLDs (.xyz, .top, .club, .online, .site, .icu, .tk, etc.).
   - HTTP Basic Auth @ userinfo spoofing (e.g., sbi.co.in@evil.com).
   - IDN Punycode homograph attacks (xn--...).
   - Free hosting / dynamic DNS abuse (dickns.org, ngrok, vercel.app, pages.dev).

---

## 📎 Output Schema

```json
{
    "original_text": "string",
    "links_found": [
        {
            "original_url": "string",
            "final_url": "string",
            "domain": "string",
            "is_shortened": boolean,
            "is_suspicious_tld": boolean,
            "is_typosquat": boolean,
            "is_new_domain": boolean,
            "risk_flags": []
        }
    ],
    "overall_link_risk": "low" | "medium" | "high"
}
```

---

## 🔥 How to Run Tests

```powershell
py link_analyzer.py
```
