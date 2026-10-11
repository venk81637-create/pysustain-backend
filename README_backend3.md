# Backend 3 – Multilingual Risk Score, Verdict & Report Engine

ScamShield’s central decision engine integrates:
- **Backend 1:** Link Unmasking & Domain Checker (`link_analyzer.py`)
- **Backend 2:** Scam Text & Coercive Language Detector (`text_analyzer.py`)

Backend 3 computes an overall calibrated risk score, determines a clear verdict, generates plain-language multilingual explanations with context-aware safety recommendations, and returns a structured JSON-serializable report.

---

## 1. Features

- **Pure Python & Standard Library Only:** Zero external dependencies (no third-party ML packages, no external translation APIs, no network calls required for offline analysis).
- **Multilingual Support:**
  - **English (`en`)**: standard text, SMS, and WhatsApp messages.
  - **Hindi (`hi`)**: Devanagari script (e.g., *"आपका बैंक खाता बंद हो जाएगा। तुरंत अपना OTP भेजें।"*).
  - **Hindi Transliteration / Romanized (Hinglish)**: English letters (e.g., *"Aapka bank account block ho jayega. Apna OTP bhejo."*).
  - **Tamil (`ta`)**: Tamil script (e.g., *"உங்கள் வங்கி கணக்கு முடக்கப்படும். உடனே OTP அனுப்புங்கள்."*).
  - **Tamil Transliteration / Romanized (Tanglish)**: English letters (e.g., *"Unga bank account block aagum. Udane OTP anuppunga."*).
  - **Code-Mixed Messages**: Mixture of English, Hindi, and Tamil (e.g., *"Ungal KYC pending hai, immediately OTP share pannunga."*).
- **Predefined & Verified Translations:** Multilingual explanations and recommendations are authored using predefined, verified translations for high reliability and zero hallucination.
- **Fail-Safe & Resilient:** Handles `None`, empty inputs, malformed types, and missing backends gracefully without crashing.
- **Strict Score Normalization:** Scores strictly clamped to **0–100** using dynamic weight renormalization for missing components.

---

## 2. Public API Specification

### Function: `analyze_message()`

```python
from backend3 import analyze_message

report = analyze_message(
    message_text="Your bank account will be blocked. Share your OTP immediately.",
    link_results=None,       # Optional: output from Backend 1
    text_results=None,       # Optional: output from Backend 2
    output_language="en"     # 'en' (default), 'hi', or 'ta'
)
```

#### Parameters:
| Parameter | Type | Default | Description |
|---|---|---|---|
| `message_text` | `str` | *Required* | The original message entered by the user. Accepts any Unicode text. |
| `link_results` | `dict` or `list` or `None` | `None` | Optional analysis from Backend 1 (`link_analyzer`). If omitted, links in the message are automatically parsed and analyzed. |
| `text_results` | `dict` or `None` | `None` | Optional analysis from Backend 2 (`text_analyzer`). If omitted, the native multilingual detection engine analyzes the text. |
| `output_language` | `str` | `"en"` | Language code for explanations and recommendations: `"en"` (English), `"hi"` (Hindi), or `"ta"` (Tamil). Unsupported codes safely fall back to `"en"`. |
| `enable_network` | `bool` | `True` | Passed to Backend 1 when auto-invoking (for URL unmasking). |
| `rdap_lookup` | `bool` | `False` | Passed to Backend 1 when auto-invoking. |

---

## 3. Risk Scoring & Formula

### Component Weights
- **Text Scam Indicators (`text_score`):** 45%
- **Coercive Language & Urgency (`coercion_score`):** 20%
- **Suspicious Link Indicators (`link_score`):** 25%
- **Domain & Impersonation Indicators (`domain_score`):** 10%

All components are strictly normalized to a **0–100** scale before computing the weighted score:

$$\text{final\_score} = (\text{text\_score} \times 0.45) + (\text{coercion\_score} \times 0.20) + (\text{link\_score} \times 0.25) + (\text{domain\_score} \times 0.10)$$

### Weight Renormalization for Missing Components
If any component is unavailable (e.g., link analysis fails or is disabled), the active weights are automatically renormalized:

$$W'_i = \frac{W_i}{\sum_{j \in \text{available}} W_j}$$

$$\text{final\_score} = \sum_{i \in \text{available}} (\text{score}_i \times W'_i)$$

Missing components are explicitly marked as `"available": false` and never assumed to be proof of safety.

### Critical Trigger Safety Floor
If high-danger credential harvesting (such as explicit requests for an OTP, PIN, or CVV) is detected, the engine enforces a safety floor guaranteeing a score of at least **75** (CRITICAL RISK), regardless of whether links are present.

### Score Clamping
Final scores are clamped strictly between **0** and **100**.

---

## 4. Risk Verdicts

The final risk score maps to standardized verdicts:

| Score Range | Risk Level (`risk_level`) | Verdict Name (`verdict`) | Meaning |
|---|---|---|---|
| **0 – 24** | `LOW` | `LOW RISK` | No strong scam indicators detected. Basic caution advised. |
| **25 – 49** | `MEDIUM` | `MEDIUM RISK` | Suspicious elements detected. User should exercise caution. |
| **50 – 74** | `HIGH` | `HIGH RISK` | Strong indicators of scam/phishing identified. Do not comply. |
| **75 – 100** | `CRITICAL` | `CRITICAL RISK` | Severe threats (e.g. OTP harvesting, fake arrest warrants, utility disconnection). Immediate danger. |

> **Note:** A low score does not guarantee that a message is authentic. The engine always returns general digital safety guidance even for low-risk inputs.

---

## 5. Structured JSON Output Schema

```json
{
  "message": "Your bank account will be blocked. Share your OTP immediately.",
  "language_detected": [
    "English"
  ],
  "risk_score": 75,
  "risk_level": "CRITICAL",
  "verdict": "Critical risk – Severe scam threats detected",
  "explanation": "This message requests an OTP or sensitive credentials and creates artificial urgency. Scammers frequently use these tactics to gain unauthorized access or induce panic. Do not share your OTP or click unverified links.",
  "output_language": "en",
  "detected_indicators": [
    "OTP harvesting",
    "False urgency",
    "Account suspension threat"
  ],
  "link_analysis": {
    "available": true,
    "risk_flags": []
  },
  "text_analysis": {
    "available": true,
    "scam_category": [
      "account_threat",
      "credential_theft"
    ],
    "detected_phrases": [
      "Share your OTP immediately"
    ],
    "coercion_score": 65
  },
  "recommendations": [
    "Do not share your OTP, PIN, CVV, or passwords under any circumstances.",
    "Verify the sender through official bank or service provider channels.",
    "Report financial cyber fraud immediately to National Helpline 1930 or cybercrime.gov.in."
  ],
  "analysis_status": "complete"
}
```

---

## 6. Frontend Integration Guide

The frontend can consume `analyze_message()` either via Python or through the REST API endpoint:

### Direct Python Call
```python
from backend3 import analyze_message

# Example with Tamil output
report = analyze_message(
    "உங்கள் வங்கி கணக்கு முடக்கப்படும். உடனே OTP அனுப்புங்கள்.",
    output_language="ta"
)

print(report["risk_score"])   # 75
print(report["verdict"])      # 'மிகவும் ஆபத்தானது – தீவிர மோசடி அச்சுறுத்தல்கள் கண்டறியப்பட்டன'
print(report["explanation"])  # Plain-language explanation in Tamil
```

### Via Flask REST API (`app.py`)
Frontend client (e.g., `script.js`):
```javascript
async function checkMessage(text, lang = "en") {
  const response = await fetch("/analyze", {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({
      message_text: text,
      output_language: lang
    })
  });
  const data = await response.json();
  
  // Render score gauge and indicators
  document.getElementById("score").textContent = data.risk_score;
  document.getElementById("verdict").textContent = data.verdict;
  document.getElementById("explanation").textContent = data.explanation;
  
  // Render recommendations
  const list = document.getElementById("recommendations");
  list.innerHTML = "";
  data.recommendations.forEach(rec => {
    const li = document.createElement("li");
    li.textContent = rec;
    list.appendChild(li);
  });
}
```

---

## 7. Automated Testing

All tests use Python's built-in `unittest` module, require no external network calls, and execute in under 1 second.

Run test suite:
```bash
python -m unittest test_backend3.py -v
```

All 15 required test scenarios are covered:
1. Normal English conversation.
2. English message requesting an OTP urgently.
3. Hindi scam message written in Devanagari.
4. Hindi scam message written in English letters.
5. Tamil scam message written in Tamil script.
6. Tamil scam message written in English letters.
7. Mixed English-Hindi-Tamil scam message.
8. Suspicious link with threatening text.
9. Harmless message containing the word "OTP" in an informational context.
10. Missing Backend 1 results.
11. Missing Backend 2 results.
12. Malformed backend output.
13. Empty and whitespace input.
14. Unsupported output language.
15. Risk score boundary values and weight renormalization.

---

## 8. Limitations & Scope

- **Text & Links Only:** Designed for SMS, email, and messaging app text. Voice calls and voice notes are outside the scope.
- **Offline Heuristics:** RDAP registration age requires network connectivity; if unavailable or offline, domain age is reported as unknown and is never fabricated.
- **Advisory in Nature:** Heuristic scam analysis is advisory. The system reminds users to verify with official institutional helplines (such as National Helpline **1930** or **cybercrime.gov.in**).
