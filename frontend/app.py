# encoding: utf-8
"""
frontend/app.py
===============
PySustain-2026 · Backend 2 Demo — Multilingual Scam Message Detector
(English, Hindi, Tamil, Hinglish, Tanglish)

This page imports analyze_text() directly from backend2 — no HTTP layer.

DISCLAIMER: Automated assessment of language only.  It does not prove
a message is fraudulent or genuine, and a low result is not a guarantee.
Support for Hindi, Tamil and romanized text is limited and has not been
fully reviewed by native speakers.
"""

import sys
import os
# Ensure the project root is on the path so backend2 can be imported.
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
os.environ["PYTHONUTF8"] = "1"

import streamlit as st

from backend2 import analyze_text

# ─── Page config ──────────────────────────────────────────────────────────────

st.set_page_config(
    page_title="PySustain-2026 · Scam Detector",
    page_icon="🛡️",
    layout="centered",
)

# ─── Sample messages ──────────────────────────────────────────────────────────

SAMPLES = {
    "— select a sample —": "",
    "English scam (OTP + threat)": (
        "Your account will be blocked immediately. "
        "Share your OTP now to avoid suspension."
    ),
    "English warning (should be Safe)": (
        "Beware of scammers! RBI never asks for your OTP or password. Stay alert."
    ),
    "English phishing link": (
        "Congratulations! You have won Rs 50,000. "
        "Click here to claim: http://fake-prize.in/claim"
    ),
    "Hindi scam · हिंदी घोटाला": (
        "आपका बैंक खाता बंद हो जाएगा। तुरंत अपना OTP साझा करें।"
    ),
    "Hindi warning · हिंदी चेतावनी (Safe)": (
        "अपना OTP किसी के साथ साझा न करें।"
    ),
    "Tamil scam · தமிழ் மோசடி": (
        "உங்கள் வங்கி கணக்கு முடக்கப்படும். உடனே உங்கள் OTP-ஐ பகிருங்கள்."
    ),
    "Tamil warning · தமிழ் எச்சரிக்கை (Safe)": (
        "உங்கள் OTP-ஐ யாருடனும் பகிர வேண்டாம்."
    ),
    "Hinglish scam": (
        "Aapka account block ho jayega. Turant apna OTP share karein."
    ),
    "Tanglish scam": (
        "Ungal account block aayidum. Udane OTP anuppunga."
    ),
    "OTP delivery notice (Safe)": (
        "Your OTP is 482910. Use it to log in. Do not share it with anyone."
    ),
    "Code-mixed (Hindi + English)": (
        "Your account is at risk. अपना OTP अभी साझा करें।"
    ),
}

# ─── CSS helper: highlight detected phrases ───────────────────────────────────

def _highlight_phrases(message: str, phrases: list[str]) -> str:
    """
    Highlight every occurrence of each detected phrase in *message* using
    an HTML <mark> tag.

    NOTE: Highlighting works by exact text search.  If a phrase appears more
    than once in the message, EVERY occurrence is highlighted.  This is a
    known limitation documented in the README.

    This operates on the ORIGINAL message (no normalization).
    """
    # Sort phrases longest-first to avoid partial replacements.
    sorted_phrases = sorted(phrases, key=len, reverse=True)
    import re
    result = message
    for phrase in sorted_phrases:
        if not phrase:
            continue
        # Escape for regex and replace all occurrences.
        escaped = re.escape(phrase)
        result = re.sub(
            escaped,
            lambda m: f'<mark style="background:#FFD700;border-radius:3px;padding:1px 3px">{m.group()}</mark>',
            result,
        )
    return result


# ─── Risk level colors ────────────────────────────────────────────────────────

RISK_COLORS = {
    "low":      "#2E7D32",  # dark green
    "medium":   "#F57F17",  # amber
    "high":     "#C62828",  # dark red
    "critical": "#6A1B9A",  # dark purple
}

RISK_EMOJI = {
    "low": "🟢",
    "medium": "🟡",
    "high": "🔴",
    "critical": "🟣",
}

CATEGORY_EMOJI = {
    "Banking Fraud": "🏦",
    "Utility Threat": "⚡",
    "Phishing": "🎣",
    "OTP/PIN Harvesting": "🔑",
    "Authority Impersonation": "👮",
    "Safe": "✅",
}


# ─── Main UI ──────────────────────────────────────────────────────────────────

st.title("🛡️ PySustain-2026 · Scam Message Detector")
st.caption("Backend 2 Demo · Multilingual scam-text and coercive-language detection")

# Disclaimer — always visible.
st.warning(
    "**⚠️ Disclaimer:** Automated assessment of language only. "
    "It does not prove a message is fraudulent or genuine, and a low result is "
    "not a guarantee of safety. "
    "Support for Hindi, Tamil and romanized text is limited and has **not** been "
    "fully reviewed by native speakers.",
    icon=None,
)

st.divider()

# Sample picker.
col1, col2 = st.columns([3, 1])
with col1:
    selected_sample = st.selectbox("Load a sample message:", list(SAMPLES.keys()))
with col2:
    st.write("")

# Message box — pre-fills from sample.
sample_text = SAMPLES[selected_sample]
message = st.text_area(
    "Message to analyze:",
    value=sample_text,
    height=140,
    placeholder="Paste or type any message in English, Hindi (हिंदी), Tamil (தமிழ்), Hinglish or Tanglish…",
    help="Supports Devanagari, Tamil script, and romanized text. Code-mixed messages work.",
)

col_analyze, col_clear = st.columns([1, 4])
with col_analyze:
    analyze_clicked = st.button("🔍 Analyze", type="primary", use_container_width=True)
with col_clear:
    if st.button("✕ Clear", use_container_width=False):
        st.rerun()

st.divider()

if analyze_clicked and message:
    result = analyze_text(message, include_details=True)

    # ── Invalid input ──────────────────────────────────────────────────────
    if result["confidence"] == 0.0 and "invalid_input" in result.get("context_flags", []):
        st.error("⚠️ This message could not be analyzed.", icon=None)
        st.info(result["recommended_actions"][0] if result["recommended_actions"] else "No analysis available.")
        st.stop()

    # ── Risk level banner ─────────────────────────────────────────────────
    rl = result["risk_level"]
    cat = result["scam_category"]
    color = RISK_COLORS.get(rl, "#555")
    emoji = RISK_EMOJI.get(rl, "")
    cat_emoji = CATEGORY_EMOJI.get(cat, "")

    st.markdown(
        f"""
        <div style="background:{color};color:white;padding:16px 20px;border-radius:10px;margin-bottom:12px">
            <span style="font-size:1.6em;font-weight:bold">{emoji} {rl.upper()} RISK</span>
            &nbsp;&nbsp;
            <span style="font-size:1.1em">{cat_emoji} {cat}</span>
        </div>
        """,
        unsafe_allow_html=True,
    )

    # ── Metrics row ───────────────────────────────────────────────────────
    m1, m2 = st.columns(2)
    m1.metric("Confidence (heuristic)", f"{result['confidence']:.0f} / 100")
    m2.metric("Coercion Score", f"{result['coercion_score']} / 100")

    st.caption(
        "Confidence is a heuristic estimate, not a calibrated probability. "
        "Coercion measures pressure signals (threats, urgency, authority)."
    )

    # ── Script / language evidence ────────────────────────────────────────
    st.subheader("🔤 Script & Language Evidence")
    st.caption(
        "Scripts detected are a Unicode fact about which character ranges are present — "
        "NOT a language identification claim. Packs matched means which rule sets produced "
        "at least one signal — a message can match multiple packs."
    )
    s_col, l_col = st.columns(2)
    with s_col:
        st.write("**Scripts detected:**")
        if result["scripts_detected"]:
            st.write(", ".join(result["scripts_detected"]))
        else:
            st.write("_(none)_")
    with l_col:
        st.write("**Rule packs matched:**")
        if result["language_packs_matched"]:
            st.write(", ".join(result["language_packs_matched"]))
        else:
            st.write("_(none)_")

    # ── Context flags ─────────────────────────────────────────────────────
    if result.get("context_flags"):
        st.subheader("ℹ️ Diagnostic Flags")
        st.caption("These flags carry NO score weight — they are for information only.")
        for cf in result["context_flags"]:
            label_map = {
                "warning_with_request": "⚠️ Warning + live request detected — treat the request as suspicious",
                "otp_delivery_notice": "📱 OTP delivery notice detected (not a request by itself)",
                "limited_coverage": "📉 Limited Hindi/Tamil coverage — result may be incomplete",
                "unsupported_language": "🌐 Unsupported script detected — treat with caution",
                "reported_incident": "📋 Reported incident context detected",
                "security_warning": "🔐 Security warning context",
                "awareness_context": "👁️ Awareness cue detected",
            }
            st.info(label_map.get(cf, f"Context: {cf}"), icon=None)

    # ── Highlighted message ───────────────────────────────────────────────
    if result["detected_phrases"]:
        st.subheader("📌 Detected Phrases in Message")
        st.caption(
            "Phrases are highlighted by exact text match. "
            "If a phrase appears multiple times, all occurrences are highlighted. "
            "Highlighting is done on the ORIGINAL text without any modification."
        )
        highlighted = _highlight_phrases(message, result["detected_phrases"])
        st.markdown(
            f'<div style="font-family:sans-serif;font-size:1.05em;line-height:1.7;'
            f'background:#F8F8F8;border:1px solid #DDD;border-radius:8px;padding:14px">'
            f'{highlighted}</div>',
            unsafe_allow_html=True,
        )

        # List of detected phrases.
        with st.expander("📋 All detected phrases"):
            for i, phrase in enumerate(result["detected_phrases"], 1):
                st.write(f"{i}. `{phrase}`")
    else:
        st.info("No suspicious phrases detected in this message.", icon=None)

    # ── Risk flags & explanations ─────────────────────────────────────────
    if result["risk_flags"]:
        st.subheader("🚩 Risk Flags (scored)")
        for exp in result.get("explanations", []):
            st.write(f"• **{exp['flag']}**: {exp['reason']}")
    else:
        if cat == "Safe":
            st.success("No scoring risk flags found.", icon=None)

    # ── Recommended actions ───────────────────────────────────────────────
    if result.get("recommended_actions"):
        st.subheader("📋 Recommended Actions")
        for action in result["recommended_actions"]:
            st.write(f"→ {action}")

    # ── Debug expander ────────────────────────────────────────────────────
    with st.expander("🔧 Full result (developer view)"):
        st.json(result)

elif analyze_clicked and not message:
    st.warning("Please enter a message to analyze.", icon=None)

# ─── Footer ───────────────────────────────────────────────────────────────────

st.divider()
st.caption(
    "PySustain-2026 · Backend 2 · Multilingual Scam Detector · "
    "SDGs: No Poverty · Quality Education · Reduced Inequalities  \n"
    "Rule-based detection. No ML. No external API. No data stored.  \n"
    "Hindi, Tamil and romanized packs are UNREVIEWED — treat results as best-effort only."
)
