"""
Unit and Integration Tests for Backend 3 (backend3.py).
Uses Python's built-in unittest framework and runs 100% offline.

Covers all 15 test requirements specified in the prompt:
1. Normal English conversation.
2. English message requesting an OTP urgently.
3. Hindi scam message written in Devanagari.
4. Hindi scam message written in English letters (transliteration).
5. Tamil scam message written in Tamil script.
6. Tamil scam message written in English letters (transliteration).
7. Mixed English-Hindi-Tamil scam message.
8. Suspicious link with threatening text.
9. Harmless message containing the word "OTP" in an informational context.
10. Missing Backend 1 results (None / fallback handling).
11. Missing Backend 2 results (None / fallback handling).
12. Malformed backend output (non-dict / corrupted types).
13. Empty input and whitespace-only input.
14. Unsupported output language (graceful fallback to 'en').
15. Risk score boundary values (clamped 0-100) and missing analysis components (weight renormalization).
"""

import json
import unittest
from unittest.mock import patch

import backend3
from backend3 import (
    RISK_LEVEL_CRITICAL,
    RISK_LEVEL_HIGH,
    RISK_LEVEL_LOW,
    RISK_LEVEL_MEDIUM,
    analyze_message,
    calculate_calibrated_risk_score,
    detect_languages,
    determine_verdict_and_level,
    normalize_component_scores,
)


class TestBackend3DecisionEngine(unittest.TestCase):
    """Test suite for Backend 3 decision engine."""

    # --------------------------------------------------------------------------
    # 1. A normal English conversation
    # --------------------------------------------------------------------------
    def test_01_normal_english_conversation(self):
        msg = "Hi Sarah, are we still meeting tomorrow for coffee at 4 PM? Let me know!"
        report = analyze_message(msg)

        self.assertIsInstance(report, dict)
        self.assertEqual(report["message"], msg)
        self.assertIn("English", report["language_detected"])
        self.assertLessEqual(report["risk_score"], 24)
        self.assertEqual(report["risk_level"], RISK_LEVEL_LOW)
        self.assertIn("Low risk", report["verdict"])
        self.assertEqual(report["detected_indicators"], [])
        self.assertTrue(report["text_analysis"]["available"])
        self.assertTrue(report["link_analysis"]["available"])
        self.assertEqual(report["analysis_status"], "complete")

        # JSON serializable verification
        json_str = json.dumps(report)
        self.assertTrue(len(json_str) > 0)

    # --------------------------------------------------------------------------
    # 2. An English message requesting an OTP urgently
    # --------------------------------------------------------------------------
    def test_02_english_urgent_otp_request(self):
        msg = "Your bank account will be blocked. Share your OTP immediately."
        report = analyze_message(msg, output_language="en")

        self.assertGreaterEqual(report["risk_score"], 75)
        self.assertEqual(report["risk_level"], RISK_LEVEL_CRITICAL)
        self.assertIn("OTP", report["explanation"])
        self.assertTrue(any("OTP" in ind for ind in report["detected_indicators"]))
        self.assertTrue(any("OTP" in rec for rec in report["recommendations"]))
        self.assertEqual(report["output_language"], "en")

    # --------------------------------------------------------------------------
    # 3. A Hindi scam message written in Devanagari
    # --------------------------------------------------------------------------
    def test_03_hindi_devanagari_scam_message(self):
        msg = "आपका बैंक खाता बंद हो जाएगा। तुरंत अपना OTP भेजें।"
        report = analyze_message(msg, output_language="hi")

        self.assertIn("Hindi", report["language_detected"])
        self.assertGreaterEqual(report["risk_score"], 75)
        self.assertEqual(report["risk_level"], RISK_LEVEL_CRITICAL)
        self.assertEqual(report["output_language"], "hi")
        self.assertTrue(len(report["explanation"]) > 0)
        self.assertTrue(any("OTP" in rec or "साझा" in rec for rec in report["recommendations"]))

    # --------------------------------------------------------------------------
    # 4. A Hindi scam message written in English letters (transliteration)
    # --------------------------------------------------------------------------
    def test_04_hindi_romanized_scam_message(self):
        msg = "Aapka bank account block ho jayega. Apna OTP bhejo."
        report = analyze_message(msg)

        self.assertIn("Hindi", report["language_detected"])
        self.assertGreaterEqual(report["risk_score"], 75)
        self.assertEqual(report["risk_level"], RISK_LEVEL_CRITICAL)
        self.assertTrue(any("OTP" in ind for ind in report["detected_indicators"]))

    # --------------------------------------------------------------------------
    # 5. A Tamil scam message written in Tamil script
    # --------------------------------------------------------------------------
    def test_05_tamil_script_scam_message(self):
        msg = "உங்கள் வங்கி கணக்கு முடக்கப்படும். உடனே OTP அனுப்புங்கள்."
        report = analyze_message(msg, output_language="ta")

        self.assertIn("Tamil", report["language_detected"])
        self.assertGreaterEqual(report["risk_score"], 75)
        self.assertEqual(report["risk_level"], RISK_LEVEL_CRITICAL)
        self.assertEqual(report["output_language"], "ta")
        self.assertIn("OTP", report["explanation"])
        self.assertTrue(any("OTP" in rec or "பகிர" in rec for rec in report["recommendations"]))

    # --------------------------------------------------------------------------
    # 6. A Tamil scam message written in English letters (transliteration)
    # --------------------------------------------------------------------------
    def test_06_tamil_romanized_scam_message(self):
        msg = "Unga bank account block aagum. Udane OTP anuppunga."
        report = analyze_message(msg)

        self.assertIn("Tamil", report["language_detected"])
        self.assertGreaterEqual(report["risk_score"], 75)
        self.assertEqual(report["risk_level"], RISK_LEVEL_CRITICAL)
        self.assertTrue(any("OTP" in ind for ind in report["detected_indicators"]))

    # --------------------------------------------------------------------------
    # 7. A mixed English-Hindi-Tamil scam message
    # --------------------------------------------------------------------------
    def test_07_mixed_language_code_switched_message(self):
        msg = "Ungal KYC pending hai, immediately OTP share pannunga."
        report = analyze_message(msg)

        # Must detect mixed language characteristics
        detected_langs = report["language_detected"]
        self.assertTrue("English" in detected_langs)
        self.assertTrue("Hindi" in detected_langs or "Tamil" in detected_langs)

        # High/Critical risk verdict
        self.assertGreaterEqual(report["risk_score"], 75)
        self.assertEqual(report["risk_level"], RISK_LEVEL_CRITICAL)
        self.assertTrue(any("OTP" in ind for ind in report["detected_indicators"]))

    # --------------------------------------------------------------------------
    # 8. A suspicious link with threatening text
    # --------------------------------------------------------------------------
    def test_08_suspicious_link_with_threatening_text(self):
        msg = "Your electricity bijli connection kat jayega tonight! Pay at http://sbi-bills.top immediately."
        report = analyze_message(msg)

        self.assertGreaterEqual(report["risk_score"], 60)
        self.assertIn(report["risk_level"], [RISK_LEVEL_HIGH, RISK_LEVEL_CRITICAL])
        self.assertTrue(any("link" in ind.lower() or "domain" in ind.lower() or "url" in ind.lower() for ind in report["detected_indicators"]))
        self.assertTrue(any("avoid" in rec.lower() or "link" in rec.lower() for rec in report["recommendations"]))

    # --------------------------------------------------------------------------
    # 9. A harmless message containing the word "OTP" in an informational context
    # --------------------------------------------------------------------------
    def test_09_harmless_otp_informational_context(self):
        msg = "Dear Customer, INR 5,000 debited from A/C XX1234. SBI never asks for your OTP or PIN. If not you, SMS BLOCK."
        report = analyze_message(msg)

        # Must NOT trigger critical OTP harvesting
        self.assertLess(report["risk_score"], 50)
        self.assertNotEqual(report["risk_level"], RISK_LEVEL_CRITICAL)
        self.assertFalse(any("OTP harvesting" == ind for ind in report["detected_indicators"]))

    # --------------------------------------------------------------------------
    # 10. Missing Backend 1 results (None / fallback handling)
    # --------------------------------------------------------------------------
    def test_10_missing_backend1_results(self):
        msg = "Aapka account block ho jayega. Check details at http://login-secure.xyz"
        # Explicitly pass link_results=None
        report = analyze_message(msg, link_results=None)

        self.assertIsInstance(report, dict)
        self.assertTrue(report["link_analysis"]["available"])
        self.assertGreaterEqual(report["risk_score"], 50)

        # Simulate link analysis explicitly unavailable
        mock_unavailable_link = {"available": False, "risk_flags": []}
        report2 = analyze_message(msg, link_results=mock_unavailable_link)
        self.assertFalse(report2["link_analysis"]["available"])
        self.assertEqual(report2["analysis_status"], "incomplete")
        self.assertGreater(report2["risk_score"], 0)

    # --------------------------------------------------------------------------
    # 11. Missing Backend 2 results (None / fallback handling)
    # --------------------------------------------------------------------------
    def test_11_missing_backend2_results(self):
        msg = "URGENT: Click http://sbi-verification.top/login"
        # Explicitly pass text_results=None
        report = analyze_message(msg, text_results=None)

        self.assertIsInstance(report, dict)
        self.assertTrue(report["text_analysis"]["available"])
        self.assertGreater(report["risk_score"], 0)

        # Simulate text analysis explicitly unavailable
        mock_unavailable_text = {"available": False, "scam_category": [], "detected_phrases": []}
        report2 = analyze_message(msg, text_results=mock_unavailable_text)
        self.assertFalse(report2["text_analysis"]["available"])
        self.assertEqual(report2["analysis_status"], "incomplete")

    # --------------------------------------------------------------------------
    # 12. Malformed backend output (non-dict / corrupted types)
    # --------------------------------------------------------------------------
    def test_12_malformed_backend_output(self):
        msg = "Your bank account will be blocked today."

        # Pass invalid types (string, int, list where dict expected, None, broken objects)
        report = analyze_message(
            message_text=msg,
            link_results="MALFORMED_STRING_NOT_DICT",
            text_results=12345
        )

        # Engine must never crash
        self.assertIsInstance(report, dict)
        self.assertIn("risk_score", report)
        self.assertIn("verdict", report)
        self.assertIn("analysis_status", report)
        self.assertEqual(report["analysis_status"], "incomplete")

    # --------------------------------------------------------------------------
    # 13. Empty input and whitespace-only input
    # --------------------------------------------------------------------------
    def test_13_empty_and_whitespace_input(self):
        for empty_val in ["", "   ", "\n\t  \n", None]:
            report = analyze_message(empty_val)
            self.assertEqual(report["risk_score"], 0)
            self.assertEqual(report["risk_level"], RISK_LEVEL_LOW)
            self.assertEqual(report["detected_indicators"], [])
            self.assertEqual(report["analysis_status"], "complete")

    # --------------------------------------------------------------------------
    # 14. An unsupported output language (graceful fallback to 'en')
    # --------------------------------------------------------------------------
    def test_14_unsupported_output_language(self):
        msg = "Your bank account will be blocked. Share your OTP immediately."
        report = analyze_message(msg, output_language="es_ES_unsupported")

        # Must fall back gracefully to English
        self.assertEqual(report["output_language"], "en")
        self.assertIn("requests an OTP", report["explanation"])

    # --------------------------------------------------------------------------
    # 15. Risk score boundary values and missing analysis components (renormalization)
    # --------------------------------------------------------------------------
    def test_15_risk_score_boundaries_and_weight_renormalization(self):
        # 1. Clamping check: scores must strictly remain in [0, 100]
        score_max = calculate_calibrated_risk_score(
            text_score=150.0,
            coercion_score=120.0,
            link_score=100.0,
            domain_score=100.0,
            availability={"text": True, "coercion": True, "link": True, "domain": True}
        )
        self.assertEqual(score_max, 100)

        score_min = calculate_calibrated_risk_score(
            text_score=-50.0,
            coercion_score=-10.0,
            link_score=0.0,
            domain_score=0.0,
            availability={"text": True, "coercion": True, "link": True, "domain": True}
        )
        self.assertEqual(score_min, 0)

        # 2. Weight renormalization when link and domain analysis are unavailable
        # text weight is 0.45, coercion is 0.20 -> renormalized: text = 0.45/0.65 (~0.692), coercion = 0.20/0.65 (~0.308)
        score_renorm = calculate_calibrated_risk_score(
            text_score=80.0,
            coercion_score=50.0,
            link_score=0.0,
            domain_score=0.0,
            availability={"text": True, "coercion": True, "link": False, "domain": False}
        )
        expected = round(80.0 * (0.45 / 0.65) + 50.0 * (0.20 / 0.65))
        self.assertEqual(score_renorm, expected)

        # 3. Verdict threshold mappings
        level_low, _ = determine_verdict_and_level(0)
        self.assertEqual(level_low, RISK_LEVEL_LOW)
        level_low_24, _ = determine_verdict_and_level(24)
        self.assertEqual(level_low_24, RISK_LEVEL_LOW)

        level_med_25, _ = determine_verdict_and_level(25)
        self.assertEqual(level_med_25, RISK_LEVEL_MEDIUM)
        level_med_49, _ = determine_verdict_and_level(49)
        self.assertEqual(level_med_49, RISK_LEVEL_MEDIUM)

        level_hi_50, _ = determine_verdict_and_level(50)
        self.assertEqual(level_hi_50, RISK_LEVEL_HIGH)
        level_hi_74, _ = determine_verdict_and_level(74)
        self.assertEqual(level_hi_74, RISK_LEVEL_HIGH)

        level_crit_75, _ = determine_verdict_and_level(75)
        self.assertEqual(level_crit_75, RISK_LEVEL_CRITICAL)
        level_crit_100, _ = determine_verdict_and_level(100)
        self.assertEqual(level_crit_100, RISK_LEVEL_CRITICAL)


if __name__ == "__main__":
    unittest.main()
