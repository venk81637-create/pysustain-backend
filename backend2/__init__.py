"""
backend2/__init__.py
====================
Public interface for Backend 2 (multilingual scam-text detector).

Backend 3 import pattern:
    from backend2 import analyze_text
    result = analyze_text("Your account will be blocked. Share OTP now.")

The contract (never changes):
    analyze_text(message_text: str, include_details: bool = True) -> dict
    {
        "detected_phrases": [str],
        "scam_category": str,   # one of the CATEGORIES list
        "confidence": float,    # 0-100; 0.0 = not analyzed
        "coercion_score": int,  # 0-100
    }

See engine.py for full docstring and invalid-input policy.
"""

# Import language packs first — they register themselves with the engine.
import backend2.languages  # noqa: F401

# Re-export the public API.
from backend2.engine import analyze_text

__all__ = ["analyze_text"]
