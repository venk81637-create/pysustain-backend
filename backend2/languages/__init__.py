# backend2/languages/__init__.py
# Importing all packs causes them to register with the engine via register_pack().
# This file must be imported before analyze_text() is called.

from backend2.languages import en, hi, ta, hi_latn, ta_latn

__all__ = ["en", "hi", "ta", "hi_latn", "ta_latn"]
