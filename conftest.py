"""
Root conftest.py — sets PYTHONUTF8=1 before anything else runs.
This ensures all file I/O and stdout use UTF-8 on Windows 11.
"""
import os
os.environ["PYTHONUTF8"] = "1"
