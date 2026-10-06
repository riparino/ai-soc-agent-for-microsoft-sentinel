"""Test defaults: the suite runs on the built-in demo fleet / mock incidents.

DEMO_MODE is False in a real install (no sample data ever stands in for a failed
call), so tests opt in explicitly before `app.config` is imported. Individual
tests flip it off again to exercise the live-mode error paths.
"""
import os

os.environ.setdefault("DEMO_MODE", "True")
os.environ.setdefault("AZURE_AUTH_MODE", "auto")
