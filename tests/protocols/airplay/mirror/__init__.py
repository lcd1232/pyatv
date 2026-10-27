"""Tests for pyatv's AirPlay screen-mirroring support.

Unit tests cover each module under ``pyatv/protocols/airplay/mirror/``;
``test_session*.py`` and ``test_mvp_integration.py`` drive a full session
against the in-process receiver in ``fake_receiver.py``.

``fply_vectors.jsonl`` holds 256 known-answer FairPlay handshakes (M2, M3,
M4, SAP secret, ekey and M3 context). The handshake code must reproduce each
of them byte for byte.
"""
