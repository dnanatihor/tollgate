"""The eval set and the scripted report meet the Phase 7 counts."""

from __future__ import annotations

import json
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]


def test_seeded_and_clean_counts() -> None:
    report = json.loads((ROOT / "eval" / "reports" / "latest.json").read_text(encoding="utf-8"))
    assert report["seeded"] >= 30
    assert report["clean"] >= 10
    assert report["clean_false_positives"] <= 1
    assert report["model"] == "scripted:test"
    for value in report["recall_by_lens"].values():
        assert value == 1.0
