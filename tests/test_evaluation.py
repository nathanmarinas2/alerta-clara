import json
from pathlib import Path

import pytest

from app.evaluation import evaluate_cases, load_cases

PROJECT_ROOT = Path(__file__).resolve().parents[1]


@pytest.mark.asyncio
async def test_seed_golden_set_passes_quality_gate() -> None:
    cases = load_cases(PROJECT_ROOT / "eval" / "golden_set.jsonl")
    thresholds = json.loads(
        (PROJECT_ROOT / "eval" / "thresholds.json").read_text(encoding="utf-8")
    )

    report = await evaluate_cases(cases, thresholds)

    assert report.passed
    assert report.scam_recall >= thresholds["min_scam_recall"]
    assert report.false_alarm_rate <= thresholds["max_false_alarm_rate"]
    assert report.signal_requirements_met
