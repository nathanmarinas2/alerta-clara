from __future__ import annotations

from datetime import date

from app.dataset_import import import_csv
from app.evaluation import EvaluationSplit


def test_importer_redacts_and_keeps_campaigns_in_one_split(tmp_path) -> None:
    source = tmp_path / "public.csv"
    source.write_text(
        "message,label,campaign,timestamp,language,scam_type,lure,destination_number\n"
        '"Paga en ES91 2100 0418 4502 0005 1332",scam,c-1,2026-01-01,es,pago,urgencia,612345678\n'
        '"Segundo mensaje de la campaña",scam,c-1,2026-01-15,es,pago,urgencia,699999999\n'
        '"Campaña posterior",scam,c-2,2026-03-01,es,pago,urgencia,611111111\n',
        encoding="utf-8",
    )

    cases = import_csv(
        source,
        profile_name="generic",
        source="public-test",
        validation_after=date(2026, 2, 1),
    )

    assert len(cases) == 3
    assert "[IBAN]" in cases[0].message
    assert "612345678" not in cases[0].model_dump_json()
    assert {case.language for case in cases} == {"es"}
    assert {case.split for case in cases} == {
        EvaluationSplit.TUNING,
        EvaluationSplit.VALIDATION,
    }
    assert len({case.split for case in cases if case.campaign_id == "c-1"}) == 1
