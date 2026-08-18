from __future__ import annotations

import argparse
import asyncio
import json
import re
from datetime import date
from enum import StrEnum
from pathlib import Path

from pydantic import BaseModel, Field

from app.config import Settings
from app.schemas import SignalStatus, VerdictLevel
from app.services.extraction import local_extract
from app.services.rules import decide
from app.services.signals import SignalCollector

PROJECT_ROOT = Path(__file__).resolve().parents[1]
DEFAULT_DATASET = PROJECT_ROOT / "eval" / "golden_set.jsonl"
DEFAULT_THRESHOLDS = PROJECT_ROOT / "eval" / "thresholds.json"


class CaseLabel(StrEnum):
    SCAM = "scam"
    LEGITIMATE = "legitimate"
    SPAM = "spam"
    UNKNOWN = "unknown"


class EvaluationSplit(StrEnum):
    TUNING = "tuning"
    VALIDATION = "validation"


class EvaluationCase(BaseModel):
    id: str
    label: CaseLabel
    message: str = Field(min_length=1)
    sender: str | None = None
    expected_level: VerdictLevel
    required_signals: list[str] = Field(default_factory=list)
    language: str = "es"
    scam_type: str | None = None
    lure: str | None = None
    campaign_id: str | None = None
    observed_at: date | None = None
    source: str = "local"
    split: EvaluationSplit = EvaluationSplit.VALIDATION
    notes: str | None = None


class CaseResult(BaseModel):
    id: str
    label: CaseLabel
    expected_level: VerdictLevel
    predicted_level: VerdictLevel
    score: int
    active_signals: list[str]
    missing_required_signals: list[str]
    language: str
    scam_type: str | None
    lure: str | None
    campaign_id: str | None
    split: EvaluationSplit


class SliceMetric(BaseModel):
    dimension: str
    value: str
    total: int
    scam_recall: float | None
    false_alarm_rate: float | None
    exact_agreement: float


class EvaluationReport(BaseModel):
    total: int
    scam_total: int
    non_scam_total: int
    true_positives: int
    false_alarms: int
    exact_matches: int
    scam_recall: float
    false_alarm_rate: float
    exact_agreement: float
    signal_requirements_met: bool
    dataset_integrity_met: bool
    passed: bool
    failures: list[str]
    slices: list[SliceMetric]
    cases: list[CaseResult]


def load_cases(path: Path) -> list[EvaluationCase]:
    cases: list[EvaluationCase] = []
    for line_number, raw_line in enumerate(path.read_text(encoding="utf-8").splitlines(), start=1):
        if not raw_line.strip() or raw_line.lstrip().startswith("#"):
            continue
        try:
            cases.append(EvaluationCase.model_validate_json(raw_line))
        except Exception as exc:
            raise ValueError(f"Caso inválido en {path}:{line_number}: {exc}") from exc
    if not cases:
        raise ValueError(f"El golden set está vacío: {path}")
    identifiers = [case.id for case in cases]
    if len(identifiers) != len(set(identifiers)):
        raise ValueError("Cada caso del golden set debe tener un id único")
    return cases


async def evaluate_cases(
    cases: list[EvaluationCase],
    thresholds: dict[str, float],
) -> EvaluationReport:
    settings = Settings(enable_network_checks=False)
    collector = SignalCollector(settings)
    results: list[CaseResult] = []

    for case in cases:
        extraction = local_extract(case.message, case.sender)
        signals = await collector.collect(extraction)
        decision = decide(
            extraction,
            signals,
            ruleset_version=settings.ruleset_version,
        )
        active_names = sorted(
            {
                signal.check_name
                for signal in signals
                if signal.status == SignalStatus.HIT
            }
        )
        missing = sorted(set(case.required_signals) - set(active_names))
        results.append(
            CaseResult(
                id=case.id,
                label=case.label,
                expected_level=case.expected_level,
                predicted_level=decision.level,
                score=decision.score,
                active_signals=active_names,
                missing_required_signals=missing,
                language=case.language,
                scam_type=case.scam_type,
                lure=case.lure,
                campaign_id=case.campaign_id,
                split=case.split,
            )
        )

    scam_results = [result for result in results if result.label == CaseLabel.SCAM]
    non_scam_results = [result for result in results if result.label != CaseLabel.SCAM]
    true_positives = sum(
        result.predicted_level == VerdictLevel.SCAM for result in scam_results
    )
    false_alarms = sum(
        result.predicted_level == VerdictLevel.SCAM for result in non_scam_results
    )
    exact_matches = sum(
        result.predicted_level == result.expected_level for result in results
    )
    scam_recall = true_positives / len(scam_results) if scam_results else 0.0
    false_alarm_rate = false_alarms / len(non_scam_results) if non_scam_results else 0.0
    exact_agreement = exact_matches / len(results)
    missing_requirements = [
        result for result in results if result.missing_required_signals
    ]

    integrity_failures = _dataset_integrity_failures(cases)
    slices = _slice_metrics(results)

    failures: list[str] = []
    if scam_recall < thresholds["min_scam_recall"]:
        failures.append(
            f"recall {scam_recall:.3f} < {thresholds['min_scam_recall']:.3f}"
        )
    if false_alarm_rate > thresholds["max_false_alarm_rate"]:
        failures.append(
            "tasa de falsas alarmas "
            f"{false_alarm_rate:.3f} > {thresholds['max_false_alarm_rate']:.3f}"
        )
    if exact_agreement < thresholds["min_exact_agreement"]:
        failures.append(
            f"acuerdo {exact_agreement:.3f} < {thresholds['min_exact_agreement']:.3f}"
        )
    for result in missing_requirements:
        failures.append(
            f"{result.id}: faltan señales {', '.join(result.missing_required_signals)}"
        )
    failures.extend(integrity_failures)

    return EvaluationReport(
        total=len(results),
        scam_total=len(scam_results),
        non_scam_total=len(non_scam_results),
        true_positives=true_positives,
        false_alarms=false_alarms,
        exact_matches=exact_matches,
        scam_recall=round(scam_recall, 4),
        false_alarm_rate=round(false_alarm_rate, 4),
        exact_agreement=round(exact_agreement, 4),
        signal_requirements_met=not missing_requirements,
        dataset_integrity_met=not integrity_failures,
        passed=not failures,
        failures=failures,
        slices=slices,
        cases=results,
    )


def _dataset_integrity_failures(cases: list[EvaluationCase]) -> list[str]:
    failures: list[str] = []
    campaigns: dict[str, set[EvaluationSplit]] = {}
    normalized_messages: dict[str, set[EvaluationSplit]] = {}
    for case in cases:
        if case.campaign_id:
            campaigns.setdefault(case.campaign_id, set()).add(case.split)
        normalized = re.sub(r"\W+", "", case.message.casefold())
        normalized_messages.setdefault(normalized, set()).add(case.split)

    leaked_campaigns = sorted(
        campaign for campaign, splits in campaigns.items() if len(splits) > 1
    )
    if leaked_campaigns:
        failures.append(
            "campañas presentes en tuning y validación: " + ", ".join(leaked_campaigns[:5])
        )
    duplicate_count = sum(len(splits) > 1 for splits in normalized_messages.values())
    if duplicate_count:
        failures.append(
            f"{duplicate_count} mensajes duplicados aparecen en ambos splits"
        )

    tuning_dates = [
        case.observed_at
        for case in cases
        if case.split == EvaluationSplit.TUNING and case.observed_at
    ]
    validation_dates = [
        case.observed_at
        for case in cases
        if case.split == EvaluationSplit.VALIDATION and case.observed_at
    ]
    if tuning_dates and validation_dates and max(tuning_dates) > min(validation_dates):
        failures.append("el corte temporal mezcla casos futuros en el conjunto de ajuste")
    return failures


def _slice_metrics(results: list[CaseResult]) -> list[SliceMetric]:
    slices: list[SliceMetric] = []
    dimensions = {
        "language": lambda result: result.language,
        "scam_type": lambda result: result.scam_type,
        "lure": lambda result: result.lure,
        "split": lambda result: result.split.value,
    }
    for dimension, getter in dimensions.items():
        values = sorted({value for result in results if (value := getter(result))})
        for value in values:
            subset = [result for result in results if getter(result) == value]
            scams = [result for result in subset if result.label == CaseLabel.SCAM]
            non_scams = [result for result in subset if result.label != CaseLabel.SCAM]
            slices.append(
                SliceMetric(
                    dimension=dimension,
                    value=str(value),
                    total=len(subset),
                    scam_recall=(
                        round(
                            sum(item.predicted_level == VerdictLevel.SCAM for item in scams)
                            / len(scams),
                            4,
                        )
                        if scams
                        else None
                    ),
                    false_alarm_rate=(
                        round(
                            sum(
                                item.predicted_level == VerdictLevel.SCAM
                                for item in non_scams
                            )
                            / len(non_scams),
                            4,
                        )
                        if non_scams
                        else None
                    ),
                    exact_agreement=round(
                        sum(item.predicted_level == item.expected_level for item in subset)
                        / len(subset),
                        4,
                    ),
                )
            )
    return slices


def _format_report(report: EvaluationReport) -> str:
    status = "APROBADO" if report.passed else "NO APROBADO"
    lines = [
        f"Golden set: {status}",
        f"Casos: {report.total} ({report.scam_total} estafas, {report.non_scam_total} no estafas)",
        f"Recall de estafas: {report.scam_recall:.1%}",
        f"Tasa de falsas alarmas: {report.false_alarm_rate:.1%}",
        f"Acuerdo con el veredicto esperado: {report.exact_agreement:.1%}",
    ]
    if report.failures:
        lines.append("Fallos:")
        lines.extend(f"- {failure}" for failure in report.failures)
    return "\n".join(lines)


async def _run(args: argparse.Namespace) -> int:
    cases = load_cases(args.dataset)
    thresholds = json.loads(args.thresholds.read_text(encoding="utf-8"))
    report = await evaluate_cases(cases, thresholds)
    if args.json:
        print(report.model_dump_json(indent=2))
    else:
        print(_format_report(report))
    return 0 if report.passed else 1


def main() -> None:
    parser = argparse.ArgumentParser(
        description="Evalúa el ruleset local contra el golden set versionado."
    )
    parser.add_argument("--dataset", type=Path, default=DEFAULT_DATASET)
    parser.add_argument("--thresholds", type=Path, default=DEFAULT_THRESHOLDS)
    parser.add_argument("--json", action="store_true", help="Devuelve el informe como JSON")
    raise SystemExit(asyncio.run(_run(parser.parse_args())))


if __name__ == "__main__":
    main()
