"""Script de evaluación del dataset de 100 SMS de estafas (Scam/Smishing) en español.

Evalúa la efectividad del motor determinista de reglas y señales de Alerta Clara
ante 100 ataques reales y simulados de estafas dirigidas a usuarios en España.
"""

from __future__ import annotations

import asyncio
import json
from collections import Counter, defaultdict
from pathlib import Path

from app.config import Settings
from app.schemas import SignalSeverity, SignalStatus, VerdictLevel
from app.services.extraction import local_extract
from app.services.message_type import classify_message_type
from app.services.rules import decide
from app.services.signals import SignalCollector

DATA_PATH = Path(__file__).resolve().parents[1] / "data" / "sms_scam_100_es.jsonl"


async def evaluate_scam_dataset() -> dict:
    settings = Settings(
        enable_network_checks=False,
        enable_cnmc_alias_registry=True,
    )
    collector = SignalCollector(settings)

    lines = DATA_PATH.read_text(encoding="utf-8").strip().splitlines()
    total = len(lines)

    by_category: dict[str, dict[str, int]] = defaultdict(Counter)
    verdict_counts = Counter()
    type_counts = Counter()
    hard_rule_counts = Counter()
    fired_signals = Counter()
    detailed_results = []

    for line in lines:
        item = json.loads(line)
        msg_id = item["id"]
        category = item["category"]
        sender = item.get("sender")
        text = item["message"]

        extraction = local_extract(text, sender=sender)
        assessment = classify_message_type(extraction)
        signals = await collector.collect(extraction)
        decision = decide(extraction, signals, message_type=assessment.message_type)

        verdict = decision.level.value
        msg_type = assessment.message_type.value

        verdict_counts[verdict] += 1
        type_counts[msg_type] += 1
        by_category[category][verdict] += 1

        active_signals = [
            s.check_name for s in signals if s.status == SignalStatus.HIT and s.weight > 0
        ]
        hard_signals = [s.check_name for s in signals if s.hard_rule and s.status == SignalStatus.HIT]

        for s_name in active_signals:
            fired_signals[s_name] += 1
        for h_name in hard_signals:
            hard_rule_counts[h_name] += 1

        detailed_results.append(
            {
                "id": msg_id,
                "category": category,
                "sender": sender,
                "text": text,
                "verdict": verdict,
                "score": decision.score,
                "confidence": decision.confidence,
                "message_type": msg_type,
                "active_signals": active_signals,
                "hard_signals": hard_signals,
                "reasons": decision.reasons,
            }
        )

    scam_count = verdict_counts[VerdictLevel.SCAM.value]
    scam_pct = (scam_count / total) * 100

    print("=" * 75)
    print(f"EVALUACIÓN DEL DATASET DE 100 SMS DE ESTAFAS EN ESPAÑOL (Total: {total})")
    print("=" * 75)

    print("\n1. VEREDICTO DE RIESGO DE SEGURIDAD (Detección de ESTAFA):")
    for verd, count in verdict_counts.most_common():
        pct = (count / total) * 100
        print(f"  - {verd.upper():<22}: {count:3d} ({pct:5.1f}%)")

    print(f"\n  >> TASA DE DETECCIÓN DE ESTAFAS: {scam_count}/{total} ({scam_pct:.1f}%)")

    print("\n2. CLASIFICACIÓN DESCRIPTIVA DE TIPO:")
    for m_type, count in type_counts.most_common():
        pct = (count / total) * 100
        print(f"  - {m_type.upper():<22}: {count:3d} ({pct:5.1f}%)")

    print("\n3. DESGLOSE POR CATEGORÍA DE ESTAFA:")
    print(f"  {'Categoría':<25} | {'ESTAFA':<8} | {'NO CONFIRMADO':<14} | {'Efectividad':<11}")
    print("  " + "-" * 67)
    for cat, counts in sorted(by_category.items()):
        scams = counts.get(VerdictLevel.SCAM.value, 0)
        uncert = counts.get(VerdictLevel.UNCERTAIN.value, 0)
        cat_total = scams + uncert
        eff = (scams / cat_total) * 100 if cat_total else 0
        print(f"  {cat:<25} | {scams:8d} | {uncert:14d} | {eff:9.1f}%")

    print("\n4. SEÑALES TÉCNICAS Y REGLAS DURAS MÁS DISPARADAS:")
    for sig_name, count in fired_signals.most_common(10):
        is_hard = " [REGLA DURA]" if sig_name in hard_rule_counts else ""
        print(f"  - {sig_name:<32}: {count:3d} veces{is_hard}")

    print("=" * 75)

    return {
        "total": total,
        "scam_detection_rate": scam_pct,
        "verdict_counts": dict(verdict_counts),
        "type_counts": dict(type_counts),
        "by_category": {cat: dict(cnt) for cat, cnt in by_category.items()},
        "results": detailed_results,
    }


if __name__ == "__main__":
    asyncio.run(evaluate_scam_dataset())
