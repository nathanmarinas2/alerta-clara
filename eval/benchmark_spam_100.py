"""Script de evaluación del dataset de 100 SMS de spam en español.

Evalúa la clasificación de tipo de mensaje (SPAM / PHISHING / DESCONOCIDO)
y el veredicto de riesgo emitido por el motor de reglas de Alerta Clara.
"""

from __future__ import annotations

import json
from collections import Counter, defaultdict
from pathlib import Path

from app.config import Settings
from app.schemas import MessageType, VerdictLevel
from app.services.extraction import local_extract
from app.services.message_type import classify_message_type
from app.services.rules import decide
from app.services.signals import SignalCollector

DATA_PATH = Path(__file__).resolve().parents[1] / "data" / "sms_spam_100_es.jsonl"


async def evaluate_spam_dataset() -> dict:
    settings = Settings(enable_network_checks=False)
    collector = SignalCollector(settings)

    lines = DATA_PATH.read_text(encoding="utf-8").strip().splitlines()
    total = len(lines)

    by_category: dict[str, dict[str, int]] = defaultdict(Counter)
    type_counts = Counter()
    verdict_counts = Counter()
    detailed_results = []

    for line in lines:
        item = json.loads(line)
        msg_id = item["id"]
        category = item["category"]
        text = item["message"]

        extraction = local_extract(text)
        assessment = classify_message_type(extraction)
        signals = await collector.collect(extraction)
        decision = decide(extraction, signals, message_type=assessment.message_type)

        type_detected = assessment.message_type.value
        verdict = decision.level.value

        type_counts[type_detected] += 1
        verdict_counts[verdict] += 1
        by_category[category][type_detected] += 1

        detailed_results.append(
            {
                "id": msg_id,
                "category": category,
                "text": text,
                "message_type": type_detected,
                "message_type_confidence": assessment.confidence,
                "reasons": assessment.reasons,
                "verdict": verdict,
                "score": decision.score,
            }
        )

    print("=" * 70)
    print(f"EVALUACIÓN DEL DATASET DE 100 SMS SPAM EN ESPAÑOL (Total: {total})")
    print("=" * 70)

    print("\n1. CLASIFICACIÓN DE TIPO DE MENSAJE:")
    for msg_type, count in type_counts.most_common():
        pct = (count / total) * 100
        print(f"  - {msg_type.upper():<15}: {count:3d} ({pct:5.1f}%)")

    spam_or_phish = type_counts[MessageType.SPAM.value] + type_counts[MessageType.PHISHING.value]
    print(
        f"\n  >> TASA DE DETECCIÓN GLOBAL (Spam o Phishing): {spam_or_phish}/{total} ({(spam_or_phish/total)*100:.1f}%)"
    )

    print("\n2. VEREDICTO DE RIESGO DE SEGURIDAD (Reglas conservadoras):")
    for verd, count in verdict_counts.most_common():
        pct = (count / total) * 100
        print(f"  - {verd.upper():<22}: {count:3d} ({pct:5.1f}%)")

    print("\n3. DESGLOSE POR CATEGORÍA:")
    print(f"  {'Categoría':<25} | {'SPAM':<6} | {'PHISHING':<8} | {'DESCONOCIDO':<11} | {'Total':<5}")
    print("  " + "-" * 65)
    for cat, counts in sorted(by_category.items()):
        sp = counts.get(MessageType.SPAM.value, 0)
        ph = counts.get(MessageType.PHISHING.value, 0)
        un = counts.get(MessageType.UNKNOWN.value, 0)
        cat_tot = sum(counts.values())
        print(f"  {cat:<25} | {sp:<6} | {ph:<8} | {un:<11} | {cat_tot:<5}")

    print("=" * 70)

    return {
        "total": total,
        "type_counts": dict(type_counts),
        "verdict_counts": dict(verdict_counts),
        "by_category": {cat: dict(cnt) for cat, cnt in by_category.items()},
        "results": detailed_results,
    }


if __name__ == "__main__":
    import asyncio

    asyncio.run(evaluate_spam_dataset())
