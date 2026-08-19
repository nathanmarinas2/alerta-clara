"""Benchmark completo de evaluación bidireccional (200 SMS en español).

Evalúa simultáneamente:
- 100 SMS de Estafas (Mide Sensibilidad / Recall de Estafas).
- 100 SMS Legítimos (Mide Tasa de Falsos Positivos / Especificidad).

Calcula la matriz de confusión, precisión, recall, F1-score y desglose
por categorías tanto en tráfico malicioso como en comunicaciones legítimas.
"""

from __future__ import annotations

import asyncio
import json
from collections import Counter, defaultdict
from pathlib import Path

from app.config import Settings
from app.schemas import VerdictLevel
from app.services.extraction import local_extract
from app.services.rules import decide
from app.services.signals import SignalCollector

ROOT = Path(__file__).resolve().parents[1]
SCAM_PATH = ROOT / "data" / "sms_scam_100_es.jsonl"
LEGIT_PATH = ROOT / "data" / "sms_legitimate_100_es.jsonl"


async def run_full_benchmark() -> dict:
    settings = Settings(
        enable_network_checks=False,
        enable_cnmc_alias_registry=False,
    )
    collector = SignalCollector(settings)

    # 1. Evaluar Estafas
    scam_lines = SCAM_PATH.read_text(encoding="utf-8").strip().splitlines()
    scam_total = len(scam_lines)
    tp = 0  # True Positives (Scam -> ESTAFA)
    fn = 0  # False Negatives (Scam -> NO_PUEDO_CONFIRMARLO)
    scams_by_cat: dict[str, Counter] = defaultdict(Counter)

    for line in scam_lines:
        item = json.loads(line)
        category = item["category"]
        sender = item.get("sender")
        text = item["message"]

        extraction = local_extract(text, sender=sender)
        signals = await collector.collect(extraction)
        decision = decide(extraction, signals, ruleset_version=settings.ruleset_version)

        verdict = decision.level.value
        scams_by_cat[category][verdict] += 1
        if decision.level == VerdictLevel.SCAM:
            tp += 1
        else:
            fn += 1

    # 2. Evaluar Mensajes Legítimos
    legit_lines = LEGIT_PATH.read_text(encoding="utf-8").strip().splitlines()
    legit_total = len(legit_lines)
    tn = 0  # True Negatives (Legit -> NO_PUEDO_CONFIRMARLO)
    fp = 0  # False Positives (Legit -> ESTAFA)
    legit_by_cat: dict[str, Counter] = defaultdict(Counter)
    fp_details: list[dict] = []

    for line in legit_lines:
        item = json.loads(line)
        category = item["category"]
        sender = item.get("sender")
        text = item["message"]

        extraction = local_extract(text, sender=sender)
        signals = await collector.collect(extraction)
        decision = decide(extraction, signals, ruleset_version=settings.ruleset_version)

        verdict = decision.level.value
        legit_by_cat[category][verdict] += 1
        if decision.level == VerdictLevel.SCAM:
            fp += 1
            fp_details.append(
                {
                    "id": item["id"],
                    "category": category,
                    "sender": sender,
                    "text": text,
                    "score": decision.score,
                    "reasons": decision.reasons,
                }
            )
        else:
            tn += 1

    total_samples = scam_total + legit_total
    recall = (tp / scam_total) * 100 if scam_total else 0.0
    fp_rate = (fp / legit_total) * 100 if legit_total else 0.0
    specificity = (tn / legit_total) * 100 if legit_total else 0.0
    precision = (tp / (tp + fp)) * 100 if (tp + fp) else 0.0
    f1 = (2 * precision * recall) / (precision + recall) if (precision + recall) else 0.0
    accuracy = ((tp + tn) / total_samples) * 100 if total_samples else 0.0

    print("=" * 78)
    print(f"BENCHMARK COMPLETO DE EVALUACION (200 SMS: 100 Estafas + 100 Legitimos)")
    print("=" * 78)

    print("\n1. MATRIZ DE CONFUSION:")
    print("                      | Prediccion: ESTAFA | Prediccion: NO_CONFIRMADO | Total")
    print("  --------------------+--------------------+---------------------------+------")
    print(f"  Real: ESTAFA (100)  | TP: {tp:3d} (Recall: {recall:5.1f}%) | FN: {fn:3d}                 | {scam_total:3d}")
    print(f"  Real: LEGITIMO (100)| FP: {fp:3d} (FPR:    {fp_rate:5.1f}%) | TN: {tn:3d} (Spec:  {specificity:5.1f}%) | {legit_total:3d}")
    print("  --------------------+--------------------+---------------------------+------")
    print(f"  Total               |     {tp+fp:3d}            |     {fn+tn:3d}                   | {total_samples:3d}")

    print("\n2. METRICAS GLOBALES DE RENDIMIENTO:")
    print(f"  - Sensibilidad / Recall de Estafas : {recall:6.2f}% ({tp}/{scam_total} estafas confirmadas)")
    print(f"  - Tasa de Falsos Positivos (FPR)  : {fp_rate:6.2f}% ({fp}/{legit_total} legitimos marcados como estafa)")
    print(f"  - Especificidad (Tasa Verdadera Neg): {specificity:6.2f}% ({tn}/{legit_total} legitimos protegidos)")
    print(f"  - Precision (VPP)                  : {precision:6.2f}%")
    print(f"  - F1-Score                         : {f1:6.2f}%")
    print(f"  - Exactitud Global (Accuracy)      : {accuracy:6.2f}%")

    print("\n3. DETALLE DE ESTAFAS POR CATEGORIA (Sensibilidad / Deteccion):")
    print(f"  {'Categoria':<25} | {'ESTAFA (TP)':<11} | {'NO CONFIRMADO (FN)':<19} | {'Recall':<7}")
    print("  " + "-" * 68)
    for cat, counts in sorted(scams_by_cat.items()):
        c_tp = counts.get(VerdictLevel.SCAM.value, 0)
        c_fn = counts.get(VerdictLevel.UNCERTAIN.value, 0)
        c_tot = c_tp + c_fn
        c_rec = (c_tp / c_tot) * 100 if c_tot else 0.0
        print(f"  {cat:<25} | {c_tp:11d} | {c_fn:19d} | {c_rec:6.1f}%")

    print("\n4. DETALLE DE MENSAJES LEGITIMOS POR CATEGORIA (Cero Falsas Alarmas):")
    print(f"  {'Categoria':<25} | {'NO CONFIRMADO (TN)':<19} | {'ESTAFA (FP)':<11} | {'Falsos Positivos'}")
    print("  " + "-" * 72)
    for cat, counts in sorted(legit_by_cat.items()):
        c_tn = counts.get(VerdictLevel.UNCERTAIN.value, 0)
        c_fp = counts.get(VerdictLevel.SCAM.value, 0)
        print(f"  {cat:<25} | {c_tn:19d} | {c_fp:11d} | {'0.0% (Correcto)' if c_fp == 0 else f'ERROR: {c_fp}'}")

    if fp_details:
        print("\n[ALERTA] DETALLE DE FALSOS POSITIVOS EN MENSAJES LEGITIMOS:")
        for fp_item in fp_details:
            print(f"  - ID: {fp_item['id']} | Remitente: {fp_item['sender']} | Score: {fp_item['score']}")
            print(f"    Texto: {fp_item['text']}")
            print(f"    Razones: {fp_item['reasons']}")
    else:
        print("\n  >> CERO FALSOS POSITIVOS EN LOS 100 SMS LEGITIMOS (100% Especificidad).")

    print("=" * 78)

    return {
        "recall": recall,
        "false_positive_rate": fp_rate,
        "specificity": specificity,
        "precision": precision,
        "f1_score": f1,
        "accuracy": accuracy,
        "confusion_matrix": {"tp": tp, "fn": fn, "tn": tn, "fp": fp},
        "false_positive_details": fp_details,
    }


if __name__ == "__main__":
    asyncio.run(run_full_benchmark())
