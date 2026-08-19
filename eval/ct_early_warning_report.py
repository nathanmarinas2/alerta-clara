"""Generador de informe de investigación y auditoría pública de Alerta Temprana (Certificate Transparency).

Demuestra la ventaja temporal (Delta-t) de detección previa a la aparición en listas públicas:
Delta-t = (fecha_aparicion_en_feed_publico) - (fecha_observacion_certificado_ct)

Audita los 4 canales de validación:
1. Feeds públicos de reputación (URLhaus, OpenPhish, PhishDestroy).
2. Avisos oficiales de INCIBE / CERTs nacionales.
3. Clones activos documentados en sandbox Playwright (formularios de credenciales/tarjeta).
4. Retrobúsqueda de SMS reportados por víctimas reales en la plataforma.
"""

from __future__ import annotations

import argparse
import json
from pathlib import Path

from app.entities import load_entities
from app.services.ct_verification import (
    AUDIT_LOG_DIR,
    calculate_lead_time_metrics,
    cross_reference_threat_feeds,
)


def print_audit_report(audit_dir: Path | None = None) -> None:
    target_dir = audit_dir or AUDIT_LOG_DIR
    metrics = calculate_lead_time_metrics(audit_dir=target_dir)
    entities = load_entities()

    print("=" * 80)
    print("INFORME DE AUDITORIA PUBLICA: MONITORIZACION CERTIFICATE TRANSPARENCY (CT)")
    print("Investigacion de Alerta Temprana frente a Smishing y Phishing en Espana")
    print("=" * 80)

    print("\n1. COBERTURA DE MONITORIZACION:")
    print(f"  - Entidades espanolas vigiladas  : {len(entities)} marcas/organismos oficiales")
    print(f"  - Registro inmutable en Git      : {target_dir}")

    manifest_file = target_dir / "manifest.json"
    if manifest_file.exists():
        try:
            manifest = json.loads(manifest_file.read_text(encoding="utf-8"))
            print(f"  - Ultima actualizacion manifest  : {manifest.get('updated_at', 'N/A')}")
            print(f"  - Total dominios registrados     : {manifest.get('total_observations', 0)}")
            print(f"  - Ficheros diarios notarizados   : {len(manifest.get('daily_files', {}))}")
        except Exception:
            pass

    lt = metrics.get("lead_time_summary", {})
    mean_days = lt.get("mean_days", 0.0)
    median_days = lt.get("median_days", 0.0)
    min_days = lt.get("min_days", 0.0)
    max_days = lt.get("max_days", 0.0)
    advance_rate = lt.get("advance_detection_rate_pct", 0.0)

    print("\n2. METRICAS DE VENTAJA TEMPORAL (Delta-t Lead Time):")
    print("  Delta-t = (Fecha publicacion en feed) - (Fecha observacion en CT)")
    print("  ------------------------------------------------------------------")
    print(f"  - Dominios sospechosos totales   : {metrics.get('total_domains_monitored', 0)}")
    print(f"  - Clones activos en Playwright   : {metrics.get('active_clones_documented', 0)} (Formularios password/tarjeta)")
    print(f"  - Dominios contrastados en feeds : {metrics.get('corroborated_phishing_domains', 0)}")
    print(f"  - Ventaja temporal MEDIA         : {mean_days:.2f} dias ({mean_days*24:.1f} horas)")
    print(f"  - Ventaja temporal MEDIANA       : {median_days:.2f} dias ({median_days*24:.1f} horas)")
    print(f"  - Rango de ventaja temporal      : [{min_days:.1f} .. {max_days:.1f}] dias")
    print(f"  - Tasa de deteccion anticipada   : {advance_rate:.1f}% de las amenazas")

    print("\n3. LAS 4 VIAS DE CONFIRMACION Y CIERRE DEL CIRCULO:")
    print("  [1] Feeds publicos (URLhaus/PhishDestroy) : Contrasta Delta-t formal.")
    print("  [2] Avisos de INCIBE                     : Respaldo de la autoridad nacional.")
    print("  [3] Sandbox Playwright (Sidecar)         : Clon activo verificado el mismo dia (sin esperar).")
    print("  [4] Reportes SMS de victimas reales      : Cierre del ciclo con fecha de impacto.")

    print("\n4. PRINCIPIO DE INTEGRIDAD Y NOTARIZACION:")
    print("  >> 'Registra cuando observas, nunca reconstruyas hacia atras.'")
    print("  >> Los commits diarios a Git atestiguan criptograficamente la fecha de observacion.")
    print("=" * 80)


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Informe de Auditoria de Alerta Temprana CT")
    parser.add_argument("--cross-reference", action="store_true", help="Cruzar con base de feeds antes de generar informe")
    args = parser.parse_args()

    if args.cross_reference:
        cross_reference_threat_feeds()

    print_audit_report()
