from __future__ import annotations

from dataclasses import dataclass

from app.schemas import (
    EvidenceSignal,
    MessageExtraction,
    MessageType,
    RequestedAction,
    RuleStatus,
    RuleTrace,
    SignalSeverity,
    SignalStatus,
    VerdictLevel,
)

CONTEXT_SUPPRESSIBLE_CHECKS = {
    "domain_age",
    "tls_certificate_age",
    "high_domain_entropy",
    "excessive_subdomains",
}

SIGNAL_FAMILIES: dict[str, str] = {
    # 1. Identidad, atribución de canal y solicitud no autenticada
    # NOTA DE DISEÑO: requested_action vive en identity_and_channel intencionadamente:
    # "dice ser un banco, desde un móvil, y pide actuar" es un único hecho de origen.
    # Separarlo en otra familia provocaría sobreacumulación y falsos positivos en alertas
    # bancarias informativas o legítimas (ej. legit-bank-forward-001).
    "bank_from_mobile_number": "identity_and_channel",
    "unverifiable_entity_claim": "identity_and_channel",
    "claimed_entity_domain_mismatch": "identity_and_channel",
    "combo_squatting": "identity_and_channel",
    "official_domain_match": "identity_and_channel",
    "requested_action": "identity_and_channel",
    # 2. Presión psicológica y urgencia
    "urgency_language": "behavioral_pressure",
    "qr_payment_request": "behavioral_pressure",
    # 3. Anomalías sintácticas y ofuscación en URL/dominio
    "raw_ip_hostname": "technical_url",
    "punycode_hostname": "technical_url",
    "risky_tld": "technical_url",
    "shortened_url": "technical_url",
    "phishing_url_keywords": "technical_url",
    "excessive_url_length": "technical_url",
    "excessive_subdomains": "technical_url",
    "deep_url_path": "technical_url",
    "high_domain_entropy": "technical_url",
    # 4. Infraestructura de red, certificados y redirecciones
    "domain_age": "network_infrastructure",
    "tls_certificate_age": "network_infrastructure",
    "redirect_chain": "network_infrastructure",
    # 5. Inteligencia de fuentes externas y reputación
    "known_bad_indicator": "threat_intelligence",
    "stale_threat_indicator": "threat_intelligence",
    "google_safe_browsing_hash_match": "threat_intelligence",
    # 6. Análisis textual y modelos auxiliares
    "text_obfuscation": "content_nlp_ml",
    "ml_phishing_classifier": "content_nlp_ml",
    # 7. Campañas coordinadas
    "known_campaign_artifacts": "campaign_intel",
    "similar_campaign_text": "campaign_intel",
    # 8. Reglas deterministas críticas
    "remote_access": "critical_payload",
    "requests_security_code": "critical_payload",
}


@dataclass(frozen=True)
class Decision:
    level: VerdictLevel
    score: int
    confidence: float
    headline: str
    summary: str
    action: str
    reasons: list[str]
    rules: list[RuleTrace]


def _safe_action(
    extraction: MessageExtraction,
    level: VerdictLevel,
    message_type: MessageType = MessageType.UNKNOWN,
) -> str:
    if level == VerdictLevel.SCAM:
        if extraction.requested_action in {
            RequestedAction.GIVE_CODE,
            RequestedAction.GIVE_CREDENTIALS,
            RequestedAction.TRANSFER,
        }:
            return (
                "No compartas nada. Si ya diste datos o dinero, llama ahora al número "
                "oficial de tu banco."
            )
        if extraction.requested_action == RequestedAction.INSTALL_APP:
            return (
                "No instales ni abras esa aplicación. Si ya lo hiciste, desconecta el "
                "dispositivo de internet y llama a tu banco."
            )
        return "No pulses nada. Borra el mensaje y contacta tú con la entidad por su canal oficial."
    if message_type == MessageType.SPAM:
        return (
            "No respondas ni pulses enlaces. Marca el remitente como spam y bórralo si no "
            "esperabas esta publicidad."
        )
    if message_type == MessageType.TRANSACTIONAL:
        return (
            "Si esperabas ese envío, comprueba el pedido desde la web o aplicación oficial de "
            "la tienda o de la empresa de transporte. No compartas el PIN por mensaje o teléfono."
        )
    return (
        "No sigas las instrucciones. Contacta tú con la entidad usando el número de tu tarjeta "
        "o su web oficial."
    )


def incident_steps(
    extraction: MessageExtraction,
    message_type: MessageType = MessageType.UNKNOWN,
) -> list[str]:
    if message_type == MessageType.SPAM:
        return [
            "No respondas ni uses los enlaces del mensaje.",
            "Márcalo como spam o publicidad desde tu aplicación de mensajes.",
            "Bloquea el remitente si vuelve a contactar contigo.",
        ]
    if message_type == MessageType.TRANSACTIONAL:
        return [
            "Comprueba el pedido desde la tienda donde compraste o desde la web oficial del "
            "transportista.",
            "Lleva tu documento solo al punto de recogida si reconoces el envío.",
            "No envíes el PIN ni tus datos por SMS, WhatsApp o teléfono.",
        ]
    if extraction.requested_action == RequestedAction.INSTALL_APP:
        return [
            "Desconecta el dispositivo de internet sin seguir instrucciones del supuesto técnico.",
            "Llama a tu banco desde otro dispositivo si abriste una app o mostraste la pantalla.",
            "Pide ayuda técnica de confianza antes de volver a usar el dispositivo para operar.",
        ]
    if extraction.requested_action in {
        RequestedAction.GIVE_CODE,
        RequestedAction.GIVE_CREDENTIALS,
    }:
        return [
            "Cambia la contraseña desde la aplicación o web oficial y cierra las demás sesiones.",
            "Llama al banco si compartiste una clave, tarjeta o código de un solo uso.",
            "Guarda el mensaje y revisa movimientos o accesos que no reconozcas.",
        ]
    if extraction.requested_action == RequestedAction.TRANSFER:
        return [
            "Llama inmediatamente al banco para intentar detener o reclamar la operación.",
            "Guarda justificante, conversación, teléfono, enlace y hora como evidencia.",
            "Llama al 017 de INCIBE y denuncia ante Policía Nacional o Guardia Civil.",
        ]
    return [
        "Cierra el enlace y no introduzcas ningún dato.",
        "Si escribiste una contraseña, cámbiala desde el servicio oficial.",
        "Conserva el mensaje; pide orientación en el 017 de INCIBE y denuncia ante "
        "Policía Nacional o Guardia Civil si hubo perjuicio.",
    ]


def _domain_from_signal(signal: EvidenceSignal) -> str | None:
    if isinstance(signal.value, dict):
        domain = signal.value.get("domain") or signal.value.get("target")
        return domain if isinstance(domain, str) else None
    if signal.check_name in {"risky_tld", "shortened_url"} and isinstance(signal.value, str):
        return signal.value
    return None


def decide(
    extraction: MessageExtraction,
    signals: list[EvidenceSignal],
    *,
    ruleset_version: str = "unversioned",
    message_type: MessageType = MessageType.UNKNOWN,
) -> Decision:
    shared_domains = {
        str(signal.value.get("domain"))
        for signal in signals
        if signal.status == SignalStatus.HIT
        and signal.check_name == "shared_infrastructure_context"
        and isinstance(signal.value, dict)
        and signal.value.get("domain")
    }
    suppressed: list[EvidenceSignal] = []
    for signal in signals:
        domain = _domain_from_signal(signal)
        if (
            signal.status == SignalStatus.HIT
            and signal.check_name in CONTEXT_SUPPRESSIBLE_CHECKS
            and domain in shared_domains
        ):
            signal.status = SignalStatus.SUPPRESSED
            suppressed.append(signal)
    active_signals = [signal for signal in signals if signal.status == SignalStatus.HIT]
    hard_signals = [signal for signal in active_signals if signal.hard_rule]
    hard_rule = bool(hard_signals)
    family_weights: dict[str, int] = {}
    for signal in active_signals:
        family = SIGNAL_FAMILIES.get(signal.check_name, signal.check_name)
        family_weights[family] = max(
            family_weights.get(family, 0),
            max(0, signal.weight),
        )
    score = min(100, sum(family_weights.values()))
    level = VerdictLevel.SCAM if hard_rule or score >= 70 else VerdictLevel.UNCERTAIN
    ranked = sorted(
        (signal for signal in active_signals if signal.severity != SignalSeverity.INFO),
        key=lambda signal: (signal.hard_rule, signal.weight),
        reverse=True,
    )
    reasons = list(dict.fromkeys(signal.summary for signal in ranked))[:3]
    if not reasons:
        reasons = ["No hay suficientes datos verificables para confirmar quién envió el mensaje."]

    if level == VerdictLevel.SCAM:
        headline = "Tiene señales claras de estafa"
        summary = "Lo comprobado basta para tratar este mensaje como peligroso."
        confidence = 0.99 if hard_rule else max(0.7, score / 100)
    else:
        headline = "No puedo confirmar que sea legítimo"
        summary = "No veo una prueba concluyente, pero tampoco hay base para decir que es seguro."
        confidence = min(0.69, max(0.2, score / 100))

    rules = [
        RuleTrace(
            rule_id="hard_evidence",
            status=RuleStatus.FIRED if hard_rule else RuleStatus.NOT_FIRED,
            version=ruleset_version,
            summary="Una señal determinista de alta certeza basta para tratarlo como estafa.",
            observed=hard_rule,
            threshold=True,
            signal_names=list(dict.fromkeys(signal.check_name for signal in hard_signals)),
            suppressed_signal_names=[],
        ),
        RuleTrace(
            rule_id="weighted_score",
            status=RuleStatus.FIRED if score >= 70 else RuleStatus.NOT_FIRED,
            version=ruleset_version,
            summary="La suma de indicios alcanza el umbral conservador.",
            observed=score,
            threshold=70,
            signal_names=list(
                dict.fromkeys(
                    signal.check_name for signal in active_signals if signal.weight > 0
                )
            ),
            suppressed_signal_names=[],
        ),
        RuleTrace(
            rule_id="shared_infrastructure_suppression",
            status=RuleStatus.FIRED if suppressed else RuleStatus.NOT_FIRED,
            version=ruleset_version,
            summary=(
                "El contexto de infraestructura compartida neutraliza solo indicios técnicos "
                "ruidosos; nunca el contenido ni la acción solicitada."
            ),
            observed=len(suppressed),
            threshold=1,
            signal_names=["shared_infrastructure_context"] if shared_domains else [],
            suppressed_signal_names=list(
                dict.fromkeys(signal.check_name for signal in suppressed)
            ),
        ),
    ]

    return Decision(
        level=level,
        score=score,
        confidence=confidence,
        headline=headline,
        summary=summary,
        action=_safe_action(extraction, level, message_type),
        reasons=reasons,
        rules=rules,
    )
