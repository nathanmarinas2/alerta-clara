from __future__ import annotations

import asyncio
import ipaddress
import math
import re
from collections import Counter
from datetime import UTC, datetime
from time import perf_counter
from urllib.parse import urlsplit

from app.config import Settings
from app.entities import (
    domain_similarity,
    get_entity,
    is_official_domain,
    normalize_token,
    registrable_domain,
)
from app.schemas import (
    EvidenceSignal,
    MessageExtraction,
    RequestedAction,
    SignalSeverity,
    SignalStatus,
)
from app.services.alias_registry import verify_sender_alias
from app.services.ml_classifier import predict_phishing
from app.services.network import follow_redirects, rdap_lookup, tls_certificate
from app.services.redaction import find_sensitive_types
from app.services.text_normalization import adversarial_obfuscations, normalize_for_detection

RISKY_TLDS = {"top", "xyz", "icu", "cfd", "sbs", "click", "zip", "mov", "cam", "rest"}
SHORTENERS = {"bit.ly", "tinyurl.com", "t.co", "cutt.ly", "is.gd", "ow.ly", "buff.ly"}
REMOTE_ACCESS_RE = re.compile(
    r"\b(?:anydesk|teamviewer|rustdesk|supremo|control remoto|compartir pantalla)\b",
    re.IGNORECASE,
)
CODE_RE = re.compile(r"\b(?:c[oó]digo\s*(?:sms)?|otp|clave\s*(?:sms)?|pin)\b", re.IGNORECASE)
MOBILE_RE = re.compile(r"^(?:34)?[67]\d{8}$")
FAMILY_TERMS_RE = re.compile(
    r"\b(?:mam[aá]|pap[aá]|mami|papi|hijo|hija|hermano|hermana|abuelo|abuela)\b",
    re.IGNORECASE,
)
DEVICE_BROKEN_RE = re.compile(
    r"\b(?:se me ha (?:ca[ií]do|roto|apagado)|roto el (?:m[oó]vil|tel[eé]fono)|"
    r"perdido el (?:m[oó]vil|tel[eé]fono)|nuevo n[uú]mero|n[uú]mero provisional|n[uú]mero temporal|"
    r"SIM temporal|cambiado de n[uú]mero|altavoz roto)\b",
    re.IGNORECASE,
)
WHATSAPP_CONTACT_RE = re.compile(
    r"\b(?:escr[ií]beme (?:por|un) whats?app|h[aá]blame por whats?app|m[aá]ndame un whats?app|"
    r"whats?app a este n[uú]mero|nuevo whats?app|hablame por whats?app|escribeme por whats?app)\b",
    re.IGNORECASE,
)
MONEY_EMERGENCY_RE = re.compile(
    r"\b(?:dinero|pagar|pago|factura|alquiler|matr[ií]cula|transferencia|cuenta|bizum|saldo|eur(?:os?)?|€)\b",
    re.IGNORECASE,
)
PHISHING_URL_RE = re.compile(
    r"(?:login|signin|acceso|verific(?:a|ar|acion)|seguridad|cuenta|password|"
    r"contrase(?:n|ñ)a|premio|factura|pago|actualiz(?:a|ar))",
    re.IGNORECASE,
)


def _signal(
    name: str,
    value: object,
    weight: int,
    severity: SignalSeverity,
    summary: str,
    *,
    detail: str | None = None,
    latency_ms: int = 0,
    hard_rule: bool = False,
    status: SignalStatus = SignalStatus.HIT,
    source: str = "local",
    version: str = "1",
) -> EvidenceSignal:
    active = status == SignalStatus.HIT
    return EvidenceSignal(
        check_name=name,
        value=value,
        weight=weight if active else 0,
        severity=severity if active else SignalSeverity.INFO,
        summary=summary,
        detail=detail,
        latency_ms=latency_ms,
        hard_rule=hard_rule if active else False,
        status=status,
        source=source,
        version=version,
    )


def _url_host(url: str) -> str | None:
    candidate = url if "://" in url else f"https://{url}"
    try:
        return (urlsplit(candidate).hostname or "").rstrip(".") or None
    except ValueError:
        return None


def _is_ip(value: str) -> bool:
    try:
        ipaddress.ip_address(value)
    except ValueError:
        return False
    return True


def _shannon_entropy(value: str) -> float:
    if not value:
        return 0.0
    counts = Counter(value)
    length = len(value)
    return -sum((count / length) * math.log2(count / length) for count in counts.values())


class SignalCollector:
    def __init__(self, settings: Settings):
        self.settings = settings

    async def collect(self, extraction: MessageExtraction) -> list[EvidenceSignal]:
        signals = self._deterministic_signals(extraction)

        urls_by_domain: dict[str, str] = {}
        for url in extraction.urls:
            domain = registrable_domain(url)
            if domain and domain not in urls_by_domain:
                urls_by_domain[domain] = url
            if len(urls_by_domain) >= 3:
                break

        if not self.settings.enable_network_checks:
            for domain in urls_by_domain:
                signals.extend(self._network_disabled_signals(domain))
            return signals

        tasks = []
        for domain, url in urls_by_domain.items():
            if _is_ip(domain):
                signals.extend(
                    [
                        self._not_applicable("domain_age", domain, "rdap"),
                        self._not_applicable("tls_certificate_age", domain, "tls"),
                    ]
                )
            else:
                tasks.extend(
                    [
                        self._with_timeout(
                            "domain_age", "rdap", domain, self._rdap_signal(domain, extraction)
                        ),
                        self._with_timeout(
                            "tls_certificate_age", "tls", domain, self._tls_signal(domain)
                        ),
                    ]
                )
            tasks.append(
                self._with_timeout(
                    "redirect_chain", "http", domain, self._redirect_signal(url, extraction)
                )
            )

        if tasks:
            signals.extend(await asyncio.gather(*tasks))
        return signals

    async def _with_timeout(
        self,
        check_name: str,
        source: str,
        target: str,
        coroutine,
    ) -> EvidenceSignal:
        started = perf_counter()
        try:
            return await asyncio.wait_for(
                coroutine, timeout=self.settings.signal_timeout_seconds
            )
        except TimeoutError:
            return _signal(
                check_name,
                {"target": target},
                0,
                SignalSeverity.INFO,
                "La comprobación agotó su tiempo y no se usó para decidir.",
                latency_ms=round((perf_counter() - started) * 1000),
                status=SignalStatus.TIMEOUT,
                source=source,
                version=self.settings.signalset_version,
            )
        except Exception as exc:
            return _signal(
                check_name,
                {"target": target},
                0,
                SignalSeverity.INFO,
                "La comprobación falló y no se usó para decidir.",
                detail=type(exc).__name__,
                latency_ms=round((perf_counter() - started) * 1000),
                status=SignalStatus.ERROR,
                source=source,
                version=self.settings.signalset_version,
            )

    def _not_applicable(self, name: str, target: str, source: str) -> EvidenceSignal:
        return _signal(
            name,
            {"target": target},
            0,
            SignalSeverity.INFO,
            "Esta comprobación no es aplicable al tipo de destino.",
            status=SignalStatus.NOT_APPLICABLE,
            source=source,
            version=self.settings.signalset_version,
        )

    def _network_disabled_signals(self, domain: str) -> list[EvidenceSignal]:
        result = [
            self._not_applicable("domain_age", domain, "rdap"),
            self._not_applicable("tls_certificate_age", domain, "tls"),
            self._not_applicable("redirect_chain", domain, "http"),
        ]
        for signal in result:
            signal.detail = "Las comprobaciones de red están desactivadas."
        return result

    def _deterministic_signals(self, extraction: MessageExtraction) -> list[EvidenceSignal]:
        version = self.settings.signalset_version
        signals: list[EvidenceSignal] = []
        entity = get_entity(extraction.claimed_entity)
        detection_text = normalize_for_detection(extraction.body_text)

        obfuscations = adversarial_obfuscations(extraction.body_text)
        signals.append(
            _signal(
                "text_obfuscation",
                obfuscations,
                15,
                SignalSeverity.WARNING,
                (
                    "El texto usa técnicas para ocultar palabras sensibles."
                    if obfuscations
                    else "No se detectaron técnicas básicas de ofuscación textual."
                ),
                detail=(
                    "La detección se repitió sobre una versión normalizada; la ofuscación añade "
                    "riesgo, pero no demuestra por sí sola que sea una estafa."
                    if obfuscations
                    else None
                ),
                status=SignalStatus.HIT if obfuscations else SignalStatus.MISS,
                version=version,
            )
        )

        ml_prediction = predict_phishing(extraction.body_text, self.settings)
        if ml_prediction is None:
            signals.append(
                self._not_applicable("ml_phishing_classifier", "local_model", "local_ml")
            )
        else:
            probability, metadata = ml_prediction
            confident = probability >= self.settings.ml_classifier_high_threshold
            signals.append(
                _signal(
                    "ml_phishing_classifier",
                    {
                        "phishing_probability": round(probability, 4),
                        "model_version": metadata["model_version"],
                    },
                    15 if confident else 0,
                    SignalSeverity.WARNING,
                    (
                        "El modelo auxiliar detecta un patrón textual parecido a phishing."
                        if confident
                        else "El modelo auxiliar no detecta un patrón textual concluyente."
                    ),
                    detail=(
                        "Es una señal auxiliar entrenada con correo y SMS en español; nunca decide "
                        "por sí sola."
                    ),
                    status=SignalStatus.HIT if confident else SignalStatus.MISS,
                    source="local_ml",
                    version=str(metadata["model_version"]),
                )
            )

        remote_access = bool(REMOTE_ACCESS_RE.search(detection_text))
        signals.append(
            _signal(
                "remote_access",
                remote_access,
                100,
                SignalSeverity.CRITICAL,
                (
                    "Pide instalar o usar una aplicación de acceso remoto."
                    if remote_access
                    else "No se detectó una petición de acceso remoto."
                ),
                hard_rule=True,
                status=SignalStatus.HIT if remote_access else SignalStatus.MISS,
                version=version,
            )
        )

        requests_code = bool(
            extraction.requested_action == RequestedAction.GIVE_CODE
            and CODE_RE.search(detection_text)
            and not re.search(
                r"\b(?:no|nunca|jam[aá]s)\s+(?:compartas?|facilites?|des|indiques?|env[ií]es?|reveles?)\b",
                detection_text,
                re.IGNORECASE,
            )
        )
        signals.append(
            _signal(
                "requests_security_code",
                requests_code,
                100,
                SignalSeverity.CRITICAL,
                (
                    "Pide compartir un código de seguridad o clave SMS."
                    if requests_code
                    else "No se detectó una petición explícita de compartir un código."
                ),
                hard_rule=True,
                status=SignalStatus.HIT if requests_code else SignalStatus.MISS,
                version=version,
            )
        )

        family_emergency = bool(
            FAMILY_TERMS_RE.search(detection_text)
            and DEVICE_BROKEN_RE.search(detection_text)
            and WHATSAPP_CONTACT_RE.search(detection_text)
            and (
                extraction.requested_action
                in {RequestedAction.TRANSFER, RequestedAction.GIVE_CREDENTIALS}
                or MONEY_EMERGENCY_RE.search(detection_text)
            )
        )
        signals.append(
            _signal(
                "family_impersonation_emergency",
                family_emergency,
                60,
                SignalSeverity.WARNING,
                (
                    "Patrón de estafa 'Hijo en apuros': simula ser un familiar con el teléfono "
                    "roto pidiendo contactar por WhatsApp para un pago o emergencia económica."
                    if family_emergency
                    else "No se detectó el patrón de suplantación de un familiar en emergencia económica."
                ),
                detail=(
                    "Modus operandi en España donde atacantes fingen ser hijos o familiares en "
                    "apuros para exigir transferencias de dinero urgente."
                ),
                hard_rule=False,
                status=SignalStatus.HIT if family_emergency else SignalStatus.MISS,
                version=version,
            )
        )

        qr_detected = bool(extraction.qr_payload_types)
        signals.append(
            _signal(
                "qr_payload_detected",
                extraction.qr_payload_types,
                0,
                SignalSeverity.INFO,
                (
                    "La captura contiene un código QR, decodificado localmente sin abrirlo."
                    if qr_detected
                    else "No se detectó contenido procedente de un código QR."
                ),
                status=SignalStatus.HIT if qr_detected else SignalStatus.MISS,
                source="image_qr",
                version=version,
            )
        )
        qr_payment = "payment" in extraction.qr_payload_types
        signals.append(
            _signal(
                "qr_payment_request",
                qr_payment,
                10,
                SignalSeverity.WARNING,
                (
                    "El código QR contiene una petición o instrucción de pago."
                    if qr_payment
                    else "El código QR no contiene una instrucción de pago reconocible."
                ),
                detail=(
                    "Un QR de pago puede ser legítimo; se valora junto con el resto del mensaje."
                ),
                status=SignalStatus.HIT if qr_payment else SignalStatus.MISS,
                source="image_qr",
                version=version,
            )
        )

        sensitive = find_sensitive_types(extraction.body_text)
        signals.append(
            _signal(
                "personal_data_present",
                sensitive,
                0,
                SignalSeverity.INFO,
                (
                    "Se han ocultado datos personales antes de guardar o consultar "
                    "servicios externos."
                    if sensitive
                    else "No se detectaron identificadores personales que redactar."
                ),
                status=SignalStatus.HIT if sensitive else SignalStatus.MISS,
                version=version,
            )
        )

        for url in extraction.urls:
            signals.extend(self._local_url_signals(url, entity))

        domains = [domain for url in extraction.urls if (domain := registrable_domain(url))]
        if entity and not domains and extraction.requested_action != RequestedAction.NONE:
            signals.append(
                _signal(
                    "unverifiable_entity_claim",
                    entity.name,
                    15,
                    SignalSeverity.WARNING,
                    f"Dice ser {entity.name}, pero no aporta un dominio que podamos verificar.",
                    version=version,
                )
            )

        if entity and entity.category == "bank":
            sender_digits = re.sub(r"\D", "", extraction.sender_number or "")
            mobile_sender = bool(
                MOBILE_RE.match(sender_digits)
                and extraction.requested_action != RequestedAction.NONE
            )
            signals.append(
                _signal(
                    "bank_from_mobile_number",
                    extraction.sender_number,
                    65,
                    SignalSeverity.WARNING,
                    (
                        "Dice ser un banco, pero llega desde un número móvil y pide actuar."
                        if mobile_sender
                        else "No se detectó una petición bancaria enviada desde un móvil."
                    ),
                    hard_rule=False,
                    status=SignalStatus.HIT if mobile_sender else SignalStatus.MISS,
                    version=version,
                )
            )

        # Verificación oficial de remitente alfanumérico en el Registro de Alias de la CNMC
        if self.settings.enable_cnmc_alias_registry:
            sender_candidate = extraction.sender_alias or extraction.sender_number
            if sender_candidate:
                signals.extend(
                    verify_sender_alias(
                        sender_candidate,
                        extraction.claimed_entity,
                        self.settings,
                    )
                )

        urgency = bool(extraction.urgency_markers)
        signals.append(
            _signal(
                "urgency_language",
                extraction.urgency_markers,
                15,
                SignalSeverity.WARNING,
                (
                    "Usa prisa o amenaza de bloqueo para forzar una decisión."
                    if urgency
                    else "No se detectó lenguaje de urgencia."
                ),
                status=SignalStatus.HIT if urgency else SignalStatus.MISS,
                version=version,
            )
        )

        action_weights = {
            RequestedAction.GIVE_CREDENTIALS: 45,
            RequestedAction.TRANSFER: 45,
            RequestedAction.INSTALL_APP: 60,
            RequestedAction.CLICK_LINK: 15,
            RequestedAction.CALL: 10,
        }
        action_weight = action_weights.get(extraction.requested_action, 0)
        action_label = extraction.requested_action.value.replace("_", " ")
        signals.append(
            _signal(
                "requested_action",
                extraction.requested_action.value,
                action_weight,
                SignalSeverity.WARNING,
                (
                    f"Solicita una acción sensible: {action_label}."
                    if action_weight
                    else "No se detectó una acción solicitada."
                ),
                status=SignalStatus.HIT if action_weight else SignalStatus.MISS,
                version=version,
            )
        )
        return signals

    def _local_url_signals(self, url: str, entity) -> list[EvidenceSignal]:
        version = self.settings.signalset_version
        host = _url_host(url)
        domain = registrable_domain(url)
        if not host or not domain:
            return [
                _signal(
                    "url_parse",
                    "invalid",
                    0,
                    SignalSeverity.INFO,
                    "No se pudo interpretar el enlace y no se usó para decidir.",
                    status=SignalStatus.ERROR,
                    version=version,
                )
            ]

        try:
            parsed = urlsplit(url if "://" in url else f"https://{url}")
        except ValueError:
            parsed = urlsplit("https://invalid")
        raw_ip = _is_ip(host)
        signals = [
            _signal(
                "raw_ip_hostname",
                host,
                40,
                SignalSeverity.WARNING,
                (
                    "El enlace usa una dirección IP en vez de un nombre de dominio."
                    if raw_ip
                    else "El enlace usa un nombre de dominio."
                ),
                status=SignalStatus.HIT if raw_ip else SignalStatus.MISS,
                version=version,
            )
        ]

        punycode = "xn--" in host.casefold() or any(ord(char) > 127 for char in host)
        signals.append(
            _signal(
                "punycode_hostname",
                domain,
                25,
                SignalSeverity.WARNING,
                (
                    "El dominio usa caracteres internacionalizados que pueden imitar letras."
                    if punycode
                    else "El dominio no usa caracteres internacionalizados."
                ),
                status=SignalStatus.HIT if punycode else SignalStatus.MISS,
                version=version,
            )
        )

        too_long = len(url) >= 120
        signals.append(
            _signal(
                "excessive_url_length",
                {"length": len(url)},
                10,
                SignalSeverity.WARNING,
                (
                    "El enlace es anormalmente largo y puede ocultar su destino."
                    if too_long
                    else "La longitud del enlace no es anómala."
                ),
                status=SignalStatus.HIT if too_long else SignalStatus.MISS,
                version=version,
            )
        )

        label_count = len(host.split("."))
        many_subdomains = label_count >= 5 and not raw_ip
        signals.append(
            _signal(
                "excessive_subdomains",
                {"labels": label_count, "domain": domain},
                10,
                SignalSeverity.WARNING,
                (
                    "El enlace encadena demasiados subdominios para dificultar su lectura."
                    if many_subdomains
                    else "El número de subdominios no es anómalo."
                ),
                status=SignalStatus.HIT if many_subdomains else SignalStatus.MISS,
                version=version,
            )
        )

        path_depth = len([part for part in parsed.path.split("/") if part])
        deep_path = path_depth >= 5
        signals.append(
            _signal(
                "deep_url_path",
                {"depth": path_depth},
                10,
                SignalSeverity.WARNING,
                (
                    "El enlace tiene una ruta inusualmente profunda."
                    if deep_path
                    else "La profundidad de la ruta no es anómala."
                ),
                status=SignalStatus.HIT if deep_path else SignalStatus.MISS,
                version=version,
            )
        )

        keyword_matches = sorted(
            {
                match.group(0).casefold()
                for match in PHISHING_URL_RE.finditer(parsed.path + parsed.query)
            }
        )
        signals.append(
            _signal(
                "phishing_url_keywords",
                keyword_matches,
                10,
                SignalSeverity.WARNING,
                (
                    "La ruta del enlace contiene palabras usadas para pedir acceso o datos."
                    if keyword_matches
                    else "La ruta no contiene palabras de suplantación conocidas."
                ),
                status=SignalStatus.HIT if keyword_matches else SignalStatus.MISS,
                version=version,
            )
        )

        longest_label = max(host.split("."), key=len)
        entropy = round(_shannon_entropy(longest_label.casefold()), 3)
        high_entropy = len(longest_label) >= 14 and entropy >= 3.7
        signals.append(
            _signal(
                "high_domain_entropy",
                {"domain": domain, "entropy": entropy},
                20,
                SignalSeverity.WARNING,
                (
                    "El dominio contiene una secuencia poco natural de caracteres."
                    if high_entropy
                    else "El dominio no parece generado aleatoriamente."
                ),
                status=SignalStatus.HIT if high_entropy else SignalStatus.MISS,
                version=version,
            )
        )

        risky_tld = domain.split(".")[-1] in RISKY_TLDS
        tld = domain.split(".")[-1]
        signals.append(
            _signal(
                "risky_tld",
                domain,
                35,
                SignalSeverity.WARNING,
                (
                    f"El enlace usa una terminación de dominio de alto riesgo: .{tld}."
                    if risky_tld
                    else "La terminación del dominio no está en la lista de alto riesgo."
                ),
                status=SignalStatus.HIT if risky_tld else SignalStatus.MISS,
                version=version,
            )
        )

        shortened = domain in SHORTENERS
        signals.append(
            _signal(
                "shortened_url",
                domain,
                25,
                SignalSeverity.WARNING,
                (
                    "El enlace está acortado y oculta el destino real."
                    if shortened
                    else "El enlace no usa un acortador conocido."
                ),
                status=SignalStatus.HIT if shortened else SignalStatus.MISS,
                version=version,
            )
        )

        if not entity:
            signals.extend(
                [
                    self._not_applicable("official_domain_match", domain, "entity_registry"),
                    self._not_applicable(
                        "claimed_entity_domain_mismatch", domain, "entity_registry"
                    ),
                    self._not_applicable("combo_squatting", domain, "entity_registry"),
                ]
            )
            return signals

        official = is_official_domain(domain, entity)
        signals.append(
            _signal(
                "official_domain_match",
                domain,
                0,
                SignalSeverity.INFO,
                (
                    f"El dominio coincide con uno publicado para {entity.name}."
                    if official
                    else f"El dominio no figura entre los oficiales de {entity.name}."
                ),
                detail="Esto no demuestra por sí solo que el mensaje sea legítimo.",
                status=SignalStatus.HIT if official else SignalStatus.MISS,
                source="entity_registry",
                version=version,
            )
        )

        maximum_similarity = max(
            domain_similarity(domain, official_domain)
            for official_domain in entity.official_domains
        )
        hard_typo = not official and maximum_similarity >= 0.82
        mismatch = not official
        signals.append(
            _signal(
                "claimed_entity_domain_mismatch",
                {
                    "domain": domain,
                    "entity": entity.name,
                    "similarity": round(maximum_similarity, 3),
                },
                100 if hard_typo else 25,
                SignalSeverity.CRITICAL if hard_typo else SignalSeverity.WARNING,
                (
                    f"El dominio imita al de {entity.name}, pero no es oficial."
                    if hard_typo
                    else (
                        f"El enlace no pertenece a un dominio oficial de {entity.name}."
                        if mismatch
                        else "El dominio no contradice la entidad declarada."
                    )
                ),
                hard_rule=hard_typo,
                status=SignalStatus.HIT if mismatch else SignalStatus.MISS,
                source="entity_registry",
                version=version,
            )
        )

        normalized_domain = normalize_token(domain)
        entity_tokens = {
            normalize_token(alias)
            for alias in (entity.name, *entity.aliases)
            if len(normalize_token(alias)) >= 4
        }
        combo_squatting = bool(
            not official and any(token in normalized_domain for token in entity_tokens)
        )
        signals.append(
            _signal(
                "combo_squatting",
                {"domain": domain, "entity": entity.name},
                35,
                SignalSeverity.WARNING,
                (
                    "El dominio combina el nombre de la entidad con palabras añadidas."
                    if combo_squatting
                    else "No se detectó el nombre de la entidad incrustado en un dominio ajeno."
                ),
                status=SignalStatus.HIT if combo_squatting else SignalStatus.MISS,
                source="entity_registry",
                version=version,
            )
        )
        return signals

    async def _rdap_signal(
        self, domain: str, extraction: MessageExtraction
    ) -> EvidenceSignal:
        started = perf_counter()
        result = await rdap_lookup(domain)
        latency = round((perf_counter() - started) * 1000)
        if not result.created_at:
            return _signal(
                "domain_age",
                {"domain": domain},
                0,
                SignalSeverity.INFO,
                "RDAP respondió, pero no publicó la fecha de registro.",
                latency_ms=latency,
                status=SignalStatus.MISS,
                source="rdap",
                version=self.settings.signalset_version,
            )
        age_days = max(0, (datetime.now(UTC) - result.created_at).days)
        entity = get_entity(extraction.claimed_entity)
        hard_rule = bool(entity and age_days < 14)
        recent = age_days < 30
        return _signal(
            "domain_age",
            {
                "domain": domain,
                "age_days": age_days,
                "created_at": result.created_at.isoformat(),
            },
            100 if hard_rule else 45,
            SignalSeverity.CRITICAL if hard_rule else SignalSeverity.WARNING,
            (
                f"El dominio se registró hace solo {age_days} días."
                if recent
                else f"El dominio tiene {age_days} días de antigüedad."
            ),
            detail=None if recent else "La antigüedad no demuestra que un sitio sea seguro.",
            latency_ms=latency,
            hard_rule=hard_rule,
            status=SignalStatus.HIT if recent else SignalStatus.MISS,
            source="rdap",
            version=self.settings.signalset_version,
        )

    async def _redirect_signal(
        self, url: str, extraction: MessageExtraction
    ) -> EvidenceSignal:
        started = perf_counter()
        result = await follow_redirects(url)
        latency = round((perf_counter() - started) * 1000)
        original_domain = registrable_domain(result.original_url)
        final_domain = registrable_domain(result.final_url)
        cross_domain = bool(result.hops and final_domain and final_domain != original_domain)
        entity = get_entity(extraction.claimed_entity)
        official_final = bool(entity and final_domain and is_official_domain(final_domain, entity))
        risky_redirect = cross_domain and not official_final
        return _signal(
            "redirect_chain",
            {"hops": result.hops, "final_domain": final_domain},
            20,
            SignalSeverity.WARNING,
            (
                f"El enlace redirige a otro dominio: {final_domain}."
                if risky_redirect
                else (
                    f"El enlace termina en un dominio oficial de {entity.name}."
                    if cross_domain and official_final and entity
                    else "El enlace no redirige a un dominio distinto."
                )
            ),
            latency_ms=latency,
            status=SignalStatus.HIT if risky_redirect else SignalStatus.MISS,
            source="http",
            version=self.settings.signalset_version,
        )

    async def _tls_signal(self, domain: str) -> EvidenceSignal:
        started = perf_counter()
        result = await tls_certificate(domain)
        latency = round((perf_counter() - started) * 1000)
        if not result.issued_at:
            return _signal(
                "tls_certificate_age",
                {"domain": domain},
                0,
                SignalSeverity.INFO,
                "El certificado no expuso una fecha de emisión utilizable.",
                latency_ms=latency,
                status=SignalStatus.MISS,
                source="tls",
                version=self.settings.signalset_version,
            )
        age_days = max(0, (datetime.now(UTC) - result.issued_at).days)
        recent = age_days < 7
        return _signal(
            "tls_certificate_age",
            {"domain": domain, "age_days": age_days},
            20,
            SignalSeverity.WARNING,
            (
                f"El certificado web se emitió hace solo {age_days} días."
                if recent
                else "El certificado web no es de emisión reciente."
            ),
            detail=(
                "Un certificado reciente es una pista, no una prueba aislada."
                if recent
                else None
            ),
            latency_ms=latency,
            status=SignalStatus.HIT if recent else SignalStatus.MISS,
            source="tls",
            version=self.settings.signalset_version,
        )
