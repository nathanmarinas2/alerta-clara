from __future__ import annotations

import re
from urllib.parse import parse_qsl, urlencode, urlsplit, urlunsplit

IBAN_LENGTHS = {
    "AD": 24,
    "AE": 23,
    "AL": 28,
    "AT": 20,
    "BA": 20,
    "BE": 16,
    "BG": 22,
    "CH": 21,
    "CY": 28,
    "CZ": 24,
    "DE": 22,
    "DK": 18,
    "EE": 20,
    "ES": 24,
    "FI": 18,
    "FR": 27,
    "GB": 22,
    "GR": 27,
    "HR": 21,
    "HU": 28,
    "IE": 22,
    "IS": 26,
    "IT": 27,
    "LI": 21,
    "LT": 20,
    "LU": 20,
    "LV": 21,
    "MC": 27,
    "ME": 22,
    "MK": 19,
    "MT": 31,
    "NL": 18,
    "NO": 15,
    "PL": 28,
    "PT": 25,
    "RO": 24,
    "RS": 22,
    "SE": 24,
    "SI": 19,
    "SK": 24,
    "SM": 27,
    "TR": 26,
    "UA": 29,
    "XK": 20,
}
IBAN_RE = re.compile(
    r"\b(?:"
    + "|".join(
        rf"{country}\s?\d{{2}}(?:[\s-]?[A-Z0-9]){{{length - 4}}}"
        for country, length in IBAN_LENGTHS.items()
    )
    + r")\b",
    re.IGNORECASE,
)
DNI_RE = re.compile(r"\b(?:\d{8}[A-Z]|[XYZ]\d{7}[A-Z])\b", re.IGNORECASE)
CARD_RE = re.compile(r"(?<!\d)(?:\d[ -]?){13,19}(?!\d)")
EMAIL_RE = re.compile(r"\b[A-Z0-9._%+-]+@[A-Z0-9.-]+\.[A-Z]{2,}\b", re.IGNORECASE)
PHONE_RE = re.compile(r"(?<!\w)(?:\+?34[\s.-]?)?[6789](?:[\s.-]?\d){8}(?!\w)")
AMOUNT_RE = re.compile(r"(?<!\w)\d{1,6}(?:[.,]\d{1,2})?\s?(?:€|EUR)\b", re.IGNORECASE)
OTP_RE = re.compile(
    r"\b(?:c[oó]digo|clave|otp|pin)\s*(?:de un solo uso|sms|de acceso)?\s*"
    r"(?:es)?\s*[:#-]?\s*\d{4,8}\b",
    re.IGNORECASE,
)
URL_RE = re.compile(r"\b(?:https?://|www\.)[^\s<>\]\[\"']+", re.IGNORECASE)

SENSITIVE_QUERY_KEYS = {
    "token",
    "code",
    "codigo",
    "email",
    "phone",
    "telefono",
    "dni",
    "iban",
    "account",
    "session",
    "password",
    "passwd",
    "key",
    "auth",
    "otp",
}


def _is_valid_iban(value: str) -> bool:
    compact = re.sub(r"[\s-]", "", value).upper()
    if not 15 <= len(compact) <= 34 or not re.fullmatch(r"[A-Z]{2}\d{2}[A-Z0-9]+", compact):
        return False
    rearranged = compact[4:] + compact[:4]
    numeric = "".join(
        char if char.isdigit() else str(ord(char) - ord("A") + 10)
        for char in rearranged
    )
    return int(numeric) % 97 == 1


def _redact_iban(match: re.Match[str]) -> str:
    return "[IBAN]" if _is_valid_iban(match.group(0)) else match.group(0)


def _is_valid_card(value: str) -> bool:
    digits = re.sub(r"[ -]", "", value)
    if not 13 <= len(digits) <= 19 or not digits.isdigit():
        return False
    checksum = 0
    parity = len(digits) % 2
    for index, digit in enumerate(digits):
        number = int(digit)
        if index % 2 == parity:
            number *= 2
            if number > 9:
                number -= 9
        checksum += number
    return checksum % 10 == 0


def _redact_card(match: re.Match[str]) -> str:
    return "[TARJETA]" if _is_valid_card(match.group(0)) else match.group(0)


def _redact_url(match: re.Match[str]) -> str:
    original = match.group(0)
    candidate = original if "://" in original else f"https://{original}"
    try:
        parsed = urlsplit(candidate)
        query = [
            (key, "[DATO]") if key.casefold() in SENSITIVE_QUERY_KEYS else (key, value)
            for key, value in parse_qsl(parsed.query, keep_blank_values=True)
        ]
        cleaned = urlunsplit((parsed.scheme, parsed.netloc, parsed.path, urlencode(query), ""))
        return cleaned if "://" in original else cleaned.removeprefix("https://")
    except ValueError:
        return "[ENLACE]"


def redact(text: str) -> str:
    """Redacta identificadores antes de persistir o llamar a un proveedor externo."""
    text = URL_RE.sub(_redact_url, text)
    text = IBAN_RE.sub(_redact_iban, text)
    replacements = (
        (OTP_RE, "[CÓDIGO]"),
        (DNI_RE, "[DNI]"),
        (CARD_RE, _redact_card),
        (EMAIL_RE, "[EMAIL]"),
        (PHONE_RE, "[TELÉFONO]"),
        (AMOUNT_RE, "[IMPORTE]"),
    )
    for pattern, replacement in replacements:
        text = pattern.sub(replacement, text)
    return text


def model_text(text: str) -> str:
    """Normaliza texto antes de pasarlo al modelo y evita guardar URLs activas.

    Las reglas de URL siguen analizando el enlace original por separado. El modelo
    aprende patrones lingüísticos y la presencia de un enlace, no dominios concretos.
    """

    return URL_RE.sub("[ENLACE]", redact(text))


def redact_value(value):
    """Redacta recursivamente valores de evidencia antes de persistirlos."""
    if isinstance(value, str):
        return redact(value)
    if isinstance(value, dict):
        return {str(key): redact_value(item) for key, item in value.items()}
    if isinstance(value, list):
        return [redact_value(item) for item in value]
    return value


def find_sensitive_types(text: str) -> list[str]:
    found: list[str] = []
    if any(_is_valid_iban(match.group(0)) for match in IBAN_RE.finditer(text)):
        found.append("iban")
    for name, pattern in (
        ("dni", DNI_RE),
        ("tarjeta", CARD_RE),
        ("email", EMAIL_RE),
        ("telefono", PHONE_RE),
    ):
        if name == "tarjeta":
            if any(_is_valid_card(match.group(0)) for match in pattern.finditer(text)):
                found.append(name)
            continue
        if pattern.search(text):
            found.append(name)
    return found


def extract_valid_ibans(text: str) -> list[str]:
    """Devuelve IBAN normalizados para convertirlos inmediatamente en HMAC."""
    return list(
        dict.fromkeys(
            re.sub(r"[\s-]", "", match.group(0)).upper()
            for match in IBAN_RE.finditer(text)
            if _is_valid_iban(match.group(0))
        )
    )
