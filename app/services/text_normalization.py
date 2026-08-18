from __future__ import annotations

import re
import unicodedata

ZERO_WIDTH_RE = re.compile(
    r"[\u00ad\u034f\u061c\u115f\u1160\u17b4\u17b5\u180b-\u180f"
    r"\u200b-\u200f\u202a-\u202e\u2060-\u2064\u2066-\u206f\u3164\ufeff]"
)
SPACED_LETTERS_RE = re.compile(r"(?<!\w)(?:[a-záéíóúüñ]\s+){2,}[a-záéíóúüñ](?!\w)", re.I)
ALNUM_TOKEN_RE = re.compile(r"(?<!\w)[a-záéíóúüñ0-9_-]+(?!\w)", re.I)

CONFUSABLES = str.maketrans(
    {
        "а": "a",
        "е": "e",
        "о": "o",
        "р": "p",
        "с": "c",
        "у": "y",
        "х": "x",
        "і": "i",
        "ј": "j",
        "ԁ": "d",
        "ԛ": "q",
        "ӏ": "l",
    }
)
LEET = str.maketrans({"0": "o", "1": "i", "3": "e", "4": "a", "5": "s", "7": "t"})


def normalize_for_detection(text: str) -> str:
    """Devuelve una vista tolerante a evasiones sin alterar el texto persistido."""

    value = unicodedata.normalize("NFKC", text).translate(CONFUSABLES)
    value = ZERO_WIDTH_RE.sub("", value)
    value = "".join(
        char for char in unicodedata.normalize("NFD", value)
        if unicodedata.category(char) != "Mn"
    )
    value = SPACED_LETTERS_RE.sub(lambda match: re.sub(r"\s+", "", match.group(0)), value)

    def replace_leet(match: re.Match[str]) -> str:
        token = match.group(0)
        return token.translate(LEET) if any(char.isalpha() for char in token) else token

    value = ALNUM_TOKEN_RE.sub(replace_leet, value)
    value = re.sub(r"\b(any|team|rust)\s+(desk|viewer)\b", r"\1\2", value, flags=re.I)
    return re.sub(r"\s+", " ", value).strip().casefold()


def adversarial_obfuscations(text: str) -> list[str]:
    """Enumera transformaciones sospechosas aplicadas a la vista de detección."""

    findings: list[str] = []
    if ZERO_WIDTH_RE.search(text):
        findings.append("caracteres invisibles")
    if SPACED_LETTERS_RE.search(text):
        findings.append("palabras separadas letra a letra")
    if re.search(r"(?i)\b(?:c[o0]d[i1]g[o0]|any\s+desk|team\s+viewer|rust\s+desk)\b", text):
        findings.append("sustitución de caracteres o nombre dividido")
    if re.search(r"(?i)\b[a-záéíóúüñ]+[013457][a-záéíóúüñ]+\b", text):
        findings.append("leet")
    return findings
