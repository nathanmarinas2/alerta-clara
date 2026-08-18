from __future__ import annotations

import hashlib
import re
import unicodedata


def normalize_campaign_text(text: str) -> str:
    normalized = unicodedata.normalize("NFKD", text).casefold()
    normalized = "".join(char for char in normalized if not unicodedata.combining(char))
    normalized = re.sub(r"https?://\S+|www\.\S+", " URL ", normalized)
    normalized = re.sub(r"\d+", " N ", normalized)
    return re.sub(r"\s+", " ", normalized).strip()


def simhash(text: str) -> int:
    tokens = re.findall(r"[a-z]{2,}|URL|N", normalize_campaign_text(text))
    if not tokens:
        return 0
    vector = [0] * 64
    for token in tokens:
        value = int.from_bytes(hashlib.blake2b(token.encode(), digest_size=8).digest(), "big")
        for bit in range(64):
            vector[bit] += 1 if value & (1 << bit) else -1
    result = 0
    for bit, score in enumerate(vector):
        if score >= 0:
            result |= 1 << bit
    return result


def similarity(left: int, right: int) -> float:
    return 1 - ((left ^ right).bit_count() / 64)


def simhash_bands(value: int) -> tuple[int, int, int, int]:
    """Divide el fingerprint en cuatro bandas indexables de 16 bits."""
    return (
        value & 0xFFFF,
        (value >> 16) & 0xFFFF,
        (value >> 32) & 0xFFFF,
        (value >> 48) & 0xFFFF,
    )
