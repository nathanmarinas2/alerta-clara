from __future__ import annotations

import ipaddress
import json
import re
import unicodedata
from contextlib import suppress
from dataclasses import dataclass
from functools import lru_cache
from pathlib import Path
from urllib.parse import urlsplit

try:
    import tldextract
except ImportError:  # pragma: no cover - optional dependency fallback for tiny installs
    tldextract = None

DATA_PATH = Path(__file__).parent / "data" / "entities.json"

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


@dataclass(frozen=True)
class OfficialPhoneNumber:
    number: str
    source: str
    verified_at: str
    purpose: str = ""


@dataclass(frozen=True)
class KnownEntity:
    name: str
    category: str
    aliases: tuple[str, ...]
    official_domains: tuple[str, ...]
    official_numbers: tuple[OfficialPhoneNumber, ...]


def normalize_token(value: str) -> str:
    value = unicodedata.normalize("NFKC", value).casefold().translate(CONFUSABLES)
    value = "".join(
        char for char in unicodedata.normalize("NFD", value) if unicodedata.category(char) != "Mn"
    )
    return re.sub(r"[^a-z0-9]", "", value)


@lru_cache
def load_entities() -> tuple[KnownEntity, ...]:
    raw_entities = json.loads(DATA_PATH.read_text(encoding="utf-8"))
    entities: list[KnownEntity] = []
    for item in raw_entities:
        phones: list[OfficialPhoneNumber] = []
        for entry in item.get("official_numbers", []):
            if isinstance(entry, dict):
                phones.append(
                    OfficialPhoneNumber(
                        number=str(entry["number"]),
                        source=str(entry.get("source", "")),
                        verified_at=str(entry.get("verified_at", "")),
                        purpose=str(entry.get("purpose", "")),
                    )
                )
        entities.append(
            KnownEntity(
                name=item["name"],
                category=item["category"],
                aliases=tuple(item["aliases"]),
                official_domains=tuple(item["official_domains"]),
                official_numbers=tuple(phones),
            )
        )
    return tuple(entities)


def find_claimed_entity(text: str) -> KnownEntity | None:
    normalized_words = unicodedata.normalize("NFKC", text).casefold().translate(CONFUSABLES)
    normalized_words = "".join(
        char for char in unicodedata.normalize("NFD", normalized_words)
        if unicodedata.category(char) != "Mn"
    )
    best_match: tuple[int, KnownEntity] | None = None
    for entity in load_entities():
        for alias in entity.aliases:
            normalized_alias = (
                unicodedata.normalize("NFKC", alias).casefold().translate(CONFUSABLES)
            )
            normalized_alias = "".join(
                char for char in unicodedata.normalize("NFD", normalized_alias)
                if unicodedata.category(char) != "Mn"
            )
            if re.search(rf"(?<!\w){re.escape(normalized_alias)}(?!\w)", normalized_words):
                alias_len = len(normalized_alias)
                if best_match is None or alias_len > best_match[0]:
                    best_match = (alias_len, entity)
    return best_match[1] if best_match else None


def get_entity(name: str | None) -> KnownEntity | None:
    if not name:
        return None
    normalized = normalize_token(name)
    for entity in load_entities():
        known_names = {normalize_token(entity.name), *(normalize_token(a) for a in entity.aliases)}
        if normalized in known_names:
            return entity
    return None


def registrable_domain(url: str) -> str | None:
    candidate = url if "://" in url else f"https://{url}"
    try:
        host = (urlsplit(candidate).hostname or "").rstrip(".").casefold()
        host = host.encode("idna").decode("ascii")
        if not host:
            return None
        try:
            ipaddress.ip_address(host)
            return host
        except ValueError:
            pass
        if tldextract is not None:
            extracted = tldextract.TLDExtract(
                suffix_list_urls=(),
                include_psl_private_domains=True,
            )(host)
            return extracted.top_domain_under_public_suffix or host

        # Fallback offline para entornos mínimos. El paquete tldextract se declara
        # como dependencia de producción y cubre la Public Suffix List completa.
        two_label_suffixes = {
            "co.uk",
            "org.uk",
            "ac.uk",
            "com.au",
            "net.au",
            "org.au",
            "co.jp",
            "co.nz",
            "com.br",
            "com.mx",
            "com.tr",
        }
        labels = host.split(".")
        suffix_size = 2 if ".".join(labels[-2:]) in two_label_suffixes else 1
        if len(labels) <= suffix_size:
            return host
        return ".".join(labels[-(suffix_size + 1) :])
    except (UnicodeError, ValueError):
        return None


def is_official_domain(domain: str, entity: KnownEntity) -> bool:
    domain = domain.rstrip(".").casefold()
    return any(
        domain == official or domain.endswith(f".{official}")
        for official in entity.official_domains
    )


def levenshtein(left: str, right: str) -> int:
    if len(left) < len(right):
        return levenshtein(right, left)
    if not right:
        return len(left)
    previous = list(range(len(right) + 1))
    for index_left, char_left in enumerate(left, start=1):
        current = [index_left]
        for index_right, char_right in enumerate(right, start=1):
            current.append(
                min(
                    current[-1] + 1,
                    previous[index_right] + 1,
                    previous[index_right - 1] + (char_left != char_right),
                )
            )
        previous = current
    return previous[-1]


def domain_similarity(domain: str, official_domain: str) -> float:
    candidate_label = domain.split(".")[0]
    official_label = official_domain.split(".")[0]
    with suppress(UnicodeError, ValueError):
        candidate_label = candidate_label.encode("ascii").decode("idna")
    candidate = normalize_token(candidate_label)
    official = normalize_token(official_label)
    maximum = max(len(candidate), len(official), 1)
    return 1 - (levenshtein(candidate, official) / maximum)
