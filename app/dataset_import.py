from __future__ import annotations

import argparse
import csv
import hashlib
from dataclasses import dataclass
from datetime import date, datetime
from pathlib import Path
from urllib.parse import urlsplit

from app.evaluation import CaseLabel, EvaluationCase, EvaluationSplit
from app.schemas import VerdictLevel
from app.services.redaction import URL_RE, redact


@dataclass(frozen=True)
class ImportProfile:
    text: tuple[str, ...]
    label: tuple[str, ...]
    campaign: tuple[str, ...]
    timestamp: tuple[str, ...]
    language: tuple[str, ...]
    scam_type: tuple[str, ...]
    lure: tuple[str, ...]
    phishing_only: bool = False


PROFILES = {
    "ncsu": ImportProfile(
        text=("message", "sms", "text", "body"),
        label=(),
        campaign=("campaign", "campaign_id", "cluster"),
        timestamp=("timestamp", "first_seen", "date"),
        language=("language", "lang"),
        scam_type=("scam_type", "category"),
        lure=("lure", "lure_type"),
        phishing_only=True,
    ),
    "imc25": ImportProfile(
        text=("message", "sms", "text", "content"),
        label=("label", "class", "is_smishing"),
        campaign=("campaign", "campaign_id", "cluster"),
        timestamp=("timestamp", "created_at", "date", "time"),
        language=("language", "lang"),
        scam_type=("scam", "scam_type", "category"),
        lure=("lure", "lure_type", "lure_principle"),
        phishing_only=True,
    ),
    "generic": ImportProfile(
        text=("message", "sms", "text", "body", "content"),
        label=("label", "class", "category"),
        campaign=("campaign", "campaign_id", "cluster"),
        timestamp=("timestamp", "observed_at", "date", "first_seen"),
        language=("language", "lang"),
        scam_type=("scam_type", "type"),
        lure=("lure", "lure_type"),
    ),
}


def _pick(row: dict[str, str], aliases: tuple[str, ...]) -> str | None:
    lowered = {key.casefold(): value for key, value in row.items()}
    return next((lowered[name].strip() for name in aliases if lowered.get(name)), None)


def _parse_date(value: str | None) -> date | None:
    if not value:
        return None
    if value.isdigit():
        try:
            return datetime.fromtimestamp(int(value)).date()
        except (OverflowError, OSError, ValueError):
            return None
    try:
        return datetime.fromisoformat(value.replace("Z", "+00:00")).date()
    except ValueError:
        try:
            return date.fromisoformat(value[:10])
        except ValueError:
            return None


def _label(value: str | None, phishing_only: bool) -> CaseLabel:
    if phishing_only:
        return CaseLabel.SCAM
    normalized = (value or "unknown").casefold()
    if normalized in {"1", "true", "phishing", "smishing", "scam", "fraud"}:
        return CaseLabel.SCAM
    if normalized in {"0", "false", "legitimate", "ham", "legit"}:
        return CaseLabel.LEGITIMATE
    if normalized == "spam":
        return CaseLabel.SPAM
    return CaseLabel.UNKNOWN


def _campaign_fallback(message: str) -> str:
    urls = [match.group(0) for match in URL_RE.finditer(message)]
    domains = []
    for url in urls:
        try:
            domains.append((urlsplit(url).hostname or "").casefold())
        except ValueError:
            continue
    basis = "|".join(sorted(set(domains))) or "".join(message.casefold().split())[:160]
    return "derived-" + hashlib.sha256(basis.encode()).hexdigest()[:16]


def import_csv(
    input_path: Path,
    *,
    profile_name: str,
    source: str,
    validation_after: date | None = None,
) -> list[EvaluationCase]:
    profile = PROFILES[profile_name]
    cases: list[EvaluationCase] = []
    with input_path.open("r", encoding="utf-8-sig", errors="replace", newline="") as handle:
        for row_number, row in enumerate(csv.DictReader(handle), start=2):
            raw_message = _pick(row, profile.text)
            if not raw_message:
                continue
            message = redact(raw_message).strip()[:20_000]
            if not message:
                continue
            label = _label(_pick(row, profile.label), profile.phishing_only)
            observed_at = _parse_date(_pick(row, profile.timestamp))
            campaign = _pick(row, profile.campaign) or _campaign_fallback(message)
            if validation_after and observed_at:
                split = (
                    EvaluationSplit.VALIDATION
                    if observed_at >= validation_after
                    else EvaluationSplit.TUNING
                )
            else:
                bucket = int(hashlib.sha256(campaign.encode()).hexdigest()[:8], 16) % 5
                split = EvaluationSplit.VALIDATION if bucket == 0 else EvaluationSplit.TUNING
            digest = hashlib.sha256(
                f"{source}|{row_number}|{message}".encode()
            ).hexdigest()[:16]
            cases.append(
                EvaluationCase(
                    id=f"{source}-{digest}",
                    label=label,
                    message=message,
                    expected_level=(
                        VerdictLevel.SCAM
                        if label == CaseLabel.SCAM
                        else VerdictLevel.UNCERTAIN
                    ),
                    language=_pick(row, profile.language) or "und",
                    scam_type=_pick(row, profile.scam_type),
                    lure=_pick(row, profile.lure),
                    campaign_id=campaign,
                    observed_at=observed_at,
                    source=source,
                    split=split,
                )
            )
    if validation_after:
        splits_by_campaign: dict[str, set[EvaluationSplit]] = {}
        for case in cases:
            if case.campaign_id:
                splits_by_campaign.setdefault(case.campaign_id, set()).add(case.split)
        crossing_campaigns = {
            campaign for campaign, splits in splits_by_campaign.items() if len(splits) > 1
        }
        cases = [case for case in cases if case.campaign_id not in crossing_campaigns]
    return cases


def main() -> None:
    parser = argparse.ArgumentParser(
        description="Convierte datasets CSV públicos al formato anonimizado del golden set."
    )
    parser.add_argument("input", type=Path)
    parser.add_argument("output", type=Path)
    parser.add_argument("--profile", choices=sorted(PROFILES), default="generic")
    parser.add_argument("--source", required=True)
    parser.add_argument("--validation-after", type=date.fromisoformat)
    args = parser.parse_args()
    cases = import_csv(
        args.input,
        profile_name=args.profile,
        source=args.source,
        validation_after=args.validation_after,
    )
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(
        "\n".join(case.model_dump_json(exclude_none=True) for case in cases) + "\n",
        encoding="utf-8",
    )
    print(f"Importados {len(cases)} casos anonimizados en {args.output}")


if __name__ == "__main__":
    main()
