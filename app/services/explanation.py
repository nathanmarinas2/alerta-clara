from __future__ import annotations

from openai import AsyncOpenAI
from pydantic import BaseModel, Field

from app.config import Settings
from app.schemas import EvidenceSignal, VerdictLevel
from app.services.rules import Decision


class ModelExplanation(BaseModel):
    headline: str = Field(max_length=90)
    summary: str = Field(max_length=180)
    reasons: list[str] = Field(min_length=1, max_length=3)


class ExplanationWriter:
    def __init__(self, settings: Settings):
        self.settings = settings
        api_key = settings.openai_api_key
        self.client = (
            AsyncOpenAI(api_key=api_key.get_secret_value(), timeout=15.0) if api_key else None
        )

    async def refine(
        self, decision: Decision, signals: list[EvidenceSignal]
    ) -> ModelExplanation | None:
        if not self.client:
            return None

        evidence = [
            {
                "hecho": signal.summary,
                "tipo": signal.severity.value,
                "regla_dura": signal.hard_rule,
            }
            for signal in signals
            if signal.weight > 0
        ][:8]
        try:
            response = await self.client.responses.parse(
                model=self.settings.openai_model,
                input=[
                    {
                        "role": "system",
                        "content": (
                            "Redacta para una persona mayor en español claro. El veredicto ya está "
                            "cerrado por reglas: no puedes cambiarlo, suavizarlo ni añadir hechos. "
                            "No uses porcentajes. Frases breves y sin jerga."
                        ),
                    },
                    {
                        "role": "user",
                        "content": (
                            f"Veredicto inmutable: {decision.level.value}. "
                            f"Evidencia verificada: {evidence}. "
                            "Redacta un titular, una frase resumen y hasta tres razones."
                        ),
                    },
                ],
                text_format=ModelExplanation,
            )
            return response.output_parsed
        except Exception:
            return None


def allow_model_copy(level: VerdictLevel, copy: ModelExplanation | None) -> bool:
    if not copy:
        return False
    # El texto generado es una capa de redacción, nunca una fuente de veredicto.
    # Revisamos también las razones: limitar la comprobación a titular y resumen
    # permitía que una afirmación tranquilizadora se colara en una viñeta.
    combined = " ".join([copy.headline, copy.summary, *copy.reasons]).casefold()
    if level == VerdictLevel.UNCERTAIN:
        forbidden = (
            "seguro",
            "legítimo",
            "legitimo",
            "fiable",
            "sin riesgo",
            "puedes confiar",
        )
        return not any(phrase in combined for phrase in forbidden)
    if level == VerdictLevel.SCAM:
        denial_phrases = (
            "no es una estafa",
            "no parece una estafa",
            "es legítimo",
            "es legitimo",
            "puedes confiar",
        )
        return not any(phrase in combined for phrase in denial_phrases)
    return True
