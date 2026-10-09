"""Geração de remediação por LLM.

Dois provedores atrás de uma interface comum (`Writer`):
- `RemediationWriter` — Claude API (SDK `anthropic`): saída estruturada com `messages.parse()` +
  Pydantic, thinking adaptativo, `effort` explícito, system prompt com cache_control.
- `OpenAICompatibleWriter` — provedor compatível com OpenAI (Groq/Gemini/Ollama). **É o que roda no
  MVP** por falta de chave Anthropic; mantém as mesmas garantias (mascara antes de enviar, saída
  validada por Pydantic, fallback para o catálogo).

Em qualquer provedor: o LLM só explica e corrige; nunca decide o status de um achado. Enquanto o MVP
usar um provedor que não é Claude, material voltado ao cliente não pode dizer "Claude".
"""

from __future__ import annotations

import json
import logging
from dataclasses import dataclass
from typing import Literal, Protocol

import anthropic
from jinja2 import Environment, StrictUndefined
from openai import OpenAI, OpenAIError
from pydantic import ValidationError

from scanner.common.masking import mask_text
from scanner.common.models import Finding
from scanner.common.owasp import CATEGORIES, OWASP_VERSION
from scanner.report import prompts
from scanner.report.models import Remediation

log = logging.getLogger(__name__)

MAX_TOKENS = 16000
COMPAT_MAX_TOKENS = 4000  # a remediação é curta; modelos gratuitos limitam a saída
DESCRIPTION_LIMIT = 1500

_SYSTEM = prompts.load(f"{prompts.PROMPT_VERSION}.system.md")
_USER = Environment(undefined=StrictUndefined, autoescape=False).from_string(  # noqa: S701 — texto puro para o LLM, não HTML
    prompts.load(f"{prompts.PROMPT_VERSION}.user.md")
)


@dataclass(frozen=True)
class RemediationRequest:
    finding: Finding
    stack: str
    language: str


def build_user_prompt(req: RemediationRequest) -> str:
    """Só dados da família da falha + stack; nada do cliente (URLs, evidências, cookies)."""
    f = req.finding
    description = mask_text((f.description or "")[:DESCRIPTION_LIMIT])
    return _USER.render(
        title=f.title,
        tool=f.source.tool,
        rule_id=f.source.rule_id,
        rule_name=f.source.rule_name,
        cwe=f.cwe,
        owasp=f.owasp,
        owasp_name=CATEGORIES.get(f.owasp or ""),
        owasp_version=OWASP_VERSION,
        stack=req.stack,
        language=req.language,
        description=description,
    )


class RemediationWriter:
    def __init__(
        self,
        client: anthropic.Anthropic,
        model: str,
        effort: Literal["low", "medium", "high", "xhigh", "max"],
    ) -> None:
        self.client = client
        self.model = model
        self.effort = effort

    def write(self, req: RemediationRequest) -> Remediation | None:
        """Retorna None em recusa, truncamento ou erro — o chamador usa o catálogo estático."""
        try:
            response = self.client.messages.parse(
                model=self.model,
                max_tokens=MAX_TOKENS,
                system=[{"type": "text", "text": _SYSTEM, "cache_control": {"type": "ephemeral"}}],
                thinking={"type": "adaptive"},
                output_config={"effort": self.effort},
                messages=[{"role": "user", "content": build_user_prompt(req)}],
                output_format=Remediation,
            )
        except anthropic.RateLimitError:
            log.warning("LLM com rate limit; usando catálogo")
            return None
        except anthropic.APIStatusError as exc:
            log.error("erro da Claude API; usando catálogo", extra={"status": exc.status_code})
            return None
        except anthropic.APIConnectionError:
            log.error("sem conexão com a Claude API; usando catálogo")
            return None

        if response.stop_reason == "refusal":
            category = getattr(response.stop_details, "category", None)
            log.warning("LLM recusou; usando catálogo", extra={"refusal_category": category})
            return None
        if response.stop_reason == "max_tokens":
            log.warning("resposta do LLM truncada; usando catálogo")
            return None
        parsed = response.parsed_output
        if parsed is None or not parsed.how_to_fix:
            log.warning("resposta do LLM sem passos de correção; usando catálogo")
            return None
        log.info(
            "remediação gerada",
            extra={
                "rule": req.finding.source.rule_id,
                "cache_read_tokens": response.usage.cache_read_input_tokens,
                "output_tokens": response.usage.output_tokens,
            },
        )
        return parsed


class Writer(Protocol):
    """Interface comum: o chamador (get_remediation) não sabe qual LLM está por trás."""

    def write(self, req: RemediationRequest) -> Remediation | None: ...


_JSON_INSTRUCTION = (
    "Responda SOMENTE com um objeto JSON válido (sem texto fora do JSON, sem ```), "
    "obedecendo exatamente a este JSON Schema:\n{schema}"
)


class OpenAICompatibleWriter:
    """Remediação via API no protocolo OpenAI (Groq, Gemini, Ollama...). MVP gratuito sem Claude.

    Mantém as regras do produto: os dados são mascarados antes de sair (`build_user_prompt` só
    envia a família da falha + stack, nunca URL/evidência/cookie do cliente), a saída é JSON
    validado por Pydantic (não é parsing de texto livre) e qualquer erro/vazio devolve None para o
    chamador cair no catálogo estático — nunca deixa o achado sem texto.
    """

    def __init__(self, client: OpenAI, model: str) -> None:
        self.client = client
        self.model = model

    def write(self, req: RemediationRequest) -> Remediation | None:
        schema = json.dumps(Remediation.model_json_schema(), ensure_ascii=False)
        system = f"{_SYSTEM}\n\n{_JSON_INSTRUCTION.format(schema=schema)}"
        try:
            response = self.client.chat.completions.create(
                model=self.model,
                messages=[
                    {"role": "system", "content": system},
                    {"role": "user", "content": build_user_prompt(req)},
                ],
                response_format={"type": "json_object"},
                temperature=0.2,
                max_tokens=COMPAT_MAX_TOKENS,
            )
        except OpenAIError as exc:
            log.error(
                "erro do LLM compatível; usando catálogo", extra={"error": type(exc).__name__}
            )
            return None

        content = response.choices[0].message.content if response.choices else None
        if not content:
            log.warning("LLM compatível sem conteúdo; usando catálogo")
            return None
        try:
            parsed = Remediation.model_validate_json(content)
        except ValidationError:
            log.warning("JSON do LLM compatível inválido; usando catálogo")
            return None
        if not parsed.how_to_fix:
            log.warning("LLM compatível sem passos de correção; usando catálogo")
            return None
        log.info("remediação gerada (compatível)", extra={"rule": req.finding.source.rule_id})
        return parsed
