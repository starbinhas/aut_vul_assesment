"""Geração de remediação com a Claude API (SDK oficial `anthropic`).

- Saída estruturada com `messages.parse()` + Pydantic (nada de parsing de texto livre).
- Thinking adaptativo e `effort` explícito.
- System prompt fixo com cache_control (prompt caching).
- O LLM só explica e corrige; nunca decide status de achado.
"""

from __future__ import annotations

import logging
from dataclasses import dataclass
from typing import Literal

import anthropic
from jinja2 import Environment, StrictUndefined

from scanner.common.masking import mask_text
from scanner.common.models import Finding
from scanner.common.owasp import CATEGORIES, OWASP_VERSION
from scanner.report import prompts
from scanner.report.models import Remediation

log = logging.getLogger(__name__)

MAX_TOKENS = 16000
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
