"""Remediação por achado: cache → LLM → catálogo estático (nunca fica sem texto)."""

from __future__ import annotations

import hashlib

from sqlalchemy.dialects.postgresql import insert
from sqlalchemy.orm import Session

from scanner.common.db import RemediationCache
from scanner.common.models import Finding
from scanner.report.catalog import static_remediation
from scanner.report.llm import RemediationRequest, RemediationWriter
from scanner.report.models import Remediation, RemediationSource
from scanner.report.prompts import PROMPT_VERSION


def rule_key(f: Finding) -> str:
    """O texto depende do tipo de falha: CWE quando houver, senão a regra da ferramenta."""
    return f"cwe:{f.cwe}" if f.cwe else f"{f.source.tool}:{f.source.rule_id}"


def cache_key(rule: str, stack: str, language: str) -> str:
    return hashlib.sha256(f"{PROMPT_VERSION}|{rule}|{stack}|{language}".encode()).hexdigest()


def get_remediation(
    session: Session,
    writer: RemediationWriter | None,
    f: Finding,
    stack: str,
    language: str,
) -> tuple[Remediation, RemediationSource]:
    rule = rule_key(f)
    key = cache_key(rule, stack, language)
    cached = session.get(RemediationCache, key)
    if cached is not None:
        return Remediation.model_validate(cached.content), "cache"

    if writer is not None:
        generated = writer.write(RemediationRequest(f, stack, language))
        if generated is not None:
            session.execute(
                insert(RemediationCache)
                .values(
                    cache_key=key,
                    rule=rule,
                    stack=stack,
                    language=language,
                    prompt_version=PROMPT_VERSION,
                    content=generated.model_dump(mode="json"),
                )
                .on_conflict_do_nothing()
            )
            return generated, "llm"

    # Recusa/erro não entra no cache: na próxima vez tentamos o LLM de novo.
    return static_remediation(f), "catalog"
