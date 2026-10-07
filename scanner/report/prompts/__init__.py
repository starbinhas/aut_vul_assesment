"""Prompts versionados. Mudou o texto? Crie um novo arquivo `_vN` e atualize PROMPT_VERSION."""

from importlib.resources import files

PROMPT_VERSION = "remediation_v1"


def load(name: str) -> str:
    return (files(__package__) / name).read_text(encoding="utf-8")
