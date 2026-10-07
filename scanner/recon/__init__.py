"""Etapa 2 (Reconhecimento): descobre portas/hosts abertos com o naabu.

Só varre hosts dentro do escopo autorizado (regra 1 e 2 do CLAUDE.md); nunca toca alvo fora
da allowlist. O núcleo testável (parsing da saída e montagem do comando) é puro, em `naabu.py`.
"""
