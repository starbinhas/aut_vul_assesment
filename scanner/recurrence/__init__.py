"""Etapa 7 — Recorrência: repete o scan dos sites conforme a preferência do cliente.

Não é consumidor de fila: é um agendador que, de tempos em tempos, verifica quais alvos estão
"vencidos" (semanal/mensal) e dispara um novo scan pelo começo do pipeline (scan.recon.requested).
"""
