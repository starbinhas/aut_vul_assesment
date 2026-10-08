---
name: pitchy-ui
description: Método para mexer na interface web do scanner (scanner/web/ — templates Jinja, app.css, HTMX) — ciclo de captura de tela, roteiro de crítica e checklist da marca Pitchy. Use ao criar ou revisar qualquer tela, componente ou estilo da interface, ou quando pedirem para "melhorar o visual", "revisar o front", "polir" uma tela.
---

# Interface do scanner: como trabalhar

As regras de marca estão em CLAUDE.md ("Identidade visual e não parecer IA") e os tokens em
`scanner/web/static/css/app.css`. Esta skill é o **método**: você não vê o que renderiza, então
toda mudança visual passa pelo ciclo abaixo.

## 1. Antes de codar: brief de uma tela

Escreva (para você mesmo, curto) antes de tocar no template:

- **Quem chega e de onde** (ex.: dev de agência, vindo do e-mail "3 falhas novas").
- **O que precisa fazer em 10 s** (ex.: saber o que corrigir primeiro e copiar a correção).
- **Ordem do que importa**: o que mudou → o que corrigir agora → histórico.
- **Referência de estrutura** (não de tipografia: Linear e Vercel usam Inter, proibida aqui):
  - lista e triagem densas → issues do Linear;
  - progresso e logs → tela de deploy da Vercel;
  - passo a passo com código copiável → documentação da Stripe;
  - o que **não** copiar → painel de KPIs (Snyk etc.). O topo é o próximo passo, não números.

## 2. Ciclo de captura

```bash
UI_SHOTS_EMAIL=... UI_SHOTS_PASSWORD=... uv run python -m tests.ui_shots [--only painel,scan] [--viewport mobile]
```

- Grava `out/ui-shots/<tela>.<desktop|mobile>.png` e `report.json`. Leia os PNGs com a ferramenta
  Read: é assim que você vê a tela.
- O relatório aponta, de forma automática: erro de console (inclui violação de CSP), requisição
  que falhou, HTTP ≥ 400 e **rolagem horizontal no celular**. Tudo isso é bloqueante.
- Credenciais: peça ao usuário. Nunca leia usuários do banco nem grave senha em arquivo.
- Capture **antes** (linha de base) e **depois** de cada mudança, nos dois tamanhos, e compare.
  Pare quando não houver regressão e a crítica abaixo não tiver nada de prioridade alta.
- O container `web` roda a imagem (o código não é montado como volume): depois de editar template
  ou CSS, `docker compose up -d --build web` antes de capturar.

## 3. Roteiro de crítica (olhando a captura)

Responda cada item com o que você vê na imagem, citando a tela. Classifique em alta, média ou
baixa.

1. **Hierarquia em 3 s**: fechando os olhos e abrindo, o que se lê primeiro? É o próximo passo?
   Há mais de um elemento competindo pelo topo?
2. **Escala tipográfica**: poucos tamanhos com saltos claros, ou vários tamanhos parecidos?
   Peso e cor (`--ink`, `--ink-soft`, `--ink-faint`) fazem a hierarquia antes do tamanho?
3. **Ritmo**: espaçamentos só da escala `--s-1…--s-8`? Grupos relacionados mais próximos entre si
   do que dos vizinhos? Alinhamentos à mesma borda?
4. **Cor com função**: cada cor é severidade, estado ou ação? O acento `--accent` aparece só na
   ação principal e no foco? Mais de um botão primário por tela é erro.
5. **Recibo da prova** (`proof`) é o único destaque? Nada mais com borda colorida ou fundo forte.
6. **Mono**: só no caminho do topo e no que é da máquina (URL, requisição, código, DNS)?
7. **Agrupamento**: a mesma falha em várias páginas aparece uma vez, com "afeta N páginas"?
8. **Estados**: vazio, carregando, erro, sem permissão. Cada um diz o próximo passo concreto?
9. **Texto**: curto, concreto, pt-BR, voz da Pitchy ("3 falhas novas desde o último scan").
   Nada de "potencialize", nada de rótulo genérico ("Detalhes", "Informações").
10. **Celular (390 px)**: sem rolagem horizontal, tabelas viram lista legível, toque ≥ 40 px,
    navegação em pílula não quebra feio.
11. **Acessibilidade**: contraste de `--ink-faint` sobre `--surface` em texto pequeno, foco
    visível em todo controle, rótulos em todo campo, `aria-current` na navegação.

## 4. Checklist da marca (proibições do CLAUDE.md)

Antes de entregar, confira na captura:
- [ ] sem degradê, sombra ou brilho de enfeite (a única luz é a da marca: `body::before`, topo do
      painel e login)
- [ ] movimento só na entrada do topo, no recibo e em resposta a ação; conferir quadro a quadro com
      `--motion` e sem ele (estado final, `prefers-reduced-motion`)
- [ ] sem Inter, Roboto ou fonte do sistema visível (General Sans e JetBrains Mono, servidas localmente)
- [ ] sem emoji, sem ícone genérico enfeitando título
- [ ] sem três cards de "benefícios" e sem bloco "número grande + legenda"
- [ ] sem metadados separados por "·", sem 01/02 fora de sequência real
- [ ] rótulos, cabeçalhos de tabela, selos e pílulas em frase (não MAIÚSCULO mono)

## 5. Restrições técnicas

- Sem build de front-end, sem CDN, sem `<script>` ou `style=""` inline (CSP estrita). JS só em
  `static/js/app.js`; HTMX para interatividade (`hx-get`, `hx-swap`, `hx-trigger`).
- Movimento: no máximo transições curtas em CSS (≤ 200 ms) com função (entrada de resultado
  HTMX, troca de estado) e `@media (prefers-reduced-motion: reduce)` desligando.
- Token novo só em `:root` de `app.css`. Valor de cor ou espaçamento solto em regra é erro.
- Tela nova: além desta skill, use a skill `frontend-design` para a direção estética.
