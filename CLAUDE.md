# CLAUDE.md

Instruções do projeto para o Claude Code e para quem trabalha neste repositório.

## O produto

Scanner de segurança automatizado (SaaS). O cliente informa uma URL/domínio e recebe um relatório
acionável. O fluxo completo tem 7 etapas (ver `docs/processo-scan-etapa-por-etapa.pdf`):

1 Autorização → 2 Reconhecimento (naabu) → 3 CVEs (nuclei) → **4 Web (OWASP ZAP)** →
**5 Validação** → **6 Relatório + LLM** → 7 Recorrência

**Este repositório cobre o pipeline inteiro** (decisão de trazer tudo para cá). Etapa 1 (Autorização,
via interface), 2 (Reconhecimento, `scanner/recon`, naabu), 3 (CVEs, `scanner/cve`, nuclei + o SCA
`scanner/sca`), 4 (Web/ZAP), 5 (Validação), 6 (Relatório), 7 (Recorrência, `scanner/recurrence`,
agendador) e a interface web (cliente e admin). O contrato entre etapas continua valendo internamente
(ver "Contrato entre etapas"). Entrada do pipeline: `scan.recon.requested`.

## Regras que nunca podem ser quebradas

1. **Nenhum scan sem autorização.** Toda tarefa recebida precisa trazer `scan_id` de um alvo
   verificado na etapa 1 e o escopo travado. Sem isso, o worker recusa e registra o erro. Nunca
   adicione um "modo de teste" que pule essa checagem contra alvos reais.
2. **Nunca sair do escopo.** O ZAP só pode tocar hosts/caminhos do escopo (contexto do ZAP com
   include/exclude gerados a partir do escopo). Redirecionamentos para fora do escopo não são seguidos.
3. **Não causar dano a site de cliente.** Perfis de scan (`scanner/web_scan/policy.py`): `safe` e
   `balanced` não têm regras destrutivas e podem rodar em cliente. `intrusive` (grava dados,
   SSRF/RFI/OAST, **sem** regras de sobrecarga) **só roda numa cópia de teste (homologação) do
   cliente** com autorização assinada, aprovada pelo time e dentro da validade
   (`scanner/common/staging.py`, `staging_cleared`), e nunca no site oficial. `aggressive` (tudo,
   inclusive DoS) **só roda contra hosts de laboratório**. A trava está em `web_scan/service.py`
   (`resolve_profile` + `policy.is_cleared`), que recusa o perfil contra qualquer outro alvo. Sempre
   valem: limite de threads/requisições por segundo e tempo máximo. A validação (etapa 5) usa provas
   não destrutivas: nada de apagar/alterar dados, nada de DoS, nada de extrair dados reais além do
   mínimo para provar.
4. **Teste local só contra alvos de laboratório** (`docker-compose.lab.yml`: OWASP Juice Shop,
   DVWA etc.). Nunca use sites reais em testes, exemplos ou fixtures.
5. **Dados do cliente são sensíveis.** Credenciais de teste, cookies e tokens nunca vão para logs,
   para o LLM ou para o relatório em texto puro (mascarar antes).

## Etapas sob nossa responsabilidade

### 4 — Teste de aplicação web (`scanner/web_scan/`)
- Entra: alvo + escopo + rotas descobertas nas etapas 2/3 (+ credenciais de teste opcionais).
- Faz: dirige o ZAP via API (spider tradicional + AJAX spider para SPAs, scan passivo, scan ativo
  com política controlada). Áreas logadas só se o cliente forneceu credenciais.
- Perfil do scan vem no `payload.profile` da mensagem (`safe` por padrão). `safe`/`balanced` em
  cliente; `intrusive` só em cópia de teste autorizada; `aggressive` só laboratório (trava em
  `resolve_profile`, que consulta a autorização no banco). Na interface (`web/services.py`,
  `profiles_for`, conferido de novo em `start_scan` contra POST forjado): o intrusivo aparece só na
  página da cópia liberada; o agressivo só para **admin** e só em **site de laboratório**; cliente
  nunca vê o agressivo. Também sai pela CLI de laboratório (`tests/lab_scan.py --profile`).
  "Laboratório" tem uma definição só: `policy.is_lab_scope` contra `settings.lab_hosts`.
- Cópia de teste (`web/staging.py`, rotas em `web/routes/staging.py`): passo a passo para cliente
  leigo — mensagem pronta para quem cuida do site, prova de domínio da cópia (DNS TXT), checklist em
  linguagem simples + termo (versão e hash gravados), revisão do time em `/admin/copias-de-teste`.
  Só alguém da organização assina (o admin não assina pelo cliente). Mudou o texto do termo →
  incrementar `TERM_VERSION`.
- Sai: candidatos a falha (`status: candidate`) no formato do contrato, cada um com a requisição e a
  resposta que o expuseram.
- Um scan = uma sessão nova do ZAP (`core.new_session`) e um contexto próprio. Nunca rodar dois
  clientes ao mesmo tempo na mesma instância do ZAP (os alertas se misturam).

### 5 — Validação (`scanner/validation/`) — diferencial do produto
- Entra: todos os candidatos (etapas 3 e 4).
- Faz: deduplica (mesma URL + parâmetro + CWE vindo de nuclei e ZAP vira um achado só), reexecuta
  uma prova determinística por tipo de falha (ex.: marcador único refletido para XSS, diferença de
  resposta para SQLi baseada em erro, checagem direta de cabeçalho), e classifica severidade.
- Sai: achados com `status` em `confirmed | likely | unconfirmed | false_positive` + evidência
  reproduzível.
- **O LLM nunca descarta um achado sozinho.** Estudos mostram que LLMs suprimem verdadeiros
  positivos. `false_positive` só vem de checagem determinística (ou revisão humana); sem prova
  conclusiva, o achado fica `unconfirmed` e aparece no relatório como tal.
- Cada validador é uma função pura e testada contra o laboratório; um validador por família de
  falha (plugin do ZAP / template do nuclei / CWE).

### 6 — Relatório e remediação (`scanner/report/`) — diferencial do produto
- Entra: achados validados e priorizados.
- Faz: para cada achado, gera "o que é / por que importa / como corrigir passo a passo" para um dev
  ou gestor leigo, mapeado à severidade e ao OWASP Top 10 vigente.
- Sai: relatório em JSON (fonte da verdade) → HTML → PDF.
- LLM: Claude API com SDK oficial `anthropic` (ver seção LLM).
- O valor é a correção executável, não o visual. Toda remediação precisa ser concreta (comando,
  config ou trecho de código), não genérica.

### Interface web (`scanner/web/`)
- Duas áreas pelo nível de acesso, na mesma aplicação:
  - **Cliente** (`role = client`): vê só o que é da própria organização — sites, verificação de
    domínio, scans, achados agrupados, relatório, comparação com o scan anterior.
  - **Admin** (`role = admin`): tudo que o cliente vê, de todas as organizações, mais as telas do
    time — clientes e usuários, operação (filas, rejeitadas), revisão humana de achados, auditoria.
- **Isolamento entre clientes é regra de segurança**: toda consulta passa por `scanner/web/tenancy.py`.
  Objeto de outra organização responde 404 (não 403, para não revelar que existe).
- A interface só **mostra** o relatório: lê o `report_json` (fonte da verdade). Revisão humana muda o
  achado no banco e pede um relatório novo ao worker-report; a interface nunca chama o LLM.
- Só a revisão humana (admin) pode marcar `false_positive` fora da validação determinística, e
  sempre com motivo registrado na auditoria.
- Stack: FastAPI + Jinja2 + HTMX (sem build de front-end). Sem CDN: fontes, JS e imagens servidos
  pela própria aplicação, com CSP estrita.
- A interface é o primeiro alvo de quem quiser atacar o produto: senha com Argon2id, cookie de
  sessão `HttpOnly`/`SameSite`, token CSRF em todo POST, bloqueio após tentativas de login,
  cabeçalhos de segurança. Ela tem de passar no nosso próprio scanner.

#### Identidade visual e "não parecer IA"
- Marca Pitchy (https://pitchy.me): fundo quase preto, General Sans em pesos leves, navegação em
  pílula, botão principal branco; logo azul `#1F62B5`; acento `#d8ff3e` só para ação principal e
  foco. Tokens em `scanner/web/static/css/app.css`.
- Mono maiúsculo espaçado (assinatura da marca) **só** no caminho do topo da página. Rótulos,
  cabeçalhos de tabela, selos e pílulas em texto normal, em frase. Mono só para o que é da máquina:
  URL, requisição, código, registro DNS.
- Elemento de assinatura: o **recibo da prova** (macro `proof`) — o que enviamos e o que o site
  respondeu, borda na cor da severidade. Ao aparecer, as linhas saem como de uma impressora e,
  se a falha foi provada, cai o carimbo ("Provada"/"Provável"). É o diferencial do produto; não
  criar outros destaques.
- O topo do painel é o **próximo passo** ("Corrija primeiro em Y: X"), não blocos de números.
- **Luz da marca:** o azul frio das fotos do pitchy.me é a atmosfera. Uma luz azul no alto de cada
  página (`body::before`), tingida de laranja/vermelho no topo do painel quando há falha alta ou
  crítica, e a lâmina de luz no login. É a **única** luz decorativa permitida.
- Cor com presença, mas com função: severidade também como superfície (fio e tom na linha da
  falha, cabeçalho do recibo); azul `--live` para tudo que está ao vivo (scan rodando).
- Movimento: uma entrada orquestrada por página (o topo), o recibo impresso, e respostas a ação
  (abrir uma falha, filtrar a lista). Nada de animação em toda seção. Sempre com
  `prefers-reduced-motion` desligando.
- Visualização com função: mapa do site (cada página na cor da falha mais grave; falhas do site
  todo ficam fora) e linha do tempo de falhas abertas por site.
- Proibido: degradês decorativos (fora a luz da marca acima), Inter/Roboto, emoji na interface, ícones genéricos enfeitando
  título, três cards de "benefícios", blocos de "número grande + legenda", metadados separados por
  "·", numeração 01/02 fora de sequências reais, sombras e brilhos em tudo, textos vagos
  ("potencialize sua segurança"). Cor só com função: severidade, estado, ação.
- Telas novas: usar o plugin `frontend-design` e conferir com captura de tela antes de entregar.
  Método (brief, ciclo de captura, roteiro de crítica): skill `.claude/skills/pitchy-ui/`;
  capturas com `tests/ui_shots.py`.
- Textos curtos, concretos, em pt-BR, na voz da Pitchy ("3 falhas novas desde o último scan").
- Primeiro o que importa: o que mudou → o que corrigir agora → histórico. A mesma falha em várias
  páginas aparece **uma vez**, com "afeta N páginas".

## Arquitetura e containers

Tudo roda em Docker. Um único pacote Python (`scanner`) gera **uma imagem** usada pelos três
workers, cada um com um comando diferente.

```
services (docker-compose.yml)
├── redis            fila entre etapas (Redis Streams) — compartilhada com o time
├── postgres         achados e estado dos scans — compartilhado com o time
├── zap              zaproxy/zap-stable em modo daemon (API só na rede interna, com API key)
├── worker-web       etapa 4  →  python -m scanner.web_scan
├── worker-validate  etapa 5  →  python -m scanner.validation
├── worker-report    etapa 6  →  python -m scanner.report
└── web              interface →  python -m scanner.web (única porta publicada)
```

- **ZAP e worker-web andam em par** (1 ZAP por worker-web, um scan por vez). Para escalar, aumente
  o número de pares; em Kubernetes vira um pod com dois containers. Não usar o socket do Docker para
  criar containers dinamicamente.
- **Redes:** `internal` (sem saída para internet) liga workers, redis, postgres e a API do ZAP.
  `egress` só para quem precisa sair: `zap` e `worker-validate` (que reenvia provas ao alvo) e
  `worker-report` (Claude API). A porta da API do ZAP nunca é publicada no host em produção.
- **Recursos do ZAP:** o scan ativo consome muita CPU/RAM (ordem de 3 GB). Definir limites
  (`mem_limit`, `cpus`) e `-Xmx` da JVM.
- Containers rodam como usuário não-root; segredos via variáveis de ambiente (`.env`, nunca commitado;
  `.env.example` documenta as chaves).

## Contrato entre etapas

Mensagens em Redis Streams, payload JSON, independente de linguagem (os colegas podem usar Go).

- Streams: `scan.web.requested` → (etapa 4) → `scan.candidates` → (etapa 5) →
  `scan.validated` → (etapa 6) → `scan.report.ready`.
- Toda mensagem carrega `scan_id`, `target_id`, `stage`, `schema_version` e o escopo (ou referência a ele).
- O formato do achado (`Finding`) está em `contracts/finding.schema.json` e é a fonte da verdade.
  Os modelos Pydantic em `scanner/common/models.py` são gerados/validados contra esse schema.
- Mudança no contrato = mudança combinada com o time + `schema_version` incrementada. Nunca quebrar
  o formato em silêncio.
- Processamento idempotente: a mesma mensagem entregue duas vezes não pode gerar achados duplicados.

- **Dono do banco: Ahmed.** O schema do Postgres e as migrações (Alembic) vivem neste repositório,
  em `migrations/`. Outras etapas leem/escrevem pelas tabelas combinadas aqui; mudança de tabela
  passa por este repositório.
- Os nomes dos streams acima são os oficiais.

> **Etapa 1 é nossa (via interface):** a verificação de domínio (DNS TXT, `web/verification.py`) e a
> trava de escopo são a etapa 1. **A integrar:** ao iniciar um scan, a etapa 1 deve disparar o
> pipeline completo (hoje publica só `scan.web.requested`; faltam `2 recon` e `3 CVEs` à frente).
> Achados das nossas checagens próprias usam `source.tool = "scanner"` (contrato 1.1).

## LLM (etapa 6)

- SDK oficial `anthropic` em Python. Modelo padrão: `claude-opus-5-5` (ID exato, sem sufixo de data).
  Trocar de modelo é decisão do time, medida contra o conjunto de avaliação.
- Saída estruturada com `client.messages.parse()` + modelo Pydantic — nunca fazer parsing de texto livre.
- Thinking adaptativo; definir `output_config.effort` explicitamente (o padrão do Opus 5.5 é `medium`).
- Tratar `stop_reason == "refusal"` (o classificador `cyber` pode recusar textos sobre
  vulnerabilidades): nesse caso usar a remediação estática do catálogo, nunca deixar o achado sem texto.
- Antes de enviar: mascarar credenciais, cookies, tokens, e-mails e dados pessoais da evidência.
- Custo: o texto de remediação depende do tipo de falha, não do cliente. Cachear por
  (CWE/plugin, stack detectada, idioma) e usar prompt caching no system prompt fixo.
- Prompts ficam em `scanner/report/prompts/` versionados, não espalhados no código.

## Estrutura do repositório

```
├── CLAUDE.md
├── docker-compose.yml          serviços de produção/dev
├── docker-compose.lab.yml      alvos vulneráveis para testes locais
├── Dockerfile                  imagem única do pacote scanner
├── .env.example
├── pyproject.toml              gerenciado com uv
├── contracts/                  JSON Schemas compartilhados com o time
├── migrations/                 schema do Postgres (Alembic) — dono: Ahmed
├── scanner/
│   ├── common/                 modelos, cliente de fila, logging, mascaramento
│   ├── web_scan/               etapa 4
│   ├── validation/             etapa 5 (um módulo por família de falha)
│   ├── report/                 etapa 6 (prompts/, templates/ HTML, geração de PDF)
│   └── web/                    interface (rotas cliente/admin, templates/, static/)
└── tests/
    ├── unit/
    └── integration/            rodam contra docker-compose.lab.yml
```

## Stack e convenções

- Python 3.13, `uv` para dependências, `ruff` (lint + format), `mypy` no pacote `scanner`, `pytest`.
- Cliente do ZAP: pacote `zaproxy`. Modelos: Pydantic v2. HTML: Jinja2. PDF: WeasyPrint.
- Logs estruturados em JSON, sempre com `scan_id`; nunca logar segredos.
- Código e identificadores em inglês; textos para o cliente final em português (pt-BR) por padrão.

## Comandos

```bash
uv sync                                                  # dependências locais (cria .venv)
uv run pytest                                            # testes unitários
uv run ruff format . && uv run ruff check . && uv run mypy   # format, lint, tipos

cp .env.example .env                                     # uma vez; preencher segredos
docker compose up -d                                     # sobe tudo (roda as migrações antes)
docker compose -f docker-compose.yml -f docker-compose.lab.yml up -d   # + alvos de laboratório
docker compose -f docker-compose.yml -f docker-compose.lab.yml --profile test run --rm tests  # integração

uv run alembic revision -m "descricao"                   # nova migração (em migrations/versions/)

uv run playwright install chromium                       # uma vez (WSL: sudo apt install libnss3 libnspr4 libasound2t64)
UI_SHOTS_EMAIL=... UI_SHOTS_PASSWORD=... uv run python -m tests.ui_shots   # capturas em out/ui-shots/
```

## Ambiente local

- O repositório vive dentro do WSL2 (Ubuntu), em `~/scan_site`, nunca no OneDrive nem em `/mnt/c`
  (bind mounts do Docker ficam lentos e a sincronização gera conflitos).
- Abrir: no terminal do Ubuntu, `cd ~/scan_site && code .` (VS Code com a extensão WSL).
- Docker Desktop precisa da integração com o Ubuntu ligada (Settings → Resources → WSL integration).
