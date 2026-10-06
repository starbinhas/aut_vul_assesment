# CLAUDE.md

Instruções do projeto para o Claude Code e para quem trabalha neste repositório.

## O produto

Scanner de segurança automatizado (SaaS). O cliente informa uma URL/domínio e recebe um relatório
acionável. O fluxo completo tem 7 etapas (ver `docs/processo-scan-etapa-por-etapa.pdf`):

1 Autorização → 2 Reconhecimento (naabu) → 3 CVEs (nuclei) → **4 Web (OWASP ZAP)** →
**5 Validação** → **6 Relatório + LLM** → 7 Recorrência

**Este repositório cobre as etapas 4, 5 e 6.** As etapas 1–3 e 7 são de outros membros do time;
falamos com elas só pelo contrato de dados (ver "Contrato entre etapas").

## Regras que nunca podem ser quebradas

1. **Nenhum scan sem autorização.** Toda tarefa recebida precisa trazer `scan_id` de um alvo
   verificado na etapa 1 e o escopo travado. Sem isso, o worker recusa e registra o erro. Nunca
   adicione um "modo de teste" que pule essa checagem contra alvos reais.
2. **Nunca sair do escopo.** O ZAP só pode tocar hosts/caminhos do escopo (contexto do ZAP com
   include/exclude gerados a partir do escopo). Redirecionamentos para fora do escopo não são seguidos.
3. **Não causar dano.** Política de scan sem regras destrutivas, limite de threads/requisições por
   segundo e tempo máximo por scan. A validação (etapa 5) usa provas não destrutivas: nada de
   apagar/alterar dados, nada de DoS, nada de extrair dados reais além do mínimo para provar.
4. **Teste local só contra alvos de laboratório** (`docker-compose.lab.yml`: OWASP Juice Shop,
   DVWA etc.). Nunca use sites reais em testes, exemplos ou fixtures.
5. **Dados do cliente são sensíveis.** Credenciais de teste, cookies e tokens nunca vão para logs,
   para o LLM ou para o relatório em texto puro (mascarar antes).

## Etapas sob nossa responsabilidade

### 4 — Teste de aplicação web (`scanner/web_scan/`)
- Entra: alvo + escopo + rotas descobertas nas etapas 2/3 (+ credenciais de teste opcionais).
- Faz: dirige o ZAP via API (spider tradicional + AJAX spider para SPAs, scan passivo, scan ativo
  com política controlada). Áreas logadas só se o cliente forneceu credenciais.
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
└── worker-report    etapa 6  →  python -m scanner.report
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

> **Pendente de alinhar com o time:** formato exato do escopo que vem da etapa 1.

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
│   └── report/                 etapa 6 (prompts/, templates/ HTML, geração de PDF)
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

> Preencher conforme o projeto for criado.

```bash
docker compose up -d                                     # sobe tudo
docker compose -f docker-compose.yml -f docker-compose.lab.yml up -d   # + alvos de laboratório
docker compose run --rm worker-web pytest                # testes
```

## Ambiente local

- O repositório vive dentro do WSL2 (Ubuntu), em `~/scan_site`, nunca no OneDrive nem em `/mnt/c`
  (bind mounts do Docker ficam lentos e a sincronização gera conflitos).
- Abrir: no terminal do Ubuntu, `cd ~/scan_site && code .` (VS Code com a extensão WSL).
- Docker Desktop precisa da integração com o Ubuntu ligada (Settings → Resources → WSL integration).
