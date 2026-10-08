# Entenda o código — guia de quem quer saber como tudo funciona

Este guia é um **passeio explicado pelo repositório**, do geral ao detalhe. A ideia é você sair
daqui entendendo *por que* cada pasta existe e *o que* cada arquivo faz — não só mexendo no escuro.
Leia de cima pra baixo na primeira vez; depois use como mapa pra achar as coisas.

> Dica de leitura: os nomes de arquivo são **links**. Clique pra abrir o arquivo ao lado e ir
> acompanhando. Comece pelos arquivos pequenos (menos de 60 linhas) — eles são os mais fáceis.

---

## 1. O que o sistema faz, em um parágrafo

É um **scanner de segurança automatizado**. O cliente informa o endereço do site dele e recebe um
relatório com as falhas de segurança encontradas e **como corrigir cada uma**. O diferencial não é
achar muita coisa — é **provar** que a falha é real e explicar a correção de forma simples.

Analogia que usamos o tempo todo: pense num **inspetor que vistoria uma casa** (o site) procurando
problemas, anota o que acha, **confirma** que o problema existe, e entrega um relatório com o que
consertar.

---

## 2. A grande ideia: uma esteira de 7 etapas

O trabalho é dividido em 7 etapas que formam uma **esteira** (pipeline). Cada etapa pega o resultado
da anterior e passa adiante. Entender essa esteira é entender 80% do projeto.

```
1 Autorização → 2 Reconhecimento → 3 CVEs ─┐
                                            ├→ (3 e 4 em paralelo)
                              4 Teste web ──┘ → 5 Validação → 6 Relatório → 7 Recorrência
```

1. **Autorização** — prova que o dono autorizou o teste e **trava o escopo** (o que pode ser tocado).
2. **Reconhecimento** — descobre o que existe no alvo (portas/serviços).
3. **CVEs** — procura falhas já conhecidas de produtos (e checa bibliotecas desatualizadas).
4. **Teste web** — explora a aplicação de verdade (com o OWASP ZAP).
5. **Validação** — pega cada suspeita e **prova** se é real.
6. **Relatório** — vira um relatório com explicação e correção passo a passo.
7. **Recorrência** — repete o scan de tempos em tempos.

As etapas **não se chamam direto**. Elas conversam por **mensagens numa fila** (Redis Streams): a
etapa 4 publica "achei estes candidatos", a etapa 5 lê e processa. Isso deixa cada etapa
independente (pode até estar em outra linguagem) e permite rodar várias ao mesmo tempo.

---

## 3. Os três conceitos que explicam quase tudo

Se você entender estes três, o resto encaixa.

### a) A fila — [scanner/common/queue.py](../scanner/common/queue.py)
É o "esteira transportadora". Cada etapa é um **worker** que fica num laço: lê uma mensagem do seu
stream, processa, e publica no próximo stream. Pontos-chave do arquivo:
- `consume(...)`: o laço de um worker. Lê uma mensagem por vez, roda o `handler`, e dá `ack`
  (confirma) só se deu certo. Se der erro, **não confirma** → a mensagem volta pra tentar de novo.
- **Idempotência**: antes de processar, grava a mensagem numa tabela (`_claim`). Se a mesma mensagem
  chegar duas vezes, a segunda é ignorada — não gera achado duplicado.
- **Dead-letter** e `on_give_up`: depois de algumas tentativas falhas, a mensagem vai pra uma fila de
  "rejeitadas" e o scan é marcado como **falhou** (em vez de ficar "rodando" pra sempre).

### b) O contrato — [scanner/common/models.py](../scanner/common/models.py) e [contracts/](../contracts/)
É o **formato dos dados** que trafega entre as etapas. O mais importante é o `Finding` (um achado) e
o `StageMessage` (um envelope de mensagem). Esses formatos também estão descritos como regra em
[contracts/finding.schema.json](../contracts/finding.schema.json) — a fonte da verdade. Mudar o
formato = subir a `schema_version` (hoje `1.1`, que adicionou a fonte `scanner` pras nossas
checagens próprias).

### c) O escopo e a autorização — [scanner/common/scope.py](../scanner/common/scope.py) e [scanner/common/authz.py](../scanner/common/authz.py)
A **regra nº 1**: nenhum scan sem autorização, e nunca sair do escopo.
- `Scope` (em models) diz quais hosts/caminhos podem ser tocados.
- `ScopeGuard` (em scope.py) é quem **recusa** qualquer requisição fora do escopo.
- `check_authorized` (em authz.py) confere, a cada etapa, que o scan existe no banco, está
  verificado, o escopo está travado e **bate** com o que veio na mensagem. Não existe atalho.

---

## 4. Mapa das pastas (uma linha cada)

```
scanner/
├── common/      os "tijolos" compartilhados por todas as etapas (fila, modelos, banco, escopo…)
├── recon/       ETAPA 2 — descoberta de portas (naabu)
├── cve/         ETAPA 3 — falhas conhecidas (nuclei)
├── sca/         ETAPA 3 (parte) — componentes vulneráveis a partir da lista de dependências
├── web_scan/    ETAPA 4 — teste da aplicação web (OWASP ZAP)
├── validation/  ETAPA 5 — prova cada achado (o diferencial)
│   └── validators/   um validador por família de falha (XSS, SQLi, cabeçalhos, cookies…)
├── report/      ETAPA 6 — relatório JSON → HTML → PDF + remediação (com a IA)
├── recurrence/  ETAPA 7 — agendador que repete scans vencidos
└── web/         a interface (área do cliente e do admin)
    └── routes/       as telas/rotas
```

Cada pasta de etapa tem o mesmo padrão: um `service.py` (a lógica) e um `__main__.py` (o worker que
roda a lógica em laço, lendo/escrevendo na fila). Para ver um worker rodar, é `python -m scanner.<pasta>`.

---

## 5. Os tijolos compartilhados (`scanner/common/`)

Leia estes primeiro — todo o resto usa eles.

- [models.py](../scanner/common/models.py) — os **moldes de dados** (Pydantic): `Finding`, `Scope`,
  `StageMessage`, `Evidence`, severidade, status. É o vocabulário do sistema.
- [queue.py](../scanner/common/queue.py) — a **fila** (explicada acima).
- [db.py](../scanner/common/db.py) — as **tabelas** do banco (SQLAlchemy): scans, findings, targets,
  usuários, auditoria. Também o `set_scan_status` (atualiza o andamento do scan numa transação curta).
- [scope.py](../scanner/common/scope.py) — o `ScopeGuard` e o `scope_for` (monta o escopo de um site).
- [authz.py](../scanner/common/authz.py) — o `check_authorized` (regra nº 1).
- [masking.py](../scanner/common/masking.py) — **mascara** senhas, tokens, e-mails antes de gravar em
  log, mandar pra IA ou pro relatório. Dado sensível nunca aparece cru.
- [owasp.py](../scanner/common/owasp.py) — tradução de CWE (tipo de falha) para a categoria do OWASP
  Top 10. É como agrupamos as falhas por categoria.
- [grouping.py](../scanner/common/grouping.py) — junta a **mesma falha repetida em várias páginas**
  num único item ("afeta N páginas").
- [evidence.py](../scanner/common/evidence.py) — recorta um trecho da resposta pra servir de prova.
- [config.py](../scanner/common/config.py) — todas as configurações (lidas de variáveis de ambiente).
- [logging.py](../scanner/common/logging.py) — logs em JSON, sempre com o `scan_id`.

---

## 6. Passeio pelas etapas

### Etapa 1 — Autorização
Mora na **interface**: [web/verification.py](../scanner/web/verification.py) prova que o domínio é
do cliente (um registro DNS TXT). Quando o scan começa, o escopo é **travado**. A trava é conferida
em toda etapa por [authz.py](../scanner/common/authz.py).

### Etapa 2 — Reconhecimento (`scanner/recon/`)
- [recon/naabu.py](../scanner/recon/naabu.py) — a parte **pura**: monta o comando do `naabu` e lê a
  saída (JSON) em uma lista de portas. Fácil de testar.
- [recon/service.py](../scanner/recon/service.py) — roda o `naabu` de verdade (subprocesso) e o
  `handle`: autoriza, descobre portas e **dispara as etapas 3 e 4 em paralelo** (fan-out).
- [recon/__main__.py](../scanner/recon/__main__.py) — o worker (laço na fila).

### Etapa 3 — CVEs e componentes (`scanner/cve/` e `scanner/sca/`)
- [cve/nuclei.py](../scanner/cve/nuclei.py) — parte pura: monta o comando do `nuclei` e **converte**
  cada achado dele num `Finding` nosso (fonte `nuclei`).
- [cve/service.py](../scanner/cve/service.py) — roda o `nuclei` e publica os candidatos.
- [sca/](../scanner/sca/) — o **scan de componentes**: recebe a lista de dependências que o cliente
  fornece ([sca/manifest.py](../scanner/sca/manifest.py) lê o arquivo) e confere cada peça contra o
  catálogo público OSV ([sca/osv.py](../scanner/sca/osv.py)). É um scan à parte (`python -m scanner.sca`).

### Etapa 4 — Teste web (`scanner/web_scan/`)
O coração da parte web.
- [web_scan/zap.py](../scanner/web_scan/zap.py) — dirige o **OWASP ZAP** pela API: cria a sessão e o
  contexto (escopo), rastreia (spider/ajax), scan passivo e ativo, faz login (token) e lê os alertas.
- [web_scan/policy.py](../scanner/web_scan/policy.py) — os **três perfis** de scan (seguro, completo
  seguro, agressivo) e a trava do agressivo (só laboratório).
- [web_scan/alerts.py](../scanner/web_scan/alerts.py) — converte um alerta do ZAP num `Finding`.
- [web_scan/service.py](../scanner/web_scan/service.py) — o `handle`: autoriza, escolhe perfil e
  limites (laboratório x cliente), roda o scan e publica os candidatos.

### Etapa 5 — Validação (`scanner/validation/`) — o diferencial
Pega cada suspeita e **prova** se é real, de forma determinística e sem causar dano.
- [validation/service.py](../scanner/validation/service.py) — orquestra: deduplica, valida cada um,
  classifica severidade e publica.
- [validation/dedup.py](../scanner/validation/dedup.py) — junta achados iguais (mesma URL+parâmetro+CWE).
- [validation/http.py](../scanner/validation/http.py) — o `ProbeClient`: cliente HTTP das provas, que
  **só** usa métodos seguros (GET/HEAD) e **só** dentro do escopo.
- [validation/validators/](../scanner/validation/validators/) — **um validador por família de falha**:
  [xss_reflected.py](../scanner/validation/validators/xss_reflected.py),
  [sqli_error.py](../scanner/validation/validators/sqli_error.py),
  [headers.py](../scanner/validation/validators/headers.py),
  [cookies.py](../scanner/validation/validators/cookies.py),
  [open_redirect.py](../scanner/validation/validators/open_redirect.py).
  Todos seguem o padrão de [base.py](../scanner/validation/validators/base.py) (`register` + `result`).
- **Checagens próprias** (as que o ZAP não faz): acesso entre usuários
  ([access_control.py](../scanner/validation/access_control.py) +
  [access_probe.py](../scanner/validation/access_probe.py)), arquivos expostos
  ([exposed_files.py](../scanner/validation/exposed_files.py)), login sem bloqueio
  ([auth_checks.py](../scanner/validation/auth_checks.py)), token sem assinatura
  ([jwt_integrity.py](../scanner/validation/jwt_integrity.py)) e monitoramento/logs
  ([logging_monitoring.py](../scanner/validation/logging_monitoring.py)). Elas viram `Finding` pela
  [proactive.py](../scanner/validation/proactive.py).
- [validation/coverage_map.py](../scanner/validation/coverage_map.py) — o **mapa honesto** do que
  cobrimos por categoria (coberto / parcial / planejado / manual / externo).
- **Regra de ouro** (veja o service): a IA **nunca descarta** um achado sozinha. "Falso positivo" só
  vem de prova determinística.

### Etapa 6 — Relatório (`scanner/report/`)
- [report/builder.py](../scanner/report/builder.py) — monta o relatório (JSON, a fonte da verdade),
  agrupando as falhas.
- [report/remediation.py](../scanner/report/remediation.py) + [report/catalog.py](../scanner/report/catalog.py)
  — o texto de correção: tenta a IA, e se ela recusa/falha, usa o **catálogo pronto** (nunca fica sem).
- [report/llm.py](../scanner/report/llm.py) — a conversa com a IA (Claude), com saída estruturada.
- [report/render.py](../scanner/report/render.py) — JSON → HTML → PDF (WeasyPrint).
- [report/service.py](../scanner/report/service.py) — espera as fontes necessárias (zap, nuclei) e
  gera o relatório.

### Etapa 7 — Recorrência (`scanner/recurrence/`)
- [recurrence/service.py](../scanner/recurrence/service.py) — `is_due` (se um alvo está vencido) e
  `run_once` (acha os vencidos e dispara um scan novo, começando pela etapa 2).
- [recurrence/__main__.py](../scanner/recurrence/__main__.py) — o agendador (um laço que verifica de
  hora em hora). Não é consumidor de fila: é baseado em tempo.

---

## 7. A interface web (`scanner/web/`)
Feita em FastAPI + Jinja2 + HTMX (sem build de front-end).
- [web/app.py](../scanner/web/app.py) — monta a aplicação, cabeçalhos de segurança, sessão.
- [web/routes/auth.py](../scanner/web/routes/auth.py) — login/logout.
- [web/routes/client.py](../scanner/web/routes/client.py) — telas do cliente (sites, scans, relatório).
- [web/routes/admin.py](../scanner/web/routes/admin.py) — telas do admin (clientes, operação, revisão).
- [web/services.py](../scanner/web/services.py) — a lógica por trás das telas (iniciar scan, comparar,
  revisão humana, operação das filas).
- [web/tenancy.py](../scanner/web/tenancy.py) — **isolamento entre clientes**: objeto de outra
  organização responde "não existe" (404). Regra de segurança.
- [web/security.py](../scanner/web/security.py) — senha (Argon2id), CSRF, bloqueio de login.
- [web/deps.py](../scanner/web/deps.py) — "quem está logado?" e a sessão de banco por requisição.

---

## 8. Como tudo roda junto (Docker)
- [Dockerfile](../Dockerfile) — **uma única imagem** com o pacote `scanner` e as ferramentas
  (naabu, nuclei + templates). Cada worker é a mesma imagem com um comando diferente.
- [docker-compose.yml](../docker-compose.yml) — os serviços: `redis` (fila), `postgres` (banco),
  `zap`, e um worker por etapa (`worker-recon`, `worker-cve`, `worker-web`, `worker-validate`,
  `worker-report`, `worker-recurrence`) + `web` (a interface).
- [docker-compose.lab.yml](../docker-compose.lab.yml) — os **alvos de laboratório** (Juice Shop, DVWA)
  e ajustes só de teste. Nunca use site real em teste.

Fluxo mental: a `web` publica `scan.recon.requested` → `worker-recon` → `worker-cve` + `worker-web` →
`scan.candidates` → `worker-validate` → `scan.validated` → `worker-report` → relatório pronto.

---

## 9. Os testes (como provam o quê)
Em [tests/unit/](../tests/unit/). Cada arquivo testa uma peça — por exemplo:
- `test_scope.py`, `test_authz.py` — as regras de segurança (escopo, autorização).
- `test_validators.py`, `test_access_control.py` — as provas de cada falha.
- `test_scan_profile.py` — a trava do perfil agressivo.
- `test_web.py` — a interface (isolamento, CSRF, login).

Rode tudo com `uv run pytest`. Os testes de integração ([tests/integration/](../tests/integration/))
rodam contra o laboratório.

---

## 10. Como continuar aprendendo (roteiro sugerido)
1. Leia [scanner/common/models.py](../scanner/common/models.py) — é o vocabulário.
2. Leia um validador pequeno inteiro: [xss_reflected.py](../scanner/validation/validators/xss_reflected.py).
   Veja como uma "prova" funciona na prática.
3. Leia [scanner/common/queue.py](../scanner/common/queue.py) `consume()` — entenda o laço de um worker.
4. Siga um scan: comece em [web/services.py](../scanner/web/services.py) `start_scan`, depois
   [recon/service.py](../scanner/recon/service.py) `handle`, e por aí vai pela esteira.
5. Rode `uv run pytest -q` e abra um teste que te interessou pra ver o comportamento esperado.

> Quando bater dúvida em qualquer arquivo, abra ele e me pergunte "me explica este arquivo linha a
> linha" — dá pra descer no detalhe que você quiser.
