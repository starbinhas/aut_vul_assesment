# Plano de ação — auditoria crítica + prioridades para ganhar

> Pedido: ser rigoroso e levantar **todas** as críticas e atrasos do nosso projeto. Este arquivo é a
> auditoria fria (o que está fraco, atrasado ou arriscado) e o plano priorizado para abrir distância.
> Base: código no branch `web-scan/aggressive-stress-copy` (2026-10-08), `docs/concorrentes.md`,
> `docs/roadmap-por-produto.md`.
>
> Evidência verificada: `uv run pytest -q` → **295 passam, 1 skip**; `ruff check` e `mypy scanner`
> **limpos**. O build é verde de verdade. **O problema não é código quebrado — é a honestidade da
> cobertura.** Várias capacidades de manchete só funcionam no laboratório.

## Veredito

A corrida não é escrever features novas. É **tornar reais as capacidades que já anunciamos** e que
hoje são de laboratório. Num demo contra um prospect, pelo menos dois itens vendidos **não acham nada
por construção**. Isso, não a falta de features, é o que nos faz perder.

## Entregue nesta sessão (verificado: 330 testes, ruff, mypy limpos)

- [x] **Assertividade e constância — benchmark com portão de regressão** (`tests/benchmark.py`): mede o
      que o scanner PROVA por família OWASP e compara com um baseline gravado; **falha (saída != 0) se
      uma capacidade de prova regride**. Scorer puro, 5 testes. O baseline se gera uma vez contra o
      laboratório (`--update`); não vem no repo para não ser "móvel de laboratório".
- [x] **Importar OpenAPI/Swagger** (`scanner/recon/openapi.py`): o recon procura o spec nos caminhos
      convencionais (`/openapi.json`, `/v3/api-docs`...) e semeia os endpoints da API (com parâmetros
      preenchidos) na árvore do ZAP. Antes, a API só era testada se o spider tropeçasse nela. v3 e v2,
      3 testes.

- [x] **IDOR / A01 no pipeline** (#2, blocker): `run_access_control` roda na etapa 4, via ZAP (sem
      sair da rede interna), quando o site tem 2º usuário de teste + recursos privados configurados.
      Prova determinística (`classify_access`), só GET, não destrutivo — roda até em cliente. Novo
      método `zap.authed_get`, campos no `LoginCredential`, colunas em `TargetAuthConfig` + migração
      0011, campos no formulário de login-teste. A01 saiu de "parcial" para "coberto" no
      `coverage_map`. 4 testes novos.
- [x] **Login por formulário/cookie** (#5): novo modo `form` no login (POST form-encoded → captura
      `Set-Cookie` → injeta cabeçalho `Cookie`), ao lado do modo `token` que já existia. Destrava a
      área logada em sites de PME com sessão por cookie (DVWA e afins), e faz A07/A08/IDOR dispararem
      nesses alvos. Campos novos no formulário + colunas em `TargetAuthConfig` + migração 0012. 4
      testes novos. Limitação: login com CSRF token no formulário ainda não é tratado.
- [x] **Integridade — perfil `safe` não trava mais conta** (#8): `run_login_lockout` agora só roda em
      perfil destrutivo (`web_scan/service.py`, gate `profile.destructive`). `safe`/`balanced` em
      cliente não fazem mais nada que altere estado.
- [x] **A04 real** (#1): `exposed_files.py` passou de 2 caminhos do Juice Shop para uma lista curada
      de ~25 caminhos reais (`.git/config`, `.env`, backups, dumps, config) + os de laboratório.
- [x] **CVSS por achado** (#7): `scanner/report/cvss.py` — nota-base v3.1 representativa por CWE, no
      relatório (`ReportItem.cvss_score`/`cvss_vector`).
- [x] **Export SARIF 2.1.0** (#7): `scanner/report/sarif.py` (`to_sarif`) — formato que GitHub code
      scanning/Invicti/Rapid7 ingerem; destrava "quebrar o build no CI".
- [x] **Eval de remediação** (#3): `scanner/report/eval.py` (rubrica de concretude) + teste que prova
      que o catálogo é concreto + runner `tests/eval_remediation.py` (hoje 8/9 concretos; o furo é o
      caso sem CWE/validador).
- [x] **Honestidade** (#3, #9): tirado "Claude" de onde roda Groq (docstring `llm.py`, CLAUDE.md);
      nota do pipeline em CLAUDE.md corrigida (estava desatualizada).

- [x] **Recon de portas + CVE multi-host** (#4): o recon deriva os alvos de CVE (base_urls + serviços
      web nas portas descobertas pelo naabu, em escopo — antes descartadas) e os passa no payload; a
      etapa 3 varre todos, deduplicando. `cve_targets`/`scan_targets`, 3 testes.
- [x] **SCA chamável por conteúdo** (#6, parcial): `load_manifest_content`/`scan_manifest_content` —
      o SCA deixou de ser só CLI de arquivo. **Integração ao pipeline de achados = decisão de time:** o
      contrato `Finding` é HTTP (`Location.method` exige método); dependência vulnerável não cabe sem
      mudar o contrato (schema_version + aval do time), e é a superfície código/repo despriorizada.
- [x] **Mais famílias de prova** (P2): validadores de **path traversal** (CWE 22, prova mínima com
      `/etc/passwd`) e **SSTI** (conta aritmética aleatória avaliada). Determinísticos, não destrutivos
      (só GET), 6 testes. Cobertura de prova passou de 5 para 7 famílias.

**Ainda aberto:** login com CSRF token no formulário (#5, sub-item); XSS armazenado/DOM e SQLi
booleano (precisam de navegador headless); **produto Pentest** (agente dentro da trava) — produto novo
com ciclo próprio (`docs/produto-pentest.md`), não entregável testado numa sessão. Integração do SCA
ao contrato depende de decisão de time.

**Pendência de UI:** os campos novos no formulário de login-teste (tipo de login, nomes de campo, 2º
usuário, recursos, marcador) passam no build, mas **não tiveram revisão visual com captura de tela**
(o stack não roda nesta sessão). Rodar a skill `pitchy-ui` nessa tela antes de mostrar a cliente.

## Parte 1 — Auditoria crítica (o que está atrasado/fraco/arriscado)

Ordenado pelo que mais nos envergonharia num demo ou numa conversa de venda.

| # | Gravidade | Problema | Evidência | Impacto |
| --- | --- | --- | --- | --- |
| 1 | **Blocker** | "Arquivos expostos" (A04) só conhece **2 caminhos do Juice Shop** | `scanner/validation/exposed_files.py:17-20` (o próprio comentário admite "em cliente, a lista viria do escopo/descoberta") | Está no pipeline e vendido como cobertura A04. Em site real, sonda 2 caminhos que não existem → **não acha nada**. Móvel de laboratório. |
| 2 | ~~Blocker~~ **Resolvido** | IDOR / controle de acesso (A01) agora **está no pipeline** | `run_access_control` (`web_scan/proactive.py`) roda na etapa 4 via ZAP; chamado de `web_scan/service.py`. Configurável pelo formulário de login-teste (2º usuário + recursos). | Era o item-bandeira do roadmap. Entregue nesta sessão (ver topo). Falta só a revisão visual da tela. |
| 3 | **Médio** | Remediação roda num **MVP via Groq (gpt-oss-120b)**, não Claude — escolha consciente por falta de chave Anthropic. A engenharia é segura (mascara antes de enviar, saída validada por Pydantic, fallback para catálogo: `llm.py:46-62,145-178`). **Residual:** (a) o pitch diz "Claude" (CLAUDE.md:196, docstring do `llm.py`) mas não é o que roda; (b) **qualidade da remediação não é medida** — não existe o conjunto de avaliação que a CLAUDE.md exige | `.env` vivo: `openai_compatible` + `gpt-oss-120b`; `common/config.py:58` padrão `none` | Pitch desonesto se mostrar "Claude" a cliente. E o nosso valor central ("correção executável, não genérica") está **sem prova**: se o modelo grátis entrega texto vago, o diferencial morre e não saberíamos. |
| 4 | **Alto** | Recon (etapa 2) é **teatro**: as portas do naabu são descartadas e o CVE só varre `base_urls[0]` | `recon/service.py:111-120` calcula `ports` e joga fora; `cve/service.py:60` `target_url = scope.base_urls[0]` | Alvo com vários hosts ou porta fora do padrão passa batido. A razão de existir da etapa 2 (achar serviço em porta incomum) é decorativa. |
| 5 | ~~Alto~~ **Resolvido** | Scan autenticado agora suporta login **JSON/Bearer e formulário/cookie** | Modo `form` em `web_scan/zap.py` (`build_login_request`/`login_response_cookies`); seletor no formulário de login-teste. | Entregue nesta sessão. Destrava a área logada em sites de PME com sessão por cookie. Falta só login com CSRF token. |
| 6 | **Médio** | SCA é **CLI órfã**, fora do pipeline | `scanner/sca/__main__.py`; não há stream `scan.sca.*` nem worker; nada fora de `scanner/sca/` o importa | Quem espera SCA dentro de um scan não recebe nada. Combina com o roadmap ("input opcional"), mas não pode ser implicado como ativo. |
| 7 | **Médio** | **Sem CVSS e sem SARIF** | `validation/severity.py:8-24` é um dicionário CWE→severidade feito à mão; grep não acha CVSS nem export SARIF | Itens de paridade que o roadmap já reconhece. Concorrente e comprador técnico vão perguntar. |
| 8 | **Médio** | Perfil `safe` **dispara bloqueio de conta** no alvo | `web_scan/service.py:189-192` roda `run_login_lockout` (tentativas de senha erradas) sempre que há credencial, sem olhar o perfil; CLAUDE.md regra #3 diz que `safe`/`balanced` não têm regra destrutiva | Viola a nossa própria promessa de "safe = não destrutivo". Só atinge a conta de teste, mas o time de segurança do cliente vê a conta travando num scan "não destrutivo". Problema de integridade, não só de demo. |
| 9 | **Baixo** | Documentação mente contra o código | CLAUDE.md:191 ainda diz "hoje publica só scan.web.requested; faltam 2 recon e 3 CVEs" — mas o pipeline **está** ligado ponta a ponta (`web/services.py:190` → recon → cve+web → candidates → validated → report) | Doc desatualizada corrói confiança de quem entra no projeto. |
| 10 | **Baixo** | Ausência de binário (naabu/nuclei) é engolida em silêncio | `recon/service.py:112-115`, `cve/service.py:63-66` capturam o erro e seguem com resultado vazio, logando erro | Um worker mal provisionado produz recon/CVE vazios e ainda reporta "scan completo". Dá para subir um deploy que parece saudável sem fazer nada nas etapas 2/3. |
| 11 | **Baixo** | ID de modelo a confirmar | `common/config.py:52` e CLAUDE.md:196 usam `claude-opus-5-5` | Inócuo com `provider=none/openai`, mas daria erro se alguém virar `provider=anthropic` sem conferir o ID atual na API. |

**Atrasos em relação ao que já prometemos** (não são features novas, é dívida): A04 real (#1), IDOR
no pipeline (#2), IA ligada com Claude (#3), recon de verdade (#4), login por formulário (#5). Esses
cinco são "já deveria funcionar e não funciona".

## Parte 2 — O que está forte (proteger, não quebrar)

- **Endurecimento da própria interface é real**, não aspiracional: Argon2id + rehash
  (`web/security.py:8,65`), bloqueio após 5 tentativas (`:17-61`), CSRF em todo router mutante
  (`auth.py:16`, `client.py:56`, `admin.py:32`), CSP estrita sem inline (`security.py:97-110`),
  cookie `HttpOnly`/`SameSite`, docs desabilitados. É um ativo de venda ("passamos no nosso próprio
  scanner") — e é verdade.
- **Isolamento entre clientes** responde 404 (não 403) em objeto de outra org (`web/tenancy.py`).
- **Comparação com o scan anterior é honesta**: avisa quando o crawl cobriu menos de 80% das páginas
  e não trata ausência como "corrigido" (`web/services.py:228,244`).
- **Disciplina de contrato**: `schema_version` é campo de primeira classe e há teste que valida o
  `model_dump()` contra o JSON Schema (`tests/unit/test_contract.py`).
- **Build verde de verdade** (295 testes, ruff, mypy).

## Parte 3 — Plano priorizado para ganhar

Quatro faixas, em ordem. Não pular a P0: ela é "parar de perder", pré-requisito de qualquer venda.

### P0 — Parar de perder no demo (semanas 1–2)

- [ ] **A04 real:** trocar a lista fixa de 2 caminhos por uma lista de verdade + o que o recon
      descobriu (`exposed_files.py`). Sem isso, não demonstrar A04. *(blocker #1)*
- [ ] **IDOR no pipeline:** ligar `run_access_probe`/`classify_access` na etapa 5 com 2 credenciais
      por site; tirar A01 de "parcial" em `coverage_map.py`. *(blocker #2)*
- [ ] **Remediação (MVP Groq):** (a) tirar "Claude" de tudo que é visível ao cliente enquanto roda
      gpt-oss; ajustar CLAUDE.md:196 e a docstring do `llm.py`. (b) **Construir o conjunto de avaliação
      de remediação** (achados por CWE/stack → rubrica "a correção é concreta: comando/config/código?")
      e rodar gpt-oss vs. catálogo — é o portão para mostrar a cliente e para qualquer troca de modelo.
      *(médio #3)*
- [ ] **Corrigir o `safe` que trava conta:** condicionar `run_login_lockout` ao perfil (não rodar em
      `safe`/`balanced`), ou reclassificar a prova como não destrutiva de verdade. *(médio #8, integridade)*
- [ ] **Atualizar CLAUDE.md:191** e varrer doc desatualizada. *(baixo #9)*

### P1 — Fechar paridade (semanas 3–6)

- [ ] **Recon de verdade:** levar as portas do naabu adiante e o CVE varrer todos os `base_urls`/hosts
      descobertos, não só o primeiro. *(alto #4)*
- [ ] **Login por formulário/cookie** (Playwright, que já usamos em `tests/ui_shots.py`): destrava
      área logada e faz A07/A08 dispararem em site de PME real. *(alto #5)*
- [ ] **CVSS por achado e export SARIF:** paridade que o comprador técnico cobra. *(médio #7)*
- [ ] **Benchmark próprio como gate em CI:** recall + taxa de falso positivo contra Juice Shop e DVWA,
      com achados esperados gravados (hoje `tests/lab_coverage.py` roda à mão). É o número que
      responde "e vocês, quanto acham?".
- [ ] **Falha de binário não pode ser silenciosa:** recon/CVE vazios por falta de naabu/nuclei devem
      marcar o scan como degradado, não "completo". *(baixo #10)*

### P2 — Diferencial (o Pentest + a prova)

- [ ] Novos validadores com prova não destrutiva: SSTI, path traversal, SQLi booleano, XSS
      armazenado/DOM (por navegador). Amplia a cobertura de prova sem sair da trava.
- [ ] SCA opcional dentro do scan (stream + worker ou chamada direta), não CLI órfã. *(médio #6)*
- [ ] Produto Pentest (agente dentro da trava) conforme `docs/produto-pentest.md`, Etapa 0 em diante.
- [ ] Enquadrar a prova como **postura de confiança** (recibo da prova + "o LLM nunca descarta um
      verdadeiro positivo"), não como mais um banner de "zero falso positivo" — porque isso todo
      concorrente já diz (ver `docs/concorrentes.md`).

### P3 — Mensagem e mercado (em paralelo, barato)

- [ ] **Segurança de produção concreta e visível:** página pública explicando DNS + escopo + perfis.
      A Horizon3 já usa "production-safe" como bandeira; a nossa precisa ser específica.
- [ ] **Selo de confiança** (estilo Site Blindado) amarrado à prova e à remediação — gancho que a
      PME/e-commerce entende.
- [ ] **Gancho de conformidade LGPD/ANPD e CMN 5.274/2025** no relatório — diferencial local.
- [ ] Mensagem sempre pelo **pacote** (pt-BR + leigo + produção-segura + prova + preço de PME), nunca
      só "a gente confirma".

## Parte 4 — Como medimos que estamos ganhando

- **P0 pronto** = num site de prospect (com autorização), A04 e IDOR produzem achado real, e a
  remediação sai em pt-BR **concreta** (medida pelo eval, não "gerada pelo Claude" como rótulo).
  Hoje A04 e IDOR não produzem achado real, e a qualidade da remediação não é medida.
- **Número público**: recall contra Juice Shop/DVWA rodando em CI, com falso positivo medido. Sem ele,
  "somos melhores" é opinião.
- **Sem regressão de integridade**: nenhum perfil `safe`/`balanced` executa ação que mude estado no
  alvo (reauditar contra a regra #3 da CLAUDE.md).

## Decisões que preciso de você

- [ ] A remediação roda hoje no MVP Groq (gpt-oss). Prioridade: **conseguir a chave Anthropic e
      migrar para Claude**, ou **validar que o gpt-oss é bom o bastante** (via eval) e segurar o MVP?
      Recomendo o eval primeiro — ele decide, com dado, se vale a migração.
- [ ] Prioridade entre fechar a **dívida do Scanner** (P0/P1) e começar o **Pentest** (P2): recomendo
      P0 inteiro antes de abrir o Pentest, senão vendemos dois produtos e nenhum fecha.
- [ ] Perseguir **CVSS/SARIF** agora (paridade técnica) ou **selo/LGPD** agora (venda PME)? Dá para
      fazer os dois na P1/P3, mas qual puxa a fila?
