# Roadmap por produto — três superfícies

> Corrige a versão anterior do plano, que misturava "determinístico" com "baseado em URL". O Scanner
> é e continua **baseado em URL/domínio** (caixa-preta, por fora, contra o site no ar). Itens que
> precisam do repositório (SAST, SCA no repo, revisão de PR por diff, autofix como PR) **não** são do
> Scanner — são uma terceira superfície, a decidir.
>
> Companheiro de `docs/produto-pentest.md` e da análise do Strix.

## A linha que divide tudo

Dois eixos, não um:

- **Eixo URL/domínio (nosso fosso):** aponte para o site no ar. É onde mora a nossa segurança
  (verificação de domínio por DNS, trava de escopo, perfil que não derruba produção). Scanner e
  Pentest vivem aqui.
- **Eixo código/repositório (mercado lotado):** precisa de acesso ao código. SAST, SCA, revisão de
  PR, autofix como PR. Snyk, Semgrep, Dependabot, GitHub Advanced Security já dominam. **Não** carrega
  o nosso diferencial.

Regra da linha, dentro do eixo URL: **Scanner = seguro e determinístico o bastante para rodar sozinho
em produção e no CI; Pentest = precisa de raciocínio ou de autorização mais forte.**

## As três superfícies

| Superfície | Alvo | Vende | Itens do plano |
| --- | --- | --- | --- |
| **Scanner** | URL/domínio, caixa-preta, no ar | Seguro, contínuo, barato, reproduzível, confirmado | Fechar o buraco de prova (IDOR no pipeline, validadores novos, login por navegador, benchmark próprio); CVSS e SARIF; recorrência; API/CLI + código de saída para disparar scan de URL no CI (contra URL de homologação) |
| **Pentest** | URL/domínio ou cópia de teste, agente | Profundidade, raciocínio, encadeia falhas, lógica de negócio | Agente dentro da trava; import OpenAPI/GraphQL para semear o agente; SSRF/OAST no perfil intrusivo; reteste sob demanda |
| **Código/repo** (aposta consciente, depois) | Repositório | Entra no fluxo do dev | SAST, SCA no repo, revisão de PR por diff, autofix como PR |

## O que é do Scanner e o que não é

- **É do Scanner (URL):** disparar um scan de URL pelo CI e falhar o build por código de saída; isso
  roda contra uma URL de homologação, não contra o código.
- **NÃO é do Scanner:** revisão de PR por diff e autofix como PR — exigem o repositório; são da
  superfície código/repo.
- **Meio-termo:** a correção de cabeçalhos/cookies sai como **texto no relatório** (conselho de
  config), não como PR, porque não temos o repo do cliente no eixo URL.
- **SCA (npm/PyPI via OSV)** já existe meio pronto (`scanner/sca`). Pode entrar como **input opcional**
  (o cliente sobe o manifesto), sem virar produto. Virar "produto de código" é decisão à parte.

## Por que isso ganha do concorrente

- A história de "contínuo e no CI" dos agentes de LLM (ex.: Strix) roda no **agente caro e variável**
  (ordem de US$ 3 por alvo, 1 a 4 h). Se o nosso **Scanner** dona "barato + seguro + reproduzível + no
  CI + confirmado", o agente deles não acompanha no custo para rodar o tempo todo.
- O **Pentest** cobre a profundidade (IDOR, SSTI, lógica de negócio) quando o cliente quer, sem perder
  a trava de segurança.
- O eixo **código/repo** fica para depois porque é onde somos mais fracos e o mercado é mais disputado;
  perseguir cedo demais dilui o fosso (URL + segurança + relatório para leigo em pt-BR).

## Decisões em aberto

- [ ] Perseguimos o eixo código/repo algum dia, ou ficamos 100% em URL/domínio?
- [ ] O SCA por manifesto entra como input opcional do Scanner, ou espera virar produto de código?
- [ ] "Disparar scan pelo CI" exige URL de homologação pública — isso cabe no perfil `safe` do cliente?

## Posicionamento vs. concorrentes

Pesquisa completa em `docs/concorrentes.md`. O que ela muda neste roadmap:

- **"Achado confirmado por prova" não é mais diferencial** — Invicti, Acunetix, Detectify,
  Pentest-Tools e todo o cluster de IA já vendem isso. O roadmap do Scanner continua valendo (fechar
  o buraco de prova é necessário para **paridade**), mas a **mensagem** não pode ser "a gente
  confirma".
- **O fosso é o pacote para a PME brasileira:** pt-BR nativo + remediação para leigo + segurança de
  produção **concreta** (DNS, escopo, perfis) + prova + self-serve barato. Nenhum concorrente combina
  os cinco no nosso público.
- **Segurança de produção precisa ser concreta e visível**, porque a Horizon3 já usa "production-safe"
  como bandeira (em infra). Vira item de roadmap: página pública + selo + gancho de conformidade
  (LGPD/ANPD, CMN 5.274/2025).
- **Confirmamos a decisão de não perseguir código/repo nem rede/nuvem cedo:** é onde Snyk, Conviso e
  Horizon3 são fortes e nós, fracos.
- **Vigiar:** Caramelo Sec (MVP com o mesmo pitch), Site Blindado (selo PME), Invicti via
  Software.com.br (já em português por canal), e Astra/Beagle/MindFort (IA self-serve, em inglês).
