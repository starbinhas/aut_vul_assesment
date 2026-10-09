# Concorrentes — pesquisa de mercado (2026-10-08)

> Pesquisa séria para posicionar o produto. Resumo: o mercado é grande e disputado, mas há um vazio
> claro no nosso alvo. **"Achado confirmado por prova" deixou de ser diferencial** — quase todo mundo
> já vende isso. Nosso fosso é o **pacote** para a PME brasileira (ver "Nosso fosso").
>
> Companheiro de `docs/roadmap-por-produto.md`, `docs/produto-pentest.md` e da análise do Strix.
>
> **Aviso sobre números:** quase todo preço aqui é estimativa de terceiros (Beagle, G2, Vendr,
> costbench), não tabela oficial. Tração (funding, nº de clientes, % de falso positivo) é declarada
> pelo fornecedor e **não auditada**. Tratar como direcional; conferir antes de pôr em qualquer deck.

## Veredito estratégico (o que importa)

1. **Prova virou "table stakes".** Invicti ("Proof-Based Scanning", "99,98% de precisão", exploits
   seguros só-leitura), Acunetix (proof-of-exploit), Detectify ("99,7% de true positive"),
   Pentest-Tools ("scans to proof") e todo o cluster de IA (XBOW, Terra, Hadrian, Astra, MindFort)
   já anunciam "validado por exploração / zero falso positivo". **Não podemos liderar com "a gente
   confirma".**
2. **Nosso diferencial é um pacote, não uma feature.** Ninguém combina, para a PME brasileira sem
   time de segurança: **pt-BR nativo + remediação que um leigo executa + segurança de produção
   concreta (verificação de domínio por DNS, trava de escopo, perfis) + prova determinística + preço
   e self-serve de PME.** É esse conjunto que lidera a venda.
3. **"Production-safe" já tem dono no enterprise** (Horizon3/NodeZero faz disso bandeira, em rede).
   Nossa mensagem de segurança precisa ser **concreta** (os perfis, a trava, o DNS), não genérica.
4. **O vento regulatório é real no Brasil:** LGPD com a ANPD já aplicando sanções e pedindo evidência
   de teste, e no setor financeiro a Resolução CMN 4.893/2021 (atualizada pela 5.274/2025) exige
   pentest independente ao menos anual, com retenção de 5 anos. Demanda de PME existe e tem prazo.
5. **Não brigar de frente com o cluster de IA enterprise** (XBOW, Horizon3, Pentera): dezenas a
   centenas de milhões em funding, público e idioma errados para nós. Nosso Pentest ataca o mesmo
   problema no segmento que eles ignoram.

## Grupo 1 — Agentes de IA autônomos (enterprise, o Pentest briga aqui, de lado)

| Concorrente | Público e preço | Superfície | Como nos ameaça / tração declarada |
| --- | --- | --- | --- |
| [XBOW](https://xbow.com/blog/series-b) | Enterprise (bancos, techs); preço fechado | Web/app (DAST-like) | Halo de marca: 1º lugar no ranking US do HackerOne (jun/2025); US$ 75M Série B, depois US$ 120M Série C a >US$ 1bi. Números do HackerOne contestados por ruído. |
| [Horizon3 / NodeZero](https://horizon3.ai/) | Enterprise/governo; ~US$ 18,6k/ano (estimativa) | Rede + externo + nuvem + web | Dona do "production-safe" (bandeira direta contra nós, mas em infra). US$ 250M Série E a >US$ 2bi; "6.500+ orgs", "225–310 mil testes" (números inconsistentes). |
| [Pentera](https://techcrunch.com/2025/03/12/pentera-nabs-60m-at-a-1b-valuation-to-build-simulated-network-attacks-to-train-security-teams) | Enterprise; ~US$ 35–100k/ano (estimativa) | Rede/infra | Líder de "validação automática". US$ 60M a US$ 1bi (mar/2025). Pouca ameaça ao nosso nicho web/PME. |
| [RunSybil](https://fortune.com/2026/03/18/exclusive-ai-cybersecurity-startup-runsybil-founded-by-openais-first-security-hire-raises-40-million-led-by-khosla-ventures) | US techs/regulados; fechado | App ao vivo | Fundadores de elite (1º de segurança da OpenAI), US$ 40M (Khosla; **Anthropic Anthology Fund**). Logos: Cursor, Notion. Postura ofensiva, sem trava explícita. |
| [Terra Security](https://www.terra.security/blog/terra-security-raises-30m-series-a-to-redefine-penetration-testing-with-agentic-ai) | Fortune 500; fechado | Web + rede + IA | Agente + humano no loop; US$ 30M Série A. Humano no loop = caro e lento = estruturalmente não-PME. |
| [Ethiack](https://blog.ethiack.com/blog/ethiack-raises-a-4-million-funding-round-to-develop-ai-powered-hackbots) (Portugal) | Enterprise EU; fechado | Superfície/contínuo | Proximidade de idioma (pt-PT) e EU. Pequena (€4M, ~50 clientes). Tratamento de falso positivo mais fraco que o nosso. |
| [Astra](https://astrasecurity.featurebase.app/changelog/introducing-astras-autonomous-pentest), [MindFort](https://www.mindfort.ai/blog/best-ai-pentesting-tools-2026-buyers-guide), Hadrian | Mid-market/PME; mais acessível | Web/pentest | **Vigiar de perto:** perfil mais próximo do nosso (self-serve, "validador independente", preço menor). Inglês. |

> Mindgard (segurança de modelos de IA) e Strix (ver doc próprio) completam o cluster.

## Grupo 2 — DAST SaaS (o Scanner briga aqui)

| Concorrente | Público e preço (estimativa) | Prova / falso positivo | Como nos ameaça |
| --- | --- | --- | --- |
| [Invicti](https://www.invicti.com/features/accurate-proof-based-scanning-technology/) (ex-Netsparker) | Enterprise; ~US$ 7k+/ano, fechado | **A régua:** Proof-Based Scanning, "99,98%", confirma 94% dos de impacto direto | Revende no Brasil via [Software.com.br](https://www.cbinsights.com/company/softwarecombr) com suporte em português — mas é cotação, não self-serve. Caro e exige time de segurança. |
| [Acunetix](https://beaglesecurity.com/blog/article/acunetix-review.html) (Invicti) | Mid-market; ~US$ 7k/ano por alvo | Proof-of-exploit + IAST (ainda há FP de XSS em reviews) | Preço por alvo pune site pequeno. |
| [Detectify](https://beaglesecurity.com/blog/article/detectify-pricing.html) | Mid/enterprise; de ~US$ 90/mês | Payload-based, "99,7% true positive" | Marca forte, cobertura via 400+ hackers, EASM. Inglês, remediação genérica. |
| [Intruder.io](https://beaglesecurity.com/blog/article/intruder-pricing.html) | **PME-to-mid** (gêmeo de posicionamento); ~US$ 99–499/mês; pentest de app US$ 3,5–4k | Foco em priorizar ruído, não "prova determinística" | GTM de PME maduro, infra+nuvem que não temos. Profundidade web fina. |
| [Probely](https://alternativeto.net/software/probe-ly/about) (Snyk) | PME/dev; de ~€39/mês | "False-positive free" com instruções de correção | Comprada pela **Snyk** (abr/2025): distribuição + dev. Português **europeu**, agora puxado pra cima/dev. |
| [Rapid7 InsightAppSec](https://www.rapid7.com/products/insightappsec/pricing/) | Mid/enterprise; de US$ 175/mês por app | "Attack Replay" reproduz o ataque | Ecossistema, mas por-app acumula; overkill pra PME. |
| [Qualys WAS](https://beaglesecurity.com/blog/article/qualys-pricing.html) | Enterprise/PCI; de ~US$ 1.995/ano (25 apps) | Volume > prova; forte em PCI | Complexo demais pro leigo. |
| [StackHawk](https://beaglesecurity.com/blog/article/stackhawk-pricing.html) | **Dev/CI**; "Wingman" US$ 10/user/mês | Reprodução via curl no CI | Público errado pra temer: precisa de dev e pipeline; nosso comprador não tem. |
| [Burp Suite DAST](https://cipherssecurity.com/burp-suite-pricing-2026-pro-vs-dast/) (PortSwigger) | Enterprise/pentester; ~US$ 6–50k/ano | Padrão-ouro de precisão (OAST/collaborator) | Exige expertise; não é relatório self-serve. |
| [Pentest-Tools.com](https://www.g2.com/products/pentest-tools-com/pricing) | PME/consultor; US$ 95–190/mês | "Scans to proof" | **Conceito próximo** ao nosso, barato — mas é um kit para operador pentester, sem trava de produção. "2.000+ times, 119 países". |
| [Beagle Security](https://beaglesecurity.com/blog/article/top-rated-dast-tools.html) | PME; ~US$ 119–359/mês | DAST com IA, relatórios de conformidade | **Vigiar:** concorrente PME próximo. Inglês. |

## Grupo 3 — PTaaS, crowd e BAS (adjacentes)

- **Cobalt.io, HackerOne, Bugcrowd, Synack:** pentest humano / crowd, enterprise, inglês, caro
  (dezenas de milhares/ano). Ganham em profundidade humana e selo de conformidade; perdem em preço,
  velocidade e self-serve. Uma PME não roda um programa de bug bounty.
- **AttackIQ, SafeBreach (BAS):** simulam ataque contra controles (EDR/SIEM) no ambiente, não é scan
  de URL. Não é concorrente real do "URL entra → relatório sai".

## Grupo 4 — Brasil / pt-BR (nosso campo)

| Concorrente | O que é | Por que não ocupa nosso lugar |
| --- | --- | --- |
| [Conviso](https://convisoappsec.com/platform/pricing) (ConvisoAppSec) | ASPM BR (SAST/DAST/SCA) + consultoria; de US$ 19/dev/mês | Centrado em **código/dev** e SDLC — altitude errada pro dono de PME não-técnico. Comprou a N-Stalker (DAST). |
| [Site Blindado](https://site-blindado.freshservice.com/support/solutions/articles/23000016123) | Scanner web + **selo** de confiança; forte em e-commerce | Dona o nicho de selo PME/e-commerce, mas é scanner **clássico** (sem prova determinística nem remediação por IA). O selo é uma feature que podemos copiar. |
| [Tempest](https://www.tempest.com.br/en/consulting/pentest) | Maior consultoria cyber BR; pentest humano (~80% manual) | Serviço, enterprise, não self-serve nem preço de PME. |
| [Clavis](https://braziljournal.com/a-clavis-quer-ser-a-solucao-anti-hacker-das-pmes-a-visagio-entrou-na-guerra/) | Cyber BR mirando PME; detecção/resposta + pentest; ~R$ 15M captados | Produto de detecção gerenciada, não scan de URL self-serve. |
| [BugHunt](https://startups.com.br/negocios/bughunt-avanca-na-america-latina-para-levar-bug-bounty-a-novos-mercados/) | Bug bounty BR ("25 mil hackers"); OLX, Enjoei | Crowd/enterprise; PME não roda bounty. |
| [HackerSec](https://hackersec.com/about?lang=en) | "Maior de segurança ofensiva da LatAm" (declarado) | Serviços ofensivos, não produto self-serve. |
| Caramelo Sec ([MVP, TabNews](https://www.tabnews.com.br/maincarmem/criei-um-scanner-de-seguranca-pra-saas-apis-e-sites-voce-so-joga-a-url)) | **Espelho quase exato do nosso pitch:** "você só joga a URL" → DAST + remediação + autofix por IA, em português, pra dev indie sem orçamento | Indie, MVP, sem funding. **Prova que a demanda e o posicionamento são reais — e que não somos os primeiros a tentar.** Ninguém venceu ainda. |

## Nosso fosso (onde ganhamos)

Ninguém combina **tudo isto para a PME brasileira sem time de segurança**:

1. **pt-BR nativo** (não pt-PT, não inglês com revenda) + remediação que um dev/gestor leigo executa
   (comando, config ou trecho de código), não "aumente sua postura de segurança".
2. **Segurança de produção concreta** como argumento de venda: verificação de domínio por DNS, trava
   de escopo em código, perfis `safe`/`balanced` que não derrubam o site, `intrusive`/`aggressive`
   só em cópia liberada. Isso é o que nos deixa rodar no site oficial sem medo.
3. **Prova determinística + o LLM nunca descarta um verdadeiro positivo** — enquadrar como postura de
   **correção/confiança** (apoiada no recibo da prova), não como mais um banner de "zero falso
   positivo".
4. **Self-serve e preço de PME** — os DAST com prova (Invicti/Acunetix) custam US$ 7k+/ano e pedem
   time de segurança; os agentes de IA custam US$ 18k–100k+/ano.
5. **Vento regulatório** (LGPD/ANPD, CMN 5.274/2025) dá urgência e um gancho de conformidade.

## Ameaças a vigiar

- **Caramelo Sec** (mesmo pitch, indie) — se levantar dinheiro, vira concorrente direto.
- **Site Blindado** — incumbente de selo na PME; o selo é um gancho de venda real.
- **Invicti via Software.com.br** — já chega no Brasil em português (canal/cotação).
- **Astra, Beagle, MindFort** — agentes/DAST de IA com perfil self-serve/PME; inglês, por enquanto.
- **Probely dentro da Snyk** — se a Snyk descer de preço e localizar, aperta.

## Implicações para o roadmap

- **Mensagem:** liderar com o pacote (pt-BR + leigo + produção-segura + prova), nunca só com "a gente
  confirma". Tornar a segurança de produção **concreta e visível** (página pública, perfis, DNS).
- **Feature de venda a considerar:** um **selo** (estilo Site Blindado) amarrado à prova e à
  remediação — gancho de confiança que a PME/e-commerce entende.
- **Conformidade:** relatório com gancho LGPD/CMN é diferencial local, não só OWASP.
- **Não perseguir** cedo o eixo código/repo nem rede/nuvem/infra: é onde os gigantes (Snyk, Conviso,
  Horizon3) são fortes e nós, fracos.

## Fontes

Agrupadas por concorrente nos links acima. Principais páginas abertas: Invicti Proof-Based Scanning,
Rapid7 InsightAppSec (preço oficial), Conviso Platform (preço), XBOW (Série B/C), Horizon3 (Série E),
Pentera (TechCrunch), RunSybil (Fortune), Terra (blog), Site Blindado (selo), Caramelo Sec (TabNews),
DeepStrike (mercado BR, LGPD/CMN), e páginas de preço de terceiros (Beagle, G2, costbench, Vendr) para
os fornecedores de cotação fechada. Números de funding/tração são declarados e não auditados.
