# Pitchy Security — dois produtos

> Documento de apresentação. Público: diretoria. Resumo do posicionamento, do que já é real e do que
> falta para competir. Detalhe técnico em `docs/plano-de-acao.md`, `docs/concorrentes.md` e
> `docs/roadmap-por-produto.md`.

## Resumo executivo

Temos dois produtos sobre a mesma base, vendáveis separadamente: o **Scan** (automático, roda no site
oficial com segurança) e o **Pentest** (agente que aprofunda, no próximo ciclo). O mercado de "achado
com prova" está lotado e "sem falso positivo" virou discurso padrão — então **o nosso diferencial não
é a prova, é o pacote**: português nativo, correção que um leigo executa, segurança de produção de
verdade (verificação de domínio, trava de escopo, perfis) e preço de PME. **No Brasil não existe um
líder financiado com esse pacote** — o espaço está aberto. A base técnica é sólida (build verde, 303
testes, interface endurecida), e nesta rodada fechamos defeitos que nos envergonhariam num demo e
adicionamos itens de paridade (CVSS, export SARIF). Falta uma sprint para o diferencial de fundo
(IDOR no pipeline, login por formulário).

## Os dois produtos

| | **Scan** (agora) | **Pentest** (próximo ciclo) |
| --- | --- | --- |
| O que é | Scanner automático de URL/domínio: aponta para o site e devolve relatório acionável | Agente que raciocina e aprofunda (IDOR, SSTI, lógica de negócio), dentro da mesma trava |
| Alvo | Site no ar (produção), caixa-preta | Site no ar ou cópia de teste |
| Quem compra | PME sem time de segurança; e-commerce | Quem já tem o Scan e quer profundidade; exigência de conformidade |
| Como roda | Contínuo, barato, reproduzível, seguro para produção | Sob demanda, mais caro, mais fundo |
| Estado | **Em produção, sendo endurecido** | **Definido e especificado** (`docs/produto-pentest.md`) |

Os dois se ajudam: o Scan gera o mapa do site e os candidatos; o Pentest parte daí. Mas o cliente pode
assinar só um.

## Onde estamos no mercado

Três fatos que orientam a estratégia (pesquisa em `docs/concorrentes.md`):

1. **"Prova / zero falso positivo" é table stakes.** Invicti (99,98%), Acunetix, Detectify (99,7%),
   Pentest-Tools e os agentes de IA (XBOW, Terra, Astra) já anunciam. Não lideramos com isso.
2. **O nosso fosso é o pacote para a PME brasileira:** pt-BR nativo + remediação para leigo +
   segurança de produção concreta + prova + preço e self-serve de PME. Ninguém junta os cinco no
   nosso público.
3. **O Brasil está aberto.** Os DAST com prova (Invicti ~US$ 7k+/ano) pedem especialista; os agentes
   de IA custam US$ 18k–100k+/ano; os players locais (Conviso, Tempest, BugHunt) são código/dev,
   consultoria ou bug bounty. O mais perto do nosso pitch é um **MVP indie** (Caramelo Sec) — demanda
   real, ninguém venceu. Vento a favor: LGPD/ANPD e CMN 5.274/2025 exigindo teste.

### Comparação condensada

| | Pitchy | DAST enterprise (Invicti/Acunetix) | Agentes de IA (XBOW/Horizon3) | Local (Conviso/Site Blindado) |
| --- | --- | --- | --- | --- |
| Alvo | PME, leigo, pt-BR | Time de segurança | Enterprise, inglês | BR, mas dev/código ou selo clássico |
| Preço | PME | ~US$ 7k+/ano | US$ 18k–100k+/ano | variado |
| Prova | sim | sim | sim | parcial |
| Produção-seguro explícito | **sim, concreto** | sim | parcial (Horizon3 em infra) | parcial |
| Remediação para leigo em pt-BR | **sim** | não | não | parcial |

## O que já é real hoje (verificável)

Honesto — sem móveis de laboratório:

- **Pipeline ponta a ponta** funcionando (recon → CVE + web → validação → relatório).
- **Interface endurecida de verdade** (passa no nosso próprio scanner): Argon2id, CSRF em tudo, CSP
  estrita, bloqueio de login, isolamento entre clientes (404, não 403).
- **Prova determinística** em 7 famílias (XSS, SQLi, redirecionamento, cabeçalhos, cookies, path
  traversal, SSTI) + A04 (arquivos expostos, agora com lista real) + IDOR, JWT e bloqueio de login
  quando há credencial (login por token **ou** formulário/cookie).
- **Paridade nova nesta rodada:** CVSS por achado e **export SARIF** (entra no fluxo de CI como os
  grandes). Correção de integridade: perfil seguro não trava mais a conta do cliente.
- **Qualidade da remediação medida** por um eval objetivo (o nosso valor central, "correção
  executável", agora tem prova, não promessa).
- **Assertividade e constância medidas:** um benchmark mede o que provamos por família OWASP e
  **falha o build se uma capacidade de prova regride** — a qualidade não cai em silêncio.
- **Cobertura de API:** importa OpenAPI/Swagger e testa os endpoints, não só o que o spider acha.
- **Build verde:** 330 testes, lint e tipos limpos.

Em andamento (próxima sprint): IDOR no pipeline, login por formulário/cookie, recon de portas.

## Roadmap

- **Feito agora:** A04 real, CVSS, SARIF, eval de remediação, correção do perfil seguro, honestidade
  de doc.
- **P0 (resto) — parar de perder no demo:** IDOR no pipeline; decidir a IA (ver abaixo).
- **P1 — paridade:** login por formulário; recon de portas; benchmark próprio (recall + falso
  positivo) rodando em CI.
- **P2 — diferencial:** Pentest (agente dentro da trava); mais provas (SSTI, path traversal).
- **P3 — mercado:** segurança de produção visível (página + selo); gancho LGPD/CMN no relatório.

## Decisões para hoje

1. **IA de remediação:** hoje roda num MVP via Groq (gpt-oss), não Claude — escolha consciente por
   falta de chave Anthropic, e bem construída (mascara dados, valida saída, cai no catálogo em falha).
   Pedido: **liberar a chave Anthropic** para migrar ao Claude (o eval prova o ganho antes de trocar),
   ou manter o MVP e validar o gpt-oss. Enquanto for Groq, **não dizer "Claude" ao cliente**.
2. **Foco:** concluir o Scan (P0/P1) antes de abrir o Pentest, para não vender dois produtos e não
   fechar nenhum.
3. **Prioridade de mercado:** CVSS/SARIF (paridade técnica, já entregue) vs. selo + LGPD (venda PME) —
   qual puxa a fila da P3.
