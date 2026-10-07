"""Remediações estáticas (pt-BR).

Usadas quando o LLM recusa (`stop_reason == "refusal"`), falha ou não está configurado.
Nenhum achado sai do relatório sem texto de remediação.
"""

from __future__ import annotations

from scanner.common.models import Finding
from scanner.report.models import FixStep, Remediation

_XSS = Remediation(
    what_it_is=(
        "Cross-Site Scripting (XSS) refletido: a página devolve o que veio na URL sem tratar, e o "
        "navegador interpreta esse conteúdo como parte da página."
    ),
    why_it_matters=(
        "Um atacante pode enviar um link preparado para um usuário. Ao abrir, código do atacante "
        "roda no navegador da vítima com a sessão dela: pode roubar dados exibidos, agir em nome do "
        "usuário ou mostrar um formulário falso de login."
    ),
    how_to_fix=[
        FixStep(
            title="Escape toda saída de dados no HTML",
            detail=(
                "Use o escape automático do seu motor de templates e nunca desligue-o para dados "
                "vindos do usuário. Em código, use a função de escape da linguagem."
            ),
            snippet=(
                "# Python (Jinja2)\nEnvironment(autoescape=True)\n\n"
                "// PHP\necho htmlspecialchars($valor, ENT_QUOTES, 'UTF-8');\n\n"
                "// React: renderize como texto ({valor}); evite dangerouslySetInnerHTML"
            ),
            snippet_language="text",
        ),
        FixStep(
            title="Adicione uma Content-Security-Policy",
            detail="A CSP limita de onde scripts podem ser carregados, reduzindo o impacto de um XSS.",
            snippet=(
                "add_header Content-Security-Policy \"default-src 'self'; script-src 'self'; "
                "object-src 'none'; frame-ancestors 'self'\" always;"
            ),
            snippet_language="nginx",
        ),
    ],
    how_to_verify=(
        "Acesse a URL do achado trocando o valor do parâmetro por <b>teste</b>: a página deve "
        "mostrar o texto literal '<b>teste</b>', e não 'teste' em negrito."
    ),
    references=[
        "https://owasp.org/www-community/attacks/xss/",
        "https://cheatsheetseries.owasp.org/cheatsheets/Cross_Site_Scripting_Prevention_Cheat_Sheet.html",
        "https://cwe.mitre.org/data/definitions/79.html",
    ],
)

_SQLI = Remediation(
    what_it_is=(
        "SQL injection: um valor enviado pelo usuário é colado diretamente dentro de uma consulta ao "
        "banco de dados, e consegue alterar a própria consulta."
    ),
    why_it_matters=(
        "Um atacante pode ler dados de outras tabelas (clientes, senhas), alterar ou apagar "
        "registros e, em alguns bancos, executar comandos no servidor."
    ),
    how_to_fix=[
        FixStep(
            title="Use consultas parametrizadas",
            detail=(
                "Nunca monte SQL concatenando strings. Passe os valores como parâmetros; o driver "
                "garante que eles são tratados como dados, nunca como código SQL."
            ),
            snippet=(
                '# Python (psycopg)\ncur.execute("SELECT * FROM produtos WHERE id = %s", (produto_id,))\n\n'
                "// PHP (PDO)\n$st = $pdo->prepare('SELECT * FROM produtos WHERE id = ?');\n"
                "$st->execute([$produtoId]);\n\n"
                "// Node (pg)\nawait client.query('SELECT * FROM produtos WHERE id = $1', [produtoId]);"
            ),
            snippet_language="text",
        ),
        FixStep(
            title="Não mostre erros do banco para o usuário",
            detail="Registre o erro no log do servidor e devolva uma mensagem genérica.",
            snippet="; php.ini\ndisplay_errors = Off\nlog_errors = On",
            snippet_language="ini",
        ),
        FixStep(
            title="Restrinja o usuário do banco",
            detail="A aplicação deve usar um usuário sem permissão de DDL nem acesso a outras bases.",
            snippet="REVOKE ALL ON ALL TABLES IN SCHEMA public FROM app;\nGRANT SELECT, INSERT, UPDATE ON produtos TO app;",
            snippet_language="sql",
        ),
    ],
    how_to_verify=(
        "Envie o valor 1' (com aspa) no parâmetro do achado: a página não pode mostrar mensagem de "
        "erro do banco e deve se comportar como para qualquer valor inválido."
    ),
    references=[
        "https://cheatsheetseries.owasp.org/cheatsheets/SQL_Injection_Prevention_Cheat_Sheet.html",
        "https://cwe.mitre.org/data/definitions/89.html",
    ],
)


def _header(
    name: str, what: str, why: str, nginx: str, apache: str, verify: str, ref: str
) -> Remediation:
    return Remediation(
        what_it_is=what,
        why_it_matters=why,
        how_to_fix=[
            FixStep(
                title=f"Envie o cabeçalho {name} (nginx)",
                detail="Adicione no bloco server do site e recarregue o nginx (nginx -s reload).",
                snippet=nginx,
                snippet_language="nginx",
            ),
            FixStep(
                title=f"Envie o cabeçalho {name} (Apache)",
                detail="Adicione no VirtualHost ou .htaccess (requer mod_headers).",
                snippet=apache,
                snippet_language="apache",
            ),
        ],
        how_to_verify=verify,
        references=[ref],
    )


_XFO = _header(
    "X-Frame-Options",
    "A página pode ser carregada dentro de um iframe de outro site (clickjacking).",
    "Um site malicioso pode exibir sua página invisível por baixo de botões falsos e induzir o "
    "usuário a clicar em ações reais (comprar, apagar, mudar configurações).",
    'add_header X-Frame-Options "SAMEORIGIN" always;\n'
    "add_header Content-Security-Policy \"frame-ancestors 'self'\" always;",
    'Header always set X-Frame-Options "SAMEORIGIN"\n'
    "Header always set Content-Security-Policy \"frame-ancestors 'self'\"",
    "curl -sI https://SEU-SITE/ | grep -i -E 'x-frame-options|frame-ancestors'",
    "https://cheatsheetseries.owasp.org/cheatsheets/Clickjacking_Defense_Cheat_Sheet.html",
)
_NOSNIFF = _header(
    "X-Content-Type-Options",
    "O servidor não impede que o navegador 'adivinhe' o tipo de um arquivo.",
    "Um arquivo enviado como texto ou imagem pode ser interpretado como script pelo navegador, "
    "abrindo caminho para execução de código malicioso.",
    'add_header X-Content-Type-Options "nosniff" always;',
    'Header always set X-Content-Type-Options "nosniff"',
    "curl -sI https://SEU-SITE/ | grep -i x-content-type-options",
    "https://developer.mozilla.org/docs/Web/HTTP/Headers/X-Content-Type-Options",
)
_HSTS = _header(
    "Strict-Transport-Security",
    "O site não obriga o navegador a usar sempre HTTPS.",
    "Na primeira visita ou em redes públicas, um atacante pode rebaixar a conexão para HTTP e "
    "interceptar senhas e cookies.",
    'add_header Strict-Transport-Security "max-age=31536000; includeSubDomains" always;',
    'Header always set Strict-Transport-Security "max-age=31536000; includeSubDomains"',
    "curl -sI https://SEU-SITE/ | grep -i strict-transport-security",
    "https://cheatsheetseries.owasp.org/cheatsheets/HTTP_Strict_Transport_Security_Cheat_Sheet.html",
)
_CSP = _header(
    "Content-Security-Policy",
    "O site não define uma política de quais scripts, estilos e frames podem ser carregados.",
    "Sem CSP, qualquer falha de XSS tem impacto máximo: o script injetado roda sem restrição.",
    "add_header Content-Security-Policy \"default-src 'self'; object-src 'none'; "
    "frame-ancestors 'self'; base-uri 'self'\" always;",
    "Header always set Content-Security-Policy \"default-src 'self'; object-src 'none'; "
    "frame-ancestors 'self'; base-uri 'self'\"",
    "curl -sI https://SEU-SITE/ | grep -i content-security-policy",
    "https://cheatsheetseries.owasp.org/cheatsheets/Content_Security_Policy_Cheat_Sheet.html",
)

_COOKIE = Remediation(
    what_it_is="Um cookie do site é criado sem os atributos de proteção recomendados.",
    why_it_matters=(
        "Sem HttpOnly, um script malicioso pode ler o cookie de sessão; sem Secure, ele pode trafegar "
        "sem criptografia; sem SameSite, o navegador o envia em requisições forjadas de outros sites."
    ),
    how_to_fix=[
        FixStep(
            title="Defina os atributos ao criar o cookie",
            detail="Cookies de sessão devem ter Secure, HttpOnly e SameSite=Lax (ou Strict).",
            snippet=(
                "Set-Cookie: sessao=...; Path=/; Secure; HttpOnly; SameSite=Lax\n\n"
                "# Django (settings.py)\nSESSION_COOKIE_SECURE = True\nSESSION_COOKIE_HTTPONLY = True\n"
                "SESSION_COOKIE_SAMESITE = 'Lax'\n\n"
                "// Express\napp.use(session({ cookie: { secure: true, httpOnly: true, sameSite: 'lax' } }));\n\n"
                "; PHP (php.ini)\nsession.cookie_secure = 1\nsession.cookie_httponly = 1\n"
                "session.cookie_samesite = Lax"
            ),
            snippet_language="text",
        ),
    ],
    how_to_verify="curl -sI https://SEU-SITE/ | grep -i set-cookie  # confira Secure; HttpOnly; SameSite",
    references=["https://owasp.org/www-community/controls/SecureCookieAttribute"],
)


def _generic(f: Finding) -> Remediation:
    return Remediation(
        what_it_is=f.title,
        why_it_matters=(
            "Esta falha foi detectada automaticamente. Consulte a referência abaixo para entender o "
            "impacto no contexto da sua aplicação."
        ),
        how_to_fix=[
            FixStep(
                title="Siga a orientação da referência para esta falha",
                detail=(
                    "Ainda não temos um passo a passo específico para este tipo de falha. A equipe de "
                    "suporte pode ajudar a priorizar e detalhar a correção."
                ),
            )
        ],
        how_to_verify="Após corrigir, solicite um novo scan e confirme que o achado não aparece mais.",
        references=[f"https://cwe.mitre.org/data/definitions/{f.cwe}.html"] if f.cwe else [],
    )


_BY_ZAP_RULE = {
    "40012": _XSS,
    "40018": _SQLI,
    "10020": _XFO,
    "10021": _NOSNIFF,
    "10035": _HSTS,
    "10038": _CSP,
    "10010": _COOKIE,
    "10011": _COOKIE,
    "10054": _COOKIE,
}
_BY_CWE = {79: _XSS, 89: _SQLI, 1021: _XFO, 614: _COOKIE, 1004: _COOKIE, 319: _HSTS}


def static_remediation(f: Finding) -> Remediation:
    for s in [f.source, *f.related_sources]:
        if s.tool == "zap" and s.rule_id in _BY_ZAP_RULE:
            return _BY_ZAP_RULE[s.rule_id]
    if f.cwe in _BY_CWE:
        return _BY_CWE[f.cwe]
    return _generic(f)
