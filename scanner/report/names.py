"""Nome da falha em pt-BR para o cliente final.

As ferramentas (ZAP, nuclei) dão títulos em inglês e com jargão. O `Finding.title` continua sendo o
da ferramenta (é o que identifica a regra); a interface e o relatório mostram `display_title`.
Título fora da tabela aparece como veio: melhor o nome técnico do que um nome inventado.
"""

from __future__ import annotations

from scanner.common.grouping import title_family

# Chave: `title_family` do título da ferramenta (minúsculas, sem a variante de método HTTP).
NAMES: dict[str, str] = {
    # injeção e XSS
    "sql injection": "Injeção de SQL",
    "sql injection - sqlite (time based)": "Injeção de SQL no SQLite (por tempo de resposta)",
    "sql injection - mysql": "Injeção de SQL no MySQL",
    "sql injection - postgresql": "Injeção de SQL no PostgreSQL",
    "cross site scripting (reflected)": "XSS refletido",
    "cross site scripting (persistent)": "XSS armazenado",
    "cross site scripting (dom based)": "XSS no navegador (DOM)",
    "remote os command injection": "Injeção de comandos no servidor",
    "path traversal": "Leitura de arquivos fora da pasta do site",
    "external redirect": "Redirecionamento para qualquer site",
    "open redirect": "Redirecionamento para qualquer site",
    # cabeçalhos de segurança
    "content security policy (csp) header not set": "Cabeçalho Content-Security-Policy ausente",
    "missing anti-clickjacking header": "Sem proteção contra clickjacking",
    "x-content-type-options header missing": "Cabeçalho X-Content-Type-Options ausente",
    "strict-transport-security header not set": "HTTPS não forçado (HSTS ausente)",
    "cross-origin-embedder-policy header missing or invalid": (
        "Cabeçalho Cross-Origin-Embedder-Policy ausente"
    ),
    "cross-origin-opener-policy header missing or invalid": (
        "Cabeçalho Cross-Origin-Opener-Policy ausente"
    ),
    "cross-origin-resource-policy header missing or invalid": (
        "Cabeçalho Cross-Origin-Resource-Policy ausente"
    ),
    "deprecated feature policy header set": "Cabeçalho Feature-Policy obsoleto",
    "deprecated feature-policy header - detection": "Cabeçalho Feature-Policy obsoleto",
    "x-recruiting header": "Cabeçalho X-Recruiting presente",
    "permissions policy header not set": "Cabeçalho Permissions-Policy ausente",
    "csp: failure to define directive with no fallback": (
        "Content-Security-Policy incompleta (diretiva sem valor padrão)"
    ),
    "csp: wildcard directive": "Content-Security-Policy aceita qualquer origem",
    "csp: script-src unsafe-inline": "Content-Security-Policy permite script embutido",
    # CORS
    "cross-domain misconfiguration": "Outros sites podem ler as respostas (CORS aberto)",
    "cors misconfiguration": "CORS mal configurado",
    "cors header": "Cabeçalho CORS presente",
    # cookies e sessão
    "cookie no httponly flag": "Cookie sem a proteção HttpOnly",
    "cookie without samesite attribute": "Cookie sem o atributo SameSite",
    "cookie with samesite attribute none": "Cookie com SameSite=None",
    "cookie without secure flag": "Cookie sem a proteção Secure",
    "loosely scoped cookie": "Cookie válido para domínios demais",
    "cookie slack detector": "Cookies que não afetam a sessão",
    "session id in url rewrite": "Identificador de sessão na URL",
    "session management response identified": "Resposta que cria sessão identificada",
    "absence of anti-csrf tokens": "Formulário sem proteção contra CSRF",
    # arquivos e informações expostas
    "backup file disclosure": "Arquivo de backup exposto",
    ".env information leak": "Arquivo .env exposto",
    ".htaccess information leak": "Arquivo .htaccess exposto",
    "elmah information leak": "Registro de erros (ELMAH) exposto",
    "trace.axd information leak": "Rastreamento trace.axd exposto",
    "source code disclosure - svn": "Código-fonte exposto (pasta do SVN)",
    "source code disclosure - git": "Código-fonte exposto (pasta do Git)",
    "hidden file found": "Arquivo oculto acessível",
    "directory browsing": "Listagem de pastas habilitada",
    "private ip disclosure": "Endereço IP interno exposto",
    "timestamp disclosure - unix": "Data e hora do servidor expostas",
    "application error disclosure": "Mensagem de erro da aplicação exposta",
    "information disclosure - debug error messages": "Mensagem de depuração exposta",
    "information disclosure - suspicious comments": "Comentários suspeitos no código da página",
    "information disclosure - sensitive information in url": "Dado sensível na URL",
    'server leaks version information via "server" http response header field': (
        "Versão do servidor exposta no cabeçalho Server"
    ),
    'server leaks information via "x-powered-by" http response header field(s)': (
        "Tecnologia exposta no cabeçalho X-Powered-By"
    ),
    "public swagger api - detect": "Documentação da API (Swagger) pública",
    "spring actuator information leak": "Endpoints de administração do Spring expostos",
    # métodos HTTP
    "insecure http method": "Métodos HTTP perigosos habilitados",
    # bibliotecas e tecnologia
    "vulnerable js library": "Biblioteca JavaScript com falha conhecida",
    "dangerous js functions": "Funções JavaScript perigosas no código",
    "add dom eventlistener - detection": "Código que reage a eventos da página (DOM) identificado",
    "fingerprinthub technology fingerprint": "Versões de tecnologia identificáveis",
    "wappalyzer technology detection": "Tecnologias do site identificáveis",
    "modern web application": "Aplicação de página única (SPA) identificada",
    "user agent fuzzer": "Resposta muda conforme o navegador",
    # cache
    "non-storable content": "Conteúdo marcado para não ser guardado em cache",
    "storable but non-cacheable content": "Conteúdo que o cache guarda mas não reaproveita",
    "storable and cacheable content": "Conteúdo guardado em cache",
    "re-examine cache-control directives": "Regras de cache a revisar",
    "retrieved from cache": "Resposta servida pelo cache",
    # arquivos públicos esperados
    "robots.txt file": "Arquivo robots.txt público",
    "robots.txt endpoint prober": "Arquivo robots.txt público",
    "security.txt file": "Arquivo security.txt publicado",
}


def display_title(title: str) -> str:
    return NAMES.get(title_family(title), title)


# Motivos gravados por versões antigas da etapa 5, no texto que o cliente entende.
REASONS = {
    "ainda não há validador para esta família": (
        "ainda não temos teste automático para este tipo de falha"
    ),
    "erro ao executar a prova": "não conseguimos repetir o teste desta vez",
}


def client_reason(reason: str) -> str:
    return REASONS.get(reason, reason)


COMMANDS = ("curl", "wget", "openssl", "dig", "nslookup", "nmap", "grep", "nc", "http")


def is_command(text: object) -> bool:
    """ "Como verificar" que é um comando de terminal vira bloco de código copiável."""
    return str(text or "").strip().split(" ", 1)[0] in COMMANDS
