# Imagem única do pacote `scanner`, usada por worker-web, worker-validate e worker-report.
FROM python:3.13-slim AS base

COPY --from=ghcr.io/astral-sh/uv:0.12 /uv /usr/local/bin/uv

# Dependências de sistema do WeasyPrint (PDF), fonte com acentuação, e libpcap (naabu).
RUN apt-get update \
 && apt-get install -y --no-install-recommends \
    libpango-1.0-0 libpangoft2-1.0-0 fonts-dejavu-core libpcap0.8 ca-certificates curl unzip \
 && rm -rf /var/lib/apt/lists/*

# Ferramentas das etapas 2 e 3 (ProjectDiscovery, binários Go): naabu (recon) e nuclei (CVEs).
ARG NAABU_VERSION=2.3.3
ARG NUCLEI_VERSION=3.3.7
RUN set -eux; \
    arch="$(dpkg --print-architecture)"; \
    cd /tmp; \
    curl -fsSL -o naabu.zip "https://github.com/projectdiscovery/naabu/releases/download/v${NAABU_VERSION}/naabu_${NAABU_VERSION}_linux_${arch}.zip"; \
    curl -fsSL -o nuclei.zip "https://github.com/projectdiscovery/nuclei/releases/download/v${NUCLEI_VERSION}/nuclei_${NUCLEI_VERSION}_linux_${arch}.zip"; \
    unzip -o naabu.zip naabu -d /usr/local/bin; \
    unzip -o nuclei.zip nuclei -d /usr/local/bin; \
    chmod +x /usr/local/bin/naabu /usr/local/bin/nuclei; \
    rm -f naabu.zip nuclei.zip
# Templates do nuclei pré-baixados no build (dir legível); sem download em tempo de execução.
# O nuclei instala em $HOME/nuclei-templates; usamos um HOME fixo só para este passo.
ENV NUCLEI_TEMPLATES_DIR=/opt/pdhome/nuclei-templates
RUN set -eux; \
    mkdir -p /opt/pdhome; \
    HOME=/opt/pdhome nuclei -update-templates; \
    chmod -R a+rX /opt/pdhome/nuclei-templates

ENV UV_COMPILE_BYTECODE=1 \
    UV_LINK_MODE=copy \
    UV_PROJECT_ENVIRONMENT=/opt/venv \
    PATH="/opt/venv/bin:$PATH" \
    PYTHONUNBUFFERED=1

WORKDIR /app

COPY pyproject.toml uv.lock* ./
RUN uv sync --no-install-project --no-dev

COPY scanner ./scanner
COPY contracts ./contracts
COPY migrations ./migrations
COPY alembic.ini ./
RUN uv sync --no-dev

RUN useradd --system --uid 10001 --home /app scanner
USER scanner

# O comando de cada worker é definido no docker-compose.yml.
CMD ["python", "-m", "scanner.web_scan"]

# Imagem de testes: inclui dependências de desenvolvimento e a pasta tests/.
FROM base AS test
USER root
COPY tests ./tests
RUN uv sync
USER scanner
CMD ["pytest"]
