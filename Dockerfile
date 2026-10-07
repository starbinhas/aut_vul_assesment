# Imagem única do pacote `scanner`, usada por worker-web, worker-validate e worker-report.
FROM python:3.13-slim AS base

COPY --from=ghcr.io/astral-sh/uv:0.12 /uv /usr/local/bin/uv

# Dependências de sistema do WeasyPrint (PDF) + fonte com acentuação.
RUN apt-get update \
 && apt-get install -y --no-install-recommends libpango-1.0-0 libpangoft2-1.0-0 fonts-dejavu-core \
 && rm -rf /var/lib/apt/lists/*

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
