"""Configuração via variáveis de ambiente (ver `.env.example`)."""

from functools import lru_cache
from typing import Literal

from pydantic import Field, SecretStr
from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    model_config = SettingsConfigDict(env_file=".env", extra="ignore")

    database_url: str = "postgresql+psycopg://scanner:scanner@localhost:5432/scanner"
    redis_url: str = "redis://localhost:6379/0"

    zap_api_url: str = "http://localhost:8080"
    zap_api_key: SecretStr = SecretStr("")

    # Limites para SITE DE CLIENTE: conservadores, para nunca sobrecarregar produção (regra 3).
    scan_max_duration_minutes: int = Field(default=60, ge=1)
    scan_threads_per_host: int = Field(default=2, ge=1, le=5)
    scan_max_requests_per_second: int = Field(default=10, ge=1, le=50)
    # Limites para LABORATÓRIO: sem cliente para proteger, pode acelerar muito. Aplicados só quando
    # todo o escopo é de laboratório (mesma trava do perfil agressivo). Tetos bem mais altos.
    scan_lab_max_duration_minutes: int = Field(default=60, ge=1)
    scan_lab_threads_per_host: int = Field(default=10, ge=1, le=40)
    scan_lab_max_requests_per_second: int = Field(default=100, ge=1, le=500)
    # Navegadores do AJAX spider (mapeamento de sites JavaScript). Laboratório pode usar mais.
    scan_ajax_browsers: int = Field(default=1, ge=1, le=8)
    scan_lab_ajax_browsers: int = Field(default=4, ge=1, le=16)
    # Portão de cobertura: abaixo disso de páginas rastreadas, o scan é marcado 'cobertura parcial'.
    coverage_min_pages: int = Field(default=15, ge=1)
    # Memória de rastreio: teto de URLs guardadas por alvo e semeadas no próximo scan.
    crawl_memory_max_routes: int = Field(default=2000, ge=1)
    # Prontidão do alvo: sondas (pelo ZAP) antes de rastrear, para não mapear um site frio/caído.
    readiness_attempts: int = Field(default=10, ge=1)
    readiness_delay_seconds: float = Field(default=3.0, ge=0)
    # Re-rastreio: se a cobertura sai rasa (abaixo do mínimo) ou regride frente ao scan anterior,
    # refaz o AJAX spider até este número de vezes. 0 desliga.
    recrawl_max_retries: int = Field(default=1, ge=0)
    # Regressão: cobertura abaixo desta fração da do scan anterior conta como rasa (0.7 = 70%).
    recrawl_regression_ratio: float = Field(default=0.7, ge=0, le=1)
    # Alvo instável no meio do scan: quanto esperar o alvo voltar antes de entregar o parcial,
    # e de quanto em quanto tempo sondar se ele voltou.
    target_recovery_max_wait_minutes: int = Field(default=10, ge=0)
    target_recovery_probe_interval_seconds: float = Field(default=15.0, ge=1)
    # O perfil agressivo (testes que podem causar dano) só roda contra estes hosts.
    # Site de cliente nunca está aqui: a trava garante que o agressivo não o atinge.
    lab_hosts: list[str] = ["juice-shop", "dvwa", "localhost", "127.0.0.1"]

    anthropic_api_key: SecretStr = SecretStr("")
    llm_model: str = "claude-opus-5-5"
    llm_effort: Literal["low", "medium", "high", "xhigh", "max"] = "high"
    # Provedor do LLM da etapa 6. "anthropic" = Claude (padrão do produto); "openai_compatible" =
    # qualquer API no protocolo OpenAI (Groq, Gemini, Ollama...) como MVP gratuito; "none" = só
    # catálogo. Para Groq: provider=openai_compatible, base_url=https://api.groq.com/openai/v1,
    # model=llama-3.3-70b-versatile, e a chave gratuita em llm_api_key.
    llm_provider: Literal["anthropic", "openai_compatible", "none"] = "none"
    llm_api_key: SecretStr = SecretStr("")
    llm_base_url: str = ""
    # Fontes que precisam ter entregue candidatos antes de gerar o relatório (PROVISÓRIO).
    report_required_tools: list[str] = ["zap", "nuclei"]

    # Interface web
    web_session_secret: SecretStr = SecretStr("")
    web_secure_cookies: bool = True  # False só em desenvolvimento local sem HTTPS
    web_session_hours: int = Field(default=12, ge=1, le=72)

    # Etapa 7: de quanto em quanto tempo o agendador verifica alvos vencidos.
    recurrence_check_minutes: int = Field(default=60, ge=1)

    log_level: str = "INFO"
    consumer_name: str = "worker-1"


@lru_cache
def get_settings() -> Settings:
    return Settings()
