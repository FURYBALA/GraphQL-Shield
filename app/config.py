from pydantic_settings import BaseSettings, SettingsConfigDict

class Settings(BaseSettings):
    PROJECT_NAME: str = "GraphQL Shield"
    VERSION: str = "0.1.0"
    ENVIRONMENT: str = "development"
    API_PREFIX: str = "/api/v1"
    DATABASE_URL: str = "sqlite:///./shield.db"
    JWT_SECRET: str = "super_secret_dev_key"
    JWT_ALGORITHM: str = "HS256"
    TAINT_ANALYSIS_MODE: str = "audit_only"
    ENABLE_DEMO_SESSION: bool = True  # Disabled automatically if ENVIRONMENT == "production"
    ASYNC_AUDIT_LOGGING: bool = False  # Set to True for non-blocking asynchronous queue persistence
    ENABLE_FIELD_LEVEL_REDACTION: bool = True  # Granular field-level redaction and masking for sensitive sinks

    # Authorization Research Engine
    ENGINE_BASE_URL: str = "http://127.0.0.1:8000"  # base URL the engine executes real HTTP against
    ENGINE_CONCURRENCY: int = 4  # bounded concurrency for live test execution

    # AI Security Analyst Configuration (Disabled by default)
    AI_EXPLANATION_ENABLED: bool = False
    AI_PROVIDER: str = "mock"  # "mock", "openai", "http_generic", "ollama"
    AI_MODEL: str = "gpt-4o-mini"
    AI_API_KEY: str = ""
    AI_API_BASE: str = ""
    AI_TIMEOUT_SECONDS: float = 15.0
    AI_MAX_TOKENS: int = 1500

    model_config = SettingsConfigDict(env_file=".env", extra="ignore")

settings = Settings()
