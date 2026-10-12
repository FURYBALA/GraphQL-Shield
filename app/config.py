from pydantic_settings import BaseSettings

class Settings(BaseSettings):
    PROJECT_NAME: str = "GraphQL Shield"
    VERSION: str = "0.1.0"
    ENVIRONMENT: str = "development"
    API_PREFIX: str = "/api/v1"
    DATABASE_URL: str = "sqlite:///./shield.db"
    JWT_SECRET: str = "super_secret_dev_key"
    JWT_ALGORITHM: str = "HS256"
    TAINT_ANALYSIS_MODE: str = "audit_only"

    # AI Security Analyst Configuration (Disabled by default)
    AI_EXPLANATION_ENABLED: bool = False
    AI_PROVIDER: str = "mock"  # "mock", "openai", "http_generic"
    AI_MODEL: str = "gpt-4o-mini"
    AI_API_KEY: str = ""
    AI_API_BASE: str = ""
    AI_TIMEOUT_SECONDS: float = 15.0
    AI_MAX_TOKENS: int = 1500

    class Config:
        env_file = ".env"

settings = Settings()
