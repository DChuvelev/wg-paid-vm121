from pydantic_settings import BaseSettings


class Settings(BaseSettings):
    database_url: str
    environment: str = "dev"
    agent_token: str = "dev-agent-token"

    class Config:
        env_file = ".env"
        extra = "ignore"


settings = Settings()
