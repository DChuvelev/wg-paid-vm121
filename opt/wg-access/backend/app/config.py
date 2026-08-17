from pydantic_settings import BaseSettings


class Settings(BaseSettings):
    database_url: str
    environment: str = "dev"
    agent_token: str = "dev-agent-token"

    # P26 identity/auth boundary. Public auth remains closed unless explicitly enabled.
    external_onboarding_active: bool = False
    auth_admin_token: str = ""
    auth_invite_ttl_seconds: int = 7 * 24 * 60 * 60
    auth_magic_link_ttl_seconds: int = 15 * 60
    auth_session_ttl_seconds: int = 7 * 24 * 60 * 60
    auth_rate_window_seconds: int = 10 * 60
    auth_login_rate_limit: int = 5
    auth_redeem_rate_limit: int = 10
    auth_magic_consume_rate_limit: int = 10

    class Config:
        env_file = ".env"
        extra = "ignore"


settings = Settings()
