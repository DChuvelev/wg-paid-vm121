from pydantic_settings import BaseSettings


class Settings(BaseSettings):
    database_url: str
    environment: str = "dev"
    agent_token: str = "dev-agent-token"

    # P26 identity/auth boundary. Public auth remains closed unless explicitly enabled.
    external_onboarding_active: bool = False
    # Durable admin authorization is file-first. Direct environment fallback is
    # disabled by default and exists only for explicit isolated/dev fixtures.
    auth_admin_token: str = ""
    auth_admin_token_file: str = ""
    auth_admin_token_env_fallback: bool = False

    auth_invite_ttl_seconds: int = 7 * 24 * 60 * 60
    auth_magic_link_ttl_seconds: int = 15 * 60
    auth_session_ttl_seconds: int = 7 * 24 * 60 * 60
    auth_rate_window_seconds: int = 10 * 60
    auth_login_rate_limit: int = 5
    auth_redeem_rate_limit: int = 10
    auth_magic_consume_rate_limit: int = 10

    # Production magic-link delivery. Only authenticated TLS modes are
    # supported; secrets are read from root-only files rather than env values.
    auth_magic_link_public_url_template: str = ""
    smtp_delivery_active: bool = False
    smtp_host: str = ""
    smtp_port: int = 587
    smtp_security: str = "starttls"
    smtp_username: str = ""
    smtp_password_file: str = ""
    smtp_from_email: str = ""
    smtp_from_name: str = "WG Paid"
    smtp_timeout_seconds: int = 10

    wg_default_node_id: str = "ddn-test"

    class Config:
        env_file = ".env"
        extra = "ignore"


settings = Settings()
