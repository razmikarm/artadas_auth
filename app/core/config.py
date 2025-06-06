from typing import Any
from pydantic import field_validator
from pydantic_settings import BaseSettings


class Settings(BaseSettings):
    app_name: str = "Artadas API"
    debug: bool = False

    postgres_auth_user: str
    postgres_auth_password: str
    postgres_auth_host: str
    postgres_auth_port: str
    postgres_auth_db: str

    secret_key: str
    access_token_timeout: int
    refresh_token_secret: str
    refresh_token_timeout: int
    algorithm: str = "HS256"

    INTERNAL_API_KEY: str
    INTERNAL_IPS: Any = []

    @property
    def database_url(self) -> str:
        return (
            f"postgresql://{self.postgres_auth_user}:{self.postgres_auth_password}"
            f"@{self.postgres_auth_host}:{self.postgres_auth_port}/{self.postgres_auth_db}"
        )

    class Config:
        env_file = ".env"
        env_file_encoding = "utf-8"

    # Custom validator for the INTERNAL_IPS field
    @field_validator("INTERNAL_IPS", mode="before")
    @classmethod
    def parse_internal_ips(cls, v):
        if isinstance(v, str):
            return v.split(",")
        return v


settings = Settings()

# print(24 * "* ", settings.model_dump())
