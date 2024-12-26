from pydantic import BaseSettings

class Settings(BaseSettings):
    DATABASE_URL: str = "postgresql+asyncpg://postgres:root@localhost/YuriPass"
    REDIS_URL: str = "redis://localhost:6379"
    SECRET_KEY: str = "lkadsjfkal0-1238-1284odhsgoh89ayf92shgohgowqeihfaf"
    ALGORITHM: str = "HS256"
    ACCESS_TOKEN_EXPIRE_MINUTES: int = 30

    class Config:
        env_file = ".env"

settings = Settings()
