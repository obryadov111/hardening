from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    model_config = SettingsConfigDict(env_file=".env", extra="ignore")

    APP_NAME: str = "Hardening API"
    API_PREFIX: str = "/api"

    DATABASE_URL: str

    JWT_SECRET_KEY: str
    JWT_ALGORITHM: str = "HS256"
    ACCESS_TOKEN_EXPIRE_MINUTES: int = 60 * 8

    # Защита от подбора: после LOGIN_MAX_FAILED_ATTEMPTS неудачных попыток подряд (пароль или код 2FA)
    # вход блокируется на LOGIN_LOCKOUT_MINUTES. Временный токен между паролем и кодом 2FA живёт
    # PRE_2FA_TOKEN_EXPIRE_MINUTES.
    LOGIN_MAX_FAILED_ATTEMPTS: int = 5
    LOGIN_LOCKOUT_MINUTES: int = 15
    PRE_2FA_TOKEN_EXPIRE_MINUTES: int = 5

    # Обязательная 2FA: сайт открыт из интернета, поэтому без второго фактора пользователь после входа
    # попадает только на подключение 2FA (и смену временного пароля), остальной API отвечает 403.
    # False — 2FA по желанию (стенд, закрытая сеть).
    REQUIRE_2FA: bool = True

    # Регистрация хостов агентами: имя хоста, который молчит дольше этого срока, может занять новая
    # установка (переустановка ОС, замена ПК с тем же именем). Хост на связи так не перехватить.
    AGENT_REENROLL_AFTER_DAYS: int = 7

    TOTP_ISSUER: str = "Hardening"
    TOTP_SECRET_ENCRYPTION_KEY: str

    FIRST_ADMIN_EMAIL: str | None = None
    FIRST_ADMIN_PASSWORD: str | None = None
    FIRST_ADMIN_NAME: str | None = None

    # Ключи подписи манифестов паков. Ed25519 (32 байта в Base64, `python -m app.commands.pack_signing_key`) —
    # основной: у агентов только открытый ключ. HMAC — старая схема на время перехода. Не задан ни один —
    # выдача манифестов агентам отключена (503).
    PACK_SIGNING_KEY: str | None = None
    PACK_SIGNING_ED25519_KEY: str | None = None
    # Каталог YAML-паков; по умолчанию app/packs рядом с кодом.
    PACKS_DIR: str | None = None

    # Часовой пояс для времени в выгрузках PDF/Excel (в БД и API время — UTC). Интерфейс переводит
    # время в пояс браузера сам; отчёт формируется на сервере, поэтому пояс задаётся здесь.
    DISPLAY_TIMEZONE: str = "UTC"

    ALLOWED_ORIGINS: str = "http://localhost:5173,http://localhost,http://192.168.0.147:5173,http://10.8.0.1:5173"

    @property
    def allowed_origins_list(self) -> list[str]:
        return [o.strip() for o in self.ALLOWED_ORIGINS.split(",") if o.strip()]


settings = Settings()