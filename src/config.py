import os


class Config:
    """Конфигурация приложения.

    Секретный ключ для подписи JWT и строка подключения к БД берутся из
    переменных окружения. Значения по умолчанию заданы только для удобства
    локального запуска и не должны использоваться в production.
    """

    SECRET_KEY = os.environ.get(
        "SECRET_KEY", "dev-secret-change-me-0123456789abcdef-min-32-bytes"
    )
    SQLALCHEMY_DATABASE_URI = os.environ.get("DATABASE_URL", "sqlite:///app.db")
    SQLALCHEMY_TRACK_MODIFICATIONS = False

    # Время жизни JWT-токена в секундах (по умолчанию 1 час).
    JWT_EXPIRES_IN = int(os.environ.get("JWT_EXPIRES_IN", "3600"))
