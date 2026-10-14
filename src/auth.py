import datetime
from functools import wraps

import bcrypt
import jwt
from flask import current_app, g, jsonify, request

from .extensions import db
from .models import User


def hash_password(password: str) -> str:
    """Возвращает bcrypt-хэш пароля.

    bcrypt автоматически генерирует соль и включает её в результат, поэтому
    хранить соль отдельно не нужно. Пароль в открытом виде нигде не сохраняется.
    """
    return bcrypt.hashpw(password.encode("utf-8"), bcrypt.gensalt()).decode("utf-8")


def verify_password(password: str, password_hash: str) -> bool:
    """Проверяет пароль против сохранённого bcrypt-хэша."""
    return bcrypt.checkpw(password.encode("utf-8"), password_hash.encode("utf-8"))


def create_token(user: User) -> str:
    """Создаёт подписанный JWT-токен для пользователя (алгоритм HS256)."""
    now = datetime.datetime.now(datetime.timezone.utc)
    payload = {
        "sub": str(user.id),
        "login": user.login,
        "iat": now,
        "exp": now + datetime.timedelta(seconds=current_app.config["JWT_EXPIRES_IN"]),
    }
    return jwt.encode(payload, current_app.config["SECRET_KEY"], algorithm="HS256")


def decode_token(token: str) -> dict:
    """Проверяет подпись и срок действия токена, возвращает его payload."""
    return jwt.decode(token, current_app.config["SECRET_KEY"], algorithms=["HS256"])


def jwt_required(view):
    """Middleware-декоратор: пускает дальше только при валидном JWT.

    Токен ожидается в заголовке `Authorization: Bearer <token>`. При ошибке
    (нет заголовка, истёкший или подделанный токен) возвращается 401.
    """

    @wraps(view)
    def wrapper(*args, **kwargs):
        header = request.headers.get("Authorization", "")
        parts = header.split()
        if len(parts) != 2 or parts[0].lower() != "bearer":
            return jsonify({"error": "Missing or malformed Authorization header"}), 401

        try:
            payload = decode_token(parts[1])
        except jwt.ExpiredSignatureError:
            return jsonify({"error": "Token expired"}), 401
        except jwt.InvalidTokenError:
            return jsonify({"error": "Invalid token"}), 401

        user = db.session.get(User, int(payload["sub"]))
        if user is None:
            return jsonify({"error": "User not found"}), 401

        g.current_user = user
        return view(*args, **kwargs)

    return wrapper
