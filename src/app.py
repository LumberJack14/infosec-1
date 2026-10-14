from flask import Flask, g, jsonify, request
from markupsafe import escape

from .auth import create_token, hash_password, jwt_required, verify_password
from .config import Config
from .extensions import db
from .models import Note, User


def create_app(config_object: type = Config) -> Flask:
    """Фабрика приложения."""
    app = Flask(__name__)
    app.config.from_object(config_object)

    db.init_app(app)
    with app.app_context():
        db.create_all()

    register_routes(app)
    return app


def register_routes(app: Flask) -> None:
    @app.post("/auth/register")
    def register():
        """Регистрация пользователя (собственный метод).

        Принимает JSON {"login", "password"}. Пароль хэшируется bcrypt,
        логин проверяется на уникальность.
        """
        data = request.get_json(silent=True) or {}
        login = data.get("login")
        password = data.get("password")

        if not login or not password:
            return jsonify({"error": "login and password are required"}), 400
        if len(password) < 8:
            return jsonify({"error": "password must be at least 8 characters"}), 400

        # Параметризованный запрос через ORM — безопасно от SQL-инъекций.
        if User.query.filter_by(login=login).first() is not None:
            return jsonify({"error": "user already exists"}), 409

        user = User(login=login, password_hash=hash_password(password))
        db.session.add(user)
        db.session.commit()

        return jsonify({"id": user.id, "login": str(escape(user.login))}), 201

    @app.post("/auth/login")
    def login():
        """Аутентификация пользователя. Возвращает JWT-токен."""
        data = request.get_json(silent=True) or {}
        login = data.get("login")
        password = data.get("password")

        if not login or not password:
            return jsonify({"error": "login and password are required"}), 400

        user = User.query.filter_by(login=login).first()
        # Одинаковый ответ и при неверном логине, и при неверном пароле,
        # чтобы не раскрывать существование учётной записи.
        if user is None or not verify_password(password, user.password_hash):
            return jsonify({"error": "invalid credentials"}), 401

        return jsonify({"token": create_token(user)}), 200

    @app.get("/api/data")
    @jwt_required
    def get_data():
        """Возвращает список заметок. Доступ только с валидным JWT.

        Поле content экранируется при выдаче — защита от XSS.
        """
        notes = Note.query.order_by(Note.id).all()
        return jsonify(
            [
                {
                    "id": note.id,
                    "author": str(escape(note.author.login)),
                    "content": str(escape(note.content)),
                }
                for note in notes
            ]
        ), 200

    @app.post("/api/data")
    @jwt_required
    def create_data():
        """Создаёт заметку от имени текущего пользователя. Доступ только с JWT."""
        data = request.get_json(silent=True) or {}
        content = data.get("content")
        if not content:
            return jsonify({"error": "content is required"}), 400

        note = Note(content=content, user_id=g.current_user.id)
        db.session.add(note)
        db.session.commit()

        return jsonify({"id": note.id, "content": str(escape(note.content))}), 201
