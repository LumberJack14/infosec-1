from .extensions import db


class User(db.Model):
    """Пользователь. Пароль хранится только в виде bcrypt-хэша."""

    __tablename__ = "users"

    id = db.Column(db.Integer, primary_key=True)
    login = db.Column(db.String(64), unique=True, nullable=False, index=True)
    password_hash = db.Column(db.String(128), nullable=False)

    notes = db.relationship("Note", backref="author", cascade="all, delete-orphan")


class Note(db.Model):
    """Произвольный пользовательский контент (заметка).

    Поле content хранится в исходном виде, а экранируется при выдаче в ответе
    API — это защищает от XSS, не искажая сами данные в БД.
    """

    __tablename__ = "notes"

    id = db.Column(db.Integer, primary_key=True)
    content = db.Column(db.Text, nullable=False)
    user_id = db.Column(db.Integer, db.ForeignKey("users.id"), nullable=False)
