import pytest

from src.app import create_app
from src.config import Config
from src.extensions import db


class TestConfig(Config):
    # Изолированная БД в памяти на время тестов.
    SQLALCHEMY_DATABASE_URI = "sqlite:///:memory:"
    SECRET_KEY = "test-secret-0123456789abcdef-min-32-bytes"


@pytest.fixture
def client():
    app = create_app(TestConfig)
    with app.app_context():
        db.drop_all()
        db.create_all()
    with app.test_client() as client:
        yield client


def register(client, login="alice", password="password123"):
    return client.post("/auth/register", json={"login": login, "password": password})


def token_for(client, login="alice", password="password123"):
    register(client, login, password)
    resp = client.post("/auth/login", json={"login": login, "password": password})
    return resp.get_json()["token"]


def test_register_and_login(client):
    assert register(client).status_code == 201
    resp = client.post("/auth/login", json={"login": "alice", "password": "password123"})
    assert resp.status_code == 200
    assert "token" in resp.get_json()


def test_login_wrong_password(client):
    register(client)
    resp = client.post("/auth/login", json={"login": "alice", "password": "wrong"})
    assert resp.status_code == 401


def test_data_requires_token(client):
    # Без токена доступ запрещён.
    assert client.get("/api/data").status_code == 401
    # С валидным токеном — разрешён.
    token = token_for(client)
    resp = client.get("/api/data", headers={"Authorization": f"Bearer {token}"})
    assert resp.status_code == 200


def test_invalid_token_rejected(client):
    resp = client.get("/api/data", headers={"Authorization": "Bearer not.a.jwt"})
    assert resp.status_code == 401


def test_xss_content_is_escaped(client):
    token = token_for(client)
    headers = {"Authorization": f"Bearer {token}"}
    client.post("/api/data", json={"content": "<script>alert(1)</script>"}, headers=headers)

    resp = client.get("/api/data", headers=headers)
    body = resp.get_json()
    # В ответе опасные символы экранированы, "сырого" тега нет.
    assert "<script>" not in body[0]["content"]
    assert "&lt;script&gt;" in body[0]["content"]
