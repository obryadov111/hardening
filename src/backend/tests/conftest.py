import os
import uuid

# По умолчанию — одноразовый PostgreSQL на 5433, а не боевой сервер БД на 5432: тесты очищают таблицы.
os.environ.setdefault("DATABASE_URL", "postgresql+psycopg://postgres:postgres@localhost:5433/app_test_db")
os.environ.setdefault("JWT_SECRET_KEY", "test-secret-key")
os.environ.setdefault("TOTP_SECRET_ENCRYPTION_KEY", "test-totp-encryption-key")
os.environ.setdefault("PACK_SIGNING_KEY", "test-pack-signing-key")

import pytest
from fastapi.testclient import TestClient
from sqlalchemy import create_engine, text
from sqlalchemy.orm import sessionmaker

from app.api.deps import get_db
from app.core.security import hash_password
from app.main import app

TEST_DATABASE_URL = os.environ["DATABASE_URL"]
engine = create_engine(TEST_DATABASE_URL, future=True)
TestingSessionLocal = sessionmaker(bind=engine, autoflush=False, autocommit=False, future=True)

TRUNCATE_TABLES = [
    "scan_check_results",
    "hardening_checks",
    "risk_exceptions",
    "agent_collections",
    "ingestion_batches",
    "hardening_reports",
    "scan_snapshots",
    "configs",
    "software",
    "assets",
    "environments",
    "agent_api_keys",
    "user_organizations",
    "user_2fa",
    "users",
    "policies",
    "client_organizations",
    "user_roles",
    "auditor_organizations",
]


def override_get_db():
    db = TestingSessionLocal()
    try:
        yield db
    finally:
        db.close()


app.dependency_overrides[get_db] = override_get_db


@pytest.fixture(autouse=True)
def clean_db():
    """hardening_rules — сид-данные, не трогаем. Всё остальное чистим между тестами."""
    yield
    with engine.begin() as conn:
        conn.execute(text(f"TRUNCATE TABLE {', '.join(TRUNCATE_TABLES)} CASCADE"))


@pytest.fixture
def db():
    session = TestingSessionLocal()
    try:
        yield session
    finally:
        session.close()


@pytest.fixture
def client():
    return TestClient(app)


@pytest.fixture
def make_org(db):
    def _make(name="Test Org"):
        org_id = str(uuid.uuid4())
        db.execute(
            text("INSERT INTO client_organizations (id, name) VALUES (:id, :name)"),
            {"id": org_id, "name": name},
        )
        db.commit()
        return org_id
    return _make


@pytest.fixture
def make_user(db):
    def _make(email, password="password123", is_superadmin=False):
        user_id = str(uuid.uuid4())
        db.execute(
            text(
                """
                INSERT INTO users (id, email, password_hash, is_active, is_superadmin, account_status)
                VALUES (:id, :email, :password_hash, true, :is_superadmin, 'active')
                """
            ),
            {
                "id": user_id,
                "email": email,
                "password_hash": hash_password(password),
                "is_superadmin": is_superadmin,
            },
        )
        db.commit()
        return user_id
    return _make


@pytest.fixture
def add_membership(db):
    def _add(user_id, organization_id, role="viewer"):
        db.execute(
            text(
                "INSERT INTO user_organizations (user_id, organization_id, role) VALUES (:uid, :oid, :role)"
            ),
            {"uid": user_id, "oid": organization_id, "role": role},
        )
        db.commit()
    return _add


@pytest.fixture
def auth_header(client):
    def _login(email, password="password123"):
        resp = client.post("/api/auth/login", json={"email": email, "password": password})
        assert resp.status_code == 200, resp.text
        token = resp.json()["access_token"]
        return {"Authorization": f"Bearer {token}"}
    return _login


@pytest.fixture
def make_agent_key(db):
    from app.core.security import generate_agent_api_key, hash_agent_api_key

    def _make(organization_id, name="agent-test"):
        raw_key = generate_agent_api_key()
        db.execute(
            text(
                "INSERT INTO agent_api_keys (organization_id, name, key_hash) VALUES (:oid, :name, :key_hash)"
            ),
            {"oid": organization_id, "name": name, "key_hash": hash_agent_api_key(raw_key)},
        )
        db.commit()
        return raw_key
    return _make
