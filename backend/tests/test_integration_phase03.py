from __future__ import annotations

import os
from collections.abc import Iterator
from concurrent.futures import ThreadPoolExecutor

import pytest
from alembic import command
from alembic.config import Config
from fastapi.testclient import TestClient
from redis import Redis
from sqlalchemy import create_engine, select, text
from sqlalchemy.exc import DBAPIError

from wto_backend.config import Settings, get_settings
from wto_backend.db.session import Database
from wto_backend.domain.models import AuditLog, AuthSession, RefreshToken, Role, User
from wto_backend.main import create_app
from wto_backend.security.passwords import PasswordManager
from wto_backend.security.tokens import TokenManager
from wto_backend.services.auth import AuthService
from wto_backend.services.bootstrap import bootstrap_administrator
from wto_backend.services.errors import InvalidSessionError, LastAdministratorError
from wto_backend.services.rbac import UserAdministrationService
from wto_backend.services.seeds import seed_rbac

pytestmark = [
    pytest.mark.integration,
    pytest.mark.skipif(
        os.environ.get("WTO_RUN_INTEGRATION") != "1",
        reason="set WTO_RUN_INTEGRATION=1 with disposable PostgreSQL and Redis",
    ),
]

ALL_TABLES = (
    "enrollment_tokens, artifacts, metrics, executions, campaigns, test_definitions, "
    "capabilities, agents, devices, refresh_tokens, sessions, role_permissions, "
    "user_roles, audit_logs, permissions, roles, users"
)
ADMIN_PASSWORD = "phase-03-integration-admin-password"


def alembic_config() -> Config:
    return Config("alembic.ini")


@pytest.fixture(scope="module")
def settings() -> Settings:
    get_settings.cache_clear()
    return get_settings()


@pytest.fixture(autouse=True)
def clean_database(settings: Settings) -> Iterator[None]:
    command.upgrade(alembic_config(), "head")
    owner = create_engine(settings.migration_database_url)
    with owner.begin() as connection:
        connection.execute(text(f"TRUNCATE TABLE {ALL_TABLES} CASCADE"))
    owner.dispose()
    redis = Redis(host=settings.redis_host, port=settings.redis_port, db=settings.redis_db)
    redis.flushdb()
    redis.close()
    database = Database(settings.database_url)
    manager = PasswordManager(
        memory_cost=settings.argon2_memory_cost,
        time_cost=settings.argon2_time_cost,
        parallelism=settings.argon2_parallelism,
    )
    with database.session_factory() as session:
        seed_rbac(session, correlation_id="integration-seed")
        bootstrap_administrator(
            session,
            username="admin",
            password=ADMIN_PASSWORD,
            passwords=manager,
            correlation_id="integration-bootstrap",
        )
    database.close()
    yield


@pytest.fixture
def client(settings: Settings) -> Iterator[TestClient]:
    with TestClient(create_app(settings), base_url="https://testserver") as test_client:
        yield test_client


def login(client: TestClient, username: str = "admin", password: str = ADMIN_PASSWORD) -> str:
    response = client.post(
        "/api/internal/v1/auth/login", json={"username": username, "password": password}
    )
    assert response.status_code == 200, response.text
    cookie = response.headers["set-cookie"]
    assert "HttpOnly" in cookie and "SameSite=strict" in cookie and "Secure" in cookie
    return str(response.json()["access_token"])


def auth_headers(access: str) -> dict[str, str]:
    return {"Authorization": f"Bearer {access}"}


def test_migration_upgrade_downgrade_reupgrade(settings: Settings) -> None:
    del settings
    command.downgrade(alembic_config(), "20260711_0001")
    command.upgrade(alembic_config(), "head")
    database = Database(get_settings().migration_database_url)
    with database.engine.connect() as connection:
        assert connection.scalar(text("SELECT version_num FROM alembic_version")) == "20260712_0003"
        assert connection.scalar(text("SELECT to_regclass('public.audit_logs')")) == "audit_logs"
    database.close()


def test_seeds_and_bootstrap_are_idempotent(settings: Settings) -> None:
    database = Database(settings.database_url)
    manager = PasswordManager(memory_cost=65536, time_cost=3, parallelism=1)
    with database.session_factory() as session:
        created, updated = seed_rbac(session, correlation_id="seed-second")
        assert created == 0 and updated == 0
        _, was_created = bootstrap_administrator(
            session,
            username="admin",
            password=ADMIN_PASSWORD,
            passwords=manager,
            correlation_id="bootstrap-second",
        )
        assert was_created is False
        assert [role.key for role in session.scalars(select(Role).order_by(Role.key))] == [
            "administrator",
            "operator",
            "test_manager",
            "viewer",
        ]
    database.close()


def test_login_refresh_rotation_reuse_and_audit(client: TestClient, settings: Settings) -> None:
    access = login(client)
    original_cookie = client.cookies.get("wto_refresh")
    assert original_cookie is not None
    me = client.get("/api/internal/v1/auth/me", headers=auth_headers(access))
    assert me.status_code == 200
    assert me.json()["must_change_password"] is True
    refreshed = client.post(
        "/api/internal/v1/auth/refresh", headers={"Origin": settings.allowed_origin}
    )
    assert refreshed.status_code == 200
    replacement_cookie = client.cookies.get("wto_refresh")
    assert replacement_cookie and replacement_cookie != original_cookie
    client.cookies.set("wto_refresh", original_cookie, path="/api/internal/v1/auth")
    reused = client.post(
        "/api/internal/v1/auth/refresh", headers={"Origin": settings.allowed_origin}
    )
    assert reused.status_code == 401
    assert reused.json()["error"]["correlation_id"]
    database = Database(settings.database_url)
    with database.session_factory() as session:
        family = session.scalar(select(AuthSession))
        assert family is not None and family.revocation_reason == "refresh_reuse"
        actions = set(session.scalars(select(AuditLog.action)))
        assert {"auth.login", "auth.refresh", "auth.refresh_reuse"}.issubset(actions)
        assert all(len(token.token_digest) == 32 for token in session.scalars(select(RefreshToken)))
    database.close()


def test_login_failures_rate_limit_and_generic_envelope(client: TestClient) -> None:
    missing = client.post(
        "/api/internal/v1/auth/login",
        json={"username": "does-not-exist", "password": "not-the-password"},
    )
    wrong = client.post(
        "/api/internal/v1/auth/login",
        json={"username": "admin", "password": "not-the-password"},
    )
    assert missing.status_code == wrong.status_code == 401
    assert missing.json()["error"]["message"] == wrong.json()["error"]["message"]
    for _ in range(5):
        response = client.post(
            "/api/internal/v1/auth/login",
            json={"username": "admin", "password": "not-the-password"},
        )
    assert response.status_code == 429
    assert response.json()["error"] == {
        "code": "login_rate_limited",
        "message": "Too many authentication attempts.",
        "details": None,
        "correlation_id": response.headers["X-Correlation-ID"],
    }


def test_csrf_rbac_role_removal_logout_and_password_change(
    client: TestClient, settings: Settings
) -> None:
    access = login(client)
    protected = client.get("/api/internal/v1/admin/protected", headers=auth_headers(access))
    assert protected.status_code == 200
    assert client.post("/api/internal/v1/auth/refresh").status_code == 403
    assert (
        client.post(
            "/api/internal/v1/auth/refresh", headers={"Origin": "https://attacker.invalid"}
        ).status_code
        == 403
    )
    database = Database(settings.database_url)
    with database.session_factory() as session:
        admin = session.scalar(select(User).where(User.username == "admin"))
        viewer_role = session.scalar(select(Role).where(Role.key == "viewer"))
        assert admin is not None and viewer_role is not None
    database.close()
    created = client.post(
        "/api/internal/v1/admin/users",
        headers=auth_headers(access),
        json={"username": "viewer1", "password": "viewer-initial-password"},
    )
    assert created.status_code == 201
    viewer_id = created.json()["id"]
    assert (
        client.put(
            f"/api/internal/v1/admin/users/{viewer_id}/roles/viewer",
            headers=auth_headers(access),
        ).status_code
        == 204
    )
    viewer_client = TestClient(client.app, base_url="https://testserver")
    viewer_access = login(viewer_client, "viewer1", "viewer-initial-password")
    assert (
        viewer_client.get(
            "/api/internal/v1/admin/protected", headers=auth_headers(viewer_access)
        ).status_code
        == 403
    )
    assert (
        client.delete(
            f"/api/internal/v1/admin/users/{viewer_id}/roles/viewer",
            headers=auth_headers(access),
        ).status_code
        == 204
    )
    assert (
        viewer_client.get(
            "/api/internal/v1/rbac/roles", headers=auth_headers(viewer_access)
        ).status_code
        == 403
    )
    changed = client.post(
        "/api/internal/v1/auth/change-password",
        headers={**auth_headers(access), "Origin": settings.allowed_origin},
        json={
            "current_password": ADMIN_PASSWORD,
            "new_password": "phase-03-rotated-admin-password",
        },
    )
    assert changed.status_code == 204
    assert client.get("/api/internal/v1/auth/me", headers=auth_headers(access)).status_code == 401


def test_last_admin_trigger_and_runtime_privileges(settings: Settings) -> None:
    database = Database(settings.database_url)
    with database.session_factory() as session:
        event = session.scalar(select(AuditLog).limit(1))
        assert event is not None
        privileges = session.execute(
            text(
                "SELECT has_table_privilege(current_user, 'audit_logs', 'UPDATE'), "
                "has_table_privilege(current_user, 'audit_logs', 'DELETE')"
            )
        ).one()
        assert privileges == (False, False)
        with pytest.raises(DBAPIError):
            session.execute(
                text("UPDATE audit_logs SET outcome='failure' WHERE id=:id"), {"id": event.id}
            )
            session.commit()
        session.rollback()
    database.close()


def test_owner_is_also_blocked_by_append_only_trigger(settings: Settings) -> None:
    owner = create_engine(settings.migration_database_url)
    with owner.connect() as connection:
        event_id = connection.scalar(text("SELECT id FROM audit_logs LIMIT 1"))
        assert event_id is not None
        with pytest.raises(DBAPIError):
            connection.execute(
                text("UPDATE audit_logs SET outcome='failure' WHERE id=:id"),
                {"id": event_id},
            )
        connection.rollback()
        constraint_count = connection.scalar(
            text(
                "SELECT count(*) FROM pg_constraint WHERE conname IN "
                "('uq_users_username','ck_sessions_absolute_expiry_after_issue',"
                "'fk_refresh_tokens_session_id_sessions')"
            )
        )
        assert constraint_count == 3
    owner.dispose()


def test_logout_global_logout_disabled_user_and_last_admin(
    client: TestClient, settings: Settings
) -> None:
    access = login(client)
    database = Database(settings.database_url)
    with database.session_factory() as session:
        admin = session.scalar(select(User).where(User.username == "admin"))
        assert admin is not None
        admin_id = admin.id
    database.close()
    cannot_disable = client.patch(
        f"/api/internal/v1/admin/users/{admin_id}",
        headers=auth_headers(access),
        json={"is_active": False},
    )
    cannot_remove = client.delete(
        f"/api/internal/v1/admin/users/{admin_id}/roles/administrator",
        headers=auth_headers(access),
    )
    assert cannot_disable.status_code == cannot_remove.status_code == 409
    logout = client.post(
        "/api/internal/v1/auth/logout",
        headers={**auth_headers(access), "Origin": settings.allowed_origin},
    )
    assert logout.status_code == 204
    assert client.get("/api/internal/v1/auth/me", headers=auth_headers(access)).status_code == 401
    access = login(client)
    logout_all = client.post(
        "/api/internal/v1/auth/logout-all",
        headers={**auth_headers(access), "Origin": settings.allowed_origin},
    )
    assert logout_all.status_code == 204
    assert client.get("/api/internal/v1/auth/me", headers=auth_headers(access)).status_code == 401
    access = login(client)
    created = client.post(
        "/api/internal/v1/admin/users",
        headers=auth_headers(access),
        json={"username": "disabled1", "password": "disabled-user-password"},
    )
    user_id = created.json()["id"]
    assert (
        client.patch(
            f"/api/internal/v1/admin/users/{user_id}",
            headers=auth_headers(access),
            json={"is_active": False},
        ).status_code
        == 200
    )
    disabled_login = client.post(
        "/api/internal/v1/auth/login",
        json={"username": "disabled1", "password": "disabled-user-password"},
    )
    assert disabled_login.status_code == 401


def test_concurrent_refresh_revokes_family_on_second_use(
    client: TestClient, settings: Settings
) -> None:
    login(client)
    refresh_token = client.cookies.get("wto_refresh")
    assert refresh_token is not None

    def rotate() -> str:
        database = Database(settings.database_url)
        try:
            with database.session_factory() as session:
                service = AuthService(
                    session,
                    passwords=PasswordManager(memory_cost=65536, time_cost=3, parallelism=1),
                    tokens=TokenManager(
                        signing_key=settings.jwt_signing_key.get_secret_value(),
                        issuer=settings.jwt_issuer,
                        audience=settings.jwt_audience,
                        ttl_minutes=settings.access_token_minutes,
                    ),
                    audit_hmac_key=settings.audit_subject_hmac_key.get_secret_value(),
                    absolute_days=30,
                    inactivity_days=7,
                )
                try:
                    service.refresh(token=refresh_token, correlation_id="concurrent-refresh")
                except InvalidSessionError:
                    return "reused"
                return "rotated"
        finally:
            database.close()

    with ThreadPoolExecutor(max_workers=2) as executor:
        results = list(executor.map(lambda _: rotate(), (1, 2)))
    assert sorted(results) == ["reused", "rotated"]
    database = Database(settings.database_url)
    with database.session_factory() as session:
        family = session.scalar(select(AuthSession))
        assert family is not None and family.revocation_reason == "refresh_reuse"
    database.close()


def test_concurrent_bootstrap_creates_one_admin(settings: Settings) -> None:
    owner = create_engine(settings.migration_database_url)
    with owner.begin() as connection:
        connection.execute(text(f"TRUNCATE TABLE {ALL_TABLES} CASCADE"))
    owner.dispose()
    database = Database(settings.database_url)
    with database.session_factory() as session:
        seed_rbac(session, correlation_id="concurrent-seed")
    database.close()

    def run_bootstrap(index: int) -> bool:
        local = Database(settings.database_url)
        try:
            with local.session_factory() as session:
                _, created = bootstrap_administrator(
                    session,
                    username="admin",
                    password=ADMIN_PASSWORD,
                    passwords=PasswordManager(memory_cost=65536, time_cost=3, parallelism=1),
                    correlation_id=f"concurrent-{index}",
                )
                return created
        finally:
            local.close()

    with ThreadPoolExecutor(max_workers=2) as executor:
        results = list(executor.map(run_bootstrap, (1, 2)))
    assert sorted(results) == [False, True]


def test_last_administrator_is_preserved_under_concurrency(settings: Settings) -> None:
    database = Database(settings.database_url)
    with database.session_factory() as session:
        admin = session.scalar(select(User).where(User.username == "admin"))
        assert admin is not None
        admin_id = admin.id
    database.close()

    def mutate(operation: str) -> str:
        local = Database(settings.database_url)
        try:
            with local.session_factory() as session:
                actor = session.scalar(select(User).where(User.id == admin_id))
                assert actor is not None
                service = UserAdministrationService(
                    session, PasswordManager(memory_cost=65536, time_cost=3, parallelism=1)
                )
                try:
                    if operation == "disable":
                        service.disable_user(
                            user_id=admin_id,
                            actor=actor,
                            correlation_id="concurrent-disable",
                        )
                    else:
                        service.remove_role(
                            user_id=admin_id,
                            role_key="administrator",
                            actor=actor,
                            correlation_id="concurrent-remove",
                        )
                except LastAdministratorError:
                    return "preserved"
                return "mutated"
        finally:
            local.close()

    with ThreadPoolExecutor(max_workers=2) as executor:
        results = list(executor.map(mutate, ("disable", "remove")))
    assert results == ["preserved", "preserved"]
