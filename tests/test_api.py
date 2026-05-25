"""FastAPI route tests."""

from fastapi.testclient import TestClient

from app.config import Settings
from app.database.models import AlertRecord, DuplicateGroupRecord
from app.database.repository import ProcessRepository
from app.database.session import create_db_engine, create_session_factory, init_db
from app.database.session import session_scope
from app.web.app import create_app


def test_health_and_stats(tmp_path) -> None:
    settings = Settings(
        data_dir=tmp_path,
        database_url=f"sqlite:///{tmp_path / 'api.db'}",
        web={"csrf_enabled": False},
    )
    engine = create_db_engine(settings)
    init_db(engine)
    app = create_app(settings, ProcessRepository(create_session_factory(engine)))
    client = TestClient(app)

    assert client.get("/health").json()["status"] == "ok"
    assert client.get("/stats").json()["processes"] == 0
    assert "last_scan_ms" in client.get("/metrics").json()
    assert "supports_procfs" in client.get("/capabilities").json()
    assert "score" in client.get("/health/score").json()


def test_operator_review_endpoints(tmp_path) -> None:
    settings = Settings(
        data_dir=tmp_path,
        database_url=f"sqlite:///{tmp_path / 'ops.db'}",
        web={"csrf_enabled": False},
    )
    engine = create_db_engine(settings)
    init_db(engine)
    factory = create_session_factory(engine)
    repository = ProcessRepository(factory)
    with session_scope(factory) as session:
        session.add(DuplicateGroupRecord(fingerprint="abc", confidence=99, process_pids="[1,2]", reason="test"))
        session.add(AlertRecord(type="security", severity="WARNING", category="test", message="check"))
    app = create_app(settings, repository)
    client = TestClient(app)

    assert client.post("/api/duplicates/1/resolve").json()["ok"] is True
    assert client.post("/api/alerts/1/resolve").json()["ok"] is True


def test_auth_blocks_dashboard_until_login(tmp_path) -> None:
    settings = Settings(
        data_dir=tmp_path,
        database_url=f"sqlite:///{tmp_path / 'auth.db'}",
        web={
            "auth_enabled": True,
            "auth_username": "admin",
            "auth_password": "secret",
            "session_secret": "test-secret",
            "csrf_enabled": False,
        },
    )
    engine = create_db_engine(settings)
    init_db(engine)
    app = create_app(settings, ProcessRepository(create_session_factory(engine)))
    client = TestClient(app)

    assert client.get("/", follow_redirects=False).status_code == 303
    response = client.post("/login", data={"username": "admin", "password": "secret"}, follow_redirects=False)
    assert response.status_code == 303
    assert client.get("/").status_code == 200


def test_csrf_blocks_mutating_requests(tmp_path) -> None:
    settings = Settings(data_dir=tmp_path, database_url=f"sqlite:///{tmp_path / 'csrf.db'}")
    engine = create_db_engine(settings)
    init_db(engine)
    factory = create_session_factory(engine)
    repository = ProcessRepository(factory)
    with session_scope(factory) as session:
        session.add(AlertRecord(type="security", severity="WARNING", category="test", message="check"))
    app = create_app(settings, repository)
    client = TestClient(app)

    assert client.post("/api/alerts/1/resolve").status_code == 403
