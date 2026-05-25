"""Database integration tests."""

from app.config import Settings
from app.database.repository import ProcessRepository
from app.database.session import create_db_engine, create_session_factory, init_db
from tests.fakes import proc


def test_repository_upsert_and_stats(tmp_path) -> None:
    settings = Settings(data_dir=tmp_path, database_url=f"sqlite:///{tmp_path / 'test.db'}")
    engine = create_db_engine(settings)
    init_db(engine)
    repository = ProcessRepository(create_session_factory(engine))
    snapshot = proc(300)
    snapshot.outbound_connections = 9

    repository.upsert_processes([snapshot])
    stats = repository.stats()

    assert stats["processes"] == 1
    stored = repository.get_process_by_pid(300)
    assert stored is not None
    assert stored.outbound_connections == 9


def test_history_sampling_bounds_writes(tmp_path) -> None:
    settings = Settings(data_dir=tmp_path, database_url=f"sqlite:///{tmp_path / 'sample.db'}")
    engine = create_db_engine(settings)
    init_db(engine)
    repository = ProcessRepository(create_session_factory(engine))
    snapshot = proc(301)

    repository.upsert_processes([snapshot], history_sample_interval_seconds=3600)
    repository.upsert_processes([snapshot], history_sample_interval_seconds=3600)
    metrics = repository.storage_metrics()

    assert metrics["history_rows"] == 1


def test_storage_maintenance_reports_timings(tmp_path) -> None:
    settings = Settings(data_dir=tmp_path, database_url=f"sqlite:///{tmp_path / 'maint.db'}")
    engine = create_db_engine(settings)
    init_db(engine)
    repository = ProcessRepository(create_session_factory(engine))

    timings = repository.run_maintenance(retention_days=1, checkpoint=True, vacuum=False)

    assert "prune_ms" in timings
    assert "checkpoint_ms" in timings


def test_pid_reuse_increments_restart_count(tmp_path) -> None:
    settings = Settings(data_dir=tmp_path, database_url=f"sqlite:///{tmp_path / 'reuse.db'}")
    engine = create_db_engine(settings)
    init_db(engine)
    repository = ProcessRepository(create_session_factory(engine))
    first = proc(777)
    second = proc(777)
    assert second.start_time is not None
    second.start_time = second.start_time.replace(second=second.start_time.second + 1)

    repository.upsert_processes([first])
    repository.upsert_processes([second])
    stored = repository.get_process_by_pid(777)

    assert stored is not None
    assert stored.restart_count == 1


def test_operator_notes_are_persisted(tmp_path) -> None:
    settings = Settings(data_dir=tmp_path, database_url=f"sqlite:///{tmp_path / 'notes.db'}")
    engine = create_db_engine(settings)
    init_db(engine)
    repository = ProcessRepository(create_session_factory(engine))

    repository.add_process_note(pid=123, fingerprint="abc", tag="known", note="intentional worker")
    notes = repository.list_process_notes(pid=123, fingerprint="abc")

    assert len(notes) == 1
    assert notes[0].tag == "known"
