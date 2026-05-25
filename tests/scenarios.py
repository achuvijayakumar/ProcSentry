"""Synthetic Linux VPS process scenarios."""

from __future__ import annotations

from datetime import datetime, timedelta, timezone

from app.core.fingerprint import FingerprintEngine
from app.schemas import ProcessSnapshot
from tests.fakes import proc

_engine = FingerprintEngine()
_base = datetime(2026, 1, 1, tzinfo=timezone.utc)


def fingerprinted(processes: list[ProcessSnapshot]) -> list[ProcessSnapshot]:
    """Apply fingerprints to scenario processes."""

    return [_engine.apply(process) for process in processes]


def uvicorn_reload() -> list[ProcessSnapshot]:
    parent = proc(100, name="uvicorn", cmdline=("uvicorn", "app:app", "--reload"))
    child = proc(101, name="python", cmdline=("python", "-c", "from multiprocessing.spawn import spawn_main"))
    child.ppid = 100
    child.ancestry = (100, 1)
    return fingerprinted([parent, child])


def gunicorn_pool(workers: int = 4) -> list[ProcessSnapshot]:
    master = proc(200, name="gunicorn", cmdline=("gunicorn", "app:app", "-w", str(workers)))
    processes = [master]
    for index in range(workers):
        worker = proc(
            201 + index,
            name="gunicorn",
            cmdline=("gunicorn: worker", "app:app"),
            executable="/usr/bin/python3",
        )
        worker.ppid = master.pid
        worker.ancestry = (master.pid, 1)
        processes.append(worker)
    return fingerprinted(processes)


def celery_prefork(workers: int = 4) -> list[ProcessSnapshot]:
    master = proc(300, name="celery", cmdline=("celery", "-A", "proj", "worker", "--pool=prefork"))
    processes = [master]
    for index in range(workers):
        worker = proc(301 + index, name="python", cmdline=("celery worker", "prefork"))
        worker.ppid = master.pid
        worker.ancestry = (master.pid, 1)
        processes.append(worker)
    return fingerprinted(processes)


def nginx_master_worker(workers: int = 2) -> list[ProcessSnapshot]:
    master = proc(400, name="nginx", cmdline=("nginx: master process", "nginx"))
    processes = [master]
    for index in range(workers):
        worker = proc(401 + index, name="nginx", cmdline=("nginx: worker process",))
        worker.ppid = master.pid
        worker.ancestry = (master.pid, 1)
        processes.append(worker)
    return fingerprinted(processes)


def postgres_workers() -> list[ProcessSnapshot]:
    names = ["checkpointer", "background writer", "walwriter", "autovacuum launcher"]
    processes = [proc(500, name="postgres", cmdline=("postgres", "-D", "/var/lib/postgresql"))]
    for index, name in enumerate(names):
        worker = proc(501 + index, name="postgres", cmdline=("postgres:", name))
        worker.ppid = 500
        worker.ancestry = (500, 1)
        processes.append(worker)
    return fingerprinted(processes)


def node_cluster(workers: int = 3) -> list[ProcessSnapshot]:
    master = proc(600, name="node", cmdline=("node", "server.js", "--cluster"))
    processes = [master]
    for index in range(workers):
        worker = proc(601 + index, name="node", cmdline=("node", "cluster", "worker", "server.js"))
        worker.ppid = master.pid
        worker.ancestry = (master.pid, 1)
        processes.append(worker)
    return fingerprinted(processes)


def docker_shim_tree() -> list[ProcessSnapshot]:
    shim = proc(700, name="containerd-shim", cmdline=("containerd-shim-runc-v2", "-namespace", "moby"))
    app = proc(701, name="python", cmdline=("python3", "app.py"))
    app.ppid = shim.pid
    app.ancestry = (shim.pid, 1)
    app.container_id = "abc123def456"
    shim.service_manager = "docker"
    shim.container_id = "abc123def456"
    return fingerprinted([shim, app])


def orphan_process() -> list[ProcessSnapshot]:
    orphan = proc(800, name="python", cmdline=("python3", "manual.py"))
    orphan.ppid = 1
    orphan.is_orphan = True
    return fingerprinted([orphan])


def zombie_process() -> list[ProcessSnapshot]:
    zombie = proc(900, name="zombie", cmdline=("zombie",))
    zombie.status = "zombie"
    zombie.is_zombie = True
    return fingerprinted([zombie])


def accidental_duplicate() -> list[ProcessSnapshot]:
    left = proc(1000, cmdline=("python3", "bot.py"), cwd="/srv/bot")
    right = proc(1001, cmdline=("python3", "bot.py"), cwd="/srv/bot")
    left.start_time = _base
    right.start_time = _base + timedelta(seconds=2)
    return fingerprinted([left, right])


def restart_loop() -> list[list[ProcessSnapshot]]:
    batches: list[list[ProcessSnapshot]] = []
    for index in range(4):
        process = proc(1100 + index, cmdline=("python3", "flaky.py"), cwd="/srv/flaky")
        process.start_time = _base + timedelta(seconds=index * 20)
        batches.append(fingerprinted([process]))
    return batches

