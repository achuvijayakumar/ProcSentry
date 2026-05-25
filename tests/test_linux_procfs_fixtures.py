"""Linux procfs/cgroup fixture validation tests."""

from pathlib import Path

from app.collectors.common.capabilities import PlatformCapabilities
from app.collectors.linux.enricher import LinuxProcessEnricher
from app.collectors.linux.procfs import read_container_id, read_executable_link, read_process_state
from app.collectors.linux.systemd import detect_service_manager, detect_systemd_unit
from tests.fakes import proc


def _linux_caps() -> PlatformCapabilities:
    return PlatformCapabilities(
        system="Linux",
        is_linux=True,
        is_windows=False,
        supports_procfs=True,
        supports_systemd=True,
        supports_cgroups=True,
        supports_deleted_exe=True,
        supports_zombie_state=True,
    )


def _write_proc_entry(root: Path, pid: int, stat_state: str = "S", cgroup: str = "") -> Path:
    entry = root / str(pid)
    entry.mkdir(parents=True)
    (entry / "stat").write_text(
        f"{pid} (fixture-proc) {stat_state} 1 1 1 0 -1 4194560 1 0 0 0 0 0 0 0 20 0 1 0 1",
        encoding="utf-8",
    )
    (entry / "cgroup").write_text(cgroup, encoding="utf-8")
    return entry


def test_zombie_detection_from_mock_proc_stat(tmp_path: Path) -> None:
    _write_proc_entry(tmp_path, 42, stat_state="Z")

    assert read_process_state(42, tmp_path) == "Z"


def test_deleted_executable_fixture_text_fallback(tmp_path: Path) -> None:
    entry = _write_proc_entry(tmp_path, 43)
    (entry / "exe").write_text("/tmp/suspicious (deleted)", encoding="utf-8")

    executable, deleted = read_executable_link(43, tmp_path)

    assert executable == "/tmp/suspicious"
    assert deleted is True


def test_systemd_and_container_mapping_from_mock_cgroup(tmp_path: Path) -> None:
    container = "abcdef1234567890"
    cgroup = (
        "0::/system.slice/ssh.service\n"
        f"1:name=systemd:/docker/{container}\n"
    )
    _write_proc_entry(tmp_path, 44, cgroup=cgroup)

    assert detect_service_manager(44, tmp_path) == "systemd"
    assert detect_systemd_unit(44, tmp_path) == "ssh.service"
    assert read_container_id(44, tmp_path) == container[:64]


def test_linux_enricher_sets_orphan_zombie_deleted_and_service(tmp_path: Path) -> None:
    entry = _write_proc_entry(
        tmp_path,
        45,
        stat_state="Z",
        cgroup="0::/system.slice/myapp.service/docker/feedfacecafebeef\n",
    )
    (entry / "exe").write_text("/usr/local/bin/myapp (deleted)", encoding="utf-8")
    snapshot = proc(45, executable=None)
    snapshot.ppid = 1

    LinuxProcessEnricher(_linux_caps(), proc_root=tmp_path).enrich(snapshot)

    assert snapshot.is_zombie is True
    assert snapshot.is_orphan is False
    assert snapshot.executable_deleted is True
    assert snapshot.executable == "/usr/local/bin/myapp"
    assert snapshot.service_manager == "systemd"
    assert snapshot.systemd_unit == "myapp.service"
    assert snapshot.container_id == "feedfacecafebeef"
