"""Startup diagnostics tests."""

from app.collectors.common.capabilities import PlatformCapabilities
from app.config import Settings
from app.diagnostics import validate_startup


def test_startup_diagnostics_warn_on_windows_degraded_mode(tmp_path) -> None:
    settings = Settings(data_dir=tmp_path, database_url=f"sqlite:///{tmp_path / 'diag.db'}")
    capabilities = PlatformCapabilities(
        system="Windows",
        is_linux=False,
        is_windows=True,
        supports_procfs=False,
        supports_systemd=False,
        supports_cgroups=False,
        supports_deleted_exe=False,
        supports_zombie_state=False,
    )

    warnings = validate_startup(settings, capabilities)

    assert any("outside Linux" in warning for warning in warnings)
