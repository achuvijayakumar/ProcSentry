"""Port mapper cache behavior tests."""

from app.core.port_mapper import PortMapper
from tests.fakes import proc


def test_port_mapper_attaches_cached_outbound_counts() -> None:
    mapper = PortMapper()
    mapper._cached_ports = {10: []}
    mapper._cached_outbound = {10: 17}
    mapper._last_collect_at = 10**9
    process = proc(10)

    mapper.attach([process])

    assert process.outbound_connections == 17
