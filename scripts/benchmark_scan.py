"""Lightweight scanner benchmark for production tuning."""

from __future__ import annotations

import argparse
import asyncio
from pathlib import Path
import statistics
import sys
import time

import psutil

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from app.core.scanner import ProcessScanner


async def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--iterations", type=int, default=10)
    parser.add_argument("--sleep", type=float, default=0.2)
    args = parser.parse_args()

    scanner = ProcessScanner()
    scanner.prime()
    durations: list[float] = []
    cold_profile: dict[str, float] = {}
    rss_before = psutil.Process().memory_info().rss
    for _ in range(args.iterations):
        started = time.perf_counter()
        snapshots = await scanner.scan()
        durations.append((time.perf_counter() - started) * 1000)
        if not cold_profile and scanner.last_profile.get("total_ms", 0) > 0:
            cold_profile = dict(scanner.last_profile)
        await asyncio.sleep(args.sleep)
    rss_after = psutil.Process().memory_info().rss
    print(f"processes={len(snapshots)}")
    print(f"scan_ms_first={durations[0]:.2f}")
    print(f"scan_ms_avg={statistics.mean(durations):.2f}")
    if len(durations) >= 2:
        print(f"scan_ms_warm_avg={statistics.mean(durations[1:]):.2f}")
    if len(durations) >= 20:
        print(f"scan_ms_p95={statistics.quantiles(durations, n=20)[-1]:.2f}")
    for key, value in cold_profile.items():
        print(f"cold_{key}={value:.2f}")
    for key, value in scanner.last_profile.items():
        print(f"last_{key}={value:.2f}")
    print(f"scanner_cache_hits={scanner.cache_hits}")
    print(f"scanner_cache_misses={scanner.cache_misses}")
    print(f"fingerprint_cache_hits={scanner.fingerprint_cache_hits}")
    print(f"fingerprint_cache_misses={scanner.fingerprint_cache_misses}")
    print(f"rss_delta_mb={(rss_after - rss_before) / 1024 / 1024:.2f}")


if __name__ == "__main__":
    asyncio.run(main())
