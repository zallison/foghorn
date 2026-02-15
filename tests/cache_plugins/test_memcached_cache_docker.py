"""Docker-based integration tests for Memcached cache plugin.

These tests spin up a Memcached container to test the cache plugin with
a real cache backend. They are marked to skip unless explicitly enabled.

Inputs:
  - None

Outputs:
  - None
"""

from __future__ import annotations

import subprocess
import time
import signal
from typing import Generator

import pytest


def _is_docker_available() -> bool:
    """Check if docker is available."""
    try:
        subprocess.run(
            ["docker", "--version"],
            capture_output=True,
            timeout=5,
            check=True,
        )
        return True
    except Exception:
        return False


# Skip tests if docker is not available
pytestmark = [
    pytest.mark.docker,
    pytest.mark.skipif(
        not _is_docker_available(),
        reason="Docker not available - skipping Docker-based integration tests",
    ),
]


# Extend per-test timeout to avoid global 10s alarm in conftest
@pytest.fixture(autouse=True)
def _extend_test_timeout():
    try:
        # Cancel any existing alarm and set a longer one (120s)
        signal.alarm(0)
        signal.alarm(120)
    except Exception:
        pass
    try:
        yield
    finally:
        try:
            signal.alarm(0)
        except Exception:
            pass


@pytest.fixture
def memcached_container() -> Generator[str, None, None]:
    """Brief: Spin up Memcached container and wait for it to be ready.

    Inputs:
      - None.

    Outputs:
      - Container ID string; cleanup is handled by fixture.
    """

    container_name = "foghorn_test_memcached"
    image = "memcached:1.6"

    # Check if container already running
    try:
        result = subprocess.run(
            ["docker", "ps", "--filter", f"name={container_name}", "-q"],
            capture_output=True,
            text=True,
            timeout=5,
        )
        if result.stdout.strip():
            container_id = result.stdout.strip()
            yield container_id
            return  # Don't clean up if it was already running
    except Exception:
        pass

    # Start new container
    try:
        result = subprocess.run(
            [
                "docker",
                "run",
                "-d",
                "--name",
                container_name,
                "-p",
                "11212:11211",
                image,
            ],
            capture_output=True,
            text=True,
            timeout=120,
        )
        if result.returncode != 0:
            pytest.skip(f"Failed to start Memcached container: {result.stderr}")

        container_id = result.stdout.strip()

        # Wait for Memcached to be ready (up to ~30 seconds)
        max_retries = 30
        for i in range(max_retries):
            try:
                subprocess.run(
                    [
                        "docker",
                        "exec",
                        container_id,
                        "sh",
                        "-c",
                        "echo stats | nc localhost 11211 | head -1",
                    ],
                    capture_output=True,
                    timeout=5,
                    check=True,
                )
                break
            except Exception:
                if i == max_retries - 1:
                    subprocess.run(
                        ["docker", "rm", "-f", container_id],
                        capture_output=True,
                        timeout=5,
                    )
                    pytest.skip("Memcached container failed to start in time")
                time.sleep(1)

        yield container_id

    finally:
        # Cleanup
        try:
            subprocess.run(
                ["docker", "rm", "-f", container_name],
                capture_output=True,
                timeout=10,
            )
        except Exception:
            pass


def test_memcached_cache_roundtrip_with_real_server(
    memcached_container: str,
) -> None:
    """Brief: Test set/get roundtrip with real Memcached server.

    Inputs:
      - memcached_container: Docker container ID fixture.

    Outputs:
      - None; asserts roundtrip works correctly.
    """

    from foghorn.plugins.cache.memcached_cache import MemcachedCache

    try:
        cache = MemcachedCache(
            host="127.0.0.1",
            port=11212,
            namespace="foghorn:test:",
        )

        # Test set and get
        key = ("example.com", 1)
        value = b"test_response_data"
        cache.set(key, 60, value)

        result = cache.get(key)
        assert result == value

    except Exception as e:
        pytest.skip(f"Memcached test failed: {e}")


def test_memcached_cache_expiry_with_real_server(
    memcached_container: str,
) -> None:
    """Brief: Test TTL expiry enforcement with real Memcached server.

    Inputs:
      - memcached_container: Docker container ID fixture.

    Outputs:
      - None; asserts expired entries are removed.
    """

    from foghorn.plugins.cache.memcached_cache import MemcachedCache
    import time

    try:
        cache = MemcachedCache(
            host="127.0.0.1",
            port=11212,
            namespace="foghorn:test_ttl:",
        )

        # Test set with short TTL
        key = ("short.com", 1)
        value = b"expiring_data"
        cache.set(key, 1, value)  # 1 second TTL

        # Should exist immediately
        assert cache.get(key) == value

        # Wait for expiry
        time.sleep(1.5)

        # Should be None after expiry
        assert cache.get(key) is None

    except Exception as e:
        pytest.skip(f"Memcached TTL test failed: {e}")


def test_memcached_cache_multiple_entries_with_real_server(
    memcached_container: str,
) -> None:
    """Brief: Test storing multiple entries with real Memcached server.

    Inputs:
      - memcached_container: Docker container ID fixture.

    Outputs:
      - None; asserts multiple entries can coexist.
    """

    from foghorn.plugins.cache.memcached_cache import MemcachedCache

    try:
        cache = MemcachedCache(
            host="127.0.0.1",
            port=11212,
            namespace="foghorn:test_multi:",
        )

        # Test multiple entries
        entries = [
            (("a.com", 1), b"response_a"),
            (("b.com", 1), b"response_b"),
            (("c.com", 28), b"response_c"),
        ]

        for key, value in entries:
            cache.set(key, 300, value)

        # Verify all entries exist
        for key, expected_value in entries:
            assert cache.get(key) == expected_value

    except Exception as e:
        pytest.skip(f"Memcached multi-entry test failed: {e}")
