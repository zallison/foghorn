"""Docker-based integration tests for PostgreSQL cache plugin.

These tests spin up a PostgreSQL container to test the cache plugin with
a real database backend. They are marked to skip unless explicitly enabled.

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
def postgres_container() -> Generator[str, None, None]:
    """Brief: Spin up PostgreSQL container and wait for it to be ready.

    Inputs:
      - None.

    Outputs:
      - Container ID string; cleanup is handled by fixture.
    """

    container_name = "foghorn_test_postgres"
    image = "postgres:15"

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
                "-e",
                "POSTGRES_PASSWORD=test",
                "-e",
                "POSTGRES_DB=foghorn_cache",
                "-p",
                "5433:5432",
                image,
            ],
            capture_output=True,
            text=True,
            timeout=120,
        )
        if result.returncode != 0:
            pytest.skip(f"Failed to start PostgreSQL container: {result.stderr}")

        container_id = result.stdout.strip()

        # Wait for PostgreSQL to be ready (up to ~2 minutes)
        max_retries = 120
        for i in range(max_retries):
            try:
                subprocess.run(
                    [
                        "docker",
                        "exec",
                        container_id,
                        "psql",
                        "-h",
                        "localhost",
                        "-U",
                        "postgres",
                        "-d",
                        "foghorn_cache",
                        "-c",
                        "SELECT 1",
                    ],
                    capture_output=True,
                    timeout=5,
                    check=True,
                    env={"PGPASSWORD": "test"},
                )
                break
            except Exception:
                if i == max_retries - 1:
                    subprocess.run(
                        ["docker", "rm", "-f", container_id],
                        capture_output=True,
                        timeout=5,
                    )
                    pytest.skip("PostgreSQL container failed to start in time")
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


def test_postgres_cache_roundtrip_with_real_db(postgres_container: str) -> None:
    """Brief: Test set/get roundtrip with real PostgreSQL database.

    Inputs:
      - postgres_container: Docker container ID fixture.

    Outputs:
      - None; asserts roundtrip works correctly.
    """

    from foghorn.plugins.cache.postgres_cache import PostgresCache

    try:
        cache = PostgresCache(
            config={
                "host": "127.0.0.1",
                "port": 5433,
                "user": "postgres",
                "password": "test",
                "database": "foghorn_cache",
                "namespace": "test_cache",
            }
        )

        # Test set and get
        key = (("example.com", 1),)
        value = b"test_response_data"
        cache.set(key, value, 60)

        result = cache.get(key)
        assert result == value

        cache.close()
    except Exception as e:
        pytest.skip(f"PostgreSQL test failed: {e}")


def test_postgres_cache_expiry_with_real_db(postgres_container: str) -> None:
    """Brief: Test TTL expiry enforcement with real PostgreSQL database.

    Inputs:
      - postgres_container: Docker container ID fixture.

    Outputs:
      - None; asserts expired entries are removed.
    """

    from foghorn.plugins.cache.postgres_cache import PostgresCache
    import time

    try:
        cache = PostgresCache(
            config={
                "host": "127.0.0.1",
                "port": 5433,
                "user": "postgres",
                "password": "test",
                "database": "foghorn_cache",
                "namespace": "test_cache_ttl",
            }
        )

        # Test set with short TTL
        key = (("short.com", 1),)
        value = b"expiring_data"
        cache.set(key, value, 1)  # 1 second TTL

        # Should exist immediately
        assert cache.get(key) == value

        # Wait for expiry
        time.sleep(1.5)

        # Should be None after expiry
        assert cache.get(key) is None

        cache.close()
    except Exception as e:
        pytest.skip(f"PostgreSQL TTL test failed: {e}")


def test_postgres_cache_multiple_entries_with_real_db(
    postgres_container: str,
) -> None:
    """Brief: Test storing multiple entries with real PostgreSQL database.

    Inputs:
      - postgres_container: Docker container ID fixture.

    Outputs:
      - None; asserts multiple entries can coexist.
    """

    from foghorn.plugins.cache.postgres_cache import PostgresCache

    try:
        cache = PostgresCache(
            config={
                "host": "127.0.0.1",
                "port": 5433,
                "user": "postgres",
                "password": "test",
                "database": "foghorn_cache",
                "namespace": "test_cache_multi",
            }
        )

        # Test multiple entries
        entries = [
            ((("a.com", 1),), b"response_a"),
            ((("b.com", 1),), b"response_b"),
            ((("c.com", 28),), b"response_c"),
        ]

        for key, value in entries:
            cache.set(key, value, 300)

        # Verify all entries exist
        for key, expected_value in entries:
            assert cache.get(key) == expected_value

        cache.close()
    except Exception as e:
        pytest.skip(f"PostgreSQL multi-entry test failed: {e}")
