"""
Brief: Tests for inotify-based automatic reload in EtcHosts plugin.

Inputs:
  - tmp_path: pytest fixture for temp directory
  - platform and pyinotify: conditionally skip on non-Linux or when pyinotify unavailable

Outputs:
  - None: assertions verifying reload within 2 seconds of file changes
"""

import os
import platform
import time

import pytest

# Skip all tests in this module if not on Linux or if pyinotify is unavailable
pytestmark = [
    pytest.mark.skipif(
        platform.system().lower() != "linux", reason="inotify only on Linux"
    ),
]

# Try to import pyinotify; skip entire module if not available
pytest.importorskip("pyinotify")


def wait_until(predicate, timeout=2.0, interval=0.05):
    """
    Brief: Poll until predicate() returns True or timeout expires.

    Inputs:
      - predicate: callable returning bool
      - timeout: maximum seconds to wait (float)
      - interval: sleep duration between polls (float)

    Outputs:
      - bool: True if condition met; False if timed out

    Example:
      assert wait_until(lambda: plugin.resolve('x') is not None, 2.0)
    """
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        if predicate():
            return True
        time.sleep(interval)
    return False


def test_inotify_reload_on_modify(tmp_path):
    """
    Brief: Modifying the hosts file triggers a reload within 2 seconds.

    Inputs:
      - tmp_path: pytest fixture for temp directory

    Outputs:
      - None: assertions verify reload is reflected

    Example:
      Initial: 127.0.0.1 foo.test
      Append:  127.0.0.1 bar.test
      Within 2s: plugin.resolve('bar.test') == '127.0.0.1'
    """
    import importlib

    mod = importlib.import_module("foghorn.plugins.etc-hosts")
    EtcHosts = mod.EtcHosts

    hosts = tmp_path / "hosts"
    hosts.write_text("127.0.0.1 foo.test\n", encoding="utf-8")

    plugin = EtcHosts(file_paths=[str(hosts)], inotify_enabled=True)
    try:
        assert plugin.hosts.get("foo.test") == "127.0.0.1"

        # Append a new entry (in-place modify)
        with hosts.open("a", encoding="utf-8") as fh:
            fh.write("127.0.0.1 bar.test\n")
            fh.flush()
            os.fsync(fh.fileno())

        # Should detect the modification and reload within 2 seconds
        assert wait_until(
            lambda: plugin.hosts.get("bar.test") == "127.0.0.1", timeout=2.0
        ), "reload did not happen within 2 seconds"
    finally:
        plugin.close()


def test_inotify_reload_on_atomic_replace(tmp_path):
    """
    Brief: Atomic file replacement (write temp + rename) triggers reload within 2 seconds.

    Inputs:
      - tmp_path: pytest fixture for temp directory

    Outputs:
      - None: assertions verify reload is reflected

    Example:
      Initial: 127.0.0.1 alpha.test
      Replace: 127.0.0.1 alpha.test
               127.0.0.1 beta.test
      Within 2s: plugin.resolve('beta.test') == '127.0.0.1'
    """
    import importlib

    mod = importlib.import_module("foghorn.plugins.etc-hosts")
    EtcHosts = mod.EtcHosts

    hosts = tmp_path / "hosts"
    hosts.write_text("127.0.0.1 alpha.test\n", encoding="utf-8")

    plugin = EtcHosts(file_paths=[str(hosts)], inotify_enabled=True)
    try:
        assert plugin.hosts.get("alpha.test") == "127.0.0.1"

        # Write new content to temp and atomically replace
        new = tmp_path / "hosts.new"
        new.write_text("127.0.0.1 alpha.test\n127.0.0.1 beta.test\n", encoding="utf-8")
        os.replace(str(new), str(hosts))  # atomic rename on POSIX

        # Should detect the replacement and reload within 2 seconds
        assert wait_until(
            lambda: plugin.hosts.get("beta.test") == "127.0.0.1", timeout=2.0
        ), "reload did not happen within 2 seconds after atomic replace"
    finally:
        plugin.close()


def test_inotify_reload_entry_removal(tmp_path):
    """
    Brief: Removing an entry from the file is reflected within 2 seconds.

    Inputs:
      - tmp_path: pytest fixture for temp directory

    Outputs:
      - None: assertions verify reload is reflected

    Example:
      Initial: 127.0.0.1 keep.test
               127.0.0.1 drop.test
      Replace: 127.0.0.1 keep.test
      Within 2s: plugin.resolve('drop.test') is None
    """
    import importlib

    mod = importlib.import_module("foghorn.plugins.etc-hosts")
    EtcHosts = mod.EtcHosts

    hosts = tmp_path / "hosts"
    hosts.write_text("127.0.0.1 keep.test\n127.0.0.1 drop.test\n", encoding="utf-8")

    plugin = EtcHosts(file_paths=[str(hosts)], inotify_enabled=True)
    try:
        assert plugin.hosts.get("drop.test") == "127.0.0.1"
        assert plugin.hosts.get("keep.test") == "127.0.0.1"

        # Remove 'drop.test' via atomic replace
        new = tmp_path / "hosts.new"
        new.write_text("127.0.0.1 keep.test\n", encoding="utf-8")
        os.replace(str(new), str(hosts))

        # Should detect the change and reload within 2 seconds
        assert wait_until(
            lambda: plugin.hosts.get("drop.test") is None, timeout=2.0
        ), "reload did not happen within 2 seconds"
        # Ensure the kept entry is still there
        assert plugin.hosts.get("keep.test") == "127.0.0.1"
    finally:
        plugin.close()


def test_inotify_disabled_no_reload(tmp_path):
    """
    Brief: With inotify disabled, file changes are not automatically detected.

    Inputs:
      - tmp_path: pytest fixture for temp directory

    Outputs:
      - None: assertions verify reload does not happen

    Example:
      Initial (inotify_enabled=False): 127.0.0.1 foo.test
      Append:  127.0.0.1 bar.test
      After 1s: plugin.resolve('bar.test') is None (still not reloaded)
    """
    import importlib

    mod = importlib.import_module("foghorn.plugins.etc-hosts")
    EtcHosts = mod.EtcHosts

    hosts = tmp_path / "hosts"
    hosts.write_text("127.0.0.1 foo.test\n", encoding="utf-8")

    plugin = EtcHosts(file_paths=[str(hosts)], inotify_enabled=False)
    try:
        assert plugin.hosts.get("foo.test") == "127.0.0.1"

        # Append a new entry
        with hosts.open("a", encoding="utf-8") as fh:
            fh.write("127.0.0.1 bar.test\n")
            fh.flush()
            os.fsync(fh.fileno())

        # Wait a bit and verify it's still not loaded (no automatic reload)
        time.sleep(0.5)
        assert plugin.hosts.get("bar.test") is None
    finally:
        plugin.close()


def test_inotify_multiple_files(tmp_path):
    """
    Brief: inotify watches multiple configured files and reloads when any change.

    Inputs:
      - tmp_path: pytest fixture for temp directory

    Outputs:
      - None: assertions verify reload happens for both files

    Example:
      Initial: f1: 127.0.0.1 host1
               f2: 127.0.0.1 host2
      Modify f1: add 127.0.0.1 host1_new
      Within 2s: plugin.resolve('host1_new') == '127.0.0.1'
    """
    import importlib

    mod = importlib.import_module("foghorn.plugins.etc-hosts")
    EtcHosts = mod.EtcHosts

    f1 = tmp_path / "hosts1"
    f2 = tmp_path / "hosts2"
    f1.write_text("127.0.0.1 host1\n", encoding="utf-8")
    f2.write_text("127.0.0.1 host2\n", encoding="utf-8")

    plugin = EtcHosts(file_paths=[str(f1), str(f2)], inotify_enabled=True)
    try:
        assert plugin.hosts.get("host1") == "127.0.0.1"
        assert plugin.hosts.get("host2") == "127.0.0.1"

        # Modify the first file
        with f1.open("a", encoding="utf-8") as fh:
            fh.write("127.0.0.1 host1_new\n")
            fh.flush()
            os.fsync(fh.fileno())

        assert wait_until(
            lambda: plugin.hosts.get("host1_new") == "127.0.0.1", timeout=2.0
        ), "reload on f1 did not happen within 2 seconds"

        # Modify the second file
        with f2.open("a", encoding="utf-8") as fh:
            fh.write("127.0.0.1 host2_new\n")
            fh.flush()
            os.fsync(fh.fileno())

        assert wait_until(
            lambda: plugin.hosts.get("host2_new") == "127.0.0.1", timeout=2.0
        ), "reload on f2 did not happen within 2 seconds"
    finally:
        plugin.close()
