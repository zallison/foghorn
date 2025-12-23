"""
Brief: Unit tests for downstream DoT server.

Inputs:
  - None

Outputs:
  - None
"""

import asyncio
import socket
import ssl
import subprocess
import threading

import pytest

from foghorn.servers.dot_server import serve_dot


def _echo_resolver(q: bytes, client_ip: str) -> bytes:
    return q


@pytest.fixture(scope="module")
def selfsigned_cert(tmp_path_factory):
    tmp = tmp_path_factory.mktemp("dotserv")
    cert_file = tmp / "cert.pem"
    key_file = tmp / "key.pem"
    try:
        subprocess.check_call(
            [
                "openssl",
                "req",
                "-x509",
                "-nodes",
                "-newkey",
                "rsa:2048",
                "-keyout",
                str(key_file),
                "-out",
                str(cert_file),
                "-subj",
                "/CN=localhost",
                "-days",
                "1",
            ],
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
        )
    except Exception:
        pytest.skip("openssl not available for generating self-signed cert")
    return str(cert_file), str(key_file)


@pytest.fixture
def running_dot_server(selfsigned_cert):
    cert_file, key_file = selfsigned_cert
    host = "127.0.0.1"
    ready = threading.Event()
    info = {}

    def runner():
        asyncio.set_event_loop(asyncio.new_event_loop())
        loop = asyncio.get_event_loop()

        async def bind_and_run():
            # Bind temp to get free port
            srv = await asyncio.start_server(lambda r, w: None, host, 0)
            port = srv.sockets[0].getsockname()[1]
            info["port"] = port
            ready.set()
            srv.close()
            await srv.wait_closed()
            await serve_dot(
                host, port, _echo_resolver, cert_file=cert_file, key_file=key_file
            )

        loop.create_task(bind_and_run())
        loop.run_forever()

    t = threading.Thread(target=runner, daemon=True)
    t.start()
    if not ready.wait(2.0):
        pytest.skip("failed to start dot server")
    yield host, info["port"]


def test_dot_server_roundtrip(running_dot_server):
    host, port = running_dot_server
    ctx = ssl.create_default_context()
    ctx.minimum_version = ssl.TLSVersion.TLSv1_2
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE
    s = ctx.wrap_socket(socket.socket(), server_hostname="localhost")
    s.settimeout(2)
    s.connect((host, port))
    try:
        q = b"\x12\x34hello"
        s.sendall(len(q).to_bytes(2, "big") + q)
        hdr = s.recv(2)
        assert len(hdr) == 2
        ln = int.from_bytes(hdr, "big")
        body = s.recv(ln)
        assert body == q
    finally:
        s.close()
