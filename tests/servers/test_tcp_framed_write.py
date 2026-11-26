"""Tests for foghorn.servers.tcp_framed_write helpers."""

from __future__ import annotations

import asyncio

from foghorn.servers.tcp_framed_write import (
    frame_dns_message,
    sendall_framed,
    write_framed,
)


def test_frame_dns_message_prefixes_length() -> None:
    """Brief: frame_dns_message adds a 2-byte big-endian length prefix.

    Inputs:
      - sample payload bytes.

    Outputs:
      - None; asserts framed length and body.
    """
    payload = b"abc"
    framed = frame_dns_message(payload)
    assert framed[:2] == b"\x00\x03"
    assert framed[2:] == payload


def test_sendall_framed_success_and_failures() -> None:
    """Brief: sendall_framed returns True on success and False on errors.

    Inputs:
      - dummy sockets that succeed or raise.

    Outputs:
      - None; asserts bool results and captured payload framing.
    """
    assert sendall_framed(None, b"x") is False
    assert sendall_framed(object(), b"") is False

    sent: list[bytes] = []

    class OkSock:
        def sendall(self, data: bytes) -> None:
            sent.append(data)

    class BoomSock:
        def sendall(self, data: bytes) -> None:
            raise OSError("broken pipe")

    assert sendall_framed(OkSock(), b"hi", client_ip="127.0.0.1") is True
    assert sent == [b"\x00\x02hi"]
    assert sendall_framed(BoomSock(), b"hi", client_ip="127.0.0.1") is False


def test_write_framed_success_and_failures() -> None:
    """Brief: write_framed returns True on success and False on errors.

    Inputs:
      - dummy asyncio writers that succeed or raise.

    Outputs:
      - None; asserts bool results and framing.
    """

    async def _run() -> None:
        assert await write_framed(None, b"x") is False
        assert await write_framed(object(), b"") is False

        written: list[bytes] = []

        class OkWriter:
            def write(self, data: bytes) -> None:
                written.append(data)

            async def drain(self) -> None:
                return None

        class BoomWriter:
            def write(self, data: bytes) -> None:
                raise ConnectionResetError("reset")

            async def drain(self) -> None:
                return None

        class DrainBoomWriter:
            def write(self, data: bytes) -> None:
                return None

            async def drain(self) -> None:
                raise OSError("broken")

        assert await write_framed(OkWriter(), b"ok", client_ip="127.0.0.1") is True
        assert written == [b"\x00\x02ok"]
        assert await write_framed(BoomWriter(), b"x") is False
        assert await write_framed(DrainBoomWriter(), b"x") is False

    asyncio.run(_run())
