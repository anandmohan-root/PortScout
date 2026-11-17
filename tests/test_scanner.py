import asyncio
import socket

import pytest

from portscout import scanner


def test_parse_ports():
    assert scanner.parse_ports("443, 22,80-82,22") == [22, 80, 81, 82, 443]
    for bad in ["", "0", "70000", "90-80", "abc"]:
        with pytest.raises(ValueError):
            scanner.parse_ports(bad)


def test_parse_targets():
    assert scanner.parse_targets("127.0.0.1, localhost\n127.0.0.1") == ["127.0.0.1", "localhost"]
    assert len(scanner.parse_targets("192.168.1.0/24")) == 254
    assert scanner.parse_targets("10.0.0.5/32") == ["10.0.0.5"]
    with pytest.raises(ValueError):
        scanner.parse_targets("10.0.0.0/16")          # over the host limit
    with pytest.raises(ValueError):
        scanner.parse_targets("   ")


def test_is_private():
    assert scanner.is_private("127.0.0.1") and scanner.is_private("192.168.1.10")
    assert not scanner.is_private("8.8.8.8")


def _free_port() -> int:
    with socket.socket() as s:
        s.bind(("127.0.0.1", 0))
        return s.getsockname()[1]


def test_scan_open_closed_and_banner():
    async def run():
        async def greet(reader, writer):
            writer.write(b"SSH-2.0-TestServer\r\n")
            await writer.drain()
            writer.close()

        server = await asyncio.start_server(greet, "127.0.0.1", 0)
        open_port = server.sockets[0].getsockname()[1]
        closed_port = _free_port()
        results = []
        async with server:
            await scanner.scan([("localhost", "127.0.0.1")], [open_port, closed_port],
                               "Normal", results.append)
        return {r.port: r for r in results}, open_port, closed_port

    got, open_port, closed_port = asyncio.run(run())
    assert got[open_port].state == "open"
    assert got[open_port].banner == "SSH-2.0-TestServer"
    assert got[closed_port].state == "closed"


def test_scan_cancel_stops_early():
    results = []
    asyncio.run(scanner.scan([("localhost", "127.0.0.1")], list(range(1, 2000)), "Normal",
                             results.append, cancelled=lambda: len(results) >= 5))
    assert len(results) < 1999


def test_self_connect_counts_as_closed(monkeypatch):
    class Writer:
        def get_extra_info(self, _):
            return ("127.0.0.1", 50000)

        def close(self):
            pass

        async def wait_closed(self):
            pass

    async def fake_open(address, port):
        return None, Writer()

    monkeypatch.setattr(scanner.asyncio, "open_connection", fake_open)
    r = asyncio.run(scanner.probe("h", "127.0.0.1", 50000, 1.0))
    assert r.state == "closed"


def test_retries_only_unanswered_probes(monkeypatch):
    def fake(*outcomes):
        calls = []

        async def open_connection(address, port):
            calls.append(port)
            raise outcomes[min(len(calls), len(outcomes)) - 1]
        monkeypatch.setattr(scanner.asyncio, "open_connection", open_connection)
        return calls

    calls = fake(asyncio.TimeoutError(), ConnectionRefusedError())   # first probe lost
    assert asyncio.run(scanner.probe("h", "10.0.0.1", 80, 1.0, retries=1)).state == "closed"
    assert len(calls) == 2

    calls = fake(asyncio.TimeoutError())                              # never answers
    assert asyncio.run(scanner.probe("h", "10.0.0.1", 80, 1.0, retries=2)).state == "filtered"
    assert len(calls) == 3

    calls = fake(OSError(10065, "host unreachable"))                  # an answer: no retry
    assert asyncio.run(scanner.probe("h", "10.0.0.1", 80, 1.0, retries=2)).state == "filtered"
    assert len(calls) == 1
