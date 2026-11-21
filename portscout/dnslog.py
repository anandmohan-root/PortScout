"""Which device on the local network looks up which site.

PortScout acts as the network's DNS server: once the router hands out this PC's address as the
DNS server, every device asks here before it opens a site or app. Each question is forwarded
unchanged to the router, the answer is passed back, and the time, the device's address and the
name it asked for are kept in a local SQLite table for 7 days. Only names are visible: full web
addresses and page contents are encrypted. Devices using private DNS (DoH/DoT) bypass this.
"""
from __future__ import annotations

import socket
import sqlite3
import struct
import subprocess
import threading
import time
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path

from . import monitor, scanner

PORT = 53
LOGGED_TYPES = {1, 28, 65}   # A, AAAA, HTTPS: what a device asks right before connecting


def question(packet: bytes) -> tuple[str, int] | None:
    """(name, type) of a plain one-question DNS query, or None if the packet isn't one."""
    try:
        flags, count = struct.unpack(">HH", packet[2:6])
        if flags & 0x8000 or count != 1:   # a response, or an unusual query
            return None
        labels, i = [], 12
        while packet[i]:
            n = packet[i]
            if n > 63:   # compression or junk: never in a query's own question
                return None
            labels.append(packet[i + 1:i + 1 + n].decode("ascii"))
            i += 1 + n
        return ".".join(labels).lower(), struct.unpack(">H", packet[i + 1:i + 3])[0]
    except (struct.error, IndexError, UnicodeDecodeError):
        return None


def gateway() -> str:
    """This PC's default gateway (the router), which also answers DNS."""
    out = subprocess.run(
        ["powershell", "-NoProfile", "-Command",
         "(Get-NetIPConfiguration | Where-Object { $_.IPv4DefaultGateway } | "
         "Select-Object -First 1).IPv4DefaultGateway.NextHop"],
        capture_output=True, text=True, timeout=20,
        creationflags=getattr(subprocess, "CREATE_NO_WINDOW", 0)).stdout.strip()
    if not out:
        raise OSError("No default gateway: is this PC connected to the Wi-Fi?")
    return out


def lan_address(router: str) -> str:
    """This PC's address on the router's network (no packet is sent)."""
    with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as s:
        s.connect((router, PORT))
        return s.getsockname()[0]


def open_db(path: Path | None = None) -> sqlite3.Connection:
    db = sqlite3.connect(path or monitor.data_dir() / "history.db", timeout=5)
    db.executescript("""
        CREATE TABLE IF NOT EXISTS dns (t REAL, client TEXT, mac TEXT, name TEXT);
        CREATE INDEX IF NOT EXISTS dns_t ON dns(t);
    """)
    db.execute("DELETE FROM dns WHERE t < ?", (time.time() - monitor.KEEP_SECONDS,))
    db.commit()
    return db


class DnsLogger:
    """Serves DNS on address:port in a background thread until stop()."""

    def __init__(self, address: str, upstream: str, db_path: Path | None = None,
                 port: int = PORT, upstream_port: int = PORT):
        self.address, self.upstream, self.db_path = address, upstream, db_path
        self.upstream_port = upstream_port
        self.sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        if hasattr(socket, "SIO_UDP_CONNRESET"):   # Windows: an ICMP error must not end recv
            self.sock.ioctl(socket.SIO_UDP_CONNRESET, False)
        self.sock.bind((address, port))   # OSError if the port is taken
        self.sock.settimeout(1)
        self.running = True
        self._rows: list[tuple] = []        # appended by the pool, saved by the server thread
        self._macs: dict[str, str] = {}
        self._pool = ThreadPoolExecutor(32)
        self._thread = threading.Thread(target=self._serve, daemon=True)
        self._thread.start()

    def stop(self):
        self.running = False
        self._thread.join(3)
        self.sock.close()
        self._pool.shutdown(wait=False, cancel_futures=True)

    def _serve(self):
        db, saved = open_db(self.db_path), time.time()
        while self.running:
            try:
                packet, client = self.sock.recvfrom(4096)
                self._pool.submit(self._forward, packet, client)
            except (socket.timeout, ConnectionResetError):
                pass
            except OSError:
                break   # socket closed
            if self._rows and time.time() - saved >= 1:   # one write per second, not per query
                rows, self._rows = self._rows, []
                db.executemany("INSERT INTO dns VALUES (?,?,?,?)", rows)
                db.commit()
                saved = time.time()
        db.close()

    def _forward(self, packet: bytes, client: tuple[str, int]):
        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as up:
            up.settimeout(4)
            try:
                up.sendto(packet, (self.upstream, self.upstream_port))
                answer = up.recv(65535)
            except OSError:
                return   # router did not answer; the device will retry
        try:
            self.sock.sendto(answer, client)
        except OSError:
            return
        q = question(packet)
        if q and q[1] in LOGGED_TYPES and "." in q[0]:
            ip = client[0]
            if ip not in self._macs:   # instant for a device that just talked to us
                self._macs[ip] = scanner.arp(ip) if ip != self.address else ""
            self._rows.append((time.time(), ip, self._macs[ip], q[0]))


def summary(db: sqlite3.Connection, since: float, client: str | None = None) -> list[tuple]:
    """[(last seen, client, mac, site, lookups)], newest first; names grouped by site."""
    q = "SELECT client, mac, name, MAX(t), COUNT(*) FROM dns WHERE t >= ?"
    args: list = [since]
    if client:
        q += " AND client = ?"
        args.append(client)
    grouped: dict[tuple, list] = {}
    for ip, mac, name, last, n in db.execute(q + " GROUP BY client, name", args):
        row = grouped.setdefault((ip, monitor.site(name, ip)), [0.0, ip, mac, "", 0])
        row[0], row[4] = max(row[0], last), row[4] + n
        row[2] = row[2] or mac
    return sorted(((t, ip, mac, s, n) for (ip, s), (t, _, mac, _, n) in grouped.items()),
                  reverse=True)
