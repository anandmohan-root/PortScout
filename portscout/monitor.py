"""Live view of this computer's own connections: program, ports, destination name,
country, plus a local SQLite history (timeline) and per-program destination memory
(new-destination alerts), and MAC vendor names. No admin rights, no drivers, nothing sent
anywhere; the only download is the vendor list, and only when the user asks for it."""
from __future__ import annotations

import bisect
import csv
import ctypes
import gzip
import ipaddress
import os
import socket
import sqlite3
import string
import subprocess
import sys
import threading
import time
import urllib.request
from concurrent.futures import ThreadPoolExecutor
from dataclasses import dataclass
from pathlib import Path

import psutil

DATA = Path(getattr(sys, "_MEIPASS", Path(__file__).resolve().parent.parent)) / "data"
KEEP_SECONDS = 7 * 24 * 3600
LOCAL = "LAN"   # pseudo country code for private / loopback addresses


def data_dir() -> Path:
    d = Path(os.environ.get("LOCALAPPDATA", Path.home())) / "PortScout"
    d.mkdir(parents=True, exist_ok=True)
    return d


# ------------------------------------------------------------------ MAC vendors

# IEEE's public registry of MAC prefixes. Downloaded per computer, only when the user clicks
# for it: it has no explicit open licence, so it is not bundled.
# shortcut: MA-L (24-bit prefixes) only; add mam.csv / oui36.csv if small vendors show blank.
OUI_URL = "https://standards-oui.ieee.org/oui/oui.csv"


def vendor_file() -> Path:
    return data_dir() / "mac-vendors.tsv"


def parse_vendors(text: str) -> dict[str, str]:
    """IEEE oui.csv -> {"AABBCC": "Vendor name"}; rejects anything that isn't that file."""
    rows = {}
    for row in csv.reader(text.splitlines()):
        if len(row) >= 3 and len(row[1]) == 6 and all(ch in string.hexdigits for ch in row[1]):
            rows[row[1].upper()] = " ".join(row[2].split())[:80]
    if len(rows) < 10000:   # the real list has ~38,000; anything far smaller is an error page
        raise ValueError("The download did not look like the IEEE vendor list.")
    return rows


def download_vendors() -> int:
    """Fetch the list from IEEE and save it for load_vendors(). Returns the vendor count."""
    req = urllib.request.Request(OUI_URL, headers={"User-Agent": "PortScout"})
    with urllib.request.urlopen(req, timeout=120) as r:
        rows = parse_vendors(r.read().decode("utf-8", "replace"))
    tmp = vendor_file().with_suffix(".tmp")
    tmp.write_text("".join(f"{k}\t{v}\n" for k, v in rows.items()), encoding="utf-8")
    tmp.replace(vendor_file())   # never leave a half-written list behind
    return len(rows)


def load_vendors() -> dict[str, str]:
    try:
        lines = vendor_file().read_text(encoding="utf-8").splitlines()
    except OSError:
        return {}   # not downloaded yet
    return dict(line.split("\t", 1) for line in lines if "\t" in line)


def vendor(vendors: dict[str, str], mac: str) -> str:
    if mac and int(mac[:2], 16) & 2:
        return "private MAC"   # randomised by the device (phones by default): no maker to find
    return vendors.get(mac.replace(":", "")[:6].upper(), "")


@dataclass
class Conn:
    program: str
    pid: int
    local_port: int
    remote_ip: str
    remote_port: int
    status: str
    host: str | None = None      # None while the name lookup is still running
    country: str = ""
    new: bool = False

    @property
    def key(self):
        return self.program, self.local_port, self.remote_ip, self.remote_port

    @property
    def dest(self) -> str:
        return self.host or self.remote_ip

    @property
    def site(self) -> str:
        return site(self.host, self.remote_ip)


def site(host: str | None, ip: str) -> str:
    """What new-destination alerts compare: the domain, or the /24 (IPv6 /48) network when there
    is no name, so a cloud or CDN service rotating through addresses does not alert every time."""
    if host:
        labels = host.lower().rstrip(".").split(".")
        # shortcut: guesses two-part suffixes (bbc.co.uk) by length instead of the public suffix
        # list; upgrade if alerts merge or split sites wrongly.
        n = 3 if len(labels) > 2 and len(labels[-1]) == 2 and len(labels[-2]) <= 3 else 2
        return ".".join(labels[-n:])
    return str(ipaddress.ip_network(f"{ip}/{48 if ':' in ip else 24}", strict=False))


# ------------------------------------------------------------------ countries

class Geo:
    """IP -> ISO country code from the bundled DB-IP Lite file (CC BY 4.0). Loads in the
    background; lookups return "" until it is ready."""

    def __init__(self, path: Path = DATA / "dbip-country-lite.csv.gz"):
        self.ready = False
        self._starts: dict[int, list[int]] = {4: [], 6: []}
        self._rows: dict[int, list[tuple[int, str]]] = {4: [], 6: []}
        threading.Thread(target=self._load, args=(path,), daemon=True).start()

    def _load(self, path: Path):
        try:
            with gzip.open(path, "rt", newline="") as f:
                for start, end, cc in csv.reader(f):
                    a, b = ipaddress.ip_address(start), ipaddress.ip_address(end)
                    self._starts[a.version].append(int(a))
                    self._rows[a.version].append((int(b), cc))
            self.ready = True
        except OSError:
            pass   # missing data file: countries stay blank, everything else works

    def country(self, ip: str) -> str:
        try:
            addr = ipaddress.ip_address(ip)
        except ValueError:
            return ""
        if addr.is_private or addr.is_loopback or addr.is_link_local:
            return LOCAL
        if not self.ready:
            return ""
        starts = self._starts[addr.version]
        i = bisect.bisect_right(starts, int(addr)) - 1
        if i >= 0:
            end, cc = self._rows[addr.version][i]
            if int(addr) <= end and cc != "ZZ":
                return cc
        return ""


# ------------------------------------------------------------------ names

def is_admin() -> bool:
    try:
        return bool(ctypes.windll.shell32.IsUserAnAdmin())
    except (AttributeError, OSError):
        return False


class Names:
    """IP -> hostname. Windows' own DNS cache first (it holds the names programs actually
    looked up), then a reverse lookup; both run off the UI thread and are cached."""

    def __init__(self):
        self._cache: dict[str, str] = {}
        self._dns: dict[str, str] = {}
        self._pending: dict[str, object] = {}
        self._pool = ThreadPoolExecutor(8)
        if is_admin():   # Windows only lets administrators read the DNS cache
            threading.Thread(target=self._dns_loop, daemon=True).start()

    def _dns_loop(self):
        while True:
            try:
                out = subprocess.run(
                    ["powershell", "-NoProfile", "-Command",
                     "Get-DnsClientCache | Where-Object { $_.Type -in 1,28 } | "
                     "ForEach-Object { $_.Data + ' ' + $_.Entry }"],
                    capture_output=True, text=True, timeout=30,
                    creationflags=getattr(subprocess, "CREATE_NO_WINDOW", 0)).stdout
                self._dns = {**self._dns, **dict(l.split(" ", 1) for l in out.splitlines()
                                                 if " " in l)}
            except (OSError, subprocess.SubprocessError):
                pass
            time.sleep(15)

    @staticmethod
    def _reverse(ip: str) -> str:
        try:
            return socket.gethostbyaddr(ip)[0]
        except OSError:
            return ""

    def close(self):
        """Drop queued lookups so the app can exit: unanswered LAN lookups take seconds each."""
        self._pool.shutdown(wait=False, cancel_futures=True)

    def name(self, ip: str) -> str | None:
        """Hostname, "" when none exists, or None while still looking it up."""
        if ip in self._dns:
            return self._dns[ip]
        if ip in self._cache:
            return self._cache[ip]
        job = self._pending.get(ip)
        if job is None:
            self._pending[ip] = self._pool.submit(self._reverse, ip)
            return None
        if not job.done():
            return None
        if job.cancelled():
            return None
        self._cache[ip] = job.result()
        del self._pending[ip]
        return self._cache[ip]


# ------------------------------------------------------------------ history

class Store:
    """Timeline of connections and the per-program destinations already seen."""

    def __init__(self, path: Path | None = None):
        self.db = sqlite3.connect(path or data_dir() / "history.db")
        self.db.executescript("""
            CREATE TABLE IF NOT EXISTS conns (id INTEGER PRIMARY KEY, program TEXT,
                local_port INT, remote_ip TEXT, remote_port INT, host TEXT, country TEXT,
                first_seen REAL, last_seen REAL);
            CREATE INDEX IF NOT EXISTS conns_last ON conns(last_seen);
            DROP TABLE IF EXISTS dests;   -- older per-host table; sites replace it
            CREATE TABLE IF NOT EXISTS sites (program TEXT, site TEXT, first_seen REAL,
                seen INT, PRIMARY KEY (program, site));
        """)
        self.prune(time.time())
        # First run (or first run with site-level alerts): learn what is normal without alerting.
        self.baseline = self.db.execute("SELECT COUNT(*) FROM sites").fetchone()[0] == 0
        self._open: dict[tuple, int] = {}   # connection key -> conns row id

    def record(self, conns: list[Conn], now: float | None = None):
        now = now or time.time()
        live = {}
        for c in conns:
            row = self._open.get(c.key)
            if row is None:
                row = self.db.execute(
                    "INSERT INTO conns (program, local_port, remote_ip, remote_port, host, country,"
                    " first_seen, last_seen) VALUES (?,?,?,?,?,?,?,?)",
                    (*c.key, c.host or "", c.country, now, now)).lastrowid
            else:
                self.db.execute("UPDATE conns SET last_seen=?, host=COALESCE(NULLIF(?, ''), host),"
                                " country=COALESCE(NULLIF(?, ''), country) WHERE id=?",
                                (now, c.host or "", c.country, row))
            live[c.key] = row
            if c.host is not None:   # only judge "new" once the name lookup has finished
                self.db.execute("INSERT OR IGNORE INTO sites VALUES (?,?,?,?)",
                                (c.program, c.site, now, int(self.baseline)))
        self._open = live
        self.prune(now)

    def prune(self, now: float):
        self.db.execute("DELETE FROM conns WHERE last_seen < ?", (now - KEEP_SECONDS,))
        self.db.commit()

    def unseen(self) -> set[tuple[str, str]]:
        return set(self.db.execute("SELECT program, site FROM sites WHERE seen=0"))

    def mark_seen(self, pairs=None):
        if pairs is None:
            self.db.execute("UPDATE sites SET seen=1")
        else:
            self.db.executemany("UPDATE sites SET seen=1 WHERE program=? AND site=?", pairs)
        self.db.commit()

    def end_baseline(self):
        self.baseline = False

    def timeline(self, since: float, program: str | None = None) -> list[tuple]:
        q = ("SELECT first_seen, last_seen, program, local_port, COALESCE(NULLIF(host,''),"
             " remote_ip), remote_ip || ':' || remote_port, country FROM conns WHERE last_seen >= ?")
        args: list = [since]
        if program:
            q += " AND program = ?"
            args.append(program)
        return self.db.execute(q + " ORDER BY first_seen DESC LIMIT 5000", args).fetchall()

    def programs(self) -> list[str]:
        return [r[0] for r in self.db.execute("SELECT DISTINCT program FROM conns ORDER BY 1")]

    def countries(self, since: float) -> dict[str, int]:
        return dict(self.db.execute(
            "SELECT country, COUNT(DISTINCT program || host || remote_ip) FROM conns "
            "WHERE last_seen >= ? AND country != '' GROUP BY country", (since,)))


# ------------------------------------------------------------------ snapshot

_names: dict[int, str] = {}


def program_name(pid: int) -> str:
    if pid not in _names:
        try:
            _names[pid] = psutil.Process(pid).name()
        except (psutil.Error, OSError):
            _names[pid] = "System" if pid in (0, 4) else f"pid {pid}"
    return _names[pid]


def listening() -> list[Conn]:
    """Ports this computer is listening on (no remote end)."""
    # Windows can report a listening TCP socket with status NONE, so go by socket type.
    return [Conn(program_name(c.pid or 0), c.pid or 0, c.laddr.port, "", 0,
                 "LISTEN" if c.type == socket.SOCK_STREAM else "UDP", host="")
            for c in psutil.net_connections(kind="inet")
            if not c.raddr and c.status in (psutil.CONN_LISTEN, psutil.CONN_NONE)]


def snapshot(names: Names, geo: Geo) -> list[Conn]:
    """Current TCP/UDP connections that have a remote end."""
    conns = []
    for c in psutil.net_connections(kind="inet"):
        # pid 0 holds leftovers of connections that already closed: no program to attribute them to.
        if not c.raddr or c.raddr.ip in ("0.0.0.0", "::") or not c.pid:
            continue
        conns.append(Conn(program_name(c.pid or 0), c.pid or 0, c.laddr.port, c.raddr.ip,
                          c.raddr.port, c.status if c.status != "NONE" else "UDP",
                          names.name(c.raddr.ip), geo.country(c.raddr.ip)))
    return conns
