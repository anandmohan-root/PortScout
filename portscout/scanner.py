"""TCP connect scan engine (stdlib only).

Behaviour mirrors Nmap's unprivileged connect scan (-sT), as mapped with REA:
  connect succeeds          -> open
  connection refused (RST)  -> closed    (the host answered, so it is up)
  timeout / unreachable     -> filtered
"""
from __future__ import annotations

import asyncio
import ipaddress
import socket
from dataclasses import dataclass

MAX_HOSTS = 256      # one /24 at most: this tool is for your own machines, not sweeps
MAX_PORTS = 65535
BANNER_BYTES = 256

# Well-known TCP ports most often found open, highest first.
COMMON_PORTS = [
    80, 23, 443, 21, 22, 25, 3389, 110, 445, 139, 143, 53, 135, 3306, 8080, 1723, 111, 995,
    993, 5900, 1025, 587, 8888, 199, 1720, 465, 548, 113, 81, 6001, 10000, 514, 5060, 179,
    1026, 2000, 8443, 8000, 32768, 554, 26, 1433, 49152, 2001, 515, 8008, 49154, 1027, 5666,
    646, 5000, 5631, 631, 49153, 8081, 2049, 88, 79, 5800, 106, 2121, 1110, 49155, 6000, 513,
    990, 5357, 427, 49156, 543, 544, 5101, 144, 7, 389, 8009, 3128, 444, 9999, 5009, 7070,
    5190, 3000, 5432, 1900, 3986, 13, 1029, 9, 5051, 6646, 49157, 1028, 873, 1755, 2717,
    4899, 9100, 119, 37,
]
PRESETS = {"Top 20": COMMON_PORTS[:20], "Top 100": COMMON_PORTS, "1-1024": list(range(1, 1025))}

# Nmap's -T names; values are (parallel connections, connect timeout seconds, delay between probes).
# Timeouts stay above 2 s: Windows retries a refused connect twice and reports it after ~2 s,
# so anything shorter turns every closed port into "filtered".
TIMING = {"Polite": (10, 4.0, 0.4), "Normal": (200, 3.0, 0.0), "Aggressive": (500, 2.5, 0.0)}

SERVICE_NAMES = {
    80: "http", 23: "telnet", 443: "https", 21: "ftp", 22: "ssh", 25: "smtp",
    3389: "ms-wbt-server", 110: "pop3", 445: "microsoft-ds", 139: "netbios-ssn", 143: "imap",
    53: "domain", 135: "msrpc", 3306: "mysql", 8080: "http-proxy", 5900: "vnc",
    5432: "postgresql", 1433: "ms-sql-s", 8443: "https-alt", 5000: "upnp", 3000: "ppp",
    9100: "jetdirect", 631: "ipp", 5357: "wsdapi", 2049: "nfs", 389: "ldap", 993: "imaps",
    995: "pop3s", 587: "submission", 465: "smtps", 1723: "pptp", 111: "rpcbind",
}


# Open ports worth a second look: (severity, what it means and what to do).
RISKS = {
    23: ("High", "Telnet sends everything, passwords included, unencrypted. Turn it off and use SSH."),
    2375: ("High", "Docker API without TLS gives full control of this machine. Close it or enable TLS."),
    3389: ("High", "Remote Desktop is attacked constantly. Keep it off the internet and use strong passwords."),
    445: ("High", "Windows file sharing (SMB) is a top worm and ransomware target. Never expose it to the internet."),
    5900: ("High", "VNC remote control often has weak or no password. Set a strong one or turn it off."),
    6379: ("High", "Redis has no password by default. Bind it to localhost or set a password."),
    27017: ("High", "MongoDB is often left without a password. Enable authentication."),
    9200: ("High", "Elasticsearch may answer anyone without a login. Enable security or bind to localhost."),
    11211: ("High", "Memcached has no login and is abused for attacks. Bind it to localhost."),
    1433: ("Medium", "SQL Server is reachable over the network. Allow only machines that need it."),
    3306: ("Medium", "MySQL is reachable over the network. Allow only machines that need it."),
    5432: ("Medium", "PostgreSQL is reachable over the network. Allow only machines that need it."),
    21: ("Medium", "FTP sends passwords unencrypted. Use SFTP or FTPS, or turn it off."),
    139: ("Medium", "Old NetBIOS file sharing. Turn off NetBIOS over TCP/IP if you don't need it."),
    5985: ("Medium", "Windows Remote Management (HTTP). Allow only admin machines."),
    135: ("Low", "Windows RPC. Normal on a Windows PC, but it should not be reachable from the internet."),
    80: ("Low", "Unencrypted web server. Check it isn't an admin or login page."),
    8080: ("Low", "Web server or proxy, often an admin or test service. Check what it is."),
    8000: ("Low", "Often a development web server. Stop it when you're not using it."),
    8888: ("Low", "Often a development or notebook server. Make sure it needs a login."),
}


def risk(port: int) -> tuple[str, str]:
    return RISKS.get(port, ("", ""))


@dataclass(frozen=True)
class PortResult:
    host: str
    address: str
    port: int
    state: str          # open | closed | filtered
    service: str
    banner: str = ""
    severity: str = ""  # High | Medium | Low, open ports only
    risk: str = ""


def service_name(port: int) -> str:
    if port in SERVICE_NAMES:
        return SERVICE_NAMES[port]
    try:
        return socket.getservbyport(port, "tcp")
    except OSError:
        return "unknown"


def parse_ports(text: str) -> list[int]:
    """'22,80,8000-8010' -> sorted unique ports. Raises ValueError on bad input."""
    ports: set[int] = set()
    for part in text.replace(" ", "").split(","):
        if not part:
            continue
        lo, _, hi = part.partition("-")
        a, b = int(lo), int(hi or lo)
        if not 1 <= a <= b <= MAX_PORTS:
            raise ValueError(f"Port range '{part}' must be between 1 and {MAX_PORTS}.")
        ports.update(range(a, b + 1))
    if not ports:
        raise ValueError("Enter at least one port.")
    return sorted(ports)


def parse_targets(text: str) -> list[str]:
    """Hostnames, IPs and CIDR blocks separated by commas, spaces or new lines."""
    hosts: list[str] = []
    for item in text.replace(",", " ").split():
        if "/" in item:
            net = ipaddress.ip_network(item, strict=False)   # ValueError on bad CIDR
            if net.num_addresses > MAX_HOSTS + 2:
                raise ValueError(f"{item} has {net.num_addresses} addresses; "
                                 f"the limit is {MAX_HOSTS} hosts per scan.")
            hosts += [str(ip) for ip in (net.hosts() if net.num_addresses > 2 else net)]
        else:
            hosts.append(item)
        if len(hosts) > MAX_HOSTS:
            raise ValueError(f"Too many targets; the limit is {MAX_HOSTS} hosts per scan.")
    if not hosts:
        raise ValueError("Enter a target, for example 127.0.0.1 or 192.168.1.0/24.")
    return list(dict.fromkeys(hosts))


def is_private(address: str) -> bool:
    ip = ipaddress.ip_address(address)
    return ip.is_private or ip.is_loopback or ip.is_link_local


def resolve(host: str) -> str:
    """Hostname -> IP address. Raises OSError when it cannot be resolved."""
    return socket.getaddrinfo(host, None, type=socket.SOCK_STREAM)[0][4][0]


async def probe(host: str, address: str, port: int, timeout: float) -> PortResult:
    state, banner = "filtered", ""
    try:
        reader, writer = await asyncio.wait_for(asyncio.open_connection(address, port), timeout)
    except ConnectionRefusedError:
        state = "closed"
    except (asyncio.TimeoutError, OSError):
        state = "filtered"
    else:
        # Self-connect: a loopback scan can hit its own source port and "connect" to itself.
        # Nmap's handleConnectResult discards these; nothing is listening, so call it closed.
        state = "closed" if writer.get_extra_info("sockname")[:2] == (address, port) else "open"
        try:   # many services (ssh, ftp, smtp) greet first; read what they say, never send
            if state != "open":
                raise OSError
            banner = (await asyncio.wait_for(reader.read(BANNER_BYTES), min(timeout, 1.0))
                      ).decode("utf-8", "replace").strip().splitlines()[0][:120]
        except (asyncio.TimeoutError, OSError, IndexError):
            pass
        writer.close()
        try:
            await writer.wait_closed()
        except OSError:
            pass
    severity, note = risk(port) if state == "open" else ("", "")
    return PortResult(host, address, port, state, service_name(port), banner, severity, note)


async def scan(targets: list[tuple[str, str]], ports: list[int], timing: str,
               on_result, cancelled=lambda: False) -> None:
    """Probe every (host, address) x port; calls on_result(PortResult) as each finishes."""
    limit, timeout, delay = TIMING[timing]
    jobs = ((h, a, p) for h, a in targets for p in ports)   # lazy: 256 hosts x 65535 ports fits

    async def worker():
        for host, address, port in jobs:   # workers share one generator; asyncio is single-threaded
            if cancelled():
                return
            on_result(await probe(host, address, port, timeout))
            if delay:
                await asyncio.sleep(delay)

    await asyncio.gather(*(worker() for _ in range(limit)))
