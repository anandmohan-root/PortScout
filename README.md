# PortScout

A desktop TCP port scanner for machines and networks you own, plus a live view of where this computer's own connections go. It runs entirely on your computer, installs no drivers and needs no admin rights.

Its scanning behaviour follows Nmap's connect scan (`nmap -sT`). That behaviour was mapped by reverse engineering `nmap.exe` 7.92 with REA and Ghidra. No Nmap code or data files are included.

## Use it
1. Enter targets: hostnames, IPs or one CIDR block, up to 256 hosts.
2. Pick a port set: Top 20, Top 100, 1–1024, or Custom (for example `22,80,8000-8100`).
3. Pick a speed: Polite, Normal or Aggressive.
4. Tick **I own these targets or have permission to scan them**, then click **Start scan**.
5. Click a host to see its open ports. Tick **Show closed and filtered ports** for everything. Use **Export…** to save CSV or JSON.

Port states, as in Nmap:
- **open**: the connection succeeded.
- **closed**: the host refused the connection.
- **filtered**: no answer, or the host was unreachable.

The app warns you before it scans any public internet address.

**Scan only systems you own or have written permission to test.** Unauthorized scanning can be illegal.

## Tabs
- **Scanner:** the port scan described above. Risky open ports get a **RISK** level (High, Medium or Low) with a plain-English note on what the port is and what to do. The note is included in the export.
- **Connections:** every connection from this computer: program, local port, destination name, remote address, country and state, refreshed every 2 seconds. Tick **Include listening ports** to also see the ports this computer is listening on.
  - **New-destination alerts:** on the very first run, PortScout spends 90 seconds learning which destinations are normal for each program. After that, a program connecting to a new site is highlighted with **NEW** and listed in a banner. A site is the domain (for example `akamaitechnologies.com`), or the /24 network when an address has no name, so a cloud service switching between its addresses does not alert each time. Updating from an earlier PortScout starts one silent 90-second learning period again. Click **Mark as seen** to accept the selected rows, or all of them if none are selected.
- **Timeline:** the connection history (first seen, last seen, program, destination, country), filtered by time range and program. It is stored only on this computer in `%LOCALAPPDATA%\PortScout\history.db` and kept for 7 days.
- **Map:** the countries your connections went to, shaded by the number of distinct destinations, with a ranked list.

Destination names come from reverse DNS, which for cloud services often shows the provider (such as `amazonaws.com`) rather than the website. When run as administrator, PortScout also reads the Windows DNS cache, which has the names programs actually looked up. Full web addresses are encrypted (HTTPS) and are never visible.

## Data and credits
- Country lookup: IP Geolocation by [DB-IP](https://db-ip.com), CC BY 4.0, bundled in `data/` (November 2026 edition). It is used offline only.
- World map: [@svg-maps/world](https://www.npmjs.com/package/@svg-maps/world), CC BY 4.0 (see `data/world-map-LICENSE.md`).

## Set up on a new computer
Needs Windows 10 or 11, [Git](https://git-scm.com) and Python 3.10 or newer (tested with 3.13, 64-bit; tick "Add python.exe to PATH" when installing). No admin rights or settings are needed.
```
git clone https://github.com/anandmohan-root/PortScout.git
cd PortScout
python -m venv .venv
.venv\Scripts\pip install -r requirements-dev.txt
.venv\Scripts\pythonw.exe main.py
```
Don't copy `.venv`, `build` or `dist` from another computer; they only work where they were made. The pip step needs internet once. Connection history and the learned destinations stay on each computer, so a new one starts with its own 90-second learning period.

## Start it
Run `.venv\Scripts\pythonw.exe main.py` in this folder, or make a desktop shortcut to it.

If Windows Smart App Control blocks the unsigned `dist\PortScout\PortScout.exe`, start it this way instead: Python's own `pythonw.exe` is signed by the Python Software Foundation, so it is allowed.

## Run from source
```
python -m venv .venv
.venv\Scripts\pip install -r requirements-dev.txt
.venv\Scripts\python main.py
.venv\Scripts\python -m pytest -q
```

## Build a Windows app folder
```
.venv\Scripts\python -m PyInstaller --noconfirm PortScout.spec
```
The app is then at `dist\PortScout\PortScout.exe`.

## Limits
- A port that gives no answer is tried again (Polite 2 more times, Normal and Aggressive once), as Nmap does. Refused or unreachable ports are not retried. Hosts that drop everything therefore take longer to finish: up to the timeout times the number of tries.
- No SYN, UDP or OS scans; those need raw packets and the Npcap driver.
- No service version detection beyond reading the greeting a service sends by itself.
- Windows reports a refused connection after about 2 seconds, so timeouts are 2.5–4 s.
- A destination's country is where the answering server is, which for content delivery networks is often a nearby city, not where the company is based.
