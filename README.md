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

**Device discovery:** for targets on this computer's own network (for example `192.168.1.0/24`), PortScout also asks each address for its hardware (MAC) address, using ARP. Phones and PCs whose firewalls drop every port still answer, so they show as **up** with their MAC address, even with 0 ports answering. This needs no admin rights and only works on the local network, not across the internet. Phones with the screen off may sleep and miss it, and some routers isolate Wi-Fi devices from each other (AP or client isolation, common on guest networks). Many phones show a randomised MAC address rather than their real one.

**Device type (a best guess):** devices found this way are labelled **Mobile**, **Laptop / PC**, **TV / streaming**, **Smart speaker**, **Router** or **Printer**, shown with a `?` because it is a guess. The first clue that matches wins:
1. The device's own name on the network, for example `C40LAP-…` (laptop), `Galaxy-…` (mobile), `BRAVIA-…` (TV), `Kitchen-Echo` (smart speaker).
2. Open ports: 8008/8009 Google Cast (Android TV, Chromecast), 55442/55443 Alexa or 4070 Spotify Connect (Amazon Echo and other smart speakers), 62078 (iPhone/iPad), Windows file sharing or Remote Desktop (PC), 9100/631 (printer), 53 DNS (router). Top 100 covers most of these; for smart speakers and iPhones choose **Custom** and add `4070,55442,55443,62078`.
3. A randomised MAC address, which phones use by default, gives **Mobile**.

With no clue, the type is left blank. The MAC address, vendor, device name and type are also included in the export.

**MAC vendor names:** click **Get vendor list** (next to Export) to download IEEE's public list of MAC address prefixes, about 4 MB, so each device shows who made it, for example a router's or TV's manufacturer. It is downloaded only when you click, saved in `%LOCALAPPDATA%\PortScout\mac-vendors.tsv`, and used offline after that; click **Update vendor list** to refresh it. It is not included in this repository because the IEEE list has no explicit open licence. Devices using a randomised MAC address (most phones) show **private MAC**, because their address does not identify the maker.

The app warns you before it scans any public internet address.

**Scan only systems you own or have written permission to test.** Unauthorized scanning can be illegal.

## Tabs
- **Scanner:** the port scan described above. Risky open ports get a **RISK** level (High, Medium or Low) with a plain-English note on what the port is and what to do. The note is included in the export.
- **Connections:** every connection from this computer: program, local port, destination name, remote address, country and state, refreshed every 2 seconds. Tick **Include listening ports** to also see the ports this computer is listening on.
  - **New-destination alerts:** on the very first run, PortScout spends 90 seconds learning which destinations are normal for each program. After that, a program connecting to a new site is highlighted with **NEW** and listed in a banner. A site is the domain (for example `akamaitechnologies.com`), or the /24 network when an address has no name, so a cloud service switching between its addresses does not alert each time. Updating from an earlier PortScout starts one silent 90-second learning period again. Click **Mark as seen** to accept the selected rows, or all of them if none are selected.
- **Timeline:** the connection history (first seen, last seen, program, destination, country), filtered by time range and program. It is stored only on this computer in `%LOCALAPPDATA%\PortScout\history.db` and kept for 7 days.
- **Map:** the countries your connections went to, shaded by the number of distinct destinations, with a ranked list.
- **Websites:** which sites each device on your Wi-Fi looks up (phones, TVs, speakers, other PCs), with the time, the device's maker and type, and how often. It is off until you click **Start DNS logging**.
  - **How it works:** PortScout becomes your network's DNS server, the service every device asks for a site's address before opening it. It passes each question unchanged to your router and records the device and the name asked for. History stays on this computer for 7 days, in the same `history.db`.
  - **One-time setup, on your router:** in its DHCP or LAN settings, set the DNS server to this PC's address (shown in the tab, for example `192.168.1.36`). Reserve that address for this PC so it doesn't change. Then reconnect the devices to Wi-Fi. If Windows asks, allow PortScout on private networks.
  - **What it can't see:** full web addresses and page contents (encrypted), and devices or browsers using private DNS (Chrome "secure DNS", Android "Private DNS", iCloud Private Relay). Apps also look up background services, so expect names like `googlevideo.com` or analytics domains.
  - **Keep this PC on:** while it is off, asleep, or PortScout is closed, the other devices can't look up names (no internet) unless the router also lists a second DNS server, in which case some lookups go there and aren't logged.
  - **Consent:** only log devices you own, or whose users know and agree. Recording other people's browsing without their knowledge can be illegal.

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

The app icon is drawn in `data\icon.svg`. After changing it, run `.venv\Scripts\python tools\make_icon.py` to regenerate `data\icon.ico`, which the window, taskbar and `.exe` use. To give a desktop shortcut the same icon, open its **Properties → Change Icon…** and pick `data\icon.ico`.

## Limits
- A port that gives no answer is tried again (Polite 2 more times, Normal and Aggressive once), as Nmap does. Refused or unreachable ports are not retried. Hosts that drop everything therefore take longer to finish: up to the timeout times the number of tries.
- No SYN, UDP or OS scans; those need raw packets and the Npcap driver.
- No service version detection beyond reading the greeting a service sends by itself.
- Windows reports a refused connection after about 2 seconds, so timeouts are 2.5–4 s.
- A destination's country is where the answering server is, which for content delivery networks is often a nearby city, not where the company is based.
