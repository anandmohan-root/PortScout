"""Connections, Timeline and Map tabs (this computer's own traffic) and the Websites tab
(sites each device on the Wi-Fi looks up)."""
from __future__ import annotations

import json
import math
import subprocess
import time

from PySide6.QtCore import QByteArray, QRectF, Qt, QTimer
from PySide6.QtGui import QColor, QPainter
from PySide6.QtSvg import QSvgRenderer
from PySide6.QtWidgets import (QAbstractItemView, QCheckBox, QComboBox, QFrame, QHBoxLayout, QHeaderView,
                               QLabel, QLineEdit, QMessageBox, QPushButton, QSplitter, QTableWidget,
                               QTableWidgetItem, QVBoxLayout, QWidget)

from . import dnslog, monitor, scanner

RANGES = {"Last hour": 3600, "Last 24 hours": 86400, "Last 7 days": monitor.KEEP_SECONDS}
BASELINE_SECONDS = 90   # first run: everything seen in this window counts as normal
WORLD = json.loads((monitor.DATA / "world.json").read_text(encoding="utf-8"))
COUNTRY_NAMES = {l["id"].upper(): l["name"] for l in WORLD["locations"]} | {
    monitor.LOCAL: "Local network"}
ATTRIBUTION = ("Country data: IP Geolocation by DB-IP (db-ip.com), CC BY 4.0. "
               "World map: @svg-maps/world, CC BY 4.0.")


def table(headers: list[str], stretch: int = -1) -> QTableWidget:
    """Read-only grid. Columns fit their contents; column `stretch` takes the spare width."""
    t = QTableWidget(0, len(headers))
    t.setHorizontalHeaderLabels(headers)
    t.verticalHeader().hide()
    t.setAlternatingRowColors(True)
    t.setShowGrid(False)
    t.setEditTriggers(QAbstractItemView.NoEditTriggers)
    t.setSelectionBehavior(QAbstractItemView.SelectRows)
    head = t.horizontalHeader()
    head.setDefaultAlignment(Qt.AlignLeft | Qt.AlignVCenter)   # line up with the left-aligned cells
    # Not ResizeToContents: that re-measures every row on each setItem, so filling n rows costs
    # n^2 and a scan's few hundred connections froze the UI for ~40 s. fill() sizes once instead.
    head.setSectionResizeMode(QHeaderView.Interactive)
    head.setSectionResizeMode(stretch % len(headers), QHeaderView.Stretch)
    return t


def fill(t: QTableWidget, rows: list[list[str]]):
    t.setRowCount(len(rows))
    for i, row in enumerate(rows):
        for j, text in enumerate(row):
            t.setItem(i, j, QTableWidgetItem(str(text)))
    fit_columns(t)


def fit_columns(t: QTableWidget):
    """Size columns to their contents once per refresh (Qt samples at most 1000 rows), leaving the
    stretch column alone: resizing it too cancels the stretch and leaves a gap on the right."""
    head = t.horizontalHeader()
    for i in range(t.columnCount()):
        if head.sectionResizeMode(i) != QHeaderView.Stretch:
            t.resizeColumnToContents(i)


def country_label(cc: str) -> str:
    return COUNTRY_NAMES.get(cc, cc)


def stamp(t: float) -> str:
    return time.strftime("%d %b %H:%M:%S", time.localtime(t))


def range_combo(default: str) -> QComboBox:
    box = QComboBox()
    box.addItems(list(RANGES))
    box.setCurrentText(default)
    return box


class ConnectionsTab(QWidget):
    COLUMNS = ["PROGRAM", "PID", "LOCAL PORT", "DESTINATION", "REMOTE", "COUNTRY", "STATE"]

    def __init__(self, c: dict, store: monitor.Store, names: monitor.Names, geo: monitor.Geo):
        super().__init__(objectName="page")
        self.c, self.store, self.names, self.geo = c, store, names, geo
        self.conns: list[monitor.Conn] = []
        self.rows: list[monitor.Conn] = []
        self.listen: list[monitor.Conn] = []

        self.banner = QFrame(objectName="banner", visible=False)
        self.banner_text = QLabel(wordWrap=True, objectName="bannerText")
        seen = QPushButton("Mark as seen", objectName="tool")
        seen.setToolTip("Marks the selected rows, or every new destination if none is selected")
        seen.clicked.connect(self.mark_seen)
        brow = QHBoxLayout(self.banner)
        brow.setContentsMargins(14, 10, 10, 10)
        brow.addWidget(self.banner_text, 1)
        brow.addWidget(seen)

        self.filter = QLineEdit(placeholderText="Filter by program, destination, port or country")
        self.filter.setAccessibleName("Filter connections")
        self.filter.textChanged.connect(self.render_rows)
        self.listening = QCheckBox("Include listening ports")
        self.listening.toggled.connect(self.refresh)
        self.count = QLabel(objectName="hint")
        self.table = table(self.COLUMNS, self.COLUMNS.index("DESTINATION"))
        self.table.setAccessibleName("Connections")
        self.table.setSortingEnabled(False)
        hint = QLabel("Live connections from this computer, refreshed every 2 seconds. "
                      "Names come from reverse DNS, which for cloud services often shows the provider "
                      "(e.g. amazonaws.com) rather than the site; run PortScout as administrator "
                      "to use the names programs actually looked up. Full web addresses are "
                      "encrypted and never visible.",
                      objectName="hint", wordWrap=True)

        col = QVBoxLayout(self)
        col.setContentsMargins(0, 12, 0, 0)
        col.addWidget(self.banner)
        bar = QHBoxLayout()
        bar.setSpacing(16)
        bar.addWidget(self.filter, 1)
        bar.addWidget(self.listening)
        bar.addWidget(self.count)
        col.addLayout(bar)
        col.addWidget(self.table, 1)
        col.addWidget(hint)

        self.timer = QTimer(self, interval=2000)
        self.timer.timeout.connect(self.refresh)
        self.timer.start()
        if store.baseline:
            QTimer.singleShot(BASELINE_SECONDS * 1000, store.end_baseline)
        QTimer.singleShot(0, self.refresh)

    def refresh(self):
        self.conns = monitor.snapshot(self.names, self.geo)
        self.listen = monitor.listening() if self.listening.isChecked() else []
        self.store.record(self.conns)
        unseen = self.store.unseen()
        for conn in self.conns:
            conn.new = conn.host is not None and (conn.program, conn.site) in unseen
        if unseen:
            sample = ", ".join(f"{p} → {d}" for p, d in sorted(unseen)[:3])
            more = f" and {len(unseen) - 3} more" if len(unseen) > 3 else ""
            self.banner_text.setText(f"<b>{len(unseen)} new destination(s)</b>: {sample}{more}")
        self.banner.setVisible(bool(unseen))
        self.render_rows()

    def visible_rows(self) -> list[monitor.Conn]:
        q = self.filter.text().strip().lower()
        rows = [c for c in self.conns + self.listen if not q or q in " ".join(
            map(str, (c.program, c.dest, c.remote_ip, c.local_port, c.remote_port,
                      country_label(c.country)))).lower()]
        return sorted(rows, key=lambda c: (not c.new, c.program.lower(), c.dest))

    def render_rows(self, *_):
        selected = self.selected_keys()
        rows = self.visible_rows()
        fill(self.table, [[c.program, c.pid, c.local_port,
                           ("NEW · " if c.new else "") + (c.dest if c.host is not None
                                                          else f"{c.remote_ip} (looking up…)"),
                           f"{c.remote_ip}:{c.remote_port}" if c.remote_ip else "—",
                           country_label(c.country), c.status]
                          for c in rows])
        self.rows = rows
        for i, conn in enumerate(rows):
            if conn.new:
                for j in range(len(self.COLUMNS)):
                    self.table.item(i, j).setBackground(QColor(self.c["accent_soft"]))
            if conn.key in selected:
                self.table.selectRow(i)
        self.count.setText(f"{len(rows)} of {len(self.conns)} connections")

    def selected_keys(self) -> set:
        rows = self.rows
        return {rows[i.row()].key for i in self.table.selectionModel().selectedRows()
                if i.row() < len(rows)}

    def mark_seen(self):
        keys = self.selected_keys()
        pairs = [(c.program, c.site) for c in self.rows if c.key in keys and c.host is not None]
        self.store.mark_seen(pairs if keys else None)   # a selection never widens to "all"
        self.refresh()


class TimelineTab(QWidget):
    COLUMNS = ["FIRST SEEN", "LAST SEEN", "PROGRAM", "LOCAL PORT", "DESTINATION", "REMOTE",
               "COUNTRY"]

    def __init__(self, store: monitor.Store):
        super().__init__(objectName="page")
        self.store = store
        self.range = range_combo("Last 24 hours")
        self.program = QComboBox()
        self.program.setMinimumWidth(220)
        self.range.currentTextChanged.connect(self.refresh)
        self.program.currentTextChanged.connect(self.refresh)
        self.count = QLabel(objectName="hint")
        self.table = table(self.COLUMNS, self.COLUMNS.index("DESTINATION"))
        self.table.setAccessibleName("Connection history")

        col = QVBoxLayout(self)
        col.setContentsMargins(0, 12, 0, 0)
        bar = QHBoxLayout()
        bar.setSpacing(8)
        bar.addWidget(QLabel("Show"))
        bar.addWidget(self.range)
        bar.addSpacing(16)   # separate the two label + box pairs
        bar.addWidget(QLabel("Program"))
        bar.addWidget(self.program)
        bar.addStretch(1)
        bar.addWidget(self.count)
        col.addLayout(bar)
        col.addWidget(self.table, 1)
        col.addWidget(QLabel("History is kept on this computer for 7 days "
                             f"({monitor.data_dir() / 'history.db'}).", objectName="hint"))

    def showEvent(self, e):
        current = self.program.currentText()
        self.program.blockSignals(True)
        self.program.clear()
        self.program.addItems(["All programs", *self.store.programs()])
        self.program.setCurrentText(current or "All programs")
        self.program.blockSignals(False)
        self.refresh()
        super().showEvent(e)

    def refresh(self, *_):
        program = self.program.currentText()
        rows = self.store.timeline(time.time() - RANGES[self.range.currentText()],
                                   None if program in ("", "All programs") else program)
        fill(self.table, [[stamp(a), stamp(b), p, lp, d, r, country_label(cc)]
                          for a, b, p, lp, d, r, cc in rows])
        self.count.setText(f"{len(rows)} connection(s)" + (" (newest 5000)" if len(rows) == 5000
                                                          else ""))


class WorldMap(QWidget):
    def __init__(self, c: dict):
        super().__init__()
        self.c = c
        self.setMinimumSize(420, 280)
        self.renderer = QSvgRenderer()
        self.set_counts({})

    def set_counts(self, counts: dict[str, int]):
        top = max(counts.values(), default=1)
        low, high = QColor(self.c["border"]), QColor(self.c["accent"])
        paths = []
        for loc in WORLD["locations"]:
            n = counts.get(loc["id"].upper(), 0)
            t = math.log1p(n) / math.log1p(top) if n else 0
            col = QColor.fromRgbF(*(low.getRgbF()[k] + (high.getRgbF()[k] - low.getRgbF()[k]) * t
                                    for k in range(3))).name() if n else low.name()
            paths.append(f'<path d="{loc["path"]}" fill="{col}" stroke="{self.c["surface"]}" '
                         f'stroke-width="0.4"/>')
        svg = (f'<svg xmlns="http://www.w3.org/2000/svg" viewBox="{WORLD["viewBox"]}">'
               + "".join(paths) + "</svg>")
        self.renderer.load(QByteArray(svg.encode()))
        self.update()

    def paintEvent(self, _):
        p = QPainter(self)
        p.setRenderHint(QPainter.Antialiasing)
        box = self.renderer.viewBoxF()
        scale = min(self.width() / box.width(), self.height() / box.height())
        w, h = box.width() * scale, box.height() * scale
        self.renderer.render(p, QRectF((self.width() - w) / 2, (self.height() - h) / 2, w, h))
        p.end()


class MapTab(QWidget):
    def __init__(self, c: dict, store: monitor.Store):
        super().__init__(objectName="page")
        self.store = store
        self.range = range_combo("Last 7 days")
        self.range.currentTextChanged.connect(self.refresh)
        self.map = WorldMap(c)
        self.table = table(["COUNTRY", "DESTINATIONS"], 0)
        self.table.setAccessibleName("Destinations by country")

        split = QSplitter()
        split.addWidget(self.map)
        split.addWidget(self.table)
        split.setSizes([700, 260])
        col = QVBoxLayout(self)
        col.setContentsMargins(0, 12, 0, 0)
        bar = QHBoxLayout()
        bar.setSpacing(8)
        bar.addWidget(QLabel("Show"))
        bar.addWidget(self.range)
        bar.addStretch(1)
        col.addLayout(bar)
        col.addWidget(split, 1)
        col.addWidget(QLabel("Darker countries received more distinct destinations. "
                             + ATTRIBUTION, objectName="hint", wordWrap=True))

    def showEvent(self, e):
        self.refresh()
        super().showEvent(e)

    def refresh(self, *_):
        counts = self.store.countries(time.time() - RANGES[self.range.currentText()])
        self.map.set_counts(counts)
        fill(self.table, [[country_label(cc), n]
                          for cc, n in sorted(counts.items(), key=lambda x: -x[1])])


class WebsitesTab(QWidget):
    """Sites each device on the Wi-Fi looks up, from PortScout acting as the network's DNS."""
    COLUMNS = ["LAST SEEN", "DEVICE", "SITE", "LOOKUPS"]

    def __init__(self):
        super().__init__(objectName="page")
        self.logger: dnslog.DnsLogger | None = None
        self.db = dnslog.open_db()
        self.vendors: dict[str, str] = {}
        self.toggle = QPushButton("Start DNS logging", objectName="tool")
        self.toggle.clicked.connect(self.start_stop)
        self.range = range_combo("Last hour")
        self.device = QComboBox()
        self.device.setMinimumWidth(260)
        self.range.currentTextChanged.connect(self.refresh)
        self.device.currentTextChanged.connect(self.refresh)
        self.count = QLabel(objectName="hint")
        self.table = table(self.COLUMNS, self.COLUMNS.index("SITE"))
        self.table.setAccessibleName("Sites looked up per device")
        self.info = QLabel(objectName="hint", wordWrap=True)
        self.info.setTextInteractionFlags(Qt.TextSelectableByMouse)

        col = QVBoxLayout(self)
        col.setContentsMargins(0, 12, 0, 0)
        bar = QHBoxLayout()
        bar.setSpacing(8)
        bar.addWidget(self.toggle)
        bar.addSpacing(16)
        bar.addWidget(QLabel("Show"))
        bar.addWidget(self.range)
        bar.addSpacing(16)
        bar.addWidget(QLabel("Device"))
        bar.addWidget(self.device)
        bar.addStretch(1)
        bar.addWidget(self.count)
        col.addLayout(bar)
        col.addWidget(self.table, 1)
        col.addWidget(self.info)
        self.timer = QTimer(self, interval=3000)
        self.timer.timeout.connect(self.refresh)
        self._info()

    def _info(self, extra: str = ""):
        if self.logger:
            ip = self.logger.address
            text = (f"<b>Logging on {ip}:53</b>, forwarding to the router {self.logger.upstream}. "
                    f"In your router's DHCP/LAN settings set the DNS server to <b>{ip}</b> (and "
                    f"reserve that address for this PC), then reconnect the devices to Wi-Fi. "
                    "If Windows asks, allow PortScout on private networks. Devices lose internet "
                    "while this PC is off or PortScout is closed, unless the router also lists a "
                    "second DNS server.")
        else:
            text = ("Shows the sites each device on your Wi-Fi looks up, by making this PC the "
                    "network's DNS server. Only site names are visible, not full web addresses or "
                    "page contents; devices using private DNS are not seen.")
        self.info.setText(text + (f"<br>{extra}" if extra else ""))

    def start_stop(self):
        if self.logger:
            self.logger.stop()
            self.logger = None
            self.toggle.setText("Start DNS logging")
            return self._info()
        if QMessageBox.question(
                self, "PortScout",
                "DNS logging records which sites each device on your Wi-Fi looks up.\n\n"
                "Only log devices you own, or whose users know and agree. Recording other "
                "people's browsing without their knowledge can be illegal.\n\nStart logging?",
                QMessageBox.Yes | QMessageBox.No, QMessageBox.No) != QMessageBox.Yes:
            return
        try:
            router = dnslog.gateway()
            self.logger = dnslog.DnsLogger(dnslog.lan_address(router), router)
        except (OSError, subprocess.SubprocessError) as e:
            return self._info(f"Could not start: {e}")
        self.toggle.setText("Stop DNS logging")
        self._info()

    def stop(self):
        if self.logger:
            self.logger.stop()

    def showEvent(self, e):
        self.vendors = monitor.load_vendors()
        self.timer.start()
        self.refresh()
        super().showEvent(e)

    def hideEvent(self, e):
        self.timer.stop()
        super().hideEvent(e)

    def describe(self, ip: str, mac: str) -> str:
        bits = [monitor.vendor(self.vendors, mac), scanner.device_type(mac, "", set())]
        return " · ".join([ip, *(b for b in bits if b)])

    def refresh(self, *_):
        since = time.time() - RANGES[self.range.currentText()]
        picked = self.device.currentData()
        rows = dnslog.summary(self.db, since, picked)
        devices = {ip: mac for _, ip, mac, _, _ in dnslog.summary(self.db, since)}
        self.device.blockSignals(True)
        self.device.clear()
        self.device.addItem("All devices", None)
        for ip in sorted(devices, key=lambda a: tuple(int(p) for p in a.split("."))):
            self.device.addItem(self.describe(ip, devices[ip]), ip)
        self.device.setCurrentIndex(max(0, self.device.findData(picked)))
        self.device.blockSignals(False)
        fill(self.table, [[stamp(t), self.describe(ip, mac), s, n] for t, ip, mac, s, n in rows])
        self.count.setText(f"{len(rows)} site(s) from {len({r[1] for r in rows})} device(s)")
