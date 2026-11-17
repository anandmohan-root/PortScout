"""PySide6 UI: targets, port set, speed, an authorization tick, one Scan button,
live progress, a host list and a port table. Follows the Windows light/dark setting."""
from __future__ import annotations

import asyncio
import csv
import ctypes
import json
import sys
import threading
from collections import defaultdict
from dataclasses import asdict

from PySide6.QtCore import QObject, Qt, QThread, QTimer, Signal
from PySide6.QtGui import QColor, QGuiApplication, QIcon
from PySide6.QtWidgets import (QApplication, QButtonGroup, QCheckBox, QFileDialog, QFrame,
                               QHBoxLayout, QLabel, QLineEdit, QListWidget, QListWidgetItem,
                               QMessageBox, QProgressBar, QPushButton, QSplitter,
                               QTableWidgetItem, QTabWidget, QVBoxLayout, QWidget)

from . import monitor, scanner, tabs

APP_NAME = "PortScout"
ICON = monitor.DATA / "icon.ico"   # made from icon.svg by tools/make_icon.py

LIGHT = dict(bg="#F3F4F8", surface="#FFFFFF", surface2="#EEF0F5", border="#E2E5EC",
             text="#12141A", muted="#687082", accent="#5B5BF6", accent2="#9B5CF6",
             accent_soft="#ECECFE", success="#159947", danger="#D93636", warn="#B7791F")
DARK = dict(bg="#0E1015", surface="#171A21", surface2="#1F232C", border="#2A2F3A",
            text="#ECEEF3", muted="#98A1B3", accent="#7476FF", accent2="#A77BFF",
            accent_soft="#262A45", success="#3CCB7F", danger="#FF6B6B", warn="#F6C35B")


def is_dark() -> bool:
    try:
        return QGuiApplication.styleHints().colorScheme() == Qt.ColorScheme.Dark
    except AttributeError:
        return False


def stylesheet(c: dict) -> str:
    return f"""
    QWidget#root {{ background: {c['bg']}; }}
    QWidget {{ color: {c['text']}; font-family: 'Segoe UI Variable Text', 'Segoe UI';
               font-size: 13px; }}
    QLabel#title {{ font-size: 22px; font-weight: 700; }}
    QLabel#badge, QLabel#hint, QLabel#status {{ color: {c['muted']}; font-size: 12px; }}
    QLabel#status[state="ok"] {{ color: {c['success']}; font-weight: 600; }}
    QLabel#status[state="error"] {{ color: {c['danger']}; font-weight: 600; }}
    QLabel#section {{ color: {c['muted']}; font-size: 11px; font-weight: 600;
                      letter-spacing: 1px; }}
    QFrame#card {{ background: {c['surface']}; border: 1px solid {c['border']};
                   border-radius: 16px; }}
    QLineEdit {{ background: {c['surface2']}; border: 1px solid {c['border']}; border-radius: 10px;
                 padding: 8px 10px; }}
    QLineEdit:focus {{ border-color: {c['accent']}; }}
    QLineEdit:disabled {{ color: {c['muted']}; }}
    QFrame#segment {{ background: {c['surface2']}; border-radius: 12px; }}
    QPushButton#seg {{ border: none; border-radius: 9px; min-height: 32px; padding: 0 12px;
        font-size: 12px; font-weight: 600; color: {c['muted']}; background: transparent; }}
    QPushButton#seg:checked {{ background: {c['surface']}; color: {c['text']}; }}
    QPushButton#seg:focus {{ outline: none; border: 1px solid {c['accent']}; }}
    QPushButton#primary {{ border: none; border-radius: 14px; min-height: 48px; font-size: 15px;
        font-weight: 600; color: white;
        background: qlineargradient(x1:0, y1:0, x2:1, y2:0,
                                    stop:0 {c['accent']}, stop:1 {c['accent2']}); }}
    QPushButton#primary:disabled {{ background: {c['surface2']}; color: {c['muted']}; }}
    QPushButton#secondary {{ border: 1px solid {c['border']}; border-radius: 14px; min-height: 48px;
        font-size: 15px; font-weight: 600; background: {c['surface']}; color: {c['danger']}; }}
    QPushButton#tool {{ border: 1px solid {c['border']}; border-radius: 10px; min-height: 34px;
        padding: 0 12px; font-weight: 600; background: {c['surface']}; }}
    QPushButton#tool:hover, QPushButton#secondary:hover {{ border-color: {c['accent']}; }}
    QPushButton#tool:disabled {{ color: {c['muted']}; }}
    QCheckBox {{ spacing: 8px; }}
    QListWidget, QTableWidget {{ background: {c['surface']}; border: 1px solid {c['border']};
        border-radius: 12px; outline: none; alternate-background-color: {c['surface2']}; }}
    QListWidget::item {{ padding: 8px; border-radius: 8px; }}
    QListWidget::item:selected {{ background: {c['accent_soft']}; color: {c['text']}; }}
    QTableWidget::item {{ padding: 0 12px 0 9px; }}  /* + Qt's 3px text margin = header's 12px */
    QTableWidget::item:selected {{ background: {c['accent_soft']}; color: {c['text']}; }}
    QHeaderView::section {{ background: {c['surface']}; color: {c['muted']}; border: none;
        border-bottom: 1px solid {c['border']}; padding: 8px 12px; font-size: 11px;
        font-weight: 600; }}
    QProgressBar {{ background: {c['surface2']}; border: none; border-radius: 3px;
                    max-height: 6px; min-height: 6px; }}
    QProgressBar::chunk {{ border-radius: 3px;
        background: qlineargradient(x1:0, y1:0, x2:1, y2:0,
                                    stop:0 {c['accent']}, stop:1 {c['accent2']}); }}
    QSplitter::handle {{ background: transparent; width: 10px; }}
    QTabWidget::pane {{ border: none; padding-top: 8px; }}
    QTabBar::tab {{ background: transparent; color: {c['muted']}; padding: 8px 14px;
        font-weight: 600; border-bottom: 2px solid transparent; }}
    QTabBar::tab:selected {{ color: {c['text']}; border-bottom-color: {c['accent']}; }}
    QTabBar::tab:hover {{ color: {c['text']}; }}
    QComboBox {{ background: {c['surface']}; border: 1px solid {c['border']}; border-radius: 10px;
                 padding: 6px 10px; min-height: 22px; }}
    QFrame#banner {{ background: {c['accent_soft']}; border: 1px solid {c['accent']};
                     border-radius: 12px; }}
    QLabel#bannerText {{ background: transparent; }}
    """


class ScanWorker(QObject):
    """Resolves targets and runs the asyncio scan off the UI thread."""
    result = Signal(object)        # scanner.PortResult
    device = Signal(str, str, str) # host, MAC, local name: found on this PC's own network
    finished = Signal()

    def __init__(self, targets: list[tuple[str, str]], ports: list[int], timing: str):
        super().__init__()
        self.targets, self.ports, self.timing = targets, ports, timing
        self.stop = False

    def run(self):
        async def both():
            await asyncio.gather(scanner.discover(self.targets, self.device.emit),
                                 scanner.scan(self.targets, self.ports, self.timing,
                                              self.result.emit, cancelled=lambda: self.stop))
        try:
            asyncio.run(both())
        finally:
            self.finished.emit()


def segment(options: list[str], checked: str) -> tuple[QFrame, QButtonGroup]:
    frame = QFrame(objectName="segment")
    row = QHBoxLayout(frame)
    row.setContentsMargins(3, 3, 3, 3)
    row.setSpacing(2)
    group = QButtonGroup(frame)
    for text in options:
        b = QPushButton(text, objectName="seg", checkable=True)
        b.setChecked(text == checked)
        b.setCursor(Qt.PointingHandCursor)
        group.addButton(b)
        row.addWidget(b)
    return frame, group


def card(title: str, *widgets: QWidget) -> QFrame:
    frame = QFrame(objectName="card")
    col = QVBoxLayout(frame)
    col.setContentsMargins(16, 14, 16, 14)
    col.setSpacing(8)
    col.addWidget(QLabel(title.upper(), objectName="section"))
    for w in widgets:
        col.addWidget(w)
    return frame


class MainWindow(QWidget):
    vendors_done = Signal(object)   # vendor count, or the error from the download thread

    def __init__(self):
        super().__init__(objectName="root")
        self.c = DARK if is_dark() else LIGHT
        self.setStyleSheet(stylesheet(self.c))
        self.setWindowTitle(APP_NAME)
        self.resize(1180, 760)
        self.results: dict[str, dict[int, scanner.PortResult]] = defaultdict(dict)
        self.devices: dict[str, tuple[str, str]] = {}   # host -> (MAC, name), answered ARP
        self.vendors = monitor.load_vendors()           # empty until the user downloads it
        self.done = self.total = 0
        self.thread: QThread | None = None
        self.worker: ScanWorker | None = None

        title = QLabel(APP_NAME, objectName="title")
        badge = QLabel("TCP port scanner for machines and networks you own, and a live view of "
                       "this PC's own connections. Runs locally.",
                       objectName="badge")

        self.target = QLineEdit(placeholderText="127.0.0.1, 192.168.1.0/24, my-nas.local")
        self.target.setAccessibleName("Targets")
        self.target.returnPressed.connect(self.start)
        targets = card("Targets", self.target,
                       QLabel(f"Hostnames, IPs or a CIDR block. Up to {scanner.MAX_HOSTS} hosts.",
                              objectName="hint"))

        port_seg, self.port_group = segment([*scanner.PRESETS, "Custom"], "Top 100")
        self.custom_ports = QLineEdit(placeholderText="22, 80, 443, 8000-8100", enabled=False)
        self.custom_ports.setAccessibleName("Custom ports")
        self.port_group.buttonToggled.connect(
            lambda b, on: on and self.custom_ports.setEnabled(b.text() == "Custom"))
        ports = card("Ports", port_seg, self.custom_ports)

        speed_seg, self.speed_group = segment(list(scanner.TIMING), "Normal")
        self.speed_hint = QLabel(objectName="hint")
        self.speed_group.buttonToggled.connect(lambda *_: self._speed_hint())
        self._speed_hint()
        speed = card("Speed", speed_seg, self.speed_hint)

        self.authorized = QCheckBox("I own these targets or have permission to scan them")
        self.authorized.toggled.connect(self._sync_buttons)

        self.scan_btn = QPushButton("Start scan", objectName="primary")
        self.scan_btn.setCursor(Qt.PointingHandCursor)
        self.scan_btn.clicked.connect(self.start)
        self.stop_btn = QPushButton("Stop", objectName="secondary", visible=False)
        self.stop_btn.clicked.connect(self.stop)
        self.progress = QProgressBar(textVisible=False, visible=False)
        self.status = QLabel("Enter a target, tick the permission box, then start the scan.",
                             objectName="status", wordWrap=True)

        left = QVBoxLayout()
        left.setSpacing(12)
        for w in (targets, ports, speed, self.authorized, self.scan_btn, self.stop_btn,
                  self.progress, self.status):
            left.addWidget(w)
        left.addStretch(1)
        left.setContentsMargins(0, 0, 0, 0)   # line the cards up with the title and tabs
        left_w = QWidget()
        left_w.setLayout(left)
        left_w.setFixedWidth(380)

        self.hosts = QListWidget()
        self.hosts.setAccessibleName("Hosts")
        self.hosts.currentItemChanged.connect(lambda *_: self.show_ports())
        self.table = tabs.table(["PORT", "STATE", "SERVICE", "RISK", "BANNER"])
        self.table.setAccessibleName("Ports")
        self.show_all = QCheckBox("Show closed and filtered ports")
        self.show_all.toggled.connect(self.show_ports)
        self.not_shown = QLabel(objectName="hint")
        self.risk_note = QLabel(objectName="hint", wordWrap=True)
        self.risk_note.setTextInteractionFlags(Qt.TextSelectableByMouse)
        self.export_btn = QPushButton("Export…", objectName="tool", enabled=False)
        self.export_btn.clicked.connect(self.export)
        self.vendor_btn = QPushButton(objectName="tool")
        self.vendor_btn.setToolTip("Downloads IEEE's public list of MAC address prefixes "
                                   "(about 4 MB) to show who made each device on your network.")
        self.vendor_btn.clicked.connect(self.get_vendors)
        self.vendors_done.connect(self.on_vendors)
        self._vendor_btn_text()

        table_box = QWidget()
        tcol = QVBoxLayout(table_box)
        tcol.setContentsMargins(0, 0, 0, 0)
        tcol.addWidget(self.table, 1)
        tcol.addWidget(self.risk_note)
        tcol.addWidget(self.not_shown)
        split = QSplitter()
        split.addWidget(self.hosts)
        split.addWidget(table_box)
        split.setSizes([260, 520])

        right = QVBoxLayout()
        bar = QHBoxLayout()   # above both panes, so the host list and port table start level
        bar.addWidget(QLabel("RESULTS", objectName="section"))
        bar.addStretch(1)
        bar.addWidget(self.show_all)
        bar.addSpacing(12)
        bar.addWidget(self.vendor_btn)
        bar.addWidget(self.export_btn)
        right.addLayout(bar)
        right.addWidget(split, 1)

        body = QHBoxLayout()
        body.setContentsMargins(0, 12, 0, 0)   # same inset as the other tabs
        body.setSpacing(20)
        body.addWidget(left_w)
        body.addLayout(right, 1)
        root = QVBoxLayout(self)
        root.setContentsMargins(24, 20, 24, 20)
        logo = QLabel()
        logo.setPixmap(QIcon(str(ICON)).pixmap(32, 32))
        head = QHBoxLayout()
        head.setSpacing(10)
        head.addWidget(logo)
        head.addWidget(title)
        head.addStretch(1)
        root.addLayout(head)
        root.addWidget(badge)
        root.addSpacing(8)
        scan_tab = QWidget()
        scan_tab.setLayout(body)
        self.store = monitor.Store()
        self.connections = tabs.ConnectionsTab(self.c, self.store, monitor.Names(), monitor.Geo())
        self.tabs = QTabWidget()
        self.tabs.addTab(scan_tab, "Scanner")
        self.tabs.addTab(self.connections, "Connections")
        self.tabs.addTab(tabs.TimelineTab(self.store), "Timeline")
        self.tabs.addTab(tabs.MapTab(self.c, self.store), "Map")
        root.addWidget(self.tabs, 1)

        self.refresh = QTimer(self, interval=150)   # batch UI updates; probes arrive by the thousand
        self.refresh.timeout.connect(self.update_view)
        self._sync_buttons()

    # ------------------------------------------------------------- helpers

    def _speed_hint(self):
        limit, timeout, delay, retries = scanner.TIMING[self.speed_group.checkedButton().text()]
        extra = f", {delay:g} s pause after each probe" if delay else ""
        self.speed_hint.setText(f"{limit} connections at once, {timeout:g} s timeout{extra}, "
                                f"{retries} retr{'y' if retries == 1 else 'ies'} if no answer.")

    def _sync_buttons(self):
        self.scan_btn.setEnabled(self.authorized.isChecked() and self.thread is None)

    def _status(self, text: str, state: str = ""):
        self.status.setText(text)
        self.status.setProperty("state", state)
        self.status.style().polish(self.status)

    def chosen_ports(self) -> list[int]:
        name = self.port_group.checkedButton().text()
        return scanner.parse_ports(self.custom_ports.text()) if name == "Custom" \
            else scanner.PRESETS[name]

    # ------------------------------------------------------------- scan flow

    def start(self):
        if self.thread is not None or not self.authorized.isChecked():
            return
        try:
            hosts = scanner.parse_targets(self.target.text())
            ports = self.chosen_ports()
        except ValueError as e:
            return self._status(str(e), "error")
        targets, skipped = [], []
        for host in hosts:
            try:
                targets.append((host, scanner.resolve(host)))
            except OSError:
                skipped.append(host)
        if not targets:
            return self._status(f"Could not resolve {', '.join(skipped)}.", "error")
        public = [h for h, a in targets if not scanner.is_private(a)]
        if public and QMessageBox.warning(
                self, APP_NAME,
                f"{', '.join(public[:3])}{' …' if len(public) > 3 else ''} is a public "
                "internet address.\n\nScanning systems you do not own or have permission to "
                "test can be illegal. Continue?",
                QMessageBox.Yes | QMessageBox.No, QMessageBox.No) != QMessageBox.Yes:
            return

        self.results.clear()
        self.devices.clear()
        self.hosts.clear()
        self.table.setRowCount(0)
        self.not_shown.clear()
        self.done, self.total = 0, len(targets) * len(ports)
        self.progress.setRange(0, self.total)
        self.progress.setValue(0)
        self.progress.show()
        self.stop_btn.show()
        self.scan_btn.hide()
        self.export_btn.setEnabled(False)
        self._status(f"Scanning {len(targets)} host(s), {len(ports)} port(s) each…"
                     + (f" Skipped (no address): {', '.join(skipped)}." if skipped else ""))

        self.thread = QThread(self)
        self.worker = ScanWorker(targets, ports, self.speed_group.checkedButton().text())
        self.worker.moveToThread(self.thread)
        self.thread.started.connect(self.worker.run)
        self.worker.result.connect(self.on_result)
        self.worker.device.connect(self.on_device)
        self.worker.finished.connect(self.on_finished)
        self.thread.start()
        self.refresh.start()
        self._sync_buttons()

    def stop(self):
        if self.worker:
            self.worker.stop = True
            self._status("Stopping after the probes already in flight…")

    def on_result(self, r: scanner.PortResult):
        self.results[r.host][r.port] = r
        self.done += 1

    def on_device(self, host: str, mac: str, name: str):
        self.devices[host] = (mac, name)

    def is_up(self, host: str) -> bool:
        return host in self.devices or _is_up(self.results.get(host, {}))

    def device(self, host: str) -> dict:
        """MAC, local name and guessed type, for devices found on this PC's own network."""
        if host not in self.devices:
            return {"mac": "", "vendor": "", "device_name": "", "device_type": ""}
        mac, name = self.devices[host]
        open_ports = {p for p, r in self.results.get(host, {}).items() if r.state == "open"}
        return {"mac": mac, "vendor": monitor.vendor(self.vendors, mac), "device_name": name,
                "device_type": scanner.device_type(mac, name, open_ports)}

    # ------------------------------------------------------------- MAC vendor list

    def _vendor_btn_text(self):
        self.vendor_btn.setText("Update vendor list" if self.vendors else "Get vendor list")

    def get_vendors(self):
        self.vendor_btn.setEnabled(False)
        self._status("Downloading the MAC vendor list from IEEE (about 4 MB)…")

        def work():
            try:
                self.vendors_done.emit(monitor.download_vendors())
            except (OSError, ValueError) as e:   # no internet, IEEE down, or not the list
                self.vendors_done.emit(e)

        threading.Thread(target=work, daemon=True).start()

    def on_vendors(self, result):
        self.vendor_btn.setEnabled(True)
        if isinstance(result, Exception):
            return self._status(f"Could not get the vendor list: {result}", "error")
        self.vendors = monitor.load_vendors()
        self._vendor_btn_text()
        self.update_view()
        self._status(f"Vendor list saved: {result:,} manufacturers.", "ok")

    def on_finished(self):
        self.refresh.stop()
        self.thread.quit()
        self.thread.wait()
        stopped = self.worker.stop
        self.thread = self.worker = None
        self.update_view()
        self.progress.hide()
        self.stop_btn.hide()
        self.scan_btn.show()
        self.export_btn.setEnabled(bool(self.results))
        open_n = sum(r.state == "open" for h in self.results.values() for r in h.values())
        up = sum(self.is_up(h) for h in self.results)
        self._status(f"{'Stopped' if stopped else 'Done'}: {up} of {len(self.results)} host(s) "
                     f"up, {open_n} open port(s).", "ok")
        self._sync_buttons()

    # ------------------------------------------------------------- views

    def update_view(self):
        self.progress.setValue(self.done)
        current = self.hosts.currentItem().data(Qt.UserRole) if self.hosts.currentItem() else None
        known = {self.hosts.item(i).data(Qt.UserRole): self.hosts.item(i)
                 for i in range(self.hosts.count())}
        for host, ports in self.results.items():
            item = known.get(host)
            if item is None:
                item = QListWidgetItem()
                item.setData(Qt.UserRole, host)
                self.hosts.addItem(item)
            open_n = sum(r.state == "open" for r in ports.values())
            address = next(iter(ports.values())).address
            label = host if host == address else f"{host}  ({address})"
            d = self.device(host)
            kind = f"  ·  {d['device_type']}?" if d["device_type"] else ""
            extra = "".join(f" · {d[k]}" for k in ("vendor", "device_name", "mac") if d[k])
            item.setText(f"{label}{kind}\n{'up' if self.is_up(host) else 'no response'} · "
                         f"{open_n} open{extra}")
            item.setToolTip(item.text() + ("\n\nDevice type is a best guess from the device's "
                                           "name, open ports and MAC address." if kind else ""))
            item.setForeground(QColor(self.c["text" if self.is_up(host) else "muted"]))
        if current is None and self.hosts.count():
            self.hosts.setCurrentRow(0)
        else:
            self.show_ports()

    def show_ports(self):
        item = self.hosts.currentItem()
        ports = self.results.get(item.data(Qt.UserRole), {}) if item else {}
        rows = [r for _, r in sorted(ports.items())
                if self.show_all.isChecked() or r.state == "open"]
        colors = {"open": self.c["success"], "closed": self.c["muted"], "filtered": self.c["warn"]}
        risk_colors = {"High": self.c["danger"], "Medium": self.c["warn"], "Low": self.c["muted"]}
        self.table.setRowCount(len(rows))
        for i, r in enumerate(rows):
            for col, text in enumerate([f"{r.port}/tcp", r.state, r.service, r.severity, r.banner]):
                cell = QTableWidgetItem(text)
                if col == 1:
                    cell.setForeground(QColor(colors[r.state]))
                if col == 3 and r.severity:
                    cell.setForeground(QColor(risk_colors[r.severity]))
                    cell.setToolTip(r.risk)
                self.table.setItem(i, col, cell)
        self.table.resizeColumnsToContents()
        self.risk_note.setText("\n".join(f"Port {r.port} ({r.severity}): {r.risk}"
                                         for r in rows if r.severity))
        hidden = defaultdict(int)
        for r in ports.values():
            if r.state != "open" and not self.show_all.isChecked():
                hidden[r.state] += 1
        self.not_shown.setText("Not shown: " + ", ".join(f"{n} {s}" for s, n in hidden.items())
                               if hidden else "")

    def export(self):
        path, _ = QFileDialog.getSaveFileName(self, "Export results", "portscout-results.csv",
                                              "CSV (*.csv);;JSON (*.json)")
        if not path:
            return
        rows = [{**asdict(r), **self.device(host)}
                for host, h in self.results.items() for _, r in sorted(h.items())]
        try:
            with open(path, "w", newline="", encoding="utf-8") as f:
                if path.lower().endswith(".json"):
                    json.dump(rows, f, indent=2)
                else:
                    w = csv.DictWriter(f, fieldnames=list(rows[0]))
                    w.writeheader()
                    w.writerows(rows)
        except OSError as e:
            return self._status(f"Could not save: {e}", "error")
        self._status(f"Saved {len(rows)} rows to {path}", "ok")

    def closeEvent(self, e):
        if self.worker:
            self.worker.stop = True
            self.hide()   # feels instant; probes in flight need up to timeout x tries to end
            self.thread.quit()   # ends the thread's event loop once the scan returns
            self.thread.wait()   # a capped wait let Qt destroy the still-running thread (crash)
        self.connections.timer.stop()
        self.connections.names.close()
        super().closeEvent(e)


def _is_up(ports: dict) -> bool:
    # Same rule as Nmap's unprivileged ping: any answer, even a refusal, means the host is there.
    return any(r.state in ("open", "closed") for r in ports.values())


def main():
    try:   # own taskbar entry and icon, instead of grouping under pythonw.exe
        ctypes.windll.shell32.SetCurrentProcessExplicitAppUserModelID(APP_NAME)
    except AttributeError:
        pass   # not Windows
    app = QApplication(sys.argv)
    app.setApplicationName(APP_NAME)
    app.setWindowIcon(QIcon(str(ICON)))
    w = MainWindow()
    w.show()
    sys.exit(app.exec())
