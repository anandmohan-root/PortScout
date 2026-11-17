import os
import socket
import threading



from PySide6.QtCore import QEventLoop, QTimer
from PySide6.QtWidgets import QApplication

from portscout.app import MainWindow

app = QApplication.instance() or QApplication([])


def test_scan_shows_open_port_and_gates_on_permission():
    server = socket.socket()
    server.bind(("127.0.0.1", 0))
    server.listen()
    port = server.getsockname()[1]
    threading.Thread(target=lambda: server.accept(), daemon=True).start()

    w = MainWindow()
    w.target.setText("127.0.0.1")
    [b for b in w.port_group.buttons() if b.text() == "Custom"][0].setChecked(True)
    w.custom_ports.setText(f"{port}, {port + 1 if port < 65535 else port - 1}")
    assert not w.scan_btn.isEnabled()            # permission box not ticked yet
    w.start()
    assert w.thread is None

    w.authorized.setChecked(True)
    loop = QEventLoop()
    w.start()
    w.worker.finished.connect(loop.quit)          # queued to the UI thread, after on_finished
    QTimer.singleShot(15000, loop.quit)
    loop.exec()

    assert w.thread is None
    assert w.hosts.count() == 1
    assert w.table.rowCount() == 1               # only open ports listed by default
    assert w.table.item(0, 0).text() == f"{port}/tcp"
    assert w.table.item(0, 1).text() == "open"
    assert "1 closed" in w.not_shown.text()
    assert w.export_btn.isEnabled()
    server.close()


def test_bad_input_shows_error():
    w = MainWindow()
    w.authorized.setChecked(True)
    w.target.setText("10.0.0.0/8")
    w.start()
    assert w.thread is None
    assert "limit" in w.status.text()


def test_connections_tab_lists_filters_and_listening():
    server = socket.socket()
    server.bind(("127.0.0.1", 0))
    server.listen()
    port = server.getsockname()[1]
    client = socket.create_connection(("127.0.0.1", port))
    w = MainWindow()
    w.show()
    tab = w.connections
    tab.refresh()
    tab.filter.setText(str(client.getsockname()[1]))    # our client's local port
    cells = [tab.table.item(r, c).text() for r in range(tab.table.rowCount())
             for c in range(tab.table.columnCount())]
    assert f"127.0.0.1:{port}" in cells and "ESTABLISHED" in cells
    assert "Local network" in cells
    tab.filter.setText("no-such-app-xyz")
    assert tab.table.rowCount() == 0
    tab.filter.setText(str(port))
    tab.listening.setChecked(True)
    states = [tab.table.item(r, 6).text() for r in range(tab.table.rowCount())]
    assert "LISTEN" in states
    for i in range(1, 4):                 # Timeline and Map render from the recorded history
        w.tabs.setCurrentIndex(i)
    assert w.tabs.widget(2).table.rowCount() >= 1
    client.close()
    server.close()


def test_risky_open_port_shows_risk():
    from portscout import scanner
    w = MainWindow()
    w.results["h"][23] = scanner.PortResult("h", "10.0.0.1", 23, "open", "telnet", "",
                                            *scanner.risk(23))
    w.update_view()
    assert w.table.item(0, 3).text() == "High"
    assert "Telnet" in w.risk_note.text()


def test_device_found_by_discovery_counts_as_up():
    from portscout import scanner
    w = MainWindow()
    w.results["phone"][80] = scanner.PortResult("phone", "192.168.1.40", 80, "filtered", "http")
    w.update_view()
    assert "no response" in w.hosts.item(0).text()
    w.on_device("phone", "1a:22:bb:b5:ec:bb", "")
    w.update_view()
    text = w.hosts.item(0).text()
    assert "up" in text and "1a:22:bb:b5:ec:bb" in text and "Mobile?" in text
    assert w.device("phone")["device_type"] == "Mobile"       # also what the export gets
