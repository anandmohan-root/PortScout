"""Regenerate data/icon.ico from data/icon.svg:  .venv\\Scripts\\python tools\\make_icon.py"""
import struct
from pathlib import Path

from PySide6.QtCore import QBuffer, QByteArray, QIODevice, Qt
from PySide6.QtGui import QGuiApplication, QImage, QPainter
from PySide6.QtSvg import QSvgRenderer

DATA = Path(__file__).resolve().parent.parent / "data"
SIZES = [16, 20, 24, 32, 40, 48, 64, 128, 256]   # what Explorer, the taskbar and title bars ask for


def png(renderer: QSvgRenderer, size: int) -> bytes:
    img = QImage(size, size, QImage.Format_ARGB32)
    img.fill(Qt.transparent)
    p = QPainter(img)
    p.setRenderHint(QPainter.Antialiasing)
    renderer.render(p)
    p.end()
    buf = QBuffer(ba := QByteArray())
    buf.open(QIODevice.WriteOnly)
    img.save(buf, "PNG")
    return bytes(ba)


def main():
    QGuiApplication([])
    renderer = QSvgRenderer(str(DATA / "icon.svg"))
    images = [png(renderer, s) for s in SIZES]
    # ICO = 6-byte header, one 16-byte entry per image, then the PNG files (Vista+ format).
    out = struct.pack("<HHH", 0, 1, len(images))
    offset = 6 + 16 * len(images)
    for size, data in zip(SIZES, images):
        out += struct.pack("<BBBBHHII", size % 256, size % 256, 0, 0, 1, 32, len(data), offset)
        offset += len(data)
    (DATA / "icon.ico").write_bytes(out + b"".join(images))
    print(f"wrote {DATA / 'icon.ico'} ({len(SIZES)} sizes)")


if __name__ == "__main__":
    main()
