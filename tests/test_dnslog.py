import socket
import struct
import threading
import time

from portscout import dnslog


def query(name: str, qtype: int = 1, qid: int = 0x1234) -> bytes:
    labels = b"".join(bytes([len(p)]) + p.encode() for p in name.split("."))
    return struct.pack(">HHHHHH", qid, 0x0100, 1, 0, 0, 0) + labels + b"\0" + \
        struct.pack(">HH", qtype, 1)


def test_question_parsing():
    assert dnslog.question(query("www.YouTube.com")) == ("www.youtube.com", 1)
    assert dnslog.question(query("example.com", 28)) == ("example.com", 28)
    answer = bytearray(query("example.com"))
    answer[2] |= 0x80                                   # a response, not a query
    assert dnslog.question(bytes(answer)) is None
    assert dnslog.question(b"\x00\x01junk") is None


def test_forwards_answers_and_logs_per_device(tmp_path):
    # Fake router: answers every query with the same bytes, response bit set.
    router = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    router.bind(("127.0.0.1", 0))

    def answer():
        while True:
            try:
                data, addr = router.recvfrom(4096)
            except OSError:
                return
            router.sendto(bytes([data[0], data[1], data[2] | 0x80]) + data[3:], addr)
    threading.Thread(target=answer, daemon=True).start()

    db = tmp_path / "h.db"
    logger = dnslog.DnsLogger("127.0.0.1", "127.0.0.1", db, port=0,
                              upstream_port=router.getsockname()[1])
    port = logger.sock.getsockname()[1]
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as device:
            device.settimeout(3)
            for name, qtype in [("rr1.googlevideo.com", 1), ("rr2.googlevideo.com", 28),
                                ("instagram.com", 1), ("wpad", 1),
                                ("1.1.168.192.in-addr.arpa", 12)]:
                device.sendto(query(name, qtype), ("127.0.0.1", port))
                reply = device.recv(4096)
                assert reply[2] & 0x80 and reply[:2] == b"\x12\x34"   # router's answer relayed
        time.sleep(2.5)                                                 # logger saves every second
    finally:
        logger.stop()
        router.close()
    rows = dnslog.summary(dnslog.open_db(db), 0)
    sites = {(ip, site): n for _, ip, _, site, n in rows}
    assert sites == {("127.0.0.1", "googlevideo.com"): 2, ("127.0.0.1", "instagram.com"): 1}
