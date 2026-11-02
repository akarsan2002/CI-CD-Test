import socket
import threading
import time
import unittest

from mini_aibom.collectors.syslog_udp import DEFAULT_HOST, SyslogListener


class Harness:
    """Start a listener on a free port in a thread; send datagrams to it."""

    def __init__(self, **kw):
        self.listener = SyslogListener("127.0.0.1", 0, **kw)
        self.stop = threading.Event()
        self.t = threading.Thread(target=self.listener.serve, args=(self.stop,), daemon=True)
        self.t.start()
        self.sender = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)

    def send(self, msg: bytes):
        self.sender.sendto(msg, ("127.0.0.1", self.listener.port))

    def wait_for(self, n, timeout=3.0):
        end = time.time() + timeout
        while self.listener.message_count < n and time.time() < end:
            time.sleep(0.02)

    def close(self):
        self.stop.set()
        self.t.join(timeout=2)
        self.listener.close()
        self.sender.close()


class SyslogTests(unittest.TestCase):
    def test_aggregates_and_rejects_lookalikes(self):
        h = Harness()
        for m in [b"q api.openai.com from 10.0.0.1", b"q api.openai.com from 10.0.0.1",
                  b"q api.openai.com.evil.example from 10.0.0.2"]:
            h.send(m)
        h.wait_for(3)
        h.close()
        self.assertEqual({k: v[1] for k, v in h.listener.seen.items()},
                         {("10.0.0.1", "api.openai.com"): 2})

    def test_source_falls_back_to_sender_address(self):
        h = Harness()
        h.send(b"lookup api.anthropic.com")  # no IP in the text
        h.wait_for(1)
        h.close()
        self.assertEqual(list(h.listener.seen), [("127.0.0.1", "api.anthropic.com")])

    def test_garbage_bytes_do_not_crash(self):
        h = Harness()
        h.send(b"\xff\xfe\x00\x01 not text")
        h.send(b"q api.openai.com from 10.0.0.9")
        h.wait_for(2)
        h.close()
        self.assertEqual(len(h.listener.seen), 1)

    def test_memory_cap_on_invented_sources(self):
        h = Harness(max_keys=3)
        for i in range(10):
            h.send(f"q api.openai.com from 10.0.0.{i}".encode())
        h.wait_for(10)
        h.close()
        self.assertEqual(len(h.listener.seen), 3)

    def test_binds_to_localhost_by_default(self):
        self.assertEqual(DEFAULT_HOST, "127.0.0.1")


if __name__ == "__main__":
    unittest.main()
