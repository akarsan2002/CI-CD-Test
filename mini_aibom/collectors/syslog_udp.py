"""A tiny UDP syslog receiver for TESTING the log-matching logic live.

Syslog (classic) is just text datagrams over UDP, usually port 514. We use
5514 by default because low ports need admin rights on many systems.

SAFETY DECISIONS (these matter in real products too):
  - Binds to 127.0.0.1 by default. A listening port is an attack surface, so
    exposing it to the network must be an explicit choice (--host 0.0.0.0).
  - UDP syslog has NO authentication or encryption. Anyone who can reach the
    port can send fake lines. Real deployments use TLS syslog or an authenticated
    forwarder. This receiver is for local testing only.
  - Memory is capped (max_keys) because senders control what gets stored.
  - Datagrams are read into a fixed 8 KB buffer; bad bytes are ignored.
"""
import socket
import threading

from ..scanners.log_scanner import observe_line

DEFAULT_HOST = "127.0.0.1"
DEFAULT_PORT = 5514


class SyslogListener:
    def __init__(self, host: str = DEFAULT_HOST, port: int = DEFAULT_PORT, max_keys: int = 10_000):
        self.sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        self.sock.bind((host, port))
        self.sock.settimeout(0.2)  # wake up regularly so we can notice a stop request
        self.host = host
        self.port = self.sock.getsockname()[1]  # real port even when 0 was requested
        self.max_keys = max_keys
        self.seen: dict = {}
        self.message_count = 0

    def serve(self, stop: threading.Event, on_new=None, max_messages: int | None = None) -> None:
        while not stop.is_set():
            try:
                data, addr = self.sock.recvfrom(8192)
            except socket.timeout:
                continue
            except OSError:  # socket closed
                break
            self.message_count += 1
            line = data.decode("utf-8", errors="ignore")
            for entry in observe_line(line, self.message_count, self.seen,
                                      default_source=addr[0], max_keys=self.max_keys):
                if on_new:
                    on_new(*entry)
            if max_messages and self.message_count >= max_messages:
                break

    def close(self) -> None:
        self.sock.close()
