"""Send fake syslog messages to a local receiver. Standard library only.

    python tools/send_test_syslog.py            # sends to 127.0.0.1:5514
    python tools/send_test_syslog.py 127.0.0.1 5514

Only send to machines you own. All data below is fake.
"""
import socket
import sys
import time

host = sys.argv[1] if len(sys.argv) > 1 else "127.0.0.1"
port = int(sys.argv[2]) if len(sys.argv) > 2 else 5514

# <14> is the syslog priority prefix (user-level, informational).
MESSAGES = [
    "<14>Oct 28 09:00:01 dnsserver dnsmasq[1]: query[A] api.openai.com from 192.168.1.10",
    "<14>Oct 28 09:00:02 dnsserver dnsmasq[1]: query[A] api.openai.com from 192.168.1.10",
    "<14>Oct 28 09:00:03 dnsserver dnsmasq[1]: query[A] api.anthropic.com from 192.168.1.20",
    "<14>Oct 28 09:00:04 dnsserver dnsmasq[1]: query[A] www.example.com from 192.168.1.10",
    "<14>Oct 28 09:00:05 dnsserver dnsmasq[1]: query[A] api.openai.com.evil.example from 192.168.1.30",
    "<14>Oct 28 09:00:06 dnsserver dnsmasq[1]: query[A] generativelanguage.googleapis.com from 192.168.1.40",
]

sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
for msg in MESSAGES:
    sock.sendto(msg.encode("utf-8"), (host, port))
    print("sent:", msg[:70])
    time.sleep(0.1)
sock.close()
