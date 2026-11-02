import argparse
import sys
import threading
from pathlib import Path

from .engine import scan_path
from .reporters import REPORTERS, table
from .risk import score_component

SEVERITY_ORDER = ["low", "medium", "high", "critical"]


def main(argv=None) -> int:
    p = argparse.ArgumentParser(prog="mini_aibom")
    sub = p.add_subparsers(dest="cmd", required=True)
    s = sub.add_parser("scan", help="scan a folder or file")
    s.add_argument("path")
    s.add_argument("-f", "--format", choices=REPORTERS, default="table")
    s.add_argument("-o", "--output", help="write the report to this file instead of printing it")
    s.add_argument("--fail-on", choices=SEVERITY_ORDER,
                   help="exit with code 1 if any finding is at or above this severity (for CI)")

    li = sub.add_parser("listen", help="receive live syslog (UDP) and report AI traffic (testing)")
    li.add_argument("--host", default="127.0.0.1",
                    help="bind address (default 127.0.0.1; 0.0.0.0 exposes it to the network)")
    li.add_argument("--port", type=int, default=5514)
    li.add_argument("--max-messages", type=int, help="stop after N messages")
    args = p.parse_args(argv)

    if args.cmd == "listen":
        return run_listen(args)

    target = Path(args.path)
    if not target.exists():
        print(f"error: {target} does not exist", file=sys.stderr)
        return 2

    findings = scan_path(target)
    if args.format == "sarif":
        rebase_to_cwd(findings, target)
    report = REPORTERS[args.format](findings)
    if args.output:
        Path(args.output).write_text(report, encoding="utf-8")
        print(f"Wrote {len(findings)} finding(s) to {args.output} ({args.format})")
    else:
        print(report)

    if args.fail_on:
        threshold = SEVERITY_ORDER.index(args.fail_on)
        if any(SEVERITY_ORDER.index(c.severity) >= threshold for c in findings):
            return 1
    return 0


def rebase_to_cwd(findings, target: Path) -> None:
    """LESSON 22: findings hold paths relative to the SCAN ROOT ("app.py"), but CI
    annotations need paths relative to the REPO ROOT ("demo_project/app.py"),
    otherwise results point at files that don't exist. In CI, cwd is the repo root."""
    base = target.resolve() if target.is_dir() else target.resolve().parent
    cwd = Path.cwd().resolve()
    for c in findings:
        try:
            c.file = (base / c.file).relative_to(cwd).as_posix()
        except ValueError:
            pass  # outside the working directory: leave as is


def run_listen(args) -> int:
    from .collectors.syslog_udp import SyslogListener
    from .scanners.log_scanner import components_from_seen

    try:
        listener = SyslogListener(args.host, args.port)
    except OSError as exc:
        print(f"error: cannot listen on {args.host}:{args.port}: {exc}", file=sys.stderr)
        return 2
    if args.host != "127.0.0.1":
        print("WARNING: listening beyond localhost. UDP syslog is unauthenticated.")
    print(f"Listening on {args.host}:{listener.port} (UDP). Ctrl+C to stop.")

    def on_new(source, host, vendor):
        print(f"NEW  {vendor} from {source} to {host}", flush=True)

    stop = threading.Event()
    try:
        listener.serve(stop, on_new=on_new, max_messages=args.max_messages)
    except KeyboardInterrupt:
        pass
    finally:
        listener.close()

    findings = [score_component(c) for c in components_from_seen(listener.seen, "syslog")]
    print(f"\nReceived {listener.message_count} message(s).")
    print(table(sorted(findings, key=lambda c: -c.risk_score)))
    return 0
