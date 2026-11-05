"""Stdlib HTTP server: serves the web GUI (web/) and a JSON API for the engine.

The browser UI talks to this server; the engine still runs the four course
ADTs (Queue, Linked List, Circular Buffer, Stack). Python standard library
only — no pip packages. Binds to 127.0.0.1 (local machine only).
"""

import json
import os
import sys
import threading
import traceback
import webbrowser
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

from engine import AnalyzerEngine
from simulator import generate_burst, generate_events

WEB_DIR = os.path.join(os.path.dirname(os.path.abspath(__file__)), "web")
DEFAULT_PORT = 8765
MAX_BODY = 8 * 1024 * 1024

STATIC_FILES = {
    "/": ("index.html", "text/html; charset=utf-8"),
    "/index.html": ("index.html", "text/html; charset=utf-8"),
    "/style.css": ("style.css", "text/css; charset=utf-8"),
    "/app.js": ("app.js", "application/javascript; charset=utf-8"),
}


class ApiError(Exception):
    def __init__(self, status, message):
        super().__init__(message)
        self.status = status
        self.message = message


def event_tag(event):
    if event.failed_auth or event.outcome == "fail":
        return "fail"
    if event.outcome == "success":
        return "success"
    return "info"


def event_lines(events, width=4):
    return [
        {"text": f"{i:{width}d}. {ev.short()}", "tag": event_tag(ev)}
        for i, ev in enumerate(events, 1)
    ]


class ApiApp:
    """Routes HTTP actions onto the AnalyzerEngine. One instance per server."""

    def __init__(self):
        self.engine = AnalyzerEngine(window_size=50, threshold=5)
        self.lock = threading.Lock()

    def dispatch(self, action, payload):
        handler = getattr(self, action, None)
        if handler is None:
            raise ApiError(404, f"unknown action: {action}")
        return handler(payload)

    # -- state ------------------------------------------------------------
    def stats_payload(self):
        stats = self.engine.stats()
        window = [
            {"text": ev.short(), "tag": event_tag(ev)}
            for ev in self.engine.last_n_events()
        ]
        blocked = sorted(self.engine.blocked)
        stack = [
            {"ip": r.get("ip"), "reason": r.get("reason")}
            for r in self.engine.blocked_records()
        ]
        return {"stats": stats, "window": window, "blocked": blocked, "stack": stack}

    # -- ingest -----------------------------------------------------------
    def generate(self, payload):
        try:
            count = int(payload.get("count", 50))
        except (TypeError, ValueError):
            raise ApiError(400, "Virtual attempts must be a number")
        count = max(1, min(count, 1000))
        attacker = str(payload.get("attacker") or "192.0.2.44").strip() or "192.0.2.44"
        lines = generate_events(count=count, attacker_ip=attacker)
        enqueued = self.engine.enqueue_lines(lines)
        out = [
            {
                "text": f"--- Generated {enqueued} virtual login/server attempts "
                f"(burst IP {attacker}) ---",
                "tag": "info",
            }
        ]
        out += [{"text": ln, "tag": "raw"} for ln in lines]
        return {"lines": out, "stats": self.stats_payload()}

    def burst(self, payload):
        ip = str(payload.get("ip") or "192.0.2.44").strip() or "192.0.2.44"
        n = max(8, int(self.engine.threshold) + 3)
        lines = generate_burst(ip, n=n)
        self.engine.enqueue_lines(lines)
        out = [
            {"text": f"--- Auto-generated burst: {len(lines)} failures from {ip} ---", "tag": "info"}
        ]
        out += [{"text": ln, "tag": "raw"} for ln in lines]
        return {"lines": out, "stats": self.stats_payload()}

    def load(self, payload):
        content = payload.get("content")
        if not isinstance(content, str):
            raise ApiError(400, "no file content received")
        name = str(payload.get("filename") or "uploaded.log").strip() or "uploaded.log"
        enqueued = self.engine.enqueue_lines(content.splitlines())
        out = [{"text": f"--- Loaded {enqueued} lines from {name} ---", "tag": "info"}]
        return {"lines": out, "stats": self.stats_payload()}

    # -- processing -------------------------------------------------------
    def process(self, payload):
        if self.engine.queue.is_empty():
            return {
                "processed": 0,
                "blocks": 0,
                "lines": [
                    {
                        "text": "Queue is empty — generate attacks or load a log file first.",
                        "tag": "info",
                    }
                ],
                "stats": self.stats_payload(),
            }
        lines = [
            {
                "text": "--- Process Queue (FIFO dequeue → parse → list → circular window → detect) ---",
                "tag": "info",
            }
        ]
        processed = 0
        blocks = 0
        while not self.engine.queue.is_empty():
            item = self.engine.process_one()
            if item is None:
                break
            processed += 1
            if item["ignored"]:
                continue
            ev = item["event"]
            lines.append({"text": ev.short(), "tag": event_tag(ev)})
            if item["block"]:
                blocks += 1
                b = item["block"]
                lines.append(
                    {
                        "text": f"[detect] IP {b['ip']}  failed_auth={b['fail_count']} "
                        f"in last {b['window']} events",
                        "tag": "block",
                    }
                )
                lines.append(
                    {"text": "         -> simulated BLOCK  (pushed on undo stack)", "tag": "block"}
                )
        lines.append(
            {"text": f"--- Done. Processed {processed} lines, new blocks: {blocks} ---", "tag": "info"}
        )
        return {
            "processed": processed,
            "blocks": blocks,
            "lines": lines,
            "stats": self.stats_payload(),
        }

    # -- inspection -------------------------------------------------------
    def history(self, payload):
        events = self.engine.history_events()
        lines = [
            {
                "text": f"--- History (Linked List)  n={len(events)}  — undo does not rewrite this ---",
                "tag": "info",
            }
        ]
        if not events:
            lines.append({"text": "(history empty)", "tag": "info"})
        else:
            lines += event_lines(events)
        return {"lines": lines, "stats": self.stats_payload()}

    def last_n(self, payload):
        events = self.engine.last_n_events()
        lines = [
            {
                "text": f"--- Last N (Circular Array)  filled={len(events)} / N={self.engine.window.N} ---",
                "tag": "info",
            }
        ]
        if not events:
            lines.append({"text": "(window empty)", "tag": "info"})
        else:
            lines += event_lines(events, width=3)
        return {"lines": lines, "stats": self.stats_payload()}

    def blocked(self, payload):
        records = self.engine.blocked_records()
        lines = [
            {
                "text": f"--- Blocked IPs  set={len(self.engine.blocked)}  stack={len(records)} ---",
                "tag": "block",
            }
        ]
        if not records:
            lines.append({"text": "(none blocked)", "tag": "info"})
        else:
            lines += [
                {"text": f"  {r.get('ip')}  |  {r.get('reason')}", "tag": "block"}
                for r in records
            ]
        return {"lines": lines, "stats": self.stats_payload()}

    # -- maintenance ------------------------------------------------------
    def undo(self, payload):
        record = self.engine.undo_last_block()
        if record is None:
            raise ApiError(409, "No simulated blocks to undo.")
        lines = [
            {
                "text": f"[undo] popped {record.get('ip')}  — {record.get('reason')}  "
                "(Linked List history unchanged)",
                "tag": "undo",
            }
        ]
        return {"lines": lines, "stats": self.stats_payload()}

    def clear(self, payload):
        self.engine.clear_all()
        return {
            "lines": [{"text": "All structures cleared.", "tag": "info"}],
            "stats": self.stats_payload(),
        }

    # -- config -----------------------------------------------------------
    def config(self, payload):
        try:
            n = int(payload.get("n", self.engine.window_size))
            threshold = int(payload.get("threshold", self.engine.threshold))
        except (TypeError, ValueError):
            raise ApiError(400, "N and threshold must be numbers")
        try:
            self.engine.set_window_size(n)
            self.engine.set_threshold(threshold)
        except ValueError as exc:
            raise ApiError(400, str(exc))
        return {"stats": self.stats_payload()}


class Handler(BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"
    server_version = "LogAnalyzer/1.0"

    @property
    def app(self):
        return self.server.app

    def _send(self, status, body, content_type):
        self.send_response(status)
        self.send_header("Content-Type", content_type)
        self.send_header("Content-Length", str(len(body)))
        self.send_header("Cache-Control", "no-store")
        self.end_headers()
        self.wfile.write(body)

    def _json(self, data, status=200):
        self._send(status, json.dumps(data).encode("utf-8"), "application/json; charset=utf-8")

    def _error(self, status, message):
        self._json({"ok": False, "error": message}, status)

    def _static(self, filename, content_type):
        path = os.path.join(WEB_DIR, filename)
        try:
            with open(path, "rb") as handle:
                body = handle.read()
        except OSError:
            return self._error(404, f"missing static file: {filename}")
        self._send(200, body, content_type)

    def _read_payload(self):
        try:
            length = int(self.headers.get("Content-Length") or 0)
        except ValueError:
            raise ApiError(400, "bad Content-Length")
        if length <= 0:
            return {}
        if length > MAX_BODY:
            raise ApiError(413, "request body too large")
        raw = self.rfile.read(length)
        try:
            return json.loads(raw.decode("utf-8"))
        except (UnicodeDecodeError, json.JSONDecodeError):
            raise ApiError(400, "request body must be JSON")

    def do_GET(self):
        path = self.path.split("?", 1)[0]
        if path in STATIC_FILES:
            return self._static(*STATIC_FILES[path])
        if path == "/api/stats":
            with self.app.lock:
                return self._json({"ok": True, **self.app.stats_payload()})
        return self._error(404, "not found")

    def do_POST(self):
        path = self.path.split("?", 1)[0]
        if not path.startswith("/api/"):
            return self._error(404, "not found")
        try:
            payload = self._read_payload()
        except ApiError as exc:
            return self._error(exc.status, exc.message)
        action = path[len("/api/"):]
        try:
            with self.app.lock:
                result = self.app.dispatch(action, payload)
            self._json({"ok": True, **result})
        except ApiError as exc:
            self._error(exc.status, exc.message)
        except Exception:
            traceback.print_exc()
            self._error(500, "internal server error")

    def log_message(self, fmt, *args):
        pass  # keep the console quiet (the UI polls /api/stats)


class Server(ThreadingHTTPServer):
    daemon_threads = True


def main():
    port = DEFAULT_PORT
    if len(sys.argv) > 1:
        try:
            port = int(sys.argv[1])
        except ValueError:
            print(f"Usage: python {os.path.basename(sys.argv[0])} [port]")
            sys.exit(2)
    try:
        server = Server(("127.0.0.1", port), Handler)
    except OSError as exc:
        print(f"Cannot start server on port {port}: {exc}")
        sys.exit(1)
    server.app = ApiApp()
    url = f"http://127.0.0.1:{port}/"
    print(f"* Log analyzer web GUI: {url}")
    print("* Press Ctrl+C to stop.")
    threading.Timer(0.8, lambda: webbrowser.open(url)).start()
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        print("\nShutting down.")
    finally:
        server.server_close()


if __name__ == "__main__":
    main()
