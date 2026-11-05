"""Parse SSH / Apache / firewall-style log lines into Event objects.

Malformed lines become events with event_type='unknown' so the pipeline
never crashes; they still go into history and the circular window.
"""

import re
from dataclasses import dataclass, field


# IPv4 (simple) — enough for course sample logs and the virtual producer.
_IP = r"(?P<ip>(?:\d{1,3}\.){3}\d{1,3})"

_SSH_FAILED = re.compile(
    r"(?P<ts>\w{3}\s+\d{1,2}\s+\d{2}:\d{2}:\d{2}).*sshd\[\d+\]:\s+"
    r"(?:Failed password|authentication failure|Invalid user).*"
    r"from\s+" + _IP,
    re.IGNORECASE,
)
_SSH_SUCCESS = re.compile(
    r"(?P<ts>\w{3}\s+\d{1,2}\s+\d{2}:\d{2}:\d{2}).*sshd\[\d+\]:\s+"
    r"Accepted (?:password|publickey).*from\s+" + _IP,
    re.IGNORECASE,
)
# Apache combined / common: 192.0.2.1 - - [21/Oct/2026:18:42:01 +0000] "GET / HTTP/1.1" 401 ...
_APACHE = re.compile(
    r"^" + _IP + r"\s+\S+\s+\S+\s+\[(?P<ts>[^\]]+)\]\s+"
    r'"(?P<req>[^"]*)"\s+(?P<status>\d{3})',
)
# Firewall-ish: Oct 21 18:42:01 fw kernel: [UFW BLOCK] IN=eth0 SRC=192.0.2.44 DST=10.0.0.5 DPT=22
_FW = re.compile(
    r"(?P<ts>\w{3}\s+\d{1,2}\s+\d{2}:\d{2}:\d{2}).*"
    r"(?:UFW\s+BLOCK|iptables|DROP|DENY|REJECT).*"
    r"SRC=" + _IP,
    re.IGNORECASE,
)
_ANY_IP = re.compile(r"(?:\d{1,3}\.){3}\d{1,3}")


@dataclass
class Event:
    raw: str
    timestamp: str = ""
    source_ip: str = ""
    event_type: str = "unknown"  # ssh / apache / firewall / unknown
    outcome: str = "other"       # success / fail / other
    failed_auth: bool = False
    detail: str = ""
    extra: dict = field(default_factory=dict)

    def short(self):
        ip = self.source_ip or "?"
        tag = "FAIL" if self.failed_auth else self.outcome.upper()
        return f"[{tag}] {self.timestamp} {self.event_type} {ip} {self.detail}".strip()


def parse_line(line):
    """Return an Event for one raw line. Never raises on bad input."""
    text = (line or "").rstrip("\n\r")
    if not text.strip() or text.lstrip().startswith("#"):
        return Event(raw=text, event_type="comment", outcome="other", detail="ignored")

    m = _SSH_FAILED.search(text)
    if m:
        return Event(
            raw=text,
            timestamp=m.group("ts"),
            source_ip=m.group("ip"),
            event_type="ssh",
            outcome="fail",
            failed_auth=True,
            detail=_ssh_detail(text),
        )

    m = _SSH_SUCCESS.search(text)
    if m:
        return Event(
            raw=text,
            timestamp=m.group("ts"),
            source_ip=m.group("ip"),
            event_type="ssh",
            outcome="success",
            failed_auth=False,
            detail=_ssh_detail(text),
        )

    m = _APACHE.match(text)
    if m:
        status = int(m.group("status"))
        failed = status in (401, 403)
        return Event(
            raw=text,
            timestamp=m.group("ts"),
            source_ip=m.group("ip"),
            event_type="apache",
            outcome="fail" if failed else ("success" if status < 400 else "other"),
            failed_auth=failed,
            detail=f'{status} {m.group("req")}',
            extra={"status": status},
        )

    m = _FW.search(text)
    if m:
        return Event(
            raw=text,
            timestamp=m.group("ts"),
            source_ip=m.group("ip"),
            event_type="firewall",
            outcome="fail",
            failed_auth=True,
            detail="blocked/dropped packet",
        )

    ip_match = _ANY_IP.search(text)
    return Event(
        raw=text,
        timestamp="",
        source_ip=ip_match.group(0) if ip_match else "",
        event_type="unknown",
        outcome="other",
        failed_auth=False,
        detail="unparsed line",
    )


def _ssh_detail(text):
    lower = text.lower()
    if "invalid user" in lower:
        return "invalid user"
    if "accepted publickey" in lower:
        return "accepted publickey"
    if "accepted password" in lower:
        return "accepted password"
    if "failed password" in lower:
        return "failed password"
    if "authentication failure" in lower:
        return "authentication failure"
    return "ssh"
