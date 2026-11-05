"""Virtual login-to-server attempt producer (no real SSH/Apache servers).

Generates realistic-looking mixed log lines: SSH success/fail, a few Apache
and firewall lines, plus a guaranteed brute-force burst so detection fires.
"""

import random
from datetime import datetime, timedelta


HOST = "10.0.0.5"
FAKE_USERS = ("root", "admin", "ubuntu", "oracle", "guest", "alice", "bob")
BENIGN_IPS = (
    "203.0.113.10",
    "203.0.113.22",
    "198.51.100.8",
    "198.51.100.40",
    "192.0.2.80",
)
ATTACKER_IPS = (
    "192.0.2.44",
    "198.51.100.77",
    "203.0.113.200",
)
PATHS = ("/", "/login", "/admin", "/wp-login.php", "/api/auth")


def _ts(dt):
    # syslog style: "Oct 21 18:42:01"
    return dt.strftime("%b %d %H:%M:%S").replace(" 0", "  ")


def ssh_failed(dt, ip, user=None, pid=None):
    user = user or random.choice(FAKE_USERS)
    pid = pid or random.randint(1200, 9999)
    port = random.randint(40000, 62000)
    return (
        f"{_ts(dt)} server sshd[{pid}]: Failed password for {user} "
        f"from {ip} port {port} ssh2"
    )


def ssh_invalid(dt, ip, user=None, pid=None):
    user = user or random.choice(("hadoop", "test", "pi", "mysql"))
    pid = pid or random.randint(1200, 9999)
    port = random.randint(40000, 62000)
    return (
        f"{_ts(dt)} server sshd[{pid}]: Invalid user {user} "
        f"from {ip} port {port}"
    )


def ssh_success(dt, ip, user=None, pid=None):
    user = user or random.choice(("alice", "bob", "ubuntu"))
    pid = pid or random.randint(1200, 9999)
    port = random.randint(40000, 62000)
    method = random.choice(("password", "publickey"))
    return (
        f"{_ts(dt)} server sshd[{pid}]: Accepted {method} for {user} "
        f"from {ip} port {port} ssh2"
    )


def apache_line(dt, ip, status=200):
    path = random.choice(PATHS)
    method = "POST" if path != "/" else "GET"
    stamp = dt.strftime("%d/%b/%Y:%H:%M:%S +0000")
    size = random.randint(120, 4096)
    return f'{ip} - - [{stamp}] "{method} {path} HTTP/1.1" {status} {size}'


def firewall_drop(dt, ip):
    return (
        f"{_ts(dt)} fw kernel: [UFW BLOCK] IN=eth0 OUT= "
        f"SRC={ip} DST={HOST} DPT=22 PROTO=TCP"
    )


def generate_events(count=50, attacker_ip=None, burst_size=None, start=None):
    """Return a list of mixed log lines, including one brute-force burst.

    count: total lines (SSH + a few Apache/firewall).
    attacker_ip: IP used for the burst (default 192.0.2.44).
    burst_size: failed attempts in the burst; default max(8, count // 5).
    """
    count = max(1, int(count))
    attacker_ip = attacker_ip or ATTACKER_IPS[0]
    if burst_size is None:
        burst_size = max(8, count // 5)
    burst_size = min(burst_size, count)
    start = start or datetime.now().replace(microsecond=0)

    lines = []
    t = start
    remaining_burst = burst_size
    other = count - burst_size

    # Mix "other" traffic with a concentrated burst so the circular window
    # still sees enough failures from the same attacker IP.
    burst_start_index = max(0, other // 3)

    def tick():
        nonlocal t
        t = t + timedelta(seconds=random.randint(1, 4))
        return t

    others_emitted = 0
    while others_emitted < other or remaining_burst > 0:
        # Inject the burst as a consecutive run once we reach burst_start_index.
        if remaining_burst > 0 and others_emitted >= burst_start_index:
            for _ in range(remaining_burst):
                kind = random.random()
                if kind < 0.75:
                    lines.append(ssh_failed(tick(), attacker_ip))
                elif kind < 0.9:
                    lines.append(ssh_invalid(tick(), attacker_ip))
                else:
                    lines.append(firewall_drop(tick(), attacker_ip))
            remaining_burst = 0
            continue

        if others_emitted >= other:
            break

        r = random.random()
        ip = random.choice(BENIGN_IPS)
        if r < 0.45:
            lines.append(ssh_success(tick(), ip))
        elif r < 0.65:
            lines.append(ssh_failed(tick(), ip))
        elif r < 0.80:
            lines.append(apache_line(tick(), ip, status=random.choice((200, 200, 304, 404))))
        elif r < 0.90:
            lines.append(apache_line(tick(), ip, status=401))
        else:
            lines.append(firewall_drop(tick(), random.choice(BENIGN_IPS)))
        others_emitted += 1

    return lines


def generate_burst(attacker_ip, n=12, start=None):
    """Optional helper: n failed attempts from one chosen attacker IP."""
    start = start or datetime.now().replace(microsecond=0)
    t = start
    lines = []
    for i in range(max(1, int(n))):
        t = t + timedelta(seconds=1)
        if i % 5 == 4:
            lines.append(firewall_drop(t, attacker_ip))
        else:
            lines.append(ssh_failed(t, attacker_ip, user="root"))
    return lines
