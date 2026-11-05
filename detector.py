"""Detection: count failed authentications per source IP inside the circular window.

If count >= threshold and the IP is not already blocked, push a simulated
block onto the Stack and mark the IP blocked.
"""


def failure_counts(window_events):
    """Return {ip: fail_count} for events currently in the circular window."""
    counts = {}
    for event in window_events:
        if event is None:
            continue
        if not event.failed_auth:
            continue
        ip = event.source_ip
        if not ip:
            continue
        counts[ip] = counts.get(ip, 0) + 1
    return counts


def should_block(ip, counts, threshold, blocked_set):
    """True when this IP just crossed the brute-force rule."""
    if not ip:
        return False
    if ip in blocked_set:
        return False
    return counts.get(ip, 0) >= threshold


def detect_after_insert(circular_buffer, event, threshold, blocked_set):
    """Scan the window after inserting `event`. Return a block dict or None."""
    counts = failure_counts(circular_buffer.items_oldest_first())
    ip = event.source_ip
    if should_block(ip, counts, threshold, blocked_set):
        n_fail = counts[ip]
        n_win = len(circular_buffer)
        reason = (
            f"failed_auth={n_fail} in last {n_win} events "
            f"(threshold={threshold})"
        )
        return {
            "ip": ip,
            "reason": reason,
            "fail_count": n_fail,
            "window": n_win,
            "threshold": threshold,
        }
    return None
