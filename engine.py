"""Analyzer engine: ties Queue, Linked List, Circular Buffer, Stack, parser, detector."""

from ds.queue import Queue, EmptyQueueError
from ds.linked_list import LinkedList
from ds.stack import Stack, EmptyStackError
from ds.circular_buffer import CircularBuffer
from parser import parse_line
from detector import detect_after_insert


class AnalyzerEngine:
    """In-memory IDS prototype. Blocks are simulated (not a real firewall)."""

    def __init__(self, window_size=50, threshold=5):
        self.queue = Queue()
        self.history = LinkedList()
        self.blocks = Stack()
        self.window_size = int(window_size)
        self.threshold = int(threshold)
        self.window = CircularBuffer(self.window_size)
        self.blocked = set()  # membership tests; undo order lives on the Stack

    def stats(self):
        return {
            "queue": len(self.queue),
            "history": len(self.history),
            "window_n": self.window.N,
            "window_count": len(self.window),
            "blocked": len(self.blocked),
            "stack": len(self.blocks),
            "threshold": self.threshold,
        }

    def set_window_size(self, n):
        n = int(n)
        if n < 1:
            raise ValueError("N must be >= 1")
        self.window_size = n
        self.window.resize(n)

    def set_threshold(self, t):
        t = int(t)
        if t < 1:
            raise ValueError("threshold must be >= 1")
        self.threshold = t

    def enqueue_line(self, line):
        text = (line or "").rstrip("\n\r")
        if text.strip() == "":
            return False
        self.queue.enqueue(text)
        return True

    def enqueue_lines(self, lines):
        n = 0
        for line in lines:
            if self.enqueue_line(line):
                n += 1
        return n

    def load_file(self, path):
        with open(path, "r", encoding="utf-8", errors="replace") as handle:
            return self.enqueue_lines(handle)

    def process_one(self):
        """Dequeue one line, parse, append history, insert window, maybe block.

        Returns a result dict, or None if the queue is empty.
        """
        try:
            raw = self.queue.dequeue()
        except EmptyQueueError:
            return None

        event = parse_line(raw)
        ignored = event.event_type == "comment"
        if not ignored:
            self.history.append_event(event)
            self.window.insert(event)

        result = {
            "raw": raw,
            "event": event,
            "ignored": ignored,
            "block": None,
        }
        if ignored or not event.failed_auth:
            return result

        block = detect_after_insert(
            self.window, event, self.threshold, self.blocked
        )
        if block:
            self.blocks.push_block(
                block["ip"],
                block["reason"],
                extra={
                    "fail_count": block["fail_count"],
                    "window": block["window"],
                    "threshold": block["threshold"],
                },
            )
            self.blocked.add(block["ip"])
            result["block"] = block
        return result

    def process_all(self):
        """Drain the queue FIFO. Returns a list of process_one() results."""
        results = []
        while not self.queue.is_empty():
            item = self.process_one()
            if item is None:
                break
            results.append(item)
        return results

    def undo_last_block(self):
        """Pop the stack and unmark the IP. Linked-list history is unchanged."""
        try:
            record = self.blocks.pop()
        except EmptyStackError:
            return None
        ip = record.get("ip")
        if ip in self.blocked:
            self.blocked.discard(ip)
        return record

    def history_events(self):
        return self.history.to_list()

    def last_n_events(self):
        return self.window.items_oldest_first()

    def blocked_records(self):
        """Stack from top (newest) to bottom, plus the current set."""
        return list(self.blocks.items_top_to_bottom())

    def clear_all(self):
        n = self.window.N
        self.queue.clear()
        self.history.clear()
        self.blocks.clear()
        self.window = CircularBuffer(n)
        self.blocked.clear()
