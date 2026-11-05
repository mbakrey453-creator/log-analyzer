"""Circular Array / ring buffer of the last N processed events.

Role in the project
-------------------
Brute-force detection must look only at a bounded recent window, not the
entire Linked List. A fixed array of length N with
    index = (index + 1) mod N
overwrites the oldest event in O(1) time and O(N) memory. After the buffer
is full, every insert discards the oldest slot automatically. Scanning N
slots per event is O(N); N is a configured constant, independent of history
length n.
"""


class CircularBuffer:
    """Fixed-capacity circular array. Oldest event is overwritten on wrap."""

    def __init__(self, n):
        if n < 1:
            raise ValueError("window size N must be at least 1")
        self.N = int(n)
        self.buf = [None] * self.N
        self.index = 0   # next write position
        self.count = 0   # logical size, 0..N

    def insert(self, event):
        """Write event at the next slot with wrap-around. O(1)."""
        self.buf[self.index] = event
        self.index = (self.index + 1) % self.N
        if self.count < self.N:
            self.count += 1

    def resize(self, new_n):
        """Rebuild with a new capacity, keeping the most recent min(count, new_n) events."""
        old = self.items_oldest_first()
        self.N = int(new_n)
        if self.N < 1:
            raise ValueError("window size N must be at least 1")
        self.buf = [None] * self.N
        self.index = 0
        self.count = 0
        keep = old[-self.N :] if old else []
        for event in keep:
            self.insert(event)

    def items_oldest_first(self):
        """Return window contents in chronological order (oldest first)."""
        if self.count == 0:
            return []
        if self.count < self.N:
            return list(self.buf[: self.count])
        start = self.index  # next write slot is the oldest event
        return [self.buf[(start + i) % self.N] for i in range(self.N)]

    def scan(self):
        """Iterate events currently in the window (oldest first)."""
        for event in self.items_oldest_first():
            yield event

    def clear(self):
        self.buf = [None] * self.N
        self.index = 0
        self.count = 0

    def __len__(self):
        return self.count
