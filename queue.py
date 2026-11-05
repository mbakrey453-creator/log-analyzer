"""FIFO Queue of raw log lines (linked list with head + tail).

Role in the project
-------------------
After Load / Generate, unprocessed text lines sit here until Process Queue
runs. Analysis must not reorder events: the first line ingested is the first
line parsed. A stack would reverse the log; a random-access list would invite
index-based shuffling. Head + tail make both enqueue and dequeue O(1).
"""


class EmptyQueueError(Exception):
    """Raised when dequeue/peek is attempted on an empty queue."""


class _Node:
    __slots__ = ("data", "next")

    def __init__(self, data):
        self.data = data
        self.next = None


class Queue:
    """Singly linked FIFO queue. collections.deque is intentionally unused."""

    def __init__(self):
        self.head = None
        self.tail = None
        self.size = 0

    def enqueue(self, line):
        """Append a raw log line at the tail. O(1)."""
        node = _Node(line)
        if self.tail is None:
            self.head = self.tail = node
        else:
            self.tail.next = node
            self.tail = node
        self.size += 1

    def dequeue(self):
        """Remove and return the oldest line (head). O(1)."""
        if self.head is None:
            raise EmptyQueueError("queue is empty")
        line = self.head.data
        self.head = self.head.next
        if self.head is None:
            self.tail = None
        self.size -= 1
        return line

    def peek(self):
        """Return the next line without removing it. O(1)."""
        if self.head is None:
            raise EmptyQueueError("queue is empty")
        return self.head.data

    def is_empty(self):
        return self.head is None

    def clear(self):
        self.head = None
        self.tail = None
        self.size = 0

    def __len__(self):
        return self.size
