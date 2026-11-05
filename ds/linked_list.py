"""Singly Linked List with a tail pointer: unbounded chronological history.

Role in the project
-------------------
Every parsed event is appended here and never discarded. History size is
unknown a priori and grows only at the end. The History button traverses from
head to tail. Undo of a simulated IP block does NOT rewrite this list — it
remains the honest audit trail of what was observed.
"""


class _Node:
    __slots__ = ("data", "next")

    def __init__(self, data):
        self.data = data
        self.next = None


class LinkedList:
    """Singly linked list with tail so append_event is O(1)."""

    def __init__(self):
        self.head = None
        self.tail = None
        self.size = 0

    def append_event(self, event):
        """Insert at the end (tail). O(1)."""
        node = _Node(event)
        if self.tail is None:
            self.head = self.tail = node
        else:
            self.tail.next = node
            self.tail = node
        self.size += 1

    def traverse(self):
        """Yield events from oldest to newest. O(n)."""
        current = self.head
        while current is not None:
            yield current.data
            current = current.next

    def to_list(self):
        """Materialize the full history as a Python list (for GUI dump)."""
        return list(self.traverse())

    def last_n(self, n):
        """Return the last n events without using extra ADTs (O(n) scan)."""
        if n <= 0 or self.size == 0:
            return []
        skip = max(0, self.size - n)
        out = []
        i = 0
        current = self.head
        while current is not None:
            if i >= skip:
                out.append(current.data)
            i += 1
            current = current.next
        return out

    def is_empty(self):
        return self.head is None

    def clear(self):
        self.head = None
        self.tail = None
        self.size = 0

    def __len__(self):
        return self.size
