"""LIFO Stack of simulated IP-block actions.

Role in the project
-------------------
When brute-force detection fires, a simulated block (IP + reason) is pushed.
Undo Last Block pops the most recent action and unmarks that IP. A queue would
undo the oldest block first; a set alone cannot restore reverse-chronological
order. History in the Linked List is left intact so the audit stays honest.
"""


class EmptyStackError(Exception):
    """Raised when pop/peek is attempted on an empty stack."""


class _Node:
    __slots__ = ("data", "next")

    def __init__(self, data, next_node=None):
        self.data = data
        self.next = next_node


class Stack:
    """Linked stack (top pointer only). collections.deque is unused."""

    def __init__(self):
        self.top = None
        self.size = 0

    def push_block(self, ip, reason, extra=None):
        """Push a simulated block record. O(1)."""
        record = {"ip": ip, "reason": reason}
        if extra:
            record.update(extra)
        self.top = _Node(record, self.top)
        self.size += 1

    def push(self, item):
        """Generic push (used if a full record dict is already built). O(1)."""
        self.top = _Node(item, self.top)
        self.size += 1

    def pop(self):
        """Undo: remove and return the most recent block. O(1)."""
        if self.top is None:
            raise EmptyStackError("stack is empty")
        record = self.top.data
        self.top = self.top.next
        self.size -= 1
        return record

    def peek(self):
        if self.top is None:
            raise EmptyStackError("stack is empty")
        return self.top.data

    def is_empty(self):
        return self.top is None

    def items_top_to_bottom(self):
        """Yield records from newest (top) to oldest. Useful for GUI listing."""
        current = self.top
        while current is not None:
            yield current.data
            current = current.next

    def clear(self):
        self.top = None
        self.size = 0

    def __len__(self):
        return self.size
