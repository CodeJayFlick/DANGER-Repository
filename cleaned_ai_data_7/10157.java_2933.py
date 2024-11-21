import weakref
from collections import defaultdict

class ConcurrentListenerSet:
    def __init__(self):
        self.storage = defaultdict(weakref.ref)

    def add(self, t):
        self.storage[t] = None  # use default value as a placeholder

    def remove(self, t):
        del self.storage[t]

    def clear(self):
        self.storage.clear()

    def iterator(self):
        return iter(self.storage.keys())

    def as_list(self):
        return list(self.storage.keys())
