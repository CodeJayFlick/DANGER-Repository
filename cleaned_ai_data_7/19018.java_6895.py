from typing import List

class KeyList:
    def __init__(self, keys: List):
        self.keys = keys

    @classmethod
    def of(cls, keys: List) -> 'KeyList':
        return cls(keys)

# Note that we can't directly translate the Java's Value.Immutable annotation as Python doesn't have a direct equivalent.
