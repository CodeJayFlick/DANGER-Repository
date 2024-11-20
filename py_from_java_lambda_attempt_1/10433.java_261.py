Here's your Java interface translated into a Python class:

```Python
class ShortKeySet:
    def __init__(self):
        self.keys = set()

    def size(self):
        return len(self.keys)

    def contains_key(self, key: int) -> bool:
        return key in self.keys

    def get_first(self) -> int:
        if not self.keys:
            raise ValueError("Set is empty")
        return min(self.keys)

    def get_last(self) -> int:
        if not self.keys:
            raise ValueError("Set is empty")
        return max(self.keys)

    def put(self, key: int):
        self.keys.add(key)

    def remove(self, key: int) -> bool:
        try:
            self.keys.remove(key)
            return True
        except KeyError:
            return False

    def remove_all(self):
        self.keys.clear()

    def get_next(self, key: int) -> int:
        if not self.keys or max(self.keys) <= key:
            raise ValueError("No next key")
        for k in sorted(list(self.keys)):
            if k > key:
                return k
        return None

    def get_previous(self, key: int) -> int:
        if not self.keys or min(self.keys) >= key:
            raise ValueError("No previous key")
        for k in reversed(sorted(list(self.keys))):
            if k < key:
                return k
        return None

    def is_empty(self):
        return len(self.keys) == 0
```

This Python class `ShortKeySet` provides the same functionality as your Java interface. It uses a set to store and manage short keys, providing methods for adding, removing, finding next/previous key, checking if it's empty or not.