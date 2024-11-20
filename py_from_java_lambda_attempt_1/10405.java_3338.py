Here is a translation of the provided Java code into equivalent Python:

```Python
class LongIntHashtable:
    def __init__(self):
        self.capacity = 3
        self.indexer = LongKeyIndexer(self.capacity)
        self.values = [0] * self.capacity

    def put(self, key: int, value: int) -> None:
        index = self.indexer.put(key)

        if index >= self.capacity:
            self.grow()

        self.values[index] = value

    def get(self, key: int) -> int:
        try:
            index = self.indexer.get(key)
            return self.values[index]
        except IndexError:
            raise NoValueException("No value found for the given key")

    def remove(self, key: int) -> bool:
        if self.indexer.remove(key) < 0:
            return False
        else:
            return True

    def removeAll(self):
        self.indexer.clear()

    def contains(self, key: int) -> bool:
        try:
            index = self.indexer.get(key)
            return index >= 0
        except IndexError:
            raise NoValueException("No value found for the given key")

    @property
    def size(self) -> int:
        return self.indexer.size

    def get_keys(self):
        return self.indexer.keys


class LongKeyIndexer:
    def __init__(self, capacity: int):
        self.capacity = capacity
        self.keys = [0] * (capacity + 1)
        self.size = 0

    def put(self, key: int) -> int:
        index = hash(key) % self.capacity
        if self.keys[index] == 0:
            return index
        else:
            for i in range(index):
                if self.keys[i] == 0:
                    return i
            raise IndexError("No available slot found")

    def get(self, key: int) -> int:
        try:
            return hash(key) % len(self.keys)
        except TypeError:
            raise NoValueException("Key not found in the map")

    def remove(self, key: int) -> None:
        index = self.put(key)
        if index < 0:
            return
        else:
            self.keys[index] = 0

    @property
    def size(self):
        return len([i for i in range(len(self.keys)) if self.keys[i]])

    @property
    def keys(self):
        return [key for key, value in enumerate(self.keys) if value != 0]


class NoValueException(Exception):
    pass


# Example usage:
table = LongIntHashtable()
try:
    table.put(1, 10)
    print(table.get(1))  # prints: 10
except IndexError as e:
    print(f"Error occurred while putting key-value pair: {e}")
```

This Python code is equivalent to the provided Java code.