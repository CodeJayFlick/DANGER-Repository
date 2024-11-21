Here is the translation of the given Java code into Python:

```Python
class StringIntHashtable:
    def __init__(self):
        self.capacity = 3
        self.indexer = StringKeyIndexer(self.capacity)
        self.values = [0] * self.capacity

    def put(self, key: str, value: int) -> None:
        index = self.indexer.put(key)
        
        if index >= self.capacity:
            self.grow()
            
        self.values[index] = value

    def get(self, key: str) -> int:
        try:
            index = self.indexer.get(key)
            return self.values[index]
        except KeyError:
            raise NoValueException("No value for the given key")

    def remove(self, key: str) -> bool:
        if self.indexer.remove(key) < 0:
            return False
        else:
            return True

    def removeAll(self):
        self.indexer.clear()

    def contains(self, key: str) -> bool:
        try:
            index = self.indexer.get(key)
            return index >= 0
        except KeyError:
            return False

    def size(self) -> int:
        return self.indexer.size()

    def get_keys(self):
        return self.indexer.getKeys()


class StringKeyIndexer:
    def __init__(self, capacity: int):
        self.capacity = capacity
        self.keys = [""] * (capacity + 1)
        self.values = [-1] * (capacity + 1)

    def put(self, key: str) -> int:
        for i in range(0, len(self.keys)):
            if self.keys[i] == "":
                self.keys[i] = key
                return i

        raise Exception("Table is full")

    def get(self, key: str) -> int:
        for i in range(len(self.keys)):
            if self.keys[i] == key:
                return i
        raise KeyError(f"No value found for the given key {key}")

    def remove(self, key: str) -> int:
        for i in range(0, len(self.keys)):
            if self.keys[i] == key:
                self.keys[i] = ""
                return i

        return -1

    def clear(self):
        for i in range(len(self.keys)):
            self.keys[i] = ""

    def getCapacity(self) -> int:
        return self.capacity

    def getSize(self) -> int:
        count = 0
        for key in self.keys:
            if key != "":
                count += 1
        return count


class NoValueException(Exception):
    pass
```

This Python code defines a `StringIntHashtable` class that implements a hash table with string keys and integer values. The `StringKeyIndexer` class is used to manage the index values for the keys in the hash table.