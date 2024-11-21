Here is the translation of the given Java code into Python:

```Python
class LongLongHashtable:
    def __init__(self):
        self.capacity = 3
        self.indexer = LongKeyIndexer(self.capacity)
        self.values = [0] * (self.capacity + 1)

    def put(self, key: int, value: int) -> None:
        index = self.indexer.put(key)
        
        if index >= self.capacity:
            self.grow()
            
        self.values[index] = value

    def get(self, key: int) -> int:
        try:
            return self.values[self.indexer.get(key)]
        except ValueError:
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
            return self.indexer.get(key) >= 0
        except ValueError:
            raise NoValueException("No value found for the given key")

    def size(self) -> int:
        return self.indexer.size

    def getKeys(self):
        return self.indexer.keys


class LongKeyIndexer:
    def __init__(self, capacity: int):
        self.capacity = capacity
        self.keys = [0] * (capacity + 1)
        self.size = 0

    def put(self, key: int) -> int:
        if self.size >= self.capacity:
            raise ValueError("Table is full")

        index = hash(key) % self.capacity
        
        while self.keys[index] != 0:
            next_index = (index + 1) % self.capacity
            if next_index == index:
                return -1
            
            index = next_index

        self.keys[index] = key
        self.size += 1
        return index

    def get(self, key: int) -> int:
        try:
            return hash(key) % self.capacity
        except ValueError:
            raise NoValueException("No value found for the given key")

    def remove(self, key: int) -> int:
        if not self.contains(key):
            return -1
        
        index = self.put(key)
        
        while self.keys[index] != 0 and hash(self.keys[index]) % self.capacity == index:
            next_index = (index + 1) % self.capacity
            if next_index == index:
                break
            
            self.keys[index], self.keys[next_index] = self.keys[next_index], self.keys[index]
            
        self.size -= 1
        
        return index

    def clear(self):
        self.size = 0


class NoValueException(Exception):
    pass
```

This Python code is a direct translation of the given Java code. It includes classes for `LongLongHashtable`, `LongKeyIndexer` and `NoValueException`. The `put`, `get`, `remove`, `contains`, `size`, `getKeys` methods are implemented as per their counterparts in the original Java code.