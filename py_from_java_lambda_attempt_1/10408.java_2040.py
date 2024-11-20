Here is the translation of the given Java code into Python:

```Python
class LongObjectHashtable:
    def __init__(self):
        self.capacity = 3
        self.indexer = LongKeyIndexer(self.capacity)
        self.values = [None] * self.capacity

    def put(self, key: int, value) -> None:
        index = self.indexer.put(key)

        if index >= self.capacity:
            self.grow()

        self.values[index] = value

    def get(self, key: int) -> object:
        index = self.indexer.get(key)
        
        if index < 0:
            return None
        
        return self.values[index]

    def remove(self, key: int) -> object:
        index = self.indexer.remove(key)

        if index < 0:
            return None

        value = self.values[index]
        self.values[index] = None
        return value

    def removeAll(self):
        self.indexer.clear()

    def contains(self, key: int) -> bool:
        return self.indexer.get(key) >= 0

    def size(self) -> int:
        return self.indexer.size()

    def get_keys(self) -> list[int]:
        return self.indexer.get_keys()

    def grow(self):
        new_capacity = self.indexer.next_prime()
        old_values = self.values
        self.capacity = new_capacity
        self.indexer.set_capacity(new_capacity)
        self.values = [None] * new_capacity

        for i in range(len(old_values)):
            if old_values[i]:
                index = self.indexer.put(i)
                self.values[index] = old_values[i]


class LongKeyIndexer:
    def __init__(self, capacity):
        self.capacity = capacity
        self.keys = [None] * (capacity + 1)

    def put(self, key: int) -> int:
        index = hash(key) % self.capacity

        if not self.keys[index]:
            return index
        
        while True:
            new_index = (index + 1) % self.capacity
            if not self.keys[new_index]:
                break
            
            index = new_index
        
        self.keys[index] = key
        return index

    def get(self, key: int) -> int:
        index = hash(key) % self.capacity

        while True:
            if self.keys[index] == key:
                return index
            
            index = (index + 1) % self.capacity
            
            if not self.keys[index]:
                break
        
        return -1

    def remove(self, key: int) -> int:
        index = hash(key) % self.capacity

        while True:
            if self.keys[index] == key:
                self.keys[index] = None
                return index
            
            index = (index + 1) % self.capacity
            
            if not self.keys[index]:
                break
        
        return -1

    def clear(self):
        for i in range(len(self.keys)):
            self.keys[i] = None

    def size(self) -> int:
        count = 0
        for key in self.keys:
            if key is not None:
                count += 1
        return count

    def get_keys(self) -> list[int]:
        keys = []
        for i, key in enumerate(self.keys):
            if key is not None:
                keys.append(key)
        
        return keys

    def next_prime(self) -> int:
        n = self.capacity + 2
        
        while True:
            if all(n % p != 0 for p in range(3, int((n ** 0.5)) + 1)):
                return n
            
            n += 2


class PrimeIndexer(LongKeyIndexer):
    def next_prime(self) -> int:
        n = self.capacity + 2
        
        while True:
            if all(n % p != 0 for p in range(3, int((n ** 0.5)) + 1)):
                return n
            
            n += 2
```

This Python code is equivalent to the given Java code and provides a basic implementation of a hash table with long keys and object values.