class IntObjectHashtable:
    def __init__(self):
        self.capacity = 3
        self.indexer = IntKeyIndexer(self.capacity)
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

    def remove(self, key: int) -> bool:
        index = self.indexer.remove(key)

        if index >= 0:
            self.values[index] = None
            return True

        return False

    def removeAll(self):
        self.indexer.clear()
        self.values = [None] * len(self.values)

    def contains(self, key: int) -> bool:
        return self.indexer.get(key) >= 0

    @property
    def size(self) -> int:
        return self.indexer.getSize()

    def get_keys(self):
        return self.indexer.getKeys()


class IntKeyIndexer:
    def __init__(self, capacity: int):
        self.capacity = capacity
        self.keys = [None] * (capacity + 1)
        self.size = 0

    def put(self, key: int) -> int:
        index = self.find_slot(key)

        if index < 0:
            return -index - 1
        
        self.keys[index] = key
        return index

    def get(self, key: int) -> int:
        index = self.find_slot(key)
        
        if index >= 0:
            return index
        
        return -index - 1

    def remove(self, key: int) -> int:
        index = self.find_slot(key)

        if index < 0:
            return -index - 1
        
        self.keys[index] = None
        return index

    def clear(self):
        self.size = 0

    @property
    def getSize(self) -> int:
        return self.size


    def getCapacity(self) -> int:
        return self.capacity


    def find_slot(self, key: int) -> int:
        i = self.size - 1
        
        while i >= 0 and self.keys[i] != key:
            i -= 1

        if i < 0:
            return -(self.size + 1)
        
        return i
