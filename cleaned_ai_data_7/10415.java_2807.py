class ObjectIntHashtable:
    def __init__(self):
        self.capacity = 3
        self.indexer = ObjectKeyIndexer()
        self.values = [0] * (1 + self.capacity)

    def put(self, key, value):
        index = self.indexer.put(key)
        
        if index >= self.capacity:
            self.grow()

        self.values[index] = value

    def get(self, key):
        try:
            return self.values[self.indexer.get(key)]
        except KeyError:
            raise NoValueException("No value for the given key")

    def remove(self, key):
        if self.indexer.remove(key) < 0:
            return False
        else:
            return True

    def removeAll(self):
        self.indexer.clear()

    def contains(self, key):
        try:
            return self.indexer.get(key) >= 0
        except KeyError:
            return False

    def size(self):
        return self.indexer.size()

    def getKeys(self):
        return list(self.indexer.keys())

    def grow(self):
        new_capacity = self.indexer.next_prime(self.capacity)
        old_values = self.values
        
        self.values = [0] * (1 + new_capacity)
        
        for i in range(len(old_values)):
            if i < len(old_values) // 2:
                self.values[i] = old_values[i]
            else:
                break


class ObjectKeyIndexer:
    def __init__(self):
        self.capacity = 3
        self.keys = [None] * (1 + self.capacity)
        self.size = 0

    def put(self, key):
        for i in range(len(self.keys)):
            if self.keys[i] is None or self.keys[i].__eq__(key):
                return i
        return len(self.keys) - 1

    def get(self, key):
        for i in range(len(self.keys)):
            if self.keys[i] == key:
                return i
        raise KeyError("No value for the given key")

    def remove(self, key):
        try:
            index = self.get(key)
            self.size -= 1
            self.keys[index] = None
            return True
        except KeyError:
            return False

    def clear(self):
        self.size = 0
        self.keys = [None] * (1 + self.capacity)

    def size(self):
        return self.size

    def keys(self, keyArray=None):
        if not keyArray:
            return list(self.keys)
        else:
            for i in range(len(keyArray)):
                try:
                    index = self.get(keyArray[i])
                    yield self.keys[index]
                except KeyError:
                    pass


class NoValueException(Exception):
    no_value_exception = "No value for the given key"
