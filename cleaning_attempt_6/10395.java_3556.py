class IntKeyIndexer:
    def __init__(self):
        self.capacity = 13
        self.keys = [0] * self.capacity
        self.indexer = {}

    def put(self, key):
        if key in self.indexer:
            return self.indexer[key]
        
        hashcode = (key & 0x7fffffff) % self.capacity
        
        for i in range(len(self.keys)):
            if self.keys[i] == -1:
                index = i
                break

        else:
            raise IndexError("Maximum capacity reached")

        self.keys[index] = key
        self.indexer[key] = index

        return index

    def get(self, key):
        if key in self.indexer:
            return self.indexer[key]
        
        return -1

    def remove(self, key):
        if key not in self.indexer:
            return -1
        
        index = self.indexer.pop(key)
        self.keys[index] = -1
        return index

    @property
    def size(self):
        return len([k for k in self.indexer])

    @property
    def capacity_(self):
        return self.capacity

    def clear(self):
        self.indexer.clear()
        self.keys.fill(-1)

    def get_keys(self):
        key_array = [0] * self.size
        pos = 0
        
        for i, k in enumerate(sorted(self.indexer)):
            index = self.indexer[k]
            while True:
                if self.keys[index] == -1 or index not in self.indexer.values():
                    break
                key_array[pos] = self.keys[index]
                pos += 1
                index = [i for i, v in enumerate(self.keys) if v == self.indexer.pop(index)][0]

        return key_array

    def find_key(self, key):
        hashcode = (key & 0x7fffffff) % self.capacity
        
        p = next((k for k, v in self.indexer.items() if v[0] == -1), None)

        while True:
            if self.keys[p] == key or p not in self.indexer.values():
                return p
            
            p = [i for i, v in enumerate(self.keys) if v == self.indexer.pop(p)][0]

        return -1

    def grow(self):
        new_capacity = 2 * self.capacity
        old_keys = list(range(len(self.keys)))
        
        self.capacity = new_capacity
        self.keys += [-1] * (new_capacity - len(old_keys))
        for k in old_keys:
            if self.keys[k] != -1:
                index = self.put(k)
