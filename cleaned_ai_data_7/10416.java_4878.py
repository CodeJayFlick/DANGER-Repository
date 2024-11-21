class ObjectKeyIndexer:
    def __init__(self):
        self.capacity = 13
        self.keys = [None] * self.capacity
        self.indexer = IntListIndexer(self.capacity)

    @staticmethod
    def next_prime(n):
        if n % 2 == 0: 
            n += 1  
        while True:
            for i in range(3, int((n**.5) + .5), 2): 
                if (n%i) == 0: 
                    n += 1
                    break
            else: return n

    def put(self, key):
        index = self.find_key(key)
        
        if index != -1:
            return index
        
        if self.indexer.size >= self.capacity:
            self.grow()
            
        hashcode = (hash(key) & 0x7FFFFFFF) % self.capacity
        index = self.indexer.add(hashcode)

        if index < 0:
            raise IndexOutOfBoundsException("Maximum capacity reached")

        self.keys[index] = key

        return index

    def get(self, key):
        return self.find_key(key)

    def remove(self, key):
        index = self.find_key(key)
        
        if index == -1:
            return -1
        
        hashcode = (hash(key) & 0x7FFFFFFF) % self.capacity
        self.indexer.remove(hashcode, index)

        return index

    @property
    def size(self):
        return self.indexer.size

    @property
    def capacity(self):
        return self._capacity

    @capacity.setter
    def capacity(self, value):
        if not isinstance(value, int) or value < 0:
            raise ValueError("Capacity must be a positive integer")
        
        self._capacity = value

    def clear(self):
        self.indexer.clear()
        for i in range(len(self.keys)):
            self.keys[i] = None

    @property
    def keys(self):
        return self.__keys

    @keys.setter
    def keys(self, value):
        if not isinstance(value, list) or len(value) != self.capacity:
            raise ValueError("Keys must be a list of length equal to the capacity")
        
        self.__keys = value

class IntListIndexer:
    def __init__(self, capacity):
        self.size = 0
        self.num_lists = [None] * (capacity // 2)
        for i in range(len(self.num_lists)):
            self.num_lists[i] = []

    @property
    def size(self):
        return sum(map(len, self.num_lists))

    @property
    def num_lists(self):
        return self.__num_lists

    @num_lists.setter
    def num_lists(self, value):
        if not isinstance(value, list) or len(value) != (self.capacity // 2):
            raise ValueError("Num lists must be a list of length equal to the capacity divided by 2")
        
        self.__num_lists = value

    def add(self, hashcode):
        for i in range(len(self.num_lists)):
            if not self.num_lists[i]:
                return len(self.num_lists) * (self.capacity // 2) + i
            elif self.num_lists[i][0] == hashcode:
                return len(self.num_lists[i])
        
        raise IndexError("No more space available")

    def first(self, list_id):
        if not self.num_lists[list_id]:
            return -1
        
        return self.num_lists[list_id].pop(0)

    def next(self, index):
        for i in range(len(self.num_lists)):
            if len(self.num_lists[i]) > 0 and self.num_lists[i][0] == (index % self.capacity) // (self.capacity // 2):
                return self.num_lists[i].pop(0)
        
        return -1

    def remove(self, hashcode, index):
        for i in range(len(self.num_lists)):
            if len(self.num_lists[i]) > 0 and self.num_lists[i][0] == hashcode:
                self.num_lists[i].remove(index % (self.capacity // 2))
        
        return 

    @property
    def capacity(self):
        return self.__capacity

    @capacity.setter
    def capacity(self, value):
        if not isinstance(value, int) or value < 0:
            raise ValueError("Capacity must be a positive integer")
        
        self.__capacity = value

class Prime:
    @staticmethod
    def next_prime(n):
        if n % 2 == 0: 
            n += 1  
        while True:
            for i in range(3, int((n**.5) + .5), 2): 
                if (n%i) == 0: 
                    n += 1
                    break
            else: return n

    @staticmethod
    def is_prime(n):
        if n < 2:
            return False
        
        for i in range(3, int((n**.5) + .5), 2): 
            if (n%i) == 0: 
                return False
        
        return True
