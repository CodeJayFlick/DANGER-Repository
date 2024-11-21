class Algorithms:
    @staticmethod
    def lower_bound(start, end, key):
        if not isinstance(key, (object.__class__)):
            raise ValueError("Element must implement Comparable")
        
        comparable_key = type(key)(key)
        cur = start.copy()
        while True:
            result = comparable_key.compare(cur.get())
            if result <= 0:
                return cur
            elif cur.equals(end):
                return end

    @staticmethod
    def upper_bound(start, end, key):
        if not isinstance(key, (object.__class__)):
            raise ValueError("Element must implement Comparable")
        
        comparable_key = type(key)(key)
        cur = start.copy()
        while True:
            result = comparable_key.compare(cur.get())
            if result < 0:
                return cur
            elif cur.equals(end):
                return end

# Example usage:

class IteratorSTL:
    def __init__(self, data):
        self.data = data
        self.index = 0

    def copy(self):
        return IteratorSTL(self.data[:])

    def get(self):
        if self.index < len(self.data):
            return self.data[self.index]
        else:
            raise StopIteration

    def increment(self):
        self.index += 1

    def equals(self, other):
        return isinstance(other, type(self)) and self.data == other.data


# Example usage:

start = IteratorSTL([1, 2, 3])
end = start.copy()
key = 2
print(Algorithms.lower_bound(start, end, key))
print(Algorithms.upper_bound(start, end, key))

