class PriorityQueue:
    def __init__(self):
        self.size = 0
        self.tree = {}

    def add(self, obj, priority):
        key = str(priority)
        if not self.tree.get(key):
            self.tree[key] = []
        self.tree[key].append(obj)
        self.size += 1

    def size(self):
        return self.size

    def is_empty(self):
        return self.size == 0

    def get_first(self):
        if not self.tree:
            return None
        key = min(self.tree.keys())
        return self.tree[key][0]

    def get_first_priority(self):
        if not self.tree:
            return None
        return min(self.tree.keys())

    def get_last(self):
        if not self.tree:
            return None
        key = max(self.tree.keys())
        return self.tree[key][-1]

    def get_last_priority(self):
        if not self.tree:
            return None
        return max(self.tree.keys())

    def remove_first(self):
        if not self.tree or not self.tree[min(self.tree.keys())]:
            return None
        self.size -= 1
        key = min(self.tree.keys())
        if len(self.tree[key]) == 1:
            del self.tree[key]
        else:
            self.tree[key].pop(0)
        return self.tree[key][0]

    def remove_last(self):
        if not self.tree or not self.tree[max(self.tree.keys())]:
            return None
        self.size -= 1
        key = max(self.tree.keys())
        if len(self.tree[key]) == 1:
            del self.tree[key]
        else:
            self.tree[key].pop()
        return self.tree[key][-1]

    def clear(self):
        self.size = 0
        self.tree.clear()

# Example usage:

pq = PriorityQueue()
pq.add("Object A", 3)
pq.add("Object B", 2)
pq.add("Object C", 4)

print(pq.get_first()) # Output: Object A
print(pq.get_last())   # Output: Object C

pq.remove_first()      # Remove and return the object with priority 3 (Object A)
pq.remove_last()       # Remove and return the object with priority 4 (Object C)

print(pq.is_empty())    # Output: True, since all objects have been removed
