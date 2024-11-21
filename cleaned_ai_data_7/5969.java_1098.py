class IntObjectCache:
    def __init__(self, size):
        self.values = [None] * size
        self.ref_queue = []

    def put(self, index, obj):
        if self.values[index] is not None:
            self.remove_stale_entries()
        self.values[index] = (index, obj)

    def get(self, index):
        if self.values[index] is not None:
            return self.values[index][1]
        else:
            return None

    def remove_stale_entries(self):
        while True:
            r = next((r for r in self.ref_queue), None)
            if r is None:
                break
            e = (index, obj) = r[0], r[1]
            self.values[e[0]] = None


class MySoftRef:
    def __init__(self, index, obj):
        self.index = index
        self.obj = obj

# Example usage:

cache = IntObjectCache(10)
for i in range(5):
    cache.put(i, f"obj_{i}")
print(cache.get(2))  # prints: "obj_2"
