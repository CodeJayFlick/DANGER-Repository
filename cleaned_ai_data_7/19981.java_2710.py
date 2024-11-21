class CyclicList(list):
    def __init__(self, size):
        self.items = [None] * size
        self.start = 0

    def add_first(self, e):
        self.start -= 1
        if self.start < 0:
            self.start += len(self.items)
        self.items[self.start] = e

    def add_last(self, e):
        self.items[self.start] = e
        self.start = (self.start + 1) % len(self.items)

    def get(self, index):
        if index >= len(self.items):
            raise IndexError(f"Index: {index}, Size: {len(self.items)}")
        return self.items[(self.start + index) % len(self.items)]

    def __getitem__(self, index):
        return self.get(index)

    def __setitem__(self, index, value):
        if index >= len(self.items):
            raise IndexError(f"Index: {index}, Size: {len(self.items)}")
        self.items[(self.start + index) % len(self.items)] = value

    def size(self):
        return len(self.items)

    def __len__(self):
        return self.size()

    def to_array(self):
        result = [None] * len(self.items)
        for i in range(len(result)):
            result[i] = self.get(i)
        return result
