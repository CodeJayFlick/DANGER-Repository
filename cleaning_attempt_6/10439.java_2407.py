class SizeLimitedAccumulatorWrapper:
    def __init__(self, accumulator, max_size):
        self.accumulator = accumulator
        self.max_size = max_size

    def iterator(self):
        return iter(self.accumulator)

    def add(self, t):
        self.accumulator.add(t)

    def add_all(self, collection):
        self.accumulator.update(collection)

    def contains(self, t):
        return t in self.accumulator

    def get(self):
        return list(self.accumulator)

    def size(self):
        return len(self.accumulator)

    def has_reached_size_limit(self):
        return len(self.accumulator) >= self.max_size
