class FilteringAccumulatorWrapper:
    def __init__(self, accumulator, predicate):
        self.predicate = predicate
        self.accumulator = accumulator

    def passes_filter(self, item):
        return self.predicate(item)

    def iterator(self):
        return iter(self.accumulator)

    def add(self, item):
        if self.passes_filter(item):
            self.accumulator.add(item)

    def add_all(self, collection):
        for item in collection:
            if self.passes_filter(item):
                self.accumulator.add(item)

    def contains(self, item):
        return self.accumulator.contains(item)

    def get(self):
        return self.accumulator.get()

    def size(self):
        return self.accumulator.size()
