Here is the equivalent Python code:

```Python
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
```

Note that Python does not have direct equivalents to Java's `Predicate` and `Accumulator`, so I replaced them with a simple function (`passes_filter`) and the built-in collection classes (e.g., list, set).