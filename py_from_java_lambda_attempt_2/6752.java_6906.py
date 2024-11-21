Here is the translation of the Java code to Python:
```
class ByteBlockSelection:
    def __init__(self, ranges=None):
        if ranges is None:
            self.ranges = []
        else:
            self.ranges = list(ranges)

    def add_range(self, range):
        self.ranges.append(range)

    @property
    def number_of_ranges(self):
        return len(self.ranges)

    def get_range(self, index):
        return self.ranges[index]
```
Note that I did not include the `ByteBlockRange` class in this translation, as it was not provided. If you need to translate that class as well, please let me know and I can help with that too!