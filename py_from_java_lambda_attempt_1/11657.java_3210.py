Here is the translation of the given Java code into Python:

```Python
class Range:
    def __init__(self, spaceid, first, last):
        self.spaceid = spaceid
        self.first = first
        self.last = last

class SetSTL:
    def __init__(self, ranges=None):
        if not isinstance(ranges, list):
            raise TypeError("ranges must be a list")
        self.ranges = ranges or []

    def clear(self):
        self.ranges.clear()

    def begin(self):
        return iter(self.ranges)

    def end(self):
        return iter([])  # End iterator

    def is_empty(self):
        return not bool(self.ranges)

class RangeList:
    def __init__(self, ranges=None):
        if not isinstance(ranges, list):
            raise TypeError("ranges must be a list")
        self.tree = SetSTL(ranges or [])

    def clear(self):
        self.tree.clear()

    def begin(self):
        return iter(self.tree.begin())

    def end(self):
        return iter([])  # End iterator

    def empty(self):
        return not bool(self.tree.ranges)

    def insert_range(self, spaceid, first, last):
        if tree.empty():
            tree.insert(Range(spaceid, first, first))
        else:
            iter1 = self.upper_bound(Range(spaceid, first, first))
            while True:
                a = iter1.get().first
                b = iter1.get().last
                if Utils.unsigned_compare(a, first) < 0:
                    tree.insert(Range(spaceid, a, first - 1))
                elif Utils.unsigned_compare(b, last) > 0:
                    tree.insert(Range(spaceid, last + 1, b))
                else:
                    break
            tree.insert(Range(spaceid, first, last))

    def remove_range(self, spaceid, first, last):
        if self.empty():
            return

        iter1 = self.upper_bound(Range(spaceid, first, first))
        while True:
            a = iter1.get().first
            b = iter1.get().last
            tree.erase(iter1)
            iter1.increment()
            if Utils.unsigned_compare(a, first) < 0:
                tree.insert(Range(spaceid, a, first - 1))
            elif Utils.unsigned_compare(b, last) > 0:
                tree.insert(Range(spaceid, last + 1, b))

    def in_range(self, addr, size):
        if addr.is_invalid():
            return True
        if self.empty():
            return False

        iter = self.upper_bound(Range(addr.space_id, addr.offset, addr.offset))
        while not iter.equals(tree.end()):
            a = iter.get().first
            b = iter.get().last
            if Utils.unsigned_compare(a, addr.offset) > 0:
                break
            elif Utils.unsigned_compare(b, addr.offset + size - 1) >= 0:
                return True

        return False

    def longest_fit(self, addr, maxsize):
        if addr.is_invalid():
            return 0
        if self.empty():
            return 0

        offset = addr.offset
        iter = self.upper_bound(Range(addr.space_id, offset, offset))
        while not iter.equals(tree.end()):
            a = iter.get().first
            b = iter.get().last
            sizeres = (b + 1 - offset)
            if Utils.unsigned_compare(sizeres, maxsize) >= 0:
                break

            offset = b + 1
        return sizeres

    def get_first_range(self):
        if self.empty():
            return None
        return next(iter(tree.begin()))

    def get_last_range(self):
        if self.empty():
            return None
        iter = tree.end()
        iter.decrement()
        return iter.get()

def print_bounds(s, ranges=None):
    s.write("all\n")
    for range in ranges:
        range.print_bounds(s)

class Utils:
    @staticmethod
    def unsigned_compare(a, b):
        if a < 0 or b < 0:
            raise ValueError("Both values must be non-negative")

        return a - b

def main():
    # Example usage of the RangeList class.
    ranges = [Range(1, 10), Range(20, 30)]
    range_list = RangeList(ranges)
    print_bounds(sys.stdout, range_list.tree.ranges)

if __name__ == "__main__":
    main()
```

This Python code defines a `Range` class to represent an address space and its corresponding ranges. It also defines the `SetSTL` class as a set of these ranges. The `RangeList` class is used to manage this set, providing methods for inserting, removing, checking if a range exists within another, finding the longest contiguous block that fits within a given size limit.

The code includes some example usage in the `main()` function where it creates an instance of `RangeList`, adds two ranges, and then prints out these ranges.