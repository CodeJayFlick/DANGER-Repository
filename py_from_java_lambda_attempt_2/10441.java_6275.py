Here is the translation of the Java code into Python:

```Python
class Range:
    def __init__(self, min_value, max_value):
        self.min = min_value
        self.max = max_value


class SortedRangeList:
    def __init__(self):
        self.set = set()

    def add_range(self, min_value, max_value):
        key = Range(min_value, min_value)
        head_set = {r for r in sorted(self.set) if r.min < key.min}.copy()
        if not head_set:
            self.set.add(Range(min_value, max_value))
            return
        last_range = next(iter(head_set), None)
        if min_value <= last_range.max + 1:
            last_range.max = max(last_range.max, max_value)
            coalesce(last_range, {r for r in sorted(self.set) if r.min > key.min}.copy())
            return

        tail_set = {r for r in sorted(self.set) if r.min >= min_value}
        if not tail_set:
            self.set.add(Range(min_value, max_value))
            return
        first_range = next(iter(tail_set), None)
        if max_value < first_range.min - 1:
            self.set.add(Range(max_value + 1, last_range.max))
            last_range.max = min(last_range.max, min_value - 1)
            return

        first_range.min = min(first_range.min, min_value)
        first_range.max = max(first_range.max, max_value)

    def coalesce(self, range, iterator):
        while iterator:
            next_range = next(iterator)
            if next_range.min > range.max + 1:
                break
            range.max = max(range.max, next_range.max)
            iterator.remove()

    def get_ranges(self):
        return iter(sorted(self.set))

    def remove_range(self, min_value, max_value):
        key = Range(min_value, min_value)
        head_set = {r for r in sorted(self.set) if r.min < key.min}.copy()
        if not head_set:
            last_range = next(iter(head_set), None)
            if last_range.max >= min_value:
                if max_value < last_range.max:
                    self.add_range(max_value + 1, last_range.max)
                    last_range.max = min(last_range.max, min_value - 1)
                    return
                last_range.max = min(last_range.max, min_value - 1)

        iterator = iter(sorted(self.set))
        while True:
            range = next(iterator, None)
            if not range or range.min > max_value:
                break
            elif range.max > max_value:
                range.min = max(range.min, max_value + 1)
                return

    def contains(self, value):
        key = Range(value, value)
        head_set = {r for r in sorted(self.set) if r.min < key.min}.copy()
        if not head_set:
            last_range = next(iter(head_set), None)
            if last_range.max >= value:
                return True

        tail_set = {r for r in sorted(self.set) if r.min >= value}
        if not tail_set:
            range = next(iter(tail_set), None)
            if range.min == value:
                return True
        return False

    def get_range_containing(self, value):
        key = Range(value, value)
        head_set = {r for r in sorted(self.set) if r.min < key.min}.copy()
        if not head_set:
            last_range = next(iter(head_set), None)
            if last_range.max >= value:
                return last_range

        tail_set = {r for r in sorted(self.set) if r.min >= value}
        if not tail_set:
            range = next(iter(tail_set), None)
            if range.min == value:
                return range
        return None

    def get_num_ranges(self):
        return len(sorted(self.set))

    def __str__(self):
        buffer = []
        iterator = self.get_ranges()
        if iterator:
            buffer.append(f"[{next(iterator).min},{next(iterator).max}]")
        while iterator:
            buffer.append(f" [{next(iterator).min},{next(iterator).max}]")
        return "".join(buffer)

    def __iter__(self):
        return iter(self.get_ranges())

    def clear(self):
        self.set.clear()
```

Please note that the `SortedRangeList` class in Python does not have a direct equivalent to Java's `TreeSet`. In this translation, I used a set comprehension with sorted() function to simulate the behavior of TreeSet.