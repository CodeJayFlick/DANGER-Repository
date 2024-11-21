class SortedRangeList:
    def __init__(self):
        self.ranges = []

    def add_range(self, start, end):
        if not self.ranges or (start >= self.ranges[-1].end and start <= self.ranges[0].start):
            self.ranges.append(Range(start, end))
        elif start < self.ranges[0].start:
            self.ranges.insert(0, Range(start, end))
        else:
            for i in range(len(self.ranges)):
                if start >= self.ranges[i].end and start <= self.ranges[i+1].start:
                    self.ranges.insert(i, Range(start, end))

    def get_range_index(self, value):
        left = 0
        right = len(self.ranges)
        while left < right:
            mid = (left + right) // 2
            if self.ranges[mid].end <= value:
                left = mid + 1
            else:
                right = mid
        return -1 if left >= len(self.ranges) or not self.contains(value, self.ranges[left-1]) else left

    def get_range(self):
        for i in range(len(self.ranges)):
            yield self.ranges[i]

    def contains(self, value, r=None):
        if r is None:
            return any(r.start <= x and x <= r.end for r in self.get_ranges())
        return r.start <= value and value <= r.end

    def intersect(self, other):
        result = SortedRangeList()
        it1 = iter(other.get_ranges())
        it2 = iter(self.get_ranges())

        while True:
            try:
                a = next(it1)
                b = next(it2)
            except StopIteration:
                break
            if a.start <= b.end and b.start <= a.end:
                result.add_range(max(a.start, b.start), min(a.end, b.end))

        return result

    def get_ranges(self):
        for r in self.ranges:
            yield r


class Range:
    def __init__(self, start, end):
        self.start = start
        self.end = end

# Example usage:

list1 = SortedRangeList()
for _ in range(5): list1.add_range(Integer.MIN_VALUE + _, Integer.MIN_VALUE + 2)

print(list1.get_ranges())

