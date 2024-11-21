Here is the translation of the Java code into Python:

```Python
class FieldSelection:
    def __init__(self):
        self.ranges = []

    def clear(self):
        self.ranges = []

    def contains(self, loc):
        for range in self.ranges:
            if range.contains(loc):
                return True
        return False

    def get_range_containing(self, loc):
        start_index = bisect.bisect_left(self.ranges, FieldRange(loc))
        if start_index >= 0 and self.ranges[start_index].contains(loc):
            return self.ranges[start_index]
        for i in range(start_index - 1, -1, -1):
            if not self.ranges[i].can_merge(FieldRange(loc)):
                break
        else:
            return None

    def contains_entirely(self, index):
        start = FieldLocation(index, 0)
        end = FieldLocation(index + 1, 0)
        range = new_field_range(start, end)
        if self.get_range_containing(range.start) is not None and range.end <= self.ranges[0].end:
            return True
        else:
            return False

    def excludes_entirely(self, index):
        start = FieldLocation(index, 0)
        end = FieldLocation(index + 1, 0)
        range = new_field_range(start, end)
        search_index = bisect.bisect_left(self.ranges, range)
        if search_index >= 0:
            return False
        for i in range(search_index - 1, -1, -1):
            if self.ranges[i].intersects(range):
                break
        else:
            return True

    def add_range(self, start, end):
        new_range = FieldRange(start, end)
        insert_index = bisect.bisect_left(self.ranges, new_range)
        if insert_index >= 0 and self.ranges[insert_index].can_merge(new_range):
            self.ranges[insert_index] = self.ranges[insert_index].merge(new_range)
        else:
            self.ranges.insert(insert_index, new_range)

    def remove_range(self, start, end):
        delete_range = FieldRange(start, end)
        insert_index = bisect.bisect_left(self.ranges, delete_range)
        if insert_index >= 0 and self.ranges[insert_index].intersects(delete_range):
            left_over = self.ranges[insert_index].subtract(delete_range)
            if left_over is not None:
                self.ranges.insert(insert_index + 1, left_over)

    def print_ranges(self):
        for range in self.ranges:
            print(range)

    def __str__(self):
        return '\n'.join([str(r) for r in self.ranges])

    def equals(self, obj):
        if not isinstance(obj, FieldSelection):
            return False
        if len(self.ranges) != len(obj.ranges):
            return False
        for i in range(len(self.ranges)):
            if self.ranges[i] != obj.ranges[i]:
                return False
        return True

    def save(self, save_state):
        list_element = Element("FIELD_ANGLES")
        for range in self.ranges:
            element = range.get_element()
            list_element.append(element)
        save_state.put_xml_element("FIELD_SELECTION", list_element)

    def load(self, save_state):
        clear()
        element = save_state.get_xml_element("FIELD_SELECTION")
        if element is not None:
            children = element.children
            for child in children:
                self.ranges.append(FieldRange(child))

    def intersect(self, index):
        start = FieldLocation(index)
        end = FieldLocation(index + 1)
        range = new_field_range(start, end)
        return self.intersect(range)

    def __iter__(self):
        return iter(self.ranges)


class FieldLocation:
    def __init__(self, index, field_num=0):
        self.index = index
        self.field_num = field_num

    def __str__(self):
        return f"FieldLocation({self.index}, {self.field_num})"


class FieldRange:
    def __init__(self, start, end):
        self.start = start
        self.end = end

    def contains(self, loc):
        if loc.index >= self.start.index and loc.index <= self.end.index:
            return True
        else:
            return False

    def can_merge(self, other_range):
        if self.start.index == other_range.start.index and self.end.index == other_range.end.index:
            return True
        elif self.start.index < other_range.start.index and self.end.index > other_range.end.index:
            return True
        else:
            return False

    def merge(self, other_range):
        new_start = min(self.start.index, other_range.start.index)
        new_end = max(self.end.index, other_range.end.index)
        return FieldRange(FieldLocation(new_start), FieldLocation(new_end))

    def subtract(self, other_range):
        if self.contains(other_range.start) and self.contains(other_range.end):
            start_index = bisect.bisect_left(range(len(self.ranges)), other_range)
            end_index = bisect.bisect_right(range(len(self.ranges)), other_range)
            for i in range(start_index, end_index + 1):
                if self.ranges[i].intersects(other_range):
                    del self.ranges[i]
        return FieldRange(self.start, self.end)

    def intersects(self, other_range):
        start = max(self.start.index, other_range.start.index)
        end = min(self.end.index, other_range.end.index)
        if start <= end:
            return True
        else:
            return False

    def get_element(self):
        element = Element("FIELD_RANGE")
        element.set_attribute("start", str(self.start))
        element.set_attribute("end", str(self.end))
        return element


class BigInteger(int):
    pass


def new_field_range(start, end):
    return FieldRange(start, end)


from bisect import *
```

Please note that Python does not have a direct equivalent to Java's `BigInteger` class. The above code uses the built-in integer type for simplicity.