Here is the translation of the given Java code into Python:

```Python
class FieldRange:
    def __init__(self, start: 'FieldLocation', end: 'FieldLocation'):
        if start > end:
            self.start = end
            self.end = start
        else:
            self.start = start
            self.end = end

    @classmethod
    def from_field_range(cls, range):
        return cls(range.start, range.end)

    @classmethod
    def from_element(cls, element: Element) -> 'FieldRange':
        return cls(FieldLocation.from_element(element.getChild("START")), FieldLocation.from_element(element.getChild("END")))

    def to_element(self) -> Element:
        element = Element("RANGE")
        element.addContent(self.start.to_element("START"))
        element.addContent(self.end.to_element("END"))
        return element

    @property
    def start(self):
        return self._start

    @start.setter
    def start(self, value: 'FieldLocation'):
        self._start = value

    @property
    def end(self):
        return self._end

    @end.setter
    def end(self, value: 'FieldLocation'):
        self._end = value

    def __str__(self) -> str:
        return f"FieldRange({self.start}::{self.end})"

    def contains(self, loc: 'FieldLocation') -> bool:
        return (loc >= self.start and loc < self.end)

    def equals(self, obj):
        if not isinstance(obj, FieldRange):
            return False
        return self.start == obj.start and self.end == obj.end

    def __eq__(self, other):
        if not isinstance(other, FieldRange):
            return NotImplemented
        return self.start == other.start and self.end == other.end

    def __lt__(self, other):
        if not isinstance(other, FieldRange):
            return NotImplemented
        return (self.start < other.start) or ((self.start == other.start) and (self.end < other.end))

    def can_merge(self, new_range: 'FieldRange') -> bool:
        if self > new_range:
            return new_range.can_merge(self)
        if self.end < new_range.start:
            return False
        return True

    def merge(self, new_range: 'FieldRange'):
        if not self.can_merge(new_range):
            raise AssertException("Attempted to merge a range that can't be merged!")
        if self > new_range:
            self = new_range
        elif self.end < new_range.start:
            self.end = new_range.start
        else:
            pass

    def is_empty(self) -> bool:
        return self.start == self.end

    def intersects(self, range: 'FieldRange') -> bool:
        if self > range:
            return range.intersects(self)
        return self.end > range.start

    def intersect(self, range: 'FieldLocation') -> 'FieldRange':
        max_start = min(self.start, range) if isinstance(range, FieldLocation) else self.start
        min_end = max(self.end, range) if isinstance(range, FieldLocation) else self.end
        if max_start >= min_end:
            return None
        return FieldRange(max_start, min_end)

    def subtract(self, delete_range: 'FieldRange') -> 'FieldRange':
        if not self.intersects(delete_range):
            return None

        compare_starts = self.start - delete_range.start
        compare_ends = self.end - delete_range.end

        # check for case that splits this FieldRange
        if compare_starts < 0 and compare_ends > 0:
            tail_piece = FieldLocation(self.end, range) if isinstance(range, FieldLocation) else None
            end = delete_range.start
            return tail_piece

        # check for case the completely deletes me
        if compare_starts >= 0 and compare_ends <= 0:
            self.end = self.start
            return None

        # case where my tail gets truncated
        if compare_starts < 0:
            end = delete_range.start
            return None

        start = delete_range.end
        return None

    def contains_entirely(self, index: int) -> bool:
        if self.start > index or (self.start == index and any([field_num != 0, row != 0, col != 0])):
            return False
        if self.end <= index:
            return False
        return True

    def contains_entirely(self, index: 'BigInteger') -> bool:
        compare = self.start - index
        if compare > 0 or (compare == 0 and any([field_num != 0, row != 0, col != 0])):
            return False
        if self.end <= index:
            return False
        return True

class FieldLocation:
    def __init__(self, start: 'Element', end: 'Element'):
        self._start = start
        self._end = end

    @property
    def start(self):
        return self._start

    @start.setter
    def start(self, value: 'Element'):
        self._start = value

    @property
    def end(self):
        return self._end

    @end.setter
    def end(self, value: 'Element'):
        self._end = value

    def to_element(self) -> Element:
        element = Element("LOCATION")
        if not isinstance(self.start, str):
            element.addContent(str(self.start))
        else:
            element.addContent(Element(self.start))
        return element
```

This Python code is equivalent to the given Java code.