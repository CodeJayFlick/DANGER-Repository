class Range:
    def __init__(self, start: int, end: int, closed: bool):
        self.start = start
        self.end = end
        self.closed = closed

    @staticmethod
    def of(start: int, end: int) -> 'Range':
        return Range(start, end, False)

    @staticmethod
    def of_closed(start: int, end: int) -> 'Range':
        return Range(start, end, True)

    @staticmethod
    def to_shape(index: int, width_range: 'Range') -> tuple:
        value = width_range.value(index)
        return (Shape(value), index // width_range.size())

    @staticmethod
    def to_shape(height_range: 'Range', width_range: 'Range') -> tuple:
        height_value = height_range.value(0)  # Assuming the start of range is used for calculation
        index //= height_range.size()
        value = width_range.value(index)
        return (Shape(height_value, value), index // width_range.size())

    @staticmethod
    def to_shape(depth_range: 'Range', height_range: 'Range', width_range: 'Range') -> tuple:
        depth_value = depth_range.value(0)  # Assuming the start of range is used for calculation
        index //= depth_range.size()
        height_value = height_range.value(index)
        index //= height_range.size()
        value = width_range.value(index)
        return (Shape(depth_value, height_value, value), index // width_range.size())

    @staticmethod
    def to_value(index: int, range_: 'Range') -> tuple:
        value = range_.value(0)  # Assuming the start of range is used for calculation
        return (value, index // range_.size())

    def size(self):
        if self.closed:
            return self.end - self.start + 1
        else:
            return self.end - self.start

    def value(self, for_index: int) -> int:
        return (for_index % self.size()) + self.start


class Shape(tuple):
    pass
