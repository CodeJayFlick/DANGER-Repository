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
