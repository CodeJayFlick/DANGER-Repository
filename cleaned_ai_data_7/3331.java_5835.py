class OffsetRanges:
    def __init__(self):
        self.first_use_ranges = {}

    def add_range_list(self, first_use, common_srl):
        if str(first_use) not in self.first_use_ranges:
            self.first_use_ranges[str(first_use)] = []
        for range_ in common_srl.get_ranges():
            self.first_use_ranges[str(first_use)].extend((range_.min, range_.max))

    def add_range(self, first_use, min_, max_):
        if str(first_use) not in self.first_use_ranges:
            self.first_use_ranges[str(first_use)] = []
        self.first_use_ranges[str(first_use)].append((min_, max_))

    def contains(self, first_use, value):
        return str(first_use) in self.first_use_ranges and any(min_<value<max_ for min_, max_ in self.first_use_ranges[str(first_use)])

    def __str__(self):
        result = ""
        for key, ranges in self.first_use_ranges.items():
            if len(ranges)>0:
                result += f"FirstUse={key} Offsets= {ranges}\n"
        return result

    def intersect(self, other_change_ranges):
        new_range = OffsetRanges()
        for first_use_offset in self.first_use_ranges.keys():
            first_use_list = self.first_use_ranges[first_use_offset]
            other_list = other_change_ranges.get(str(first_use_offset), [])
            if len(other_list)>0:
                intersection = list(set([min_ for min_, max_ in first_use_list] + [max_ for min_, max_ in other_list]))
                new_range.add_range_list(int(min_), SortedRangeList(intersection, intersection))
        return new_range

    def union(self, other_change_ranges):
        new_range = OffsetRanges()
        keys = list(set(list(self.first_use_ranges.keys())+list(other_change_ranges.get_keys())))
        for first_use_offset in keys:
            if str(first_use_offset) not in self.first_use_ranges or str(first_use_offset) not in other_change_ranges.get_keys():
                continue
            first_use_list = self.first_use_ranges[str(first_use_offset)]
            other_list = other_change_ranges.get(str(first_use_offset), [])
            combined_list = list(set([min_ for min_, max_ in first_use_list] + [max_ for min_, max_ in other_list]))
            new_range.add_range_list(int(min_), SortedRangeList(combined_list, combined_list))
        return new_range

class SortedRangeList:
    def __init__(self):
        self.ranges = []

    def add_range(self, min_, max_):
        if len(self.ranges)>0 and (min_<self.ranges[0][1] or max_>self.ranges[-1][0]):
            self.ranges.append((min_, max_))
        elif min_<=self.ranges[0][1]:
            self.ranges[0]=(min_,max_)
        else:
            self.ranges.insert(0,(min_,max_))

    def get_ranges(self):
        return [(range_[0], range_[1]) for range_ in self.ranges]

class Range:
    def __init__(self, min_, max_):
        self.min = int(min_)
        self.max = int(max_)

def main():
    offset_ranges = OffsetRanges()
    # Add ranges
    offset_ranges.add_range_list(0, [Range(1, 5), Range(10, 15)])
    offset_ranges.add_range_list(1, [Range(2, 4), Range(11, 14)])

    print(offset_ranges)

if __name__ == "__main__":
    main()
