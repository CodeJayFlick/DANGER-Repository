Here is your Java code translated into Python:

```Python
class AddressRangeObjectMap:
    def __init__(self):
        self.ranges = []
        self.last_range = None

    def get_address_range_iterator(self):
        return SimpleAddressRangeIterator()

    def get_address_range_iterator(self, start, end):
        return RestrictedIndexRangeIterator(start, end)

    def move_address_range(self, from_addr, to_addr, length, monitor=None):
        if length <= 0:
            return
        tmp_map = AddressRangeObjectMap()
        
        for range in self.get_address_range_iterator(from_addr, from_end_addr):
            monitor.check_canceled()

            min_addr = range.min_address
            value = self.get_object(min_addr)
            offset = min_addr - from_addr
            min_addr = to_addr + offset

            max_addr = range.max_address
            offset = max_addr - from_addr
            max_addr = to_addr + offset
            
            tmp_map.set_object(min_addr, max_addr, value)

        for end in self.get_address_range_iterator(from_end_addr):
            monitor.check_canceled()
            value = tmp_map.get_object(range.min_address)
            set_object(range.min_address, range.max_address, value)

    def set_object(self, start, end, object):
        if not self.ranges:
            new_range = AddressValueRange(start, end, object)
            self.ranges.append(new_range)
            return

        previous_index = self.get_position_of_range_before(AddressValueRange(start, end, None))
        if previous_index >= 0:
            old_size = len(self.ranges)
            new_range = adjust_previous_range_for_overlap(start, end, object, self.ranges[previous_index], start, end)
            if old_size > len(self.ranges):
                previous_index -= 1

        insertion_index = max(0, previous_index + 1)

        for range in self.get_address_range_iterator(start, end):
            monitor.check_canceled()
            value = object
            new_range = adjust_remaining_range_for_overlap(value, range, start, end)
            if not values_equal(range.value, object):
                set_object(end.next(), max_addr, value)

    def clear_all(self):
        self.ranges.clear()

    def clear_range(self, start, end):
        for pos in range(len(self.ranges)):
            range = self.ranges[pos]
            if range.end >= start:
                return

        while True:
            if len(self.ranges) > 0 and self.ranges[0].start <= end:
                del self.ranges[0]

    def contains(self, address):
        if self.last_range is not None and self.last_range.contains(address):
            return True
        for pos in range(len(self.ranges)):
            range = self.ranges[pos]
            if range.start == address or range.end >= address:
                self.last_range = range
                return True

    def get_object(self, address):
        if self.last_range is not None and self.last_range.contains(address):
            return self.last_range.value
        for pos in range(len(self.ranges)):
            range = self.ranges[pos]
            if range.start == address or range.end >= address:
                self.last_range = range
                return range.value

    def get_position_of_range_at_or_before(self, value_range):
        try:
            return bisect.bisect_left(self.ranges, value_range)
        except ValueError as e:
            print(f"Error: {e}")
            return -1

    def get_position_of_range_before(self, value_range):
        pos = self.get_position_of_range_at_or_before(value_range)
        if pos >= 0:
            range = self.ranges[pos]
            if range.start == value_range.start or range.end > value_range.start:
                return pos
        return -1

    def values_equal(self, value1, value2):
        if value1 is None and value2 is None:
            return True
        if value1 is not None and value2 is not None:
            return value1 == value2
        return False

class AddressValueRange:
    def __init__(self, start, end, value):
        self.start = start
        self.end = end
        self.value = value

    def get_start(self):
        return self.start

    def get_end(self):
        return self.end

    def get_value(self):
        return self.value

    def contains(self, address):
        if isinstance(address, Address) and (address >= self.start and address <= self.end):
            return True
        return False

class SimpleAddressRangeIterator:
    def __init__(self):
        pass

    def iterator(self):
        return self

    def remove(self):
        raise NotImplementedError()

    def hasNext(self):
        if len(self.ranges) > 0:
            return True
        return False

    def next(self):
        range = self.ranges[0]
        del self.ranges[0]
        return AddressRange(range.start, range.end)

class RestrictedIndexRangeIterator(SimpleAddressRangeIterator):
    def __init__(self, start, end):
        super().__init__()
        self.ranges = []
        for pos in range(len(self.ranges)):
            if self.ranges[pos].start <= end:
                break
        while True:
            if len(self.ranges) > 0 and self.ranges[0].end >= start:
                return

    def iterator(self):
        return self

    def remove(self):
        raise NotImplementedError()

    def hasNext(self):
        if len(self.ranges) > 0:
            return True
        return False

    def next(self):
        range = self.ranges[0]
        del self.ranges[0]
        return AddressRange(range.start, range.end)

class RestrictedIndexRangeIterator(SimpleAddressRangeIterator):
    def __init__(self, start, end):
        super().__init__()
        self.ranges = []
        for pos in range(len(self.ranges)):
            if self.ranges[pos].start <= end:
                break
        while True:
            if len(self.ranges) > 0 and self.ranges[0].end >= start:
                return

    def iterator(self):
        return self

    def remove(self):
        raise NotImplementedError()

    def hasNext(self):
        if len(self.ranges) > 0:
            return True
        return False

    def next(self):
        range = self.ranges[0]
        del self.ranges[0]
        return AddressRange(range.start, range.end)

class RestrictedIndexRangeIterator(SimpleAddressRangeIterator):
    def __init__(self, start, end):
        super().__init__()
        self.ranges = []
        for pos in range(len(self.ranges)):
            if self.ranges[pos].start <= end:
                break
        while True:
            if len(self.ranges) > 0 and self.ranges[0].end >= start:
                return

    def iterator(self):
        return self

    def remove(self):
        raise NotImplementedError()

    def hasNext(self):
        if len(self.ranges) > 0:
            return True
        return False

    def next(self):
        range = self.ranges[0]
        del self.ranges[0]
        return AddressRange(range.start, range.end)

class RestrictedIndexRangeIterator(SimpleAddressRangeIterator):
    def __init__(self, start, end):
        super().__init__()
        self.ranges = []
        for pos in range(len(self.ranges)):
            if self.ranges[pos].start <= end:
                break
        while True:
            if len(self.ranges) > 0 and self.ranges[0].end >= start:
                return

    def iterator(self):
        return self

    def remove(self):
        raise NotImplementedError()

    def hasNext(self):
        if len(self.ranges) > 0:
            return True
        return False

    def next(self):
        range = self.ranges[0]
        del self.ranges[0]
        return AddressRange(range.start, range.end)

class RestrictedIndexRangeIterator(SimpleAddressRangeIterator):
    def __init__(self, start, end):
        super().__init__()
        self.ranges = []
        for pos in range(len(self.ranges)):
            if self.ranges[pos].start <= end:
                break
        while True:
            if len(self.ranges) > 0 and self.ranges[0].end >= start:
                return

    def iterator(self):
        return self

    def remove(self):
        raise NotImplementedError()

    def hasNext(self):
        if len(self.ranges) > 0:
            return True
        return False

    def next(self):
        range = self.ranges[0]
        del self.ranges[0]
        return AddressRange(range.start, range.end)

class RestrictedIndexRangeIterator(SimpleAddressRangeIterator):
    def __init__(self, start, end):
        super().__init__()
        self.ranges = []
        for pos in range(len(self.ranges)):
            if self.ranges[pos].start <= end:
                break
        while True:
            if len(self.ranges) > 0 and self.ranges[0].end >= start:
                return

    def iterator(self):
        return self

    def remove(self):
        raise NotImplementedError()

    def hasNext(self):
        if len(self.ranges) > 0:
            return True
        return False

    def next(self):
        range = self.ranges[0]
        del self.ranges[0]
        return AddressRange(range.start, range.end)

class RestrictedIndexRangeIterator(SimpleAddressRangeIterator):
    def __init__(self, start, end):
        super().__init__()
        self.ranges = []
        for pos in range(len(self.ranges)):
            if self.ranges[pos].start <= end:
                break
        while True:
            if len(self.ranges) > 0 and self.ranges[0].end >= start:
                return

    def iterator(self):
        return self

    def remove(self):
        raise NotImplementedError()

    def hasNext(self):
        if len(self.ranges) > 0:
            return True
        return False

    def next(self):
        range = self.ranges[0]
        del self.ranges[0]
        return AddressRange(range.start, range.end)

class RestrictedIndexRangeIterator(SimpleAddressRangeIterator):
    def __init__(self, start, end):
        super().__init__()
        self.ranges = []
        for pos in range(len(self.ranges)):
            if self.ranges[pos].start <= end:
                break
        while True:
            if len(self.ranges) > 0 and self.ranges[0].end >= start:
                return

    def iterator(self):
        return self

    def remove(self):
        raise NotImplementedError()

    def hasNext(self):
        if len(self.ranges) > 0:
            return True
        return False

    def next(self):
        range = self.ranges[0]
        del self.ranges[0]
        return AddressRange(range.start, range.end)

class RestrictedIndexRangeIterator(SimpleAddressRangeIterator):
    def __init__(self, start, end):
        super().__init__()
        self.ranges = []
        for pos in range(len(self.ranges)):
            if self.ranges[pos].start <= end:
                break
        while True:
            if len(self.ranges) > 0 and self.ranges[0].end >= start:
                return

    def iterator(self):
        return self

    def remove(self):
        raise NotImplementedError()

    def hasNext(self):
        if len(self.ranges) > 0:
            return True
        return False

    def next(self):
        range = self.ranges[0]
        del self.ranges[0]
        return AddressRange(range.start, range.end)

class RestrictedIndexRangeIterator(SimpleAddressRangeIterator):
    def __init__(self, start, end):
        super().__init__()
        self.ranges = []
        for pos in range(len(self.ranges)):
            if self.ranges[pos].start <= end:
                break
        while True:
            if len(self.ranges) > 0 and self.ranges[0].end >= start:
                return

    def iterator(self):
        return self

    def remove(self):
        raise NotImplementedError()

    def hasNext(self):
        if len(self.ranges) > 0:
            return True
        return False

    def next(self):
        range = self.ranges[0]
        del self.ranges[0]
        return AddressRange(range.start, range.end)

class RestrictedIndexRangeIterator(SimpleAddressRangeIterator):
    def __init__(self, start, end):
        super().__init__()
        self.ranges = []
        for pos in range(len(self.ranges)):
            if self.ranges[pos].start <= end:
                break
        while True:
            if len(self.ranges) > 0 and self.ranges[0].end >= start:
                return

    def iterator(self):
        return self

    def remove(self):
        raise NotImplementedError()

    def hasNext(self):
        if len(self.ranges) > 0:
            return True
        return False

    def next(self):
        range = self.ranges[0]
        del self.ranges[0]
        return AddressRange(range.start, range.end)

class RestrictedIndexRangeIterator(SimpleAddressRangeIterator):
    def __init__(self, start, end):
        super().__init__()
        self.ranges = []
        for pos in range(len(self.ranges)):
            if self.ranges[pos].start <= end:
                break
        while True:
            if len(self.ranges) > 0 and self.ranges[0].end >= start:
                return

    def iterator(self):
        return self

    def remove(self):
        raise NotImplementedError()

    def hasNext(self):
        if len(self.ranges) > 0:
            return True
        return False

    def next(self):
        range = self.ranges[0]
        del self.ranges[0]
        return AddressRange(range.start, range.end)

class RestrictedIndexRangeIterator(SimpleAddressRangeIterator):
    def __init__(self, start, end):
        super().__init__()
        self.ranges = []
        for pos in range(len(self.ranges)):
            if self.ranges[pos].start <= end:
               