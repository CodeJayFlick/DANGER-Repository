Here is the translation of the given Java code into Python:

```Python
class AddressRange:
    def __init__(self, start: 'Address', end: 'Address'):
        self.start = start
        self.end = end


class AddressSetView:
    def __init__(self):
        pass

    def contains(self, addr: 'Address') -> bool:
        # Implement the logic to check if an address is contained in this set.
        return False  # Replace with your implementation.

    def contains(self, start: 'Address', end: 'Address') -> bool:
        # Implement the logic to check if a range of addresses is contained in this set.
        return self.contains(start) and self.contains(end)

    def contains(self, addr_set_view: 'AddressSetView') -> bool:
        # Implement the logic to check if an address set view is contained in this set.
        for addr_range in addr_set_view.get_address_ranges():
            if not self.contains(addr_range.start):
                return False
        return True

    def is_empty(self) -> bool:
        # Check if the set is empty.
        return len(list(self)) == 0

    @property
    def min_address(self) -> 'Address':
        # Return the minimum address in this set. Returns None if the set is empty.
        addresses = list(self)
        if not addresses:
            return None
        return min(addresses)

    @property
    def max_address(self) -> 'Address':
        # Return the maximum address in this set. Returns None if the set is empty.
        addresses = list(self)
        if not addresses:
            return None
        return max(addresses)

    def get_num_address_ranges(self) -> int:
        # Return the number of address ranges in this set.
        return len(list(self))

    def get_address_ranges(self, forward: bool = True) -> 'AddressRangeIterator':
        # Implement an iterator over all addresses in this set. The order is determined by the "forward" parameter.
        for addr_range in self:
            yield from (addr_range.start if forward else addr_range.end).iterate(forward)

    def get_addresses(self, start: 'Address', forward: bool = True) -> 'AddressIterator':
        # Implement an iterator over all addresses starting at a given address. The order is determined by the "forward" parameter.
        for addr_range in self:
            if not (start <= addr_range.start and addr_range.end >= start):
                continue
            yield from (addr_range.start if forward else addr_range.end).iterate(forward)

    def intersects(self, addr_set_view: 'AddressSetView') -> bool:
        # Check if this set intersects with the given address set.
        for addr_range in self.get_address_ranges():
            for other_addr_range in addr_set_view.get_address_ranges():
                if (addr_range.start <= other_addr_range.end and
                        other_addr_range.start <= addr_range.end):
                    return True
        return False

    def intersect(self, addr_set_view: 'AddressSetView') -> 'AddressSet':
        # Compute the intersection of this set with the given address set.
        result = AddressSet()
        for addr_range in self.get_address_ranges():
            if all(start <= end and start >= other_start and end <= other_end
                   for (start, end), (other_start, other_end) in zip(addr_range.iterate(), addr_set_view)):
                result.add(addr_range)
        return result

    def union(self, addr_set_view: 'AddressSetView') -> 'AddressSet':
        # Compute the union of this set with the given address set.
        result = AddressSet()
        for addr_range in self.get_address_ranges():
            if not any(start <= end and start >= other_start and end <= other_end
                       for (start, end), (other_start, other_end) in zip(addr_range.iterate(), addr_set_view)):
                result.add(addr_range)
        return result

    def subtract(self, addr_set_view: 'AddressSetView') -> 'AddressSet':
        # Compute the difference of this set with the given address set.
        result = AddressSet()
        for addr_range in self.get_address_ranges():
            if not any(start <= end and start >= other_start and end <= other_end
                       for (start, end), (other_start, other_end) in zip(addr_range.iterate(), addr_set_view)):
                result.add(addr_range)
        return result

    def xor(self, addr_set_view: 'AddressSetView') -> 'AddressSet':
        # Compute the exclusive-or of this set with the given address set.
        result = AddressSet()
        for addr_range in self.get_address_ranges():
            if any(start <= end and start >= other_start and end <= other_end
                   for (start, end), (other_start, other_end) in zip(addr_range.iterate(), addr_set_view)):
                continue
            result.add(addr_range)
        return result

    def has_same_addresses(self, addr_set_view: 'AddressSetView') -> bool:
        # Check if the given address set contains the same addresses as this set.
        for addr_range1 in self.get_address_ranges():
            for addr_range2 in addr_set_view.get_address_ranges():
                if (addr_range1.start <= addr_range2.end and
                        addr_range2.start <= addr_range1.end):
                    return True
        return False

    def get_first_range(self) -> 'AddressRange':
        # Return the first range in this set or None if the set is empty.
        for addr_range in self.get_address_ranges():
            return addr_range
        return None

    def get_last_range(self) -> 'AddressRange':
        # Return the last range in this set or None if the set is empty.
        for addr_range in reversed(list(self)):
            return addr_range
        return None

    def get_range_containing(self, address: 'Address') -> 'AddressRange':
        # Find the first range that contains a given address.
        for addr_range in self.get_address_ranges():
            if (addr_range.start <= address and address <= addr_range.end):
                return addr_range
        return None

    @staticmethod
    def trim_start(addr_set_view: 'AddressSetView', addr: 'Address') -> 'AddressSet':
        # Trim an address set removing all addresses less-than-or-equal to a specified address.
        trimmed_set = AddressSet()
        for addr_range in addr_set_view.get_address_ranges():
            if (addr_range.start > addr):
                trimmed_set.add(addr_range)
            elif (addr_range.end > addr):
                trimmed_set.add((addr, addr_range.end))
        return trimmed_set

    @staticmethod
    def trim_end(addr_set_view: 'AddressSetView', addr: 'Address') -> 'AddressSet':
        # Trim an address set removing all addresses greater-than-or-equal to a specified address.
        trimmed_set = AddressSet()
        for addr_range in reversed(list(addr_set_view)):
            if (addr_range.end < addr):
                trimmed_set.add(addr_range)
            elif (addr_range.start < addr):
                trimmed_set.add((addr_range.start, addr))
        return trimmed_set
```

Please note that the above Python code is a direct translation of your given Java code. However, it may not work as expected because you have to implement the logic for various methods in this class based on how they are used in your application.

Here's an example implementation:

```Python
class Address:
    def __init__(self, value):
        self.value = value

    def iterate(self, forward=True):
        if forward:
            yield from range(self.value, int('1e9'))
        else:
            yield from range(int('-1e9'), self.value)

    def next(self):
        return Address(self.value + 1)

    def previous(self):
        return Address(self.value - 1)
```

This is a very basic implementation. You may need to adjust it based on your specific requirements.

Also, the above Python code does not include any error handling or exception handling which you might want to add depending on how this class will be used in your application.