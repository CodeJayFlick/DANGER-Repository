class ListingDisplaySearchAddressIterator:
    def __init__(self, start_address, iterators, forward):
        self.forward = forward
        self.update_last_address(start_address)

        for iterator in iterators:
            last_address_map[iterator] = None

    def update_last_address(self, address):
        if not address:
            return

        if self.forward and address.get_offset() > 0:
            self.last_address = address.subtract(1)
        else:
            max_address = address.get_address_space().get_max_address()
            start_offset = address.get_offset()

            result = start_offset + 1
            if result > start_offset and result < max_address.get_offset():
                self.last_address = address.add(1)

    def has_next(self):
        next_address = self.get_already_found_next_address()
        if next_address:
            return True

        self.maybe_push_iterators_forward()

        for iterator in last_address_map.keys():
            if iterator.has_next():
                return True

        return self.get_already_found_next_address() is not None

    def get_already_found_next_address(self):
        addresses = []
        values = list(last_address_map.values())
        for address in values:
            if address:
                addresses.append(address)

        addresses.sort()
        if not self.forward:
            addresses.reverse()

        for address in addresses:
            if self.is_greater_than_last_address(address):
                return address

        return None

    def next(self):
        next_address = self.maybe_push_iterators_forward()
        self.last_address = next_address
        return next_address

    def maybe_push_iterators_forward(self):
        keys = list(last_address_map.keys())
        for iterator in keys:
            current = last_address_map[iterator]
            if not self.is_greater_than_last_address(current):
                continue  # last value for this iterator is still good--don't move forward
            next_address = self.move_past_last_address(iterator)
            last_address_map[iterator] = next_address

        return self.get_already_found_next_address()

    def move_past_last_address(self, iterator):
        while iterator.has_next():
            address = iterator.next()
            if self.is_greater_than_last_address(address):
                return address
        return None

    def is_greater_than_last_address(self, address):
        if not address:
            return False
        if not self.last_address:
            return True

        if self.forward:
            return self.last_address.get_offset() < address.get_offset()
        else:
            return self.last_address.get_offset() > address.get_offset()

last_address_map = {}
