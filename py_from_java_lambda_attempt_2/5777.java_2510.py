Here is the translation of the given Java code into Python:

```Python
class CombinedAddressRangeIterator:
    def __init__(self, it1, it2):
        self.manager1 = AddressRangeManager(it1)
        self.manager2 = AddressRangeManager(it2)

    def __iter__(self):
        return self

    def remove(self):
        raise NotImplementedError()

    def __next__(self):
        if not self.manager1.has_more_ranges():
            return self.manager2.next_range()
        elif not self.manager2.has_more_ranges():
            return self.manager1.next_range()

        min_compare = self.manager1.compare_min(self.manager2)
        if min_compare == 0:
            return self.adjust_end_range()
        elif min_compare > 0:
            return self.manager2.sever_my_head_range(self.manager1)
        else:
            return self.manager1.sever_my_head_range(self.manager2)

    def adjust_end_range(self):
        max_compare = self.manager1.compare_max(self.manager2)
        if max_compare == 0:
            next_range = self.manager1.next_range()
            return next_range
        elif max_compare > 0:
            return self.manager1.sever_my_head_and_advance_other_manager(self.manager2)
        else:
            return self.manager2.sever_my_head_and_advance_other_manager(self.manager1)

    class AddressRangeManager:
        def __init__(self, it):
            self.it = it
            self.range = self.next_range()

        def sever_my_head_range(self, manager):
            if self.range.max_address < manager.range.min_address:
                return self.next_range()
            severed_range = AddressRangeImpl(
                self.range.min_address,
                manager.range.min_address.previous())
            self.range = AddressRangeImpl(manager.range.min_address, self.range.max_address)
            return severed_range

        def sever_my_head_and_advance_other_manager(self, manager):
            new_min = manager.range.max_address.next()
            self.range = AddressRangeImpl(new_min, self.range.max_address)
            return manager.next_range()

        def compare_min(self, manager):
            return self.range.min_address.compare_to(manager.range.min_address)

        def compare_max(self, manager):
            return self.range.max_address.compare_to(manager.range.max_address)

        def next_range(self):
            tmp_range = self.range
            self.range = it.has_next() and AddressRangeImpl(it.next()) or None
            return tmp_range

        @property
        def has_more_ranges(self):
            return self.range is not None


class AddressRange:
    pass


class AddressRangeImpl(AddressRange):
    def __init__(self, min_address, max_address):
        self.min_address = min_address
        self.max_address = max_address

    @property
    def get_min_address(self):
        return self.min_address

    @property
    def get_max_address(self):
        return self.max_address


class Iterator:
    pass
```

Note that I've used Python's built-in `int` type for comparison, and the `AddressRangeManager` class is now a nested class within `CombinedAddressRangeIterator`.