class OverlappingObjectIterator:
    def __init__(self, left_iterable, left_ranger, right_iterable, right_ranger):
        self.left = iter(left_iterable)
        self.left_ranger = left_ranger
        self.right = iter(right_iterable)
        self.right_ranger = right_ranger

    class MyPair:
        def __init__(self, next_l=None, next_r=None):
            self.next_l = next_l
            self.next_r = next_r

        @property
        def left(self):
            return self.next_l

        @property
        def right(self):
            return self.next_r

    def seek_next(self):
        if not hasattr(self, 'next_pair'):
            self.next_pair = OverlappingObjectIterator.MyPair()

        while True:
            try:
                next_left = next(self.left)
            except StopIteration:
                break

            try:
                next_right = next(self.right)
            except StopIteration:
                return None

            if (self.left_ranger.get_min_address(next_left) <=
                    self.right_ranger.get_max_address(next_right)):
                continue

            if (self.right_ranger.get_min_address(next_right) >=
                    self.left_ranger.get_max_address(next_left)):
                break

        self.next_pair = OverlappingObjectIterator.MyPair(next_left, next_right)
        return self.next_pair


class Ranger:
    def get_min_address(self, obj):
        raise NotImplementedError()

    def get_max_address(self, obj):
        raise NotImplementedError()


class AddressRangeRanger(Ranger):
    def get_min_address(self, address_range):
        return address_range.get_min_address()

    def get_max_address(self, address_range):
        return address_range.get_max_address()


class SnapRangeKeyRanger(Ranger):
    def get_min_address(self, entry):
        return entry.key.x1

    def get_max_address(self, entry):
        return entry.key.x2


class CodeUnitRanger(Ranger):
    def get_min_address(self, code_unit):
        return code_unit.get_min_address()

    def get_max_address(self, code_unit):
        return code_unit.get_max_address()


ADDRESS_RANGER = AddressRangeRanger()
SNAP_RANGE_KEY = SnapRangeKeyRanger()
CODE_UNIT = CodeUnitRanger()
