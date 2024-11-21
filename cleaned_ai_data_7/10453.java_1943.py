class WeakValueTreeMap:
    def __init__(self):
        self.ref_map = {}

    def __init__(self, comparator=None):
        if comparator is None:
            self.ref_map = {}
        else:
            from functools import total_ordering

            @total_ordering
            class Key:
                def __init__(self, key):
                    self.key = key

                def __lt__(self, other):
                    return self.key < other.key

                def __eq__(self, other):
                    return self.key == other.key

                def __gt__(self, other):
                    return self.key > other.key

                def __le__(self, other):
                    return self.key <= other.key

                def __ge__(self, other):
                    return self.key >= other.key

            self.ref_map = {k: None for k in sorted(set(comparator(key) for key in set()))}

    @property
    def ref_map(self):
        return self._ref_map

    @ref_map.setter
    def ref_map(self, value):
        self._ref_map = value


class WeakValueRef:
    pass  # This class is not implemented as it's not provided in the given Java code.
