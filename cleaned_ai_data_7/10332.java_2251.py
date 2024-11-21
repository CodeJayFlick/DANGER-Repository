from collections import OrderedDict, deque

class ValueSortedMap:
    def __init__(self):
        self.entries = OrderedDict()

    class EntrySet(deque):
        pass

    class KeySet(OrderedDict):
        pass

    def entry_set(self):
        return self.EntrySet(list(self.entries.items()))

    def lower_entry_by_value(self, value):
        for k, v in reversed(list(self.entries.items())):
            if v < value:
                return (k, v)
        return None

    def floor_entry_by_value(self, value):
        for k, v in list(self.entries.items()):
            if v <= value:
                return (k, v)
        return None

    def ceiling_entry_by_value(self, value):
        for k, v in self.entries.items():
            if v >= value:
                return (k, v)
        return None

    def higher_entry_by_value(self, value):
        for k, v in list(self.entries.items()):
            if v > value:
                return (k, v)
        return None

    def sub_map_by_value(self, from_value, from_inclusive=True, to_value=None, to_inclusive=False):
        result = ValueSortedMap()
        for k, v in self.entries.items():
            if ((from_inclusive and v >= from_value) or
                (not from_inclusive and v > from_value)):
                if (to_value is None or
                    (to_inclusive and v <= to_value) or
                    (not to_inclusive and v < to_value)):
                    result.entries[k] = v
        return result

    def head_map_by_value(self, to_value, inclusive=False):
        return self.sub_map_by_value(None, True, to_value, inclusive)

    def tail_map_by_value(self, from_value=None, inclusive=True):
        if from_value is None:
            return ValueSortedMap()
        else:
            return self.sub_map_by_value(from_value, inclusive, None, False)

    def key_set(self):
        return self.KeySet(list(self.entries.keys()))

    def update(self, key):
        # TO DO: implement this method
        pass

    def values(self):
        return list(self.entries.values())

class ValueSortedMapKeyList:
    def __init__(self, keys):
        self.keys = deque(keys)

    @property
    def spliterator(self):
        return Spliterators.spliterator(self.keys, Spliterator.ORDERED | Spliterator.DISTINCT)
