from collections import defaultdict

class SpatialMap:
    def __init__(self):
        self._map = defaultdict(dict)

    @property
    def empty(self):
        return EmptySpatialMap()

    def put(self, shape: 'BoundedShape', value) -> T:
        raise NotImplementedError('Method not implemented')

    def remove(self, shape: 'BoundedShape', value) -> bool:
        raise NotImplementedError('Method not implemented')

    def remove_entry(self, entry: tuple) -> bool:
        raise NotImplementedError('Method not implemented')

    @property
    def size(self):
        return len(self._map)

    def is_empty(self):
        return self.size == 0

    def entries(self):
        for shape in self._map:
            yield from self._map[shape].items()

    def ordered_entries(self):
        raise NotImplementedError('Method not implemented')

    def keys(self):
        return list(self._map.keys())

    def ordered_keys(self):
        raise NotImplementedError('Method not implemented')

    def values(self):
        for shape in self._map:
            yield from self._map[shape].values()

    def ordered_values(self):
        raise NotImplementedError('Method not implemented')

    def reduce(self, query) -> 'SpatialMap':
        raise NotImplementedError('Method not implemented')

    def first_entry(self):
        if not self.is_empty():
            for shape in self._map:
                for value in self._map[shape].values():
                    return (shape, value)
        return None

    def first_key(self):
        if not self.is_empty():
            return next(iter(self._map))
        return None

    def first_value(self) -> T:
        if not self.is_empty():
            shape = self.first_key()
            for value in self._map[shape].values():
                return value
        return None

    def clear(self):
        pass


class EmptySpatialMap(SpatialMap):
    @property
    def size(self):
        return 0

    def is_empty(self):
        return True

    def entries(self) -> list:
        return []

    def ordered_entries(self) -> list:
        raise NotImplementedError('Method not implemented')

    def keys(self) -> list:
        return []

    def ordered_keys(self) -> list:
        raise NotImplementedError('Method not implemented')

    def values(self) -> list:
        return []

    def ordered_values(self) -> list:
        raise NotImplementedError('Method not implemented')

    def reduce(self, query):
        return self

    def first_entry(self):
        return None

    def first_key(self):
        return None

    def first_value(self) -> T:
        return None
