class BiDiMap:
    def __init__(self):
        self._other = None

    def put(self, key: object, value: object) -> object:
        if not (key or value):
            raise ValueError("Can't store null in a BidiHashMap")
        
        old_value = super().put(key, value)
        self._other[value] = key
        return old_value

    def get(self, key: object) -> object:
        return super().get(key)

    def put_all(self, values):
        for k, v in values.items():
            self.put(k, v)

    def remove(self, key: object) -> object:
        value = super().remove(key)
        if value is not None:
            del self._other[value]
        return value

    def clear(self):
        super().clear()
        self._other.clear()

    def contains_value(self, value: object) -> bool:
        return value in self._other.keys()

    def entry_set(self) -> set:
        return frozenset(super().items())

    def key_set(self) -> set:
        return frozenset(super().keys())

    def values(self):
        return self.value_set()

    def value_set(self) -> set:
        return frozenset(self._other.keys())

    def clone(self) -> 'BiDiMap':
        other = BiDiMap()
        for k, v in super().items():
            other.put(v, k)
        return other

class BidiHashMap(BiDiMap):
    pass
