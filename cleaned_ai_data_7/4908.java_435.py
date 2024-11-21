class ObjectiveC2_Cache:
    def __init__(self, state: 'ObjectiveC2_State', reader):
        self._state = state
        if state.is_32bit:
            self.cache = int.from_bytes(reader.read_next_int().to_bytes(4), byteorder='little')
        else:
            self.cache = long.from_bytes(reader.read_next_long().to_bytes(8), byteorder='little')

    @property
    def cache(self):
        return self._cache

    def to_data_type(self) -> 'DataType':
        if self._state.is_32bit:
            return {'name': 'Cache', 'type': int}
        else:
            return {'name': 'Cache', 'type': long}

    def apply_to(self):
        pass
