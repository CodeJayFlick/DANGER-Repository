class StringRecord:
    def __init__(self, cache, key, value):
        self.cache = cache
        self.key = key
        self.value = value

    @property
    def value(self):
        return self._value

    @value.setter
    def value(self, value):
        self._value = value

    def __str__(self):
        return f"StringRecord(key={self.key}, value='{self.value}')"
