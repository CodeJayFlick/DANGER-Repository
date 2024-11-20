class DWARFNumericAttribute:
    def __init__(self, value):
        self.value = value

    @property
    def value(self):
        return self._value

    @value.setter
    def value(self, value):
        self._value = value

    @property
    def unsigned_value(self):
        return self._value

    def __str__(self):
        return f"DWARFNumericAttribute: {self.value} [{self.value}]"
