class SomeEntity:
    def __init__(self, value: int):
        self.value = value

    @property
    def value(self) -> int:
        return self._value

# Note that in Python, we don't need annotations for not null or min/max values.
