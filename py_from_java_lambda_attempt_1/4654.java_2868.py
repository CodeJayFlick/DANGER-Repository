Here is the translation of the given Java code into equivalent Python:

```Python
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
```

Please note that Python does not have direct equivalent of Java's `long` type. In this translation, I used the built-in integer type (`int`) which can hold values up to 2^31-1 (2147483647). If you need to handle larger integers, consider using a library like `gmpy2`.