Here is the equivalent Python code:

```Python
class DWARFInline:
    NOT_INLINED = 0x0
    INLINED = 0x1
    DECLARED_NOT_INLINED = 0x2
    DECLARED_INLINED = 0x3

    _value_map = {}

    def __new__(cls, value):
        instance = super().__new__(cls)
        instance._value = value
        cls._value_map[value] = instance
        return instance

    @property
    def value(self):
        return self._value

    @classmethod
    def find(cls, key):
        if isinstance(key, int):
            return cls._value_map.get(key)
        else:
            raise ValueError(f"Invalid integer value: {key}")
```

Note that Python does not have an exact equivalent to Java's enum type. The above code uses a class with static methods and properties to achieve similar functionality.