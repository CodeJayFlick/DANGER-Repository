Here is the equivalent Python code:

```Python
class DWARFChildren:
    NO = 0
    YES = 1

    _value_map = {}

    def __init__(self, value):
        self.value = value

    @classmethod
    def get_value(cls, key):
        return cls._get_value(key)

    @classmethod
    def find(cls, key):
        if isinstance(key, int):
            return cls._get_value(key)
        else:
            raise ValueError("Invalid integer value: {}".format(key))

    @classmethod
    def _init_map(cls):
        for access in [DWARFChildren.NO, DWARFChildren.YES]:
            cls._value_map[access.value] = access

    NO = DWARFChildren(NO)
    YES = DWARFChildren(YES)

    _init_map()
```

This Python code defines an enum-like class `DWARFChildren` with two values: `NO` and `YES`. It also includes methods to get the value of a given instance, find an instance by its value, and initialize the `_value_map` dictionary.