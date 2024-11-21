Here is the equivalent Python code:

```Python
class WatchpointKind:
    eWatchpointKindWrite = "eWatchpointKindWrite"
    eWatchpointKindRead = "eWatchpointKindRead"

    def __init__(self, swig_name):
        self.swig_name = swig_name
        global next_value
        self.swig_value = next_value
        nonlocal next_value
        next_value += 1

    @classmethod
    def swig_to_enum(cls, swig_value):
        if 0 <= swig_value < len(values) and values[swig_value].swig_value == swig_value:
            return values[swig_value]
        for value in values:
            if value.swig_value == swig_value:
                return value
        raise ValueError(f"No enum {cls.__name__} with value {swig_value}")

    def __str__(self):
        return self.swig_name

    @property
    def swig_value(self):
        return self._swig_value

    @classmethod
    def swig_values(cls):
        if not hasattr(cls, 'values'):
            cls.values = [cls(eWatchpointKindWrite), cls(eWatchpointKindRead)]
        return cls.values


next_value = 0
```

Please note that Python does not have direct equivalent of Java's `public`, `private` and `final`. The access modifiers are more relaxed in Python.