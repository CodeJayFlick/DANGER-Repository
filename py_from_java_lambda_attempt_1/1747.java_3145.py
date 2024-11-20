Here is the equivalent Python code:

```Python
class ConnectionStatus:
    _values = [
        ("eConnectionStatusSuccess", 0),
        ("eConnectionStatusEndOfFile", 1),
        ("eConnectionStatusError", 2),
        ("eConnectionStatusTimedOut", 3),
        ("eConnectionStatusNoConnection", 4),
        ("eConnectionStatusLostConnection", 5),
        ("eConnectionStatusInterrupted", 6)
    ]

    def __init__(self, name):
        self.name = name
        ConnectionStatus._values.append((name, len(ConnectionStatus._values) - 1))

    @classmethod
    def swig_to_enum(cls, value):
        for k, v in cls._values:
            if v == value:
                return getattr(cls, k)
        raise ValueError(f"No enum {cls.__name__} with value {value}")

    def __str__(self):
        return self.name

    @property
    def swig_value(self):
        return [k for k, v in ConnectionStatus._values if v == self][0]
```

Note that Python does not have an exact equivalent to Java's `enum` type. Instead, we use a class with static values and methods to achieve similar functionality.