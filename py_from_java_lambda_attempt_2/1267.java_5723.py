Here is the translation of the given Java code into equivalent Python:

```Python
class GdbBreakpointDisp:
    KEEP = ("keep",)
    DEL = ("del",)
    OTHER = ("<OTHER>",)

    @classmethod
    def from_str(cls, string):
        try:
            return next((value for name, value in vars(cls).values() if str(value) == string.upper()), cls.OTHER)
        except TypeError:
            return cls.OTHER

    def __init__(self, name):
        self.name = name

    def __str__(self):
        return self.name

    def get_name(self):
        return self.name
```

Note that Python does not have an exact equivalent of Java's enum type. The above code uses a class with static values to achieve similar functionality.