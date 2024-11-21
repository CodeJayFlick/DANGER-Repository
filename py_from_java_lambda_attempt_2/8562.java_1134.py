Here is the translation of the given Java code into equivalent Python:

```Python
class PdbApplicatorControl:
    ALL = ("Process All",)
    DATA_TYPES_ONLY = ("Data Types Only",)
    PUBLIC_SYMBOLS_ONLY = ("Public Symbols Only",)

    def __str__(self):
        return self.label

    def __init__(self, label):
        self.label = label
```

Note that Python does not have an equivalent to Java's `enum` type. Instead, we define a class with static variables and use the same naming convention as in the original code. The `__str__` method is used to provide a string representation of each instance, similar to how it works in Java.