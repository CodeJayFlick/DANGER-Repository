Here is the equivalent Python code:

```Python
class VtShapeDescriptorMsProperty:
    NEAR = ("near", 0)
    FAR = ("far", 1)
    THIN = ("thin", 2)
    OUTER = ("outer", 3)
    META = ("meta", 4)
    NEAR32 = ("near32", 5)
    FAR32 = ("far32", 6)
    UNUSED = ("unused", 7)

    BY_VALUE = {v[1]: k for k, v in vars(VtShapeDescriptorMsProperty).items()}

    def __init__(self, label, value):
        self.label = label
        self.value = value

    def __str__(self):
        return self.label

    @classmethod
    def from_value(cls, val):
        return cls.BY_VALUE.get(val, VtShapeDescriptorMsProperty.UNUSED)
```

Note that Python does not have an exact equivalent to Java's enum. Instead, we define a class with static values and use the `__init__` method to initialize each instance. The rest of the code is similar to the original Java code.