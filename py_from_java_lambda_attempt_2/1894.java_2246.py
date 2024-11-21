Here is the translation of the given Java code into equivalent Python:

```Python
class TypeFlags:
    _values = [
        ("eTypeHasChildren", 0),
        ("eTypeHasValue", 1),
        ("eTypeIsArray", 2),
        ("eTypeIsBlock", 3),
        ("eTypeIsBuiltIn", 4),
        ("eTypeIsClass", 5),
        ("eTypeIsCPlusPlus", 6),
        ("eTypeIsEnumeration", 7),
        ("eTypeIsFuncPrototype", 8),
        ("eTypeIsMember", 9),
        ("eTypeIsObjC", 10),
        ("eTypeIsPointer", 11),
        ("eTypeIsReference", 12),
        ("eTypeIsStructUnion", 13),
        ("eTypeIsTemplate", 14),
        ("eTypeIsTypedef", 15),
        ("eTypeIsVector", 16),
        ("eTypeIsScalar", 17),
        ("eTypeIsInteger", 18),
        ("eTypeIsFloat", 19),
        ("eTypeIsComplex", 20),
        ("eTypeIsSigned", 21),
        ("eTypeInstanceIsPointer", 22)
    ]

    def __init__(self, name):
        self.name = name
        TypeFlags._values.append((name, len(TypeFlags._values) - 1))

    @classmethod
    def swig_to_enum(cls, value):
        for k, v in cls._values:
            if v == value:
                return cls(k)
        raise ValueError(f"No enum {cls.__name__} with value {value}")

    def __str__(self):
        return self.name

    def get_value(self):
        return [k[1] for k in TypeFlags._values].index(self.name)

# Create instances of the enums
eTypeHasChildren = TypeFlags("eTypeHasChildren")
eTypeHasValue = TypeFlags("eTypeHasValue")
...
```

Please note that Python does not have an exact equivalent to Java's `enum` type. The above code uses a list of tuples to simulate the behavior of the given Java enum class.