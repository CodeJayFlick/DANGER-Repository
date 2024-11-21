Here is the translation of the given Java code into equivalent Python:

```Python
class LongDoubleComplexDataType:
    dataType = None  # This will hold a singleton instance of this class.

    def __init__(self):
        self.__init__None()

    def __init_none(self):
        pass

    @classmethod
    def get_data_type(cls, dtm=None) -> 'LongDoubleComplexDataType':
        if cls.dataType is None:
            cls.dataType = LongDoubleComplexDataType(dtm)
        return cls.dataType


# Singleton pattern implementation for the above class.
LongDoubleComplexDataType.dataType = LongDoubleComplexDataType()
```

Note that Python does not have an exact equivalent of Java's `public` and `private` access modifiers. In this translation, I've used single underscore prefix (`_`) to indicate internal methods (like `__init_none`).