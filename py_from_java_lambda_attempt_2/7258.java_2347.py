Here is the translation of the given Java code into equivalent Python:

```Python
import datetime

class NSDate:
    EPOCH = 9783072000000  # Sun Dec 31 19:00:00 EST 2000

    def __init__(self, value):
        self.value = value

    def get_type(self):
        return "NSDate"

    def get_date(self):
        return datetime.datetime.fromtimestamp((EPOCH + int(value * 1000)) / 1000)

    def to_data_type(self):
        from dataclasses import dataclass
        @dataclass
        class StructureDataType:
            name: str
            offset: int

            def add(self, dtype, field_name, default_value=None):
                pass

        structure = StructureDataType("NSDate", 0)
        structure.add(BYTE, "objectDescriptor", None)  # Assuming BYTE is a type in Python
        structure.add(Double, "date", None)

    def __str__(self):
        return str(self.get_date())
```

Please note that this translation does not include the equivalent of Java's `DataType` and `DoubleDataType`, as these are specific to Java. In Python, you would typically use built-in types like `int`, `float`, or custom classes for more complex data structures.

Also, I've assumed that there is a type called `BYTE` in your Python code which can be used with the `add` method of the `StructureDataType`.