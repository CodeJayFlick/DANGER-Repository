Here is the translation of the given Java code into equivalent Python:

```Python
import uuid
from enum import Enum

class Type(Enum):
    UNKNOWN = 0
    ICEBERG_TABLE = 1
    DELTA_LAKE_TABLE = 2
    VIEW = 3


class Contents:
    def __init__(self):
        self._id = str(uuid.uuid4())

    @property
    def id(self) -> str:
        return self._id

    def unwrap(self, clazz: type) -> Optional:
        if issubclass(clazz, type(self)):
            return Optional.of(type(self)(clazz))
        else:
            return Optional.empty()


class IcebergTable(Contents):
    pass


class DeltaLakeTable(Contents):
    pass


class SqlView(Contents):
    pass
```

Please note that Python does not have direct equivalent of Java's `@JsonSubTypes`, `@JsonTypeInfo` and other Jackson annotations. You would need to use a library like `marshmallow` or `jsonschema` for JSON serialization/deserialization in Python.

Also, the concept of `enum` is different between Java and Python. In Java, an enum is essentially a special type of class that can be used as a set of named values. In Python, you would typically use a regular class with static methods to achieve similar functionality.