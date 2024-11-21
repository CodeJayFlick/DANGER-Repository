Here is the translation of the Java interface `MsType` into a Python class:

```python
class MsType:
    def __init__(self):
        self._name = ""
        self._record_number = RecordNumber.NO_TYPE
        self._size = 0

    @property
    def name(self) -> str:
        return self._name

    @name.setter
    def name(self, value: str):
        self._name = value

    @property
    def record_number(self) -> 'RecordNumber':
        return self._record_number

    @record_number.setter
    def record_number(self, value: 'RecordNumber'):
        self._record_number = value

    @property
    def size(self) -> int:
        return self._size

    @size.setter
    def size(self, value: int):
        self._size = value

    def get_length(self) -> int:
        return self.size


class RecordNumber:
    NO_TYPE = 0


# Usage example:

ms_type = MsType()
print(ms_type.name)  # prints ""
print(ms_type.record_number)  # prints 0
print(ms_type.size)  # prints 0

ms_type.name = "My Type"
ms_type.record_number = RecordNumber.NO_TYPE + 1
ms_type.size = 10

print(ms_type.name)  # prints "My Type"
print(ms_type.record_number)  # prints 1
print(ms_type.get_length())  # prints 10
```

Note that I created a separate `RecordNumber` class to represent the enum-like values in Java. In Python, we don't have built-in support for enums like Java does, so we can use an integer or string value as a proxy instead.