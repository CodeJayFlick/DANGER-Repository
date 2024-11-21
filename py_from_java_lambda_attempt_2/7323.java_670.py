Here is the translation of the given Java code into equivalent Python:

```Python
class BTreeUserDataRecord:
    def __init__(self):
        self.unused = None

    def set_unused(self, unused: bytes) -> None:
        self.unused = unused

    def get_unused(self) -> bytes:
        return self.unused


def to_data_type(self) -> dict:
    return {"unused": self.unused}
```

Note that Python does not have direct equivalent of Java's `byte[]` type. In this translation, I used the built-in `bytes` type in Python which is similar but not exactly same as Java's byte array.

Also note that there are no exceptions handling like `IOException`, `DuplicateNameException` etc., because Python has different way to handle errors and exceptions compared to Java.