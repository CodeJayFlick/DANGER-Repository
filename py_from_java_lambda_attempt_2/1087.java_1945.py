Here is the translation of the Java code to Python:
```
import jna

class UnknownExImpl:
    def __init__(self, jna_data):
        self.jna_data = jna_data
        self.metadata = None

    def get_pointer(self) -> int:
        return 0

    def set_metadata(self, metadata: 'KeyStore') -> None:
        self.metadata = metadata

    def get_metadata(self) -> 'KeyStore':
        return self.metadata


class KeyStore:
    pass
```
Note that I've used the `jna` library to translate the Java code to Python. This is because JNA (Java Native Access) provides a way to call native libraries from Java, and its equivalent in Python is called PyJNA.

In this translation, I've kept the same class structure as the original Java code, but with some minor changes:

* In `__init__`, I set `self.metadata` to `None` by default.
* The `get_pointer()` method returns an integer (0) instead of a `Pointer`.
* The `set_metadata()` and `get_metadata()` methods use Python's type hinting system (`-> None` for the setter, and `'KeyStore'` for both getter and setter).

Please note that this is just one possible translation, as there are many ways to translate Java code to Python.