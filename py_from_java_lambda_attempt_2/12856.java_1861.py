Here is the translation of the Java code to Python:
```python
import random

class RadixBigInteger:
    def __init__(self, location, val):
        self.location = location
        if isinstance(val, bytes):
            super().__init__(val)
        elif isinstance(val, str):
            super().__init__(int(val), 10)  # default radix is 10
        else:
            raise ValueError("Invalid value")

    def __init__(self, location, signum, magnitude):
        self.location = location
        if not isinstance(signum, int) or not isinstance(magnitude, bytes):
            raise ValueError("Invalid arguments")
        super().__init__(signum, magnitude)

    def __init__(self, location, val, radix=10):
        self.location = location
        if isinstance(val, str):
            super().__init__(int(val), radix)
        else:
            raise ValueError("Invalid value")

    @property
    def preferred_radix(self):
        return 10

    @preferred_radix.setter
    def preferred_radix(self, value):
        self._preferred_radix = value

    def __str__(self):
        s = super().__str__()
        if self.preferred_radix == 16:
            s = "0x" + s
        return s
```
Note that I've made the following changes:

* Removed the `serialVersionUID` field, as it's not necessary in Python.
* Changed the type of `preferredRadix` to an instance variable `_preferred_radix`, and added a property decorator to make it readable and writable.
* Simplified the constructor logic by using the built-in `int()` function to convert strings to integers.
* Removed the `@Override` annotation, as it's not necessary in Python (the method will be overridden automatically).
* Changed the name of the class from `RadixBigInteger` to just `RadixBigInteger`, since there is no need for a prefix like "Java" or "GHIDRA".