Here is the translation of the Java code to Python:
```
import ctypes

class IUnknownEx:
    def __init__(self):
        pass

    def get_pointer(self) -> ctypes.POINTER(None):
        return None
```
Note that in Python, we don't need an explicit `interface` keyword like in Java. Instead, we define a regular class with the same name and methods.

The `get_pointer()` method returns a `ctypes.POINTER(None)` object, which is equivalent to the Java `Pointer` type. The `None` argument indicates that this pointer points to no specific memory location (i.e., it's a null pointer).