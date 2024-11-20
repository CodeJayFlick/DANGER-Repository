Here is the translation of the given Java interface into a Python equivalent:

```Python
import ctypes

class IDebugOutputCallbacksWide:
    IID_IDEBUG_OUTPUT_CALLBACKS_WIDE = "4c7fd663-394-c26-8ef1-34ad5ed3764c"

    def __init__(self):
        pass

    def Output(self, Mask: int, Text: str) -> ctypes.c_long:
        return 0
```

Note that Python does not have a direct equivalent to Java's `interface` keyword. Instead, we define a class with the same name and use it as an interface by defining methods without implementation.

The `ctypes.c_long` type is used for the return value of the `Output` method because in C++, which is what JNA (Java Native Access) uses under the hood, the equivalent function would have a long integer (`HRESULT`) return type.