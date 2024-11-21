Here is the translation of the given Java code into equivalent Python:

```Python
import ctypes

class WrapIDebugHostSymbol2:
    def __init__(self):
        pass

    def __init__(self, pv_instance):
        super().__init__()
        self.pv_instance = pv_instance

    def EnumerateChildrenEx(self, kind: int, name: str, search_info: dict, pp_enum: ctypes.POINTER(ctypes.c_void_p)):
        return 0  # Assuming HRESULT is equivalent to Python's integer type. In real scenarios, you would need a more complex implementation.

    def GetLanguage(self):
        p_kind = ctypes.pointer(ctypes.c_ulong(0))  # Assuming ULONGByReference is equivalent to Python's ctypes library.
        return None

class ByReference:
    pass
```

Please note that this translation assumes the following:

- `HRESULT` in Java is equivalent to a Python integer type (like int or long).
- `ULONG`, `WString`, and other types are not directly translatable into Python. You would need more complex implementations for these.
- The JNA library used in Java does not have an exact equivalent in Python, so you might need to use the ctypes library instead.

This translation is a simplified version of your original code. In real scenarios, you may need to handle errors and exceptions differently than what's shown here.