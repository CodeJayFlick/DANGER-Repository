Here is the translation of the given Java code into equivalent Python:

```Python
class WrapIDebugHostMemory2:
    def __init__(self):
        pass

    def __init__(self, pv_instance):
        super().__init__()

    def LinearizeLocation(self, context, location, p_linearized_location):
        # Assuming _invokeHR and VTIndices2 are defined elsewhere in the code
        return self._invokeHR(0x0001, None, context, location, p_linearized_location)

class LOCATION:
    pass

class LOCATION_ByReference:
    pass
```

Please note that this translation is not a direct conversion from Java to Python. The original Java code seems to be using JNA (Java Native Access) for interacting with native libraries and structures. In the given Python version, I have removed these parts as they are specific to Java's interaction with native libraries.

In particular:

- `Pointer` class in Java is used to interact with memory pointers. This concept does not directly translate into Python.
- The `Structure.ByReference` interface in Java represents a reference to an instance of the structure type, which also doesn't have direct equivalent in Python.
- `_invokeHR` method seems to be calling some native function and returning its result as HRESULT (a Windows error code). This is specific to JNA's interaction with native libraries.

These parts are removed from this translation.