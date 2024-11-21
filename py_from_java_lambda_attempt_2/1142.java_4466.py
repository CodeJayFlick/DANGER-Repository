Here is a translation of the Java code into equivalent Python code:

```Python
import ctypes

class WrapIDataModelScriptClient:
    def __init__(self):
        pass

    def __init__(self, pv_instance):
        super().__init__()
        self.pv_instance = pv_instance

    def report_error(self, err_class: int, hr_fail: int, message: str, line: int, position: int) -> int:
        return ctypes.windll.user32._invokeHR(0x0001, 0, err_class, hr_fail, message.encode(), line, position)

class ByReference(WrapIDataModelScriptClient):
    pass
```

Please note that this translation is not a direct equivalent of the Java code. Python does not have built-in support for structures or pointers like Java has with JNA. The `ctypes` library was used to simulate some functionality similar to what JNA provides in Java.

The `_invokeHR` function and its parameters are also simulated, as there seems to be no direct equivalent of this method in the Python standard library.