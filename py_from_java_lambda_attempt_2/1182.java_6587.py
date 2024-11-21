Here is a translation of the Java code into equivalent Python:

```Python
import ctypes
from comtypes import HRESULT, ULONG, WString

class WrapIDebugHostErrorSink:
    def __init__(self):
        pass

    def __init__(self, pv_instance):
        super().__init__()
        self.pv_instance = pv_instance

    def ReportError(self, err_class: int, hr_error: HRESULT, message: str) -> HRESULT:
        return _invoke_hr(VTIndices.REPORT_ERROR, self.pv_instance, err_class, hr_error, WString(message))

class ByReference(WrapIDebugHostErrorSink):
    pass

def _invoke_hr(index: int, pv_instance, err_class: int, hr_error: HRESULT, message: str) -> HRESULT:
    # implement the actual logic for invoking HR
    return 0x80000000  # replace with your own implementation


class VTIndices:
    REPORT_ERROR = 1

if __name__ == "__main__":
    pass
```

Please note that this is a translation and not an exact equivalent. Python does not have direct equivalents to Java's classes, interfaces, or some of the other constructs used in the original code.