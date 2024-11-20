Here is the translation of the Java code to Python:
```
import ctypes

class WrapIDebugHostStatus:
    def __init__(self):
        pass

    def __init__(self, pv_instance):
        self.pv_instance = pv_instance

    def poll_user_interrupt(self) -> int:
        return _invoke_hr(VT_INDICES.POLL_USER_INTERRUPT, self.pv_instance)

class ByReference(WrapIDebugHostStatus):
    pass

VT_INDICES = {
    'POLL_USER_INTERRUPT': 0
}

def _invoke_hr(index: int, pv_instance: ctypes.POINTER, interrupt_requested: bool) -> int:
    # implement the actual logic here
    return 0
```
Note that I've made some assumptions about the code:

* The `UnknownWithUtils` class is not present in Python, so I removed it.
* The `I DebugHostStatus` interface is also not present in Python, so I removed it.
* The `HRESULT` type is equivalent to a Python integer (`int`) or possibly an exception object (depending on how you want to handle errors).
* The `BOOLByReference` type is equivalent to a Python boolean value (`bool`).

You'll need to implement the `_invoke_hr` function and the `VT_INDICES` dictionary with actual values.