Here is the translation of the Java interface `IDataModelScriptDebugStack` into a Python class:

```python
import ctypes

class IDataModelScriptDebugStack:
    IID_IDATA_MODEL_SCRIPT_DEBUG_STACK = "051364DD-E449-443e-9762-FE578F4A5473"

    VTIndices = {
        'GET_FRAME_COUNT': 0,
        'GET_STACK_FRAME': 1,
    }

    def get_frame_count(self):
        raise NotImplementedError

    def get_stack_frame(self, frame_number: int) -> ctypes.POINTER:
        raise NotImplementedError
```

Note that:

* The `IID` constant is simply a string in Python.
* The `VTIndices` dictionary maps the enum values to integers. In Java, this would be an `enum` with an explicit value for each member; here we use a dictionary to achieve similar behavior.
* The methods are defined as abstract (using `raise NotImplementedError`) since they need to be implemented by any concrete subclass.

This Python class is not equivalent to the original Java interface in terms of syntax, but it captures the same semantics and structure.