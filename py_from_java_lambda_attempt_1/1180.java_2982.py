Here is the translation of the Java code to Python:
```
import ctypes

class WrapIDebugHostContext:
    def __init__(self):
        pass

    def __init__(self, pv_instance: bytes):
        self.pv_instance = pv_instance

    def IsEqualTo(self, p_context: bytes, p_is_equal: int) -> int:
        return _invoke_hr(VT_INDICES.IS_EQUAL_TO, self.pv_instance, p_context, p_is_equal)

def _invoke_hr(index: int, instance: bytes, context: bytes, is_equal: int) -> int:
    # implement the actual invocation logic here
    pass

class VTIndices:
    IS_EQUAL_TO = 0x1234

if __name__ == "__main__":
    wrap_idebug_host_context = WrapIDebugHostContext(b"instance")
    result = wrap_idebug_host_context.IsEqualTo(b"context", 1)
    print(result)