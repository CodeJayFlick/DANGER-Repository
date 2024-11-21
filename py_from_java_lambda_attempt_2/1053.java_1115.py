Here is the translation of the given Java code into equivalent Python:

```Python
import ctypes

class DebugHostStatus:
    def __init__(self, jna_data):
        self.cleanable = None  # Equivalent to OpaqueCleanable in Java
        self.jna_data = jna_data

    def get_pointer(self):
        return self.jna_data.get_pointer()  # Assuming this method exists in the parent class

    def poll_user_interrupt(self):
        p_interrup_requested = ctypes.c_bool(0)  # Equivalent to BOOLByReference in Java
        result = self.jna_data.poll_user_interrupt(p_interrup_requested)
        return bool(p_interrup_requested.value)

# Example usage:
jna_data = None  # Replace with actual implementation of IDebugHostStatus
status_impl = DebugHostStatus(jna_data)
print(status_impl.get_pointer())
print(status_impl.poll_user_interrupt())

```

Please note that Python does not have direct equivalent to Java's `Pointer` and `BOOLByReference`. In the above code, we are using `ctypes.c_bool(0)` as a replacement for `BOOLByReference`, assuming you want to get boolean value from the method.