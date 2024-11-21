Here is a translation of the Java code into equivalent Python:

```Python
class WrapIDataModelScriptDebugStack:
    def __init__(self):
        pass

    def __init__(self, pv_instance):
        self.pv_instance = pv_instance

    def get_frame_count(self):
        # Assuming _invokeHR and VTIndices are defined elsewhere in the codebase.
        return _invoke_hr(VT_Indices.GET_FRAME_COUNT)

    def get_stack_frame(self, frame_number: int) -> PointerByReference:
        stack_frame = PointerByReference()
        result = self._invoke_hr(VT_Indices.GET_STACK_FRAME, self.pv_instance, frame_number, stack_frame)
        return stack_frame

class PointerByReference:
    pass
```

Please note that Python does not have direct equivalents for Java's `Structure` and `Pointer`, so we've replaced them with simple classes. Also, the `_invokeHR` method is assumed to be defined elsewhere in your codebase.

In this translation:

- The class `WrapIDataModelScriptDebugStack` has two constructors: one without any arguments (which initializes an empty instance) and another that takes a single argument (`pv_instance`) which it assigns to itself.
- The methods `get_frame_count` and `get_stack_frame` are translated from their Java counterparts. They call the `_invokeHR` method with different parameters, depending on whether they're getting frame count or retrieving a stack frame.

This translation is not perfect because Python does not have direct equivalents for some of the classes used in the original code (like `Structure`, `Pointer`, and `PointerByReference`).