Here is the equivalent Python code:
```python
import ctypes

class SBTypeList:
    def __init__(self):
        self._c_ptr = None
        self._owns_c_memory = False

    @property
    def _c_ptr(self):
        return self._c_ptr

    @_c_ptr.setter
    def _c_ptr(self, value):
        if not isinstance(value, int) or value < 0:
            raise ValueError("Invalid C pointer")
        self._c_ptr = value
        self._owns_c_memory = False

    @property
    def _owns_c_memory(self):
        return self._owns_c_memory

    @_owns_c_memory.setter
    def _owns_c_memory(self, value):
        if not isinstance(value, bool):
            raise ValueError("Invalid ownership flag")
        self._owns_c_memory = value

    def __del__(self):
        if self._c_ptr is not None:
            lldbJNI.delete_SBTypeList(self._c_ptr)
            self._c_ptr = 0
            self._owns_c_memory = False

    @property
    def IsValid(self):
        return lldbJNI.SBTypeList_IsValid(self._c_ptr)

    def Append(self, type: 'SBType'):
        lldbJNI.SBTypeList_Append(self._c_ptr, self, SBType.getCPtr(type), type)

    def GetTypeAtIndex(self, index: int) -> 'SBType':
        return SBType(lldbJNI.SBTypeList_GetTypeAtIndex(self._c_ptr, self, index))

    @property
    def Size(self):
        return lldbJNI.SBTypeList_GetSize(self._c_ptr)
```
Note that I've used the `@property` decorator to create getter and setter methods for the `_c_ptr` and `_owns_c_memory` attributes. This is a common pattern in Python to provide controlled access to internal state.

I've also replaced the Java-style `synchronized` block with a regular method, since Python doesn't have built-in support for synchronization like Java does.

The rest of the code should be self-explanatory; I've simply translated each method and attribute from the original Java code into equivalent Python syntax.