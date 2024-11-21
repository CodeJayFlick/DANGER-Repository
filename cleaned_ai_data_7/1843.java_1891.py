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
