class SBMemoryRegionInfo:
    def __init__(self):
        self._swig_c_ptr = None
        self._swig_cmemoown = False

    @staticmethod
    def get_c_ptr(obj):
        if obj is None:
            return 0
        else:
            return obj._swig_c_ptr

    def delete(self):
        if self._swig_c_ptr != 0:
            if self._swig_cmemoown:
                self._swig_cmemoown = False
                lldb_jni.delete_SBMemoryRegionInfo(self._swig_c_ptr)
            self._swig_c_ptr = 0

    def __del__(self):
        self.delete()

    @property
    def cptr(self):
        return self._swig_c_ptr

    @cptr.setter
    def cptr(self, value):
        if not isinstance(value, int) or value < 0:
            raise ValueError("Invalid C pointer")
        self._swig_c_ptr = value

    @property
    def cmemoown(self):
        return self._swig_cmemoown

    @cmemoown.setter
    def cmemoown(self, value):
        if not isinstance(value, bool):
            raise ValueError("Boolean expected for cmoewwn")
        self._swig_cmemoown = value

    def clear(self):
        lldb_jni.SBMemoryRegionInfo_Clear(self.cptr)

    @property
    def region_base(self):
        return lldb_jni.SBMemoryRegionInfo_GetRegionBase(self.cptr)

    @property
    def region_end(self):
        return lldb_jni.SBMemoryRegionInfo_GetRegionEnd(self.cptr)

    def is_readable(self):
        return lldb_jni.SBMemoryRegionInfo_IsReadable(self.cptr)

    def is_writable(self):
        return lldb_jni.SBMemoryRegionInfo_IsWritable(self.cptr)

    def is_executable(self):
        return lldb_jni.SBMemoryRegionInfo_IsExecutable(self.cptr)

    def is_mapped(self):
        return lldb_jni.SBMemoryRegionInfo_IsMapped(self.cptr)

    @property
    def name(self):
        return lldb_jni.SBMemoryRegionInfo_GetName(self.cptr)

    def get_description(self, description_stream):
        return lldb_jni.SBMemoryRegionInfo_GetDescription(self.cptr, description_stream)

    def __str__(self):
        return lldb_jni.SBMemoryRegionInfo___str__(self.cptr)
