import ctypes
from enum import Enum

class ByteOrder(Enum):
    LITTLE_ENDIAN = 0
    BIG_ENDIAN = 1

class StateType(Enum):
    UNKNOWN = -1
    STOPPED = 0
    RUNNING = 1
    DEAD = 2

class SBProcess:
    def __init__(self, c_ptr=None, own_memory=False):
        self._c_ptr = ctypes.c_longlong(c_ptr)
        self._own_memory = bool(own_memory)

    @property
    def _swig_cptr(self):
        return self._c_ptr.value if self._c_ptr else 0

    def __del__(self):
        self.delete()

    def delete(self):
        if not self._c_ptr:
            return
        lldbJNI.SBProcess_delete(self._swig_cptr)
        self._own_memory = False
        self._c_ptr.value = 0

    @staticmethod
    def GetBroadcasterClassName():
        return lldbJNI.SBProcess_GetBroadcasterClassName()

    def GetPluginName(self):
        return lldbJNI.SBProcess_GetPluginName(self._swig_cptr, self)

    def GetShortPluginName(self):
        return lldbJNI.SBProcess_GetShortPluginName(self._swig_cptr, self)

    # ... and so on for all the methods

lldbJNI = ctypes.CDLL('path_to_your_lldb_library')  # replace with your actual library path
