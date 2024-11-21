from ctypes import wstring_at as WString
import win32api  # for WinDef types (ULONG, ULONGLONG)
import sys  # for HRESULT type

class ListenerIDebugOutputCallbacks2:
    FIELDS = ["vtbl"]

    def __init__(self, callback):
        self.vtbl = self.construct_vtable()
        self.init_vtable(callback)

    @property
    def vtbl(self):
        return self._vtbl

    @vtbl.setter
    def vtbl(self, value):
        self._vtbl = value

    def construct_vtable(self):
        # equivalent to new VTableIDebugOutputCallbacks2.ByReference()
        pass  # implement this in Python

    def init_vtable(self, callback):
        self.vtbl.QueryInterfaceCallback = lambda refid, ppvObject: callback.QueryInterface(refid, ppvObject)
        self.vtbl.AddRefCallback = lambda: callback.AddRef()
        self.vtbl.ReleaseCallback = lambda: callback.Release()
        self.vtbl.OutputCallback = lambda Mask, Text: callback.Output(Mask, Text)
        self.vtbl.GetInterestMaskCallback = lambda Mask: callback.GetInterestMask(Mask)
        self.vtbl.Output2Callback = lambda Which, Flags, Arg, Text: callback.Output2(Which, Flags, Arg, Text)

    def Output(self, Mask, Text):
        return self.vtbl.OutputCallback(Mask, Text)

    def GetInterestMask(self, Mask):
        return self.vtbl.GetInterestMaskCallback(Mask)

    def Output2(self, Which, Flags, Arg, Text):
        return self.vtbl.Output2Callback(Which, Flags, Arg, Text)
