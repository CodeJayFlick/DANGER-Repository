import ctypes

class XWrapIDebugHostBaseClass:
    def __init__(self):
        pass

    def __init__(self, pv_instance):
        super().__init__()
        self.pv_instance = pv_instance

    def get_offset(self, offset):
        return _invoke_hr(VT_INDICES.GET_OFFSET, self.get_pointer(), offset)

class ByReference(XWrapIDebugHostBaseClass):
    pass

def _invoke_hr(method, pointer, offset):
    # implement this function to handle the HR (HRESULT) and VT_INDICES
    pass

VT_INDICES = {
    'GET_OFFSET': 0,
}

HResult = ctypes.c_int  # or some other suitable type for HRESULT
ULONGLONGByReference = ctypes.POINTER(ctypes.c_ulonglong)

# usage example:
x = XWrapIDebugHostBaseClass()
offset = ULONGLONGByReference(0)
hr = x.get_offset(offset)
print(hr)  # print the result of _invoke_hr function
