from ctypes import POINTER, HRESULT, c_bool

class VTIndices:
    IS_EQUAL_TO = 0

start = 3

def get_index(self):
    return self.ordinal() + start


class IDebugHostContext:
    IID_IDEBUG_HOST_CONTEXT = "A68C70D8-5EC0-46e5-B775-3134A48EA2E3"

    def IsEqualTo(self, p_context: POINTER, p_is_equal_by_ref: c_bool) -> HRESULT:
        pass
