import ctypes
from comtypes import HRESULT, COMError

class ModelPropertyAccessorImpl:
    def __init__(self, jna_data):
        self.cleanable = None  # OpaqueCleanable in Java
        self.jna_data = jna_data

    def get_pointer(self):
        return self.jna_data.get_pointer()

    def get_value(self, key: str, context_object) -> object:
        p_context_object = ctypes.cast(context_object.get_pointer(), ctypes.POINTER(ctypes.c_void_p))
        pp_value = ctypes.pointer(ctypes.c_void_p())
        hr = self.jna_data.get_value(key.encode('utf-8'), p_context_object, pp_value)
        if hr == HRESULT.E_INVALID_PARAMETER:
            print(f"{key} invalid param")
            return None
        COMError.check_rc(hr)

        value_pointer = pp_value.contents.value
        try:
            return ModelObject(value_pointer)  # equivalent to WrapIModelObject in Java
        finally:
            ctypes.c_void_p.from_address(value_pointer).release()

    def set_value(self, key: str, context_object, value):
        p_context_object = ctypes.cast(context_object.get_pointer(), ctypes.POINTER(ctypes.c_void_p))
        p_value = ctypes.cast(value.get_pointer(), ctypes.POINTER(ctypes.c_void_p))
        self.jna_data.set_value(key.encode('utf-8'), p_context_object, p_value)
