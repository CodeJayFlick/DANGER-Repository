from enum import Enum
import ctypes

class VTIndices(Enum):
    GET_KEY_NAME = 0
    GET_ORIGINAL_OBJECT = 1
    GET_CONTAINING_OBJECT = 2
    GET_KEY = 3
    GET_KEY_VALUE = 4
    SET_KEY = 5
    SET_KEY_VALUE = 6


class IModelKeyReference:
    IID_IMEDEL_REFERENCE = "5253DCF8-5AFF-4c62-B302-56A289E00998"

    def __init__(self):
        pass

    def get_key_name(self) -> str:
        # Implement the GetKeyName method
        raise NotImplementedError("Method not implemented")

    def get_original_object(self) -> ctypes.POINTER(None):
        # Implement the GetOriginalObject method
        raise NotImplementedError("Method not implemented")

    def get_context_object(self) -> ctypes.POINTER(None):
        # Implement the GetContextObject method
        raise NotImplementedError("Method not implemented")

    def get_key(self, object: ctypes.POINTER(None), metadata: ctypes.POINTER(None)) -> int:
        # Implement the GetKey method
        raise NotImplementedError("Method not implemented")

    def get_key_value(self, object: ctypes.POINTER(None), metadata: ctypes.POINTER(None)) -> int:
        # Implement the GetKeyValue method
        raise NotImplementedError("Method not implemented")

    def set_key(self, object: ctypes.POINTER(None), metadata: ctypes.POINTER(None)) -> int:
        # Implement the SetKey method
        raise NotImplementedError("Method not implemented")

    def set_key_value(self, object: ctypes.POINTER(None)) -> int:
        # Implement the SetKeyValue method
        raise NotImplementedError("Method not implemented")
