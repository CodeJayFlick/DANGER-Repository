import ctypes

class IUnknownEx:
    def __init__(self):
        pass

    def get_pointer(self) -> ctypes.POINTER(None):
        return None
