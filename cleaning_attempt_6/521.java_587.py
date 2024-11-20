class WrapIDebugControl2:
    def __init__(self):
        pass

    def __init__(self, pv_instance):
        super().__init__(pv_instance)

# Define a nested class ByReference that inherits from Structure.ByReference
class ByReference(Structure.ByReference):
    _fields_ = []
