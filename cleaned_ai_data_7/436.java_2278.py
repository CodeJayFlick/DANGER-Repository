class DebugAdvancedImpl1:
    def __init__(self, jna_advanced):
        self.cleanable = None  # Equivalent to OpaqueCleanable in Java
        self.jna_advanced = jna_advanced

    def get_thread_basic_information(self, tid):
        raise NotImplementedError("Not supported by this interface")
