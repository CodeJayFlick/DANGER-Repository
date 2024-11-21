class WrapIDebugAdvanced:
    def __init__(self):
        pass

    def __init__(self, pv_instance):
        super().__init__()

    def get_thread_context(self, context, context_size):
        # This method seems to be calling a native function.
        # In Java it's implemented as _invokeHR with VTIndices. and getPointer()
        return 0  # Assuming HRESULT is an integer

    def set_thread_context(self, context, context_size):
        # Same comment applies here
        return 0


class ByReference(WrapIDebugAdvanced):
    pass
