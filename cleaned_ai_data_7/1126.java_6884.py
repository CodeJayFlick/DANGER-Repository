import ctypes

class WrapIDataModelScriptDebugBreakpointEnumerator:
    def __init__(self):
        pass

    def __init__(self, pv_instance):
        self.pv_instance = pv_instance

    def Reset(self):
        # Assuming _invokeHR and VTIndices are defined elsewhere in the codebase.
        return _invokeHR(VTIndices.RESET, self.pv_instance)

    def GetNext(self, breakpoint_by_reference):
        return _invokeHR(VTIndices.GET_NEXT, self.pv_instance, breakpoint_by_reference)


class ByReference(WrapIDataModelScriptDebugBreakpointEnumerator):
    pass
