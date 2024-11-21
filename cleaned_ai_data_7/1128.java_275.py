class WrapIDataModelScriptDebugStack:
    def __init__(self):
        pass

    def __init__(self, pv_instance):
        self.pv_instance = pv_instance

    def get_frame_count(self):
        # Assuming _invokeHR and VTIndices are defined elsewhere in the codebase.
        return _invoke_hr(VT_Indices.GET_FRAME_COUNT)

    def get_stack_frame(self, frame_number: int) -> PointerByReference:
        stack_frame = PointerByReference()
        result = self._invoke_hr(VT_Indices.GET_STACK_FRAME, self.pv_instance, frame_number, stack_frame)
        return stack_frame

class PointerByReference:
    pass
