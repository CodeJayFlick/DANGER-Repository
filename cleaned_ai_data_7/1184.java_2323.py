class WrapIDebugHostEvaluator2:
    def __init__(self):
        pass

    def __init__(self, pv_instance):
        super().__init__()
        self.pv_instance = pv_instance

    def AssignTo(self, assignment_reference, assignment_value, assignment_result=None, assignment_metadata=None):
        return self._invoke_hr(VTIndices2.ASSIGN_TO, self.get_pointer(), assignment_reference, assignment_value,
                               assignment_result if assignment_result is not None else PointerByReference(None),
                               assignment_metadata if assignment_metadata is not None else PointerByReference(None))

class ByReference(WrapIDebugHostEvaluator2):
    pass

class HRESULT:
    def __init__(self):
        pass
