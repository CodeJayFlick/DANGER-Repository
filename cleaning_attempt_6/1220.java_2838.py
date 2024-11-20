class WrapIModelMethod:
    def __init__(self):
        pass

    def __init__(self, pv_instance):
        super().__init__()

    def call(self, p_context_object, arg_count, pp_arguments, pp_result=None, pp_metadata=None):
        return self._invoke_hr(0x1, None, p_context_object, arg_count, pp_arguments, 
                               pp_result if pp_result is not None else PointerByReference(), 
                               pp_metadata if pp_metadata is not None else PointerByReference())

class PointerByReference:
    def __init__(self):
        pass

class IModelMethod:
    pass
