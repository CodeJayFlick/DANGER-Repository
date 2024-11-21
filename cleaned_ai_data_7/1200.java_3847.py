class WrapIDebugHostType2:
    def __init__(self):
        pass

    def __init__(self, pv_instance):
        super().__init__()

    def IsTypedef(self, is_typedef):
        # Assuming _invokeHR and VTIndices2 are defined elsewhere in the codebase.
        return self._invoke_hr(VTIndices2.IS_TYPEDEF, self.get_pointer(), is_typedef)

    def GetTypedefBaseType(self, base_type):
        return self._invoke_hr(VTIndices2.GET_ETYPEDEF_BASE_TYPE, self.get_pointer(), base_type)

    def GetTypedefFinalBaseType(self, final_base_type):
        return self._invoke_hr(VTIndices2.GET_ETYPEDEF_FINAL_BASE_TYPE, self.get_pointer(), final_base_type)

    def GetFunctionVarArgsKind(self, var_args_kind):
        return self._invoke_hr(VTIndices2.GET_FUNCTION_VARARGS_KIND, self.get_pointer(), var_args_kind)

    def GetFunctionInstancePointerType(self, instance_pointertype):
        return self._invoke_hr(VTIndices2.GET_FUNCTION_INSTANCE_POINTER_TYPE, self.get_pointer(), instance_pointertype)


class ByReference:
    pass
