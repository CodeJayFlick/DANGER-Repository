import ctypes

class WrapIDataModelScriptTemplateEnumerator:
    def __init__(self):
        pass

    def __init__(self, pv_instance):
        self.pv_instance = pv_instance

    def Reset(self) -> int:
        return _invoke_hr(0x0001, self.pv_instance)

    def GetNext(self, template_content: ctypes.POINTER(ctypes.c_void_p)) -> int:
        return _invoke_hr(0x0002, self.pv_instance, template_content)

def _invoke_hr(operation_id: int, pv_instance: int, *args) -> int:
    # implement the actual invocation logic here
    pass

class ByReference(WrapIDataModelScriptTemplateEnumerator):
    def __init__(self):
        super().__init__()

# usage example:
wrapper = WrapIDataModelScriptTemplateEnumerator()
result = wrapper.Reset()  # returns an integer (HRESULT)
template_content = ctypes.POINTER(ctypes.c_void_p)()
result = wrapper.GetNext(template_content)  # returns an integer (HRESULT)
