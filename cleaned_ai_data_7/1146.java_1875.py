import ctypes

class WrapIDataModelScriptProviderEnumerator:
    def __init__(self):
        pass

    def __init__(self, pv_instance):
        self.pv_instance = pv_instance

    def Reset(self) -> int:
        return _invoke_hr(0x0001, self.pv_instance)

    def GetNext(self, provider: ctypes.POINTER(None)) -> int:
        return _invoke_hr(0x0002, self.pv_instance, provider)


def _invoke_hr(op_code: int, pv_instance: int, *args) -> int:
    # implement the actual invocation logic here
    pass

class ByReference(WrapIDataModelScriptProviderEnumerator):
    def __init__(self):
        super().__init__()

# usage example
provider = WrapIDataModelScriptProviderEnumerator()
result = provider.Reset()  # call Reset method
print(result)  # print the result

next_provider = ctypes.POINTER(None)(0)
result = provider.GetNext(next_provider)  # call GetNext method
print(result)  # print the result
