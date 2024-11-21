Here is the translation of the Java code to Python:
```
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
```
Note that I've used `ctypes` library to represent Java's `Pointer` and `HRESULT` types in Python. The `_invoke_hr` function is a placeholder for the actual implementation of the invocation logic, which you would need to implement based on your specific requirements.

Also, please note that this translation is not exact, as some details like type conversions and method signatures might be different between Java and Python.