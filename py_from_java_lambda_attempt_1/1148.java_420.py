Here is the translation of the Java code to Python:
```
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
```
Note that I had to make some assumptions about the `_invoke_hr` function, as it was not provided in the original Java code. You will need to implement this function according to your specific requirements.

Also, I used the `ctypes` library to represent pointers and void pointers in Python, which is a common approach when working with C-like APIs.