Here is a translation of the Java interface into equivalent Python code:

```Python
from comtypes import GUID, HRESULT, BSTR, POINTER

class IDataModelScriptDebugVariableSetEnumerator:
    IID_ = GUID("0F9FEED7-D045-4ac3-98A8-A98942CF6A35")

    class VTIndices(int):
        RESET = 1
        GET_NEXT = 2

    def Reset(self) -> HRESULT:
        pass

    def GetNext(self, variableName: POINTER(BSTR), variableValue: POINTER(None), 
                variableMetadata: POINTER(None)) -> HRESULT:
        pass
```

Please note that Python does not have direct equivalent of Java's interface or enum. The above code is a simple translation and may need further modification based on your actual requirements.

Also, please be aware that the `comtypes` library used in this example provides a way to work with COM interfaces from Python, but it might require additional setup depending on how you are using it.