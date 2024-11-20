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
