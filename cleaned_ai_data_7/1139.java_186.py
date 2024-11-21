from comtypes import GUID, HRESULT, _None
import ctypes

class IDataModelScriptTemplateEnumerator:
    IID_IDATA_MODEL_SCRIPT_TEMPLATE_ENUMERATOR = GUID("69CE6AE2-2268-4e6f-B062-20CE62BFE677")

    VTIndices = {
        'RESET': 0,
        'GET_NEXT': 1
    }

    def __init__(self):
        self.vt_indices_start = 3

    @property
    def vtable_index(self):
        return lambda: [x + self.vt_indices_start for x in self.VTIndices.values()]

    def Reset(self) -> HRESULT:
        pass

    def GetNext(self, template_content: ctypes.POINTER(ctypes.c_char)) -> HRESULT:
        pass
