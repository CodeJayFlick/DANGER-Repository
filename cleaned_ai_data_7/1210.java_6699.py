from ctypes import POINTER, HRESULT, GUID

class VTableIndex:
    OVERRIDE_CONTEXT_OBJECT = 0

    def __init__(self):
        self.start = type(self).OVERRIDE_CONTEXT_OBJECT + 1

    @property
    def getIndex(self):
        return self.ordinal() + self.start


class IModelKeyReference2(IModelKeyReference):
    IID_IMODEL_REFERENCE2 = GUID("80E2F7C5-7159-4e92-887E-7E0347E88406")

    VTIndices2 = VTableIndex()

    def OverrideContextObject(self, new_context_object: POINTER) -> HRESULT:
        pass


class IModelKeyReference:
    pass
