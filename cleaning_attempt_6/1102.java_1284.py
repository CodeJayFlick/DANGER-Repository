from ctypes import POINTER, HRESULT, byref
import uuid

class IPreferredRuntimeTypeConcept:
    IID_ = uuid.UUID('9D6C1D7B-A76F-4618-8068-5F76BD9A4E8A')

    VTIndices = {
        'CAST_TO_PREFERRED_RUNTIME_TYPE': 0,
    }

    def cast_to_preferred_runtime_type(self, context_object: POINTER, object_byref: byref):
        pass
