import ctypes

class IDataModelNameBinder:
    IID_IDATA_MODEL_NAME_BINDER = "AF352B7B-8292-4c01-B360-2DC3696C65E7"

    VTIndices = {
        'BIND_VALUE': 0,
        'BIND_REFERENCE': 1,
        'ENUMERATE_VALUES': 2,
        'ENUMERATE_REFERENCES': 3
    }

    def bind_value(self, context_object, name: str, value, metadata):
        return ctypes.c_long(-1)  # assume HRESULT is a long

    def bind_reference(self, context_object, name: str, reference, metadata):
        return ctypes.c_long(-1)

    def enumerate_values(self, context_object, enumerator):
        return ctypes.c_long(-1)

    def enumerate_references(self, context_object, enumerator):
        return ctypes.c_long(-1)
