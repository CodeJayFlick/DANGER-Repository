from ctypes import POINTER, HRESULT, WINERROR_HRESULT
import uuid

class IModelPropertyAccessor:
    IID_IMODEL_PROPERTY_ACCESSOR = uuid.UUID('5A0C63D9-0526-42b8-960C-9516A3254C85')

    VTIndices = {
        'GET_VALUE': 3,
        'SET_VALUE': 4
    }

    def __init__(self):
        pass

    @WINERROR_HRESULT
    def get_value(self, key: str, context_object: int, value_ref: POINTER) -> None:
        raise NotImplementedError('Method not implemented')

    @WINERROR_HRESULT
    def set_value(self, key: str, context_object: int, pvalue: int) -> None:
        raise NotImplementedError('Method not implemented')
