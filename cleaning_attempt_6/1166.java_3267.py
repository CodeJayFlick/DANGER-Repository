from enum import Enum

class VTableIndex(Enum):
    IS_MATCH = 3


class IDebugHostModuleSignature:
    IID_IDEBUG_HOST_MODULE_SIGNATURE = "31E53A5A-01EE-4BBB-89944B46AE7D595C"

    def __init__(self):
        pass

    def is_match(self, p_module: object, is_match_by_ref: bool) -> int:
        # This method should return a Windows HRESULT value
        raise NotImplementedError("is_match must be implemented")
