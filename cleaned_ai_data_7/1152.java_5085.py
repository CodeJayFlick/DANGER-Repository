from enum import Enum

class VTIndices(Enum):
    GET_HOST_DEFINED_INTERFACE = 3
    GET_CURRENT_CONTEXT = 4
    GET_DEFAULT_METADATA = 5


class IDebugHost:
    IID_IDEBUG_HOST = "B8C74943-6B2C-4eeb-B5C5-35D378A6D99D"

    def __init__(self):
        pass

    def get_host_defined_interface(self, host_unk):
        # Implement the method
        raise NotImplementedError("Method not implemented")

    def get_current_context(self, context):
        # Implement the method
        raise NotImplementedError("Method not implemented")

    def get_default_metadata(self, default_metadata_store):
        # Implement the method
        raise NotImplementedError("Method not implemented")
