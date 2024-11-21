from enum import Enum

class VTIndicesX(Enum):
    GET_LOCATION_KIND = 0
    GET_LOCATION = 1


class IDebugHostPublic:
    IID_IDEBUG_HOST_PUBLIC = "6C597AC9-FB4D-4f6d-9F39-22488539F8F4"

    def get_location_kind(self):
        pass

    def get_location(self, location):
        pass
