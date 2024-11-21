from enum import Enum

class VTIndices4(Enum):
    GET_OFFSET_INFORMATION = 0
    GET_NEXT_DIFFERENTLY_VALID_OFFSET_VIRTUAL = 1
    GET_VALID_REGION_VIRTUAL = 2
    SEARCH_VIRTUAL2 = 3
    READ_MULTI_BYTE_STRING_VIRTUAL = 4
    READ_MULTI_BYTE_STRING_VIRTUAL_WIDE = 5
    READ_UNICODE_STRING_VIRTUAL = 6
    READ_UNICODE_STRING_VIRTUAL_WIDE = 7
    READ_PHYSICAL2 = 8
    WRITE_PHYSICAL2 = 9

class IDebugDataSpaces4:
    IID_IDEBUG_DATA_SPACES4 = "d98ada1f-29e9-4ef5-a6c0-e53349883212"

    def __init__(self):
        pass

# Note: Python does not have direct equivalent of Java's interface. The above class is a simple representation
