from enum import Enum

class VTIndices2(Enum):
    VIRTUAL_TO_PHYSICAL = 0
    GET_VIRTUAL_TRANSLATION_PHYSICAL_OFFSETS = 1
    READ_HANDLE_DATA = 2
    FILL_VIRTUAL = 3
    FILL_PHYSICAL = 4
    QUERY_VIRTUAL = 5


class IDebugDataSpaces2:
    IID_IDEBUG_DATA_SPACES2 = "7a5e852f-96e9-468f-ac1b-0b3addc4a049"

    def QueryVirtual(self, Offset: int, Info):
        pass
