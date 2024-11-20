from enum import Enum

class VTIndices(Enum):
    RESET = 0
    GET_NEXT = 1


class IDataModelScriptDebugBreakpointEnumerator:
    IID_IData_Model_Script_Debug_Breakpoint_Enum = "39484A75-4F3B479986DA691AF57B299"

    def __init__(self):
        pass

    def Reset(self) -> int:
        # Implement the logic for resetting
        return 0

    def GetNext(self, breakpoint: 'PointerByReference') -> int:
        # Implement the logic for getting next breakpoint
        return 0


class PointerByReference:
    def __init__(self):
        pass
