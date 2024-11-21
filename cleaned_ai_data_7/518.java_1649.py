from enum import Enum

class VTIndices6(Enum):
    GET_EXECUTABLE_STATUS_EX = 0
    GET_SYNCHRONIZATION_STATUS = 1


class IDebugControl6:
    IID_IDEBUG_CONTROL6 = "bc0d583f-126d-43a1-9cc4-860ab1d537b"

    def get_execution_status_ex(self, status):
        pass

# Note: The following Python code is not equivalent to the given Java code.
# It's just a simple translation of the interface and enum definitions.

