from enum import Enum

class VTIndices5(Enum):
    GET_STACK_TRACE_EX = 0
    OUTPUT_STACK_TRACE_EX = 1
    GET_CONTEXT_STACK_TRACE_EX = 2
    OUTPUT_CONTEXT_STACK_TRACE_EX = 3
    GET_BREAKPOINT_BY_GUID = 4


class IDebugControl5:
    IID_IDEBUG_CONTROL5 = "b2ffe162-2412-429f-8d1d-5bf6dd824696"

    def __init__(self):
        pass

    @classmethod
    def get_stack_trace_ex(cls, *args):
        # TO DO: implement this method
        return None

    @classmethod
    def output_stack_trace_ex(cls, *args):
        # TO DO: implement this method
        return None

    @classmethod
    def get_context_stack_trace_ex(cls, *args):
        # TO DO: implement this method
        return None

    @classmethod
    def output_context_stack_trace_ex(cls, *args):
        # TO DO: implement this method
        return None

    @classmethod
    def get_breakpoint_by_guid(cls, guid):
        # TO DO: implement this method
        return None


if __name__ == "__main__":
    i = IDebugControl5()
