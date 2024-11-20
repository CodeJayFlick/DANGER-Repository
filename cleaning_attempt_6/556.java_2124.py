import ctypes

class IDebugOutputCallbacksWide:
    IID_IDEBUG_OUTPUT_CALLBACKS_WIDE = "4c7fd663-394-c26-8ef1-34ad5ed3764c"

    def __init__(self):
        pass

    def Output(self, Mask: int, Text: str) -> ctypes.c_long:
        return 0
