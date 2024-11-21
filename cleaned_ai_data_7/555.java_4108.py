import ctypes

class IDebugOutputCallbacks2:
    IID_IDEBUG_OUTPUT_CALLBACKS2 = "67721fe9-56d2-4a44-a325-2b65513ce6eb"

    def get_interest_mask(self):
        raise NotImplementedError("GetInterestMask not implemented")

    def output2(self, which: int, flags: int, arg: int, text: str) -> None:
        raise NotImplementedError("Output2 not implemented")
