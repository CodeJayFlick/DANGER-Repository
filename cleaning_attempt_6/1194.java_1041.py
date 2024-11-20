import ctypes

class WrapIDebugHostStatus:
    def __init__(self):
        pass

    def __init__(self, pv_instance):
        self.pv_instance = pv_instance

    def poll_user_interrupt(self) -> int:
        return _invoke_hr(VT_INDICES.POLL_USER_INTERRUPT, self.pv_instance)

class ByReference(WrapIDebugHostStatus):
    pass

VT_INDICES = {
    'POLL_USER_INTERRUPT': 0
}

def _invoke_hr(index: int, pv_instance: ctypes.POINTER, interrupt_requested: bool) -> int:
    # implement the actual logic here
    return 0
