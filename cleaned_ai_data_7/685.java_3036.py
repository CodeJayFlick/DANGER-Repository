class DbgBreakpointCreatedEvent:
    def __init__(self, info):
        self._bkpt_info = info

    @property
    def breakpoint_info(self):
        return self._bkpt_info


from typing import Any

class AbstractDbgEvent(T):  # Note: This is not a built-in Python class. You would need to define it.
    pass
