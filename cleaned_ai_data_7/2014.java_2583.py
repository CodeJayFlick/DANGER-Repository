class JdiReason:
    class Reasons(enum.Enum):
        NONE = "No reason"
        STEP = "Step"
        INTERRUPT = "Interrupt"
        BREAKPOINT_HIT = "Breakpoint hit"
        WATCHPOINT_HIT = "Watchpoint hit"
        ACCESS_WATCHPOINT_HIT = "Access Watchpoint"
        RESUMED = "Target resumed"
        UNKNOWN = "Unknown"

    def __init__(self, reason):
        self.reason = reason

    @property
    def desc(self):
        return self.reason


class JdiReasonFactory:
    _reasons_map = {
        "signal-received": lambda: JdiSignalReceivedReason(),
        "breakpoint-hit": lambda: JdiBreakpointHitReason(),
        "end-stepping-range": lambda: JdiEndSteppingRangeReason(),
        "exited": lambda: JdiExitedReason(),
        "exited-normally": lambda: JdiExitNormallyReason()
    }

    @classmethod
    def get_reason(cls, reason):
        return cls._reasons_map.get(reason.lower(), lambda: JdiUnknownReason())()


class JdiSignalReceivedReason(JdiReason):
    pass


class JdiBreakpointHitReason(JdiReason):
    pass


class JdiEndSteppingRangeReason(JdiReason):
    pass


class JdiExitedReason(JdiReason):
    pass


class JdiExitNormallyReason(JdiReason):
    pass


class JdiUnknownReason(JdiReason):
    def __init__(self):
        super().__init__("A reason was given, but the manager does not understand it")
