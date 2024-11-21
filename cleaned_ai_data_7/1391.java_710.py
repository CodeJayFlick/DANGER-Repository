class GdbReason:
    """Indicates the reason for a thread's state to change."""
    
    class Reasons(enum.Enum):
        NONE = "No reason"
        UNKNOWN = "Unknown"

    @staticmethod
    def get_reason(info: dict) -> 'GdbReason':
        if not info.get("reason"):
            return GdbReason.Reasons.NONE
        
        reason_str = info["reason"]
        
        for k, v in GdbReason.TYPES.items():
            if k == reason_str:
                return v[0](info)
        
        print(f"Unknown stop reason: {reason_str}")
        return GdbReason.Reasons.UNKNOWN

    @staticmethod
    def get_types() -> dict:
        return {
            "signal-received": lambda x: GdbSignalReceivedReason(),
            "breakpoint-hit": lambda x: GdbBreakpointHitReason(),
            "end-stepping-range": lambda x: GdbEndSteppingRangeReason(),
            "exited": lambda x: GdbExitedReason(),
            "exited-normally": lambda x: GdbExitNormallyReason()
        }

class GdbSignalReceivedReason:
    pass

class GdbBreakpointHitReason:
    pass

class GdbEndSteppingRangeReason:
    pass

class GdbExitedReason:
    pass

class GdbExitNormallyReason:
    pass
