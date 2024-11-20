class LldbBreakpointType:
    BREAKPOINT = 'BREAKPOINT'
    HW_BREAKPOINT = 'HW_BREAKPOINT'
    WRITE_WATCHPOINT = 'WRITE_WATCHPOINT'
    READ_WATCHPOINT = 'READ_WATCHPOINT'
    ACCESS_WATCHPOINT = 'ACCESS_WATCHPOINT'
    OTHER = 'OTHER'

    @classmethod
    def from_str(cls, string):
        try:
            return getattr(LldbBreakpointType, string)
        except AttributeError:
            return LldbBreakpointType.OTHER

